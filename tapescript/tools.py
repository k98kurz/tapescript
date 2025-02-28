from __future__ import annotations
from .AMHL import AMHL
from .classes import Tape, Stack
from .errors import tert, vert, yert
from .parsing import (
    compile_script,
    decompile_script,
    add_opcode_parsing_handlers,
    is_hex,
    assemble,
    get_symbols,
    parse_comptime,
)
from .functions import (
    opcodes_inverse,
    opcode_aliases,
    nopcodes_inverse,
    run_script,
    run_tape,
    run_auth_script,
    add_opcode,
    add_contract,
    remove_contract,
    add_contract_interface,
    remove_contract_interface,
    clamp_scalar,
    derive_key_from_seed,
    derive_point_from_scalar,
    aggregate_points,
    aggregate_scalars,
    sign_with_scalar,
    bytes_to_float,
    bytes_to_int,
    version,
    xor,
)
from .interfaces import ScriptProtocol
from dataclasses import dataclass, field
from hashlib import sha256
from sys import argv
from time import time
from typing import Callable
import nacl.bindings
import json
import struct


@dataclass
class Script:
    """Represent a script as a pairing of source and byte code."""
    src: str = field()
    bytes: bytes = field()

    @classmethod
    def from_src(cls, src: str) -> Script:
        """Create an instance from tapescript source code."""
        return cls(src, compile_script(src))

    @classmethod
    def from_bytes(cls, code: bytes) -> Script:
        """Create an instance from tapescript byte code."""
        return cls('\n'.join(decompile_script(code)), code)

    def commitment(self) -> bytes:
        """Return a cryptographic commitment for the Script."""
        return sha256(self.bytes).digest()

    def __bytes__(self) -> bytes:
        """Return the tapescript byte code."""
        return self.bytes

    def __str__(self) -> str:
        """Return the tapescript source code."""
        return self.src

    def __add__(self, other: Script) -> Script:
        """Add two instances together."""
        tert(isinstance(other, Script), 'cannot add Script to non-Script')
        return Script(f'{self.src}\n{other.src}', self.bytes + other.bytes)


@dataclass
class ScriptLeaf:
    """A leaf in a Merklized script tree."""
    hash: bytes = field()
    script: Script|None = field(default=None)
    parent: ScriptNode|None = field(default=None)

    def __str__(self) -> str:
        """Return a human-readable string representation of the script leaf."""
        return f"ScriptLeaf(src='{self.script.src}', hash={self.hash.hex()})"

    @classmethod
    def from_script(cls, script: Script) -> ScriptLeaf:
        """Create an instance from a Script object."""
        return cls(script.commitment(), script)

    @classmethod
    def from_src(cls, src: str) -> ScriptLeaf:
        """Create an instance from the source code."""
        return cls.from_script(Script.from_src(src))

    @classmethod
    def from_code(cls, code: bytes) -> ScriptLeaf:
        """Create an instance from the byte code."""
        return cls.from_script(Script.from_bytes(code))

    def commitment(self) -> bytes:
        """Return the cryptographic commitment for the leaf."""
        return self.hash

    def unlocking_script(self) -> Script:
        """Calculate an unlocking script recursively, traveling up the
            parents. Returns a Script with the source and byte codes.
            When executed, this will validate the LeafScript against the
            root ScriptNode commitment (within an `OP_MERKLEVAL` locking
            script), and then `OP_MERKLEVAL` will execute the underlying
            script.
        """
        vert(self.parent is not None,
             'leaf must be part of a tree to generate an unlocking script')
        other = self.parent.right if self.parent.left is self else self.parent.left
        commitment = other.commitment()
        src = f'push x{commitment.hex()}\npush x{self.script.bytes.hex()}'
        script = Script.from_src(src)

        previous = self.parent.unlocking_script()
        return Script(f'{script.src}\n{previous.src}', script.bytes + previous.bytes)

    def pack(self) -> bytes:
        """Serialize the instance to bytes."""
        return self.script.bytes

    @classmethod
    def unpack(cls, serialized: bytes) -> ScriptLeaf:
        """Deserialize an instance from bytes."""
        return cls.from_code(serialized)


class ScriptNode:
    """A node in a Merklized script tree."""
    left: ScriptLeaf|ScriptNode
    right: ScriptLeaf|ScriptNode
    parent: ScriptNode|None

    def __init__(self, left: ScriptLeaf|ScriptNode, right: ScriptLeaf|ScriptNode) -> None:
        """Initialize the instance."""
        left.parent = self
        right.parent = self
        self.left = left
        self.right = right
        self.parent = None

    def __str__(self) -> str:
        """Return a human-readable string representation of the node."""
        return f'{self.root().hex()}: [{self.left}, {self.right}]'

    def root(self) -> bytes:
        """Calculate and return the local root between the two branches."""
        return xor(
            sha256(self.left.commitment()).digest(),
            sha256(self.right.commitment()).digest()
        )

    def locking_script(self) -> Script:
        """Calculates the locking script for the node. Returns a Script
            with the source and byte codes in the form
            `OP_MERKLEVAL <root>`.
        """
        return Script.from_src(f'OP_MERKLEVAL x{self.root().hex()}')

    def commitment(self) -> bytes:
        """Calculates the commitment to execute this ScriptNode and
            returns as bytes.
        """
        return self.locking_script().commitment()

    def unlocking_script(self) -> Script:
        """Calculates a recursive unlocking script for the node. Returns
            a Script with the source and byte codes.
        """
        if not self.parent:
            return Script('', b'')

        other = self.parent.right if self.parent.left is self else self.parent.left
        commitment = other.commitment()
        src = f'push x{commitment.hex()}\npush x{self.locking_script().bytes.hex()}'
        script = Script.from_src(src)
        previous = self.parent.unlocking_script()
        return Script(f'{script.src}\n{previous.src}', script.bytes + previous.bytes)

    def pack(self) -> bytes:
        """Serialize the script tree to bytes."""
        left = self.left.pack()
        right = self.right.pack()
        return struct.pack(
            f'!cH{len(left)}scH{len(right)}s',
            b'L' if isinstance(self.left, ScriptLeaf) else b'N',
            len(left),
            left,
            b'L' if isinstance(self.right, ScriptLeaf) else b'N',
            len(right),
            right,
        )

    @classmethod
    def unpack(cls, data: bytes) -> ScriptNode:
        """Deserialize a script tree from bytes."""
        left_type, left_len, data = struct.unpack(f'!cH{len(data)-3}s', data)
        left_data, right_type, right_len, data = struct.unpack(
            f'!{left_len}scH{len(data)-3-left_len}s',
            data
        )
        right_data = data
        if len(data) > right_len:
            right_data, data = struct.unpack(f'!{right_len}s{len(data)-right_len}s', data)

        left = ScriptLeaf.unpack(left_data) if left_type == b'L' else ScriptNode.unpack(left_data)
        right = ScriptLeaf.unpack(right_data) if right_type == b'L' else ScriptNode.unpack(right_data)
        return cls(left, right)


def make_script_tree_prioritized(
        leaves: list[str|ScriptProtocol], tree: ScriptNode|None = None
    ) -> ScriptNode:
    """Construct a script tree from the leaves using a ScriptLeaf for
        each leaf script, combining the last two into a ScriptNode and
        then recursively combining a ScriptLeaf for the last of the
        remaining script leaves with the previously generated ScriptNode
        until all leaves have been included, priorizing the lower index
        leaf scripts with smaller unlocking script sizes.
    """
    tert(type(leaves) in (list, tuple), 'leaves must be list or tuple of str')
    for leaf in leaves:
        tert(type(leaf) is str or isinstance(leaf, ScriptProtocol),
             'leaves must be list or tuple of str|ScriptProtocol')
        vert(len(str(leaf)) > 0, 'leaves must not be empty')
    vert(len(leaves) >= 1, 'must be at least 1 leaf')

    for i in range(len(leaves)):
        if type(leaves[i]) is str:
            leaves[i] = Script.from_src(leaves[i])

    if tree:
        node = ScriptNode(
            ScriptLeaf.from_script(leaves.pop()),
            tree
        )
        if len(leaves):
            return make_script_tree_prioritized(leaves, node)
        return node

    if len(leaves) == 1:
        leaves.append(Script.from_src('false')) # filler branch

    # combine final 2 leaves
    node = ScriptNode(
        right=ScriptLeaf.from_script(leaves.pop()),
        left=ScriptLeaf.from_script(leaves.pop())
    )

    if len(leaves):
        return make_script_tree_prioritized(leaves, node)
    return node

def make_merklized_script_prioritized(
        leaves: list[str|ScriptProtocol]
    ) -> tuple[Script, list[Script]]:
    """Produces a Merklized, branching script structure with one leaf
        and one node at every level except for the last node, which is
        balanced. Returns a tuple of root locking script and list of
        unlocking scripts. The tree is unbalanced; execution is
        optimized for earlier branches (lower index leaf scripts), and
        execution is linearly worse for each subsequent branch. In
        practice, the input scripts should be locking scripts, and then
        they should be used by concatenating the corresponding unlocking
        script and the unlocking script from this function.
    """
    tree = make_script_tree_prioritized(leaves)
    lock = tree.locking_script()
    scripts = [tree.left.unlocking_script()]
    while type(tree.right) is ScriptNode:
        tree = tree.right
        scripts.append(tree.left.unlocking_script())
    scripts.append(tree.right.unlocking_script())
    return (lock, scripts)

def make_script_tree_balanced(leaves: list[str|ScriptProtocol]) -> ScriptNode:
    """Create a balanced script tree from the leaves, filling with
        filler leaves/branches to make sure the tree is balanced. The
        filler leaves take the form of `push x{16 random bytes} return`,
        so they can never validate, and they will have unique hashes to
        avoid revealing the presence of empty leaves/branches during
        execution of actual leaf scripts. Used internally by the
        `make_merklized_script_balanced` function.
    """
    tert(type(leaves) in (list, tuple), 'leaves must be list or tuple')
    for item in leaves:
        tert(type(item) is str or isinstance(item, ScriptProtocol),
             'leaves must be list or tuple of str|ScriptProtocol')

    # prepare leaves
    leaves = [Script.from_src(l) if type(l) is str else l for l in leaves]
    leaves: list[ScriptLeaf] = [ScriptLeaf.from_script(l) for l in leaves]
    empty_leaf = lambda: ScriptLeaf.from_src('push ~! { push d16 random } return')
    empty_node = lambda: ScriptNode(empty_leaf(), empty_leaf())
    if len(leaves) % 2:
        leaves.append(empty_leaf())

    # first combine leaves into nodes two at a time
    leaves.reverse()
    nodes = []
    while len(leaves):
        nodes.append(ScriptNode(leaves.pop(), leaves.pop()))

    while len(nodes) > 1:
        if len(nodes) % 2:
            nodes.append(empty_node())
        nodes.reverse()
        new_nodes = []
        while len(nodes):
            new_nodes.append(ScriptNode(nodes.pop(), nodes.pop()))
        nodes = new_nodes

    return nodes[0]

def make_merklized_script_balanced(
        leaves: list[str|ScriptProtocol]
    ) -> tuple[Script, list[Script]]:
    """Produces a Merklized, branching script with a balanced tree
        structure, filling with filler branches to make sure the tree is
        balanced (calls `make_script_tree_balanced` under the hood).
        Returns a tuple of root locking script and list of unlocking
        scripts corresponding to the input scripts. In practice, the
        input scripts should be locking scripts, and then they should be
        used by concatenating the corresponding unlocking script and the
        unlocking script from this function.
    """
    leaves = [Script.from_src(l) if type(l) is str else l for l in leaves]
    tree = make_script_tree_balanced(leaves)
    lock = tree.locking_script()

    def _find_leaves(node: ScriptNode) -> list[ScriptLeaf]:
        _leaves = []
        if type(node.left) is ScriptLeaf:
            _leaves.append(node.left)
        else:
            _leaves.extend(_find_leaves(node.left))
        if type(node.right) is ScriptLeaf:
            _leaves.append(node.right)
        else:
            _leaves.extend(_find_leaves(node.right))
        return _leaves

    script_leaves = _find_leaves(tree)
    script_leaves = script_leaves[:len(leaves)]
    scripts = [leaf.unlocking_script() for leaf in script_leaves]
    return lock, scripts

def repl(
        cache: dict = {}, contracts: dict = {}, add_flags: dict = {},
        plugins: dict = {}
    ) -> None:
    """Provides a REPL (Read Execute Print Loop). Lines of source code
        are read, compiled, and executed, and the runtime state is
        shared between executions. If a code block is opened, the Read
        functionality will continue accepting input until all opened
        code blocks have closed, and it will automatically indent the
        input line. To exit the loop, type "return", "exit", or "quit".
    """
    if "timestamp" not in cache:
        cache["timestamp"] = int(time())
    stack = Stack()
    defs = {}
    macros = {}

    def printout():
        print(f'stack: {[f"0x{item.hex()}" for item in stack.deque]}')
        pc = {
            key: (f'0x{val.hex()}' if type(val) is bytes else (
                [f'0x{v.hex()}' if type(v) is bytes else v for v in val]
                if type(val) is list else val
            ))
            for key, val in cache.items()
            if type(key) in (str, int) and type(val)
        }
        pc = {
            **pc,
            ** {
                f'0x{key.hex()}': (f'0x{val.hex()}' if type(val) is bytes else (
                    [f'0x{v.hex()}' if type(v) is bytes else v for v in val]
                    if type(val) is list else val
                ))
                for key, val in cache.items()
                if type(key) is bytes
            }
        }
        print(f'cache: {pc}')

    while True:
        src = input("> ")

        # repl helpers
        if src == '':
            continue
        if src == "show":
            printout()
            continue
        if src in ("quit", "return", "exit", "q"):
            return
        if src == '~ts':
            cache["timestamp"] = int(time())
            print(cache["timestamp"])
            continue
        try:
            if src == '~d':
                print(bytes_to_int(stack.peek()))
                continue
            if src == '~f':
                val = stack.peek()
                print(bytes_to_float(val))
                continue
            if src.split()[0][:2] == '~s':
                src = src.split(maxsplit=1)
                src2 = ''.join(src[1:])
                src = f'sigfield{src[0][2:]}'
                if len(src2) > 1:
                    if 'x' in src2[:2]:
                        cache[src] = bytes.fromhex(src2.split('x')[1])
                    elif len(src2):
                        cache[src] = src2.encode()
                print(cache[src])
                continue
        except BaseException as e:
            print(f"{e.__class__.__name__}: {str(e)}")
            continue
        if src in ("help", "?"):
            print(
                'Assembles and runs scripts. Type "exit", "quit", or "q" ' +\
                'to exit; "show" to show the stack and cache; "~~ x<hex>" ' +\
                'to decompile bytecode; "~ts" to update the cached ' +\
                'timestamp to the current Unix epoch timestamp; ' +\
                '"~s[1-8]" to read the sigfield[1-8] and print out; ' +\
                '"~s[1-8] x<hex>" or "~s[1-8] str str str..." to set the ' +\
                'sigfield[1-8] to the given value; "~d" to decode the top ' +\
                'value as a signed int and print; "~f" to decode the top ' +\
                'value as a float32 and print.'
            )
            continue

        while src.count("{") > src.count("}") or src.count("(") > src.count("}"):
            indent = src.count("{") - src.count("}") + src.count("(") - src.count(")")
            src += "\n" + input("".join(["  " for _ in range(indent)]) + "> ")

        if src.startswith('~~'):
            try:
                src = src[2:].strip()
                if src.startswith('0x'):
                    src = src[2:]
                elif src.startswith('x'):
                    src = src[1:]
                print('\n'.join(decompile_script(bytes.fromhex(src))))
            except BaseException as e:
                print(str(e))
            continue

        try:
            tape = Tape(
                assemble(get_symbols(src), macros=macros),
                definitions=defs,
                contracts=contracts,
                plugins=plugins,
            )
            run_tape(
                tape,
                stack,
                cache,
                add_flags,
            )
            defs = tape.definitions
            printout()
        except BaseException as e:
            print(str(e))

def _format_docstring(docstring: str) -> str:
    """Takes a docstring, tokenizes it, and returns a str formatted to
        80 chars or fewer per line without splitting tokens.
    """
    if not docstring:
        return ""
    def make_line(tokens: list[str]) -> tuple[str, list[str]]:
        line = ''
        while len(tokens) and len(line) + len(tokens[0]) <= 80:
            line += tokens[0] + ' '
            tokens = tokens[1:]
        return (line[:-1], tokens)

    tokens = docstring.split()
    lines = []

    while len(tokens):
        line, tokens = make_line(tokens)
        if len(line) == 0 and len(tokens):
            lines.append(tokens[0])
            tokens = tokens[1:]
        else:
            lines.append(line)

    return '\n'.join(lines)

def _format_function_doc(function: Callable, extra_indent: int = 0) -> str:
    """Documents a function with header hashtags, annotations, and
        docstring.
    """
    docstring = _format_docstring(function.__doc__)
    name = function.__name__ or 'None'

    annotations = [
        f'{key}: {value.__name__ if hasattr(value, "__name__") else value}'
        for key,value in function.__annotations__.items()
        if key != 'return'
    ]
    defaults = [*function.__defaults__] if function.__defaults__ else []
    offset = len(annotations) - len(defaults)
    for i in range(len(defaults)):
        annotations[i+offset] += f' = {defaults[i]}'
    annotations = ', '.join(annotations) or ''

    return_annotation = function.__annotations__.get('return', 'unseen_return_value')
    if hasattr(return_annotation, '__name__'):
        return_annotation = return_annotation.__name__

    val = f'\n\n##{"".join(["#" for _ in range(extra_indent)])} `{name}'
    val += f'({annotations}): -> {return_annotation}`'
    val += f'\n\n{docstring}'
    return val

def _format_class_doc(cls: type) -> str:
    """Documents a class. Imports from autodox because I did not want to
        replicate code, but it is not ordinarily called during package
        use, so autodox is not considered a main dependency.
    """
    if 'dox_a_class' not in dir():
        from autodox import dox_a_class
    return dox_a_class(cls, {'header_level': 1})

def _get_op_aliases() -> dict[str, list[str]]:
    """Find and return all aliases for all ops."""
    aliases = {
        opname: []
        for opname in opcodes_inverse
    }
    for alias in opcode_aliases:
        aliases[opcode_aliases[alias]].append(alias)
    return aliases

def generate_docs() -> list[str]:
    """Generates the docs file using annotations and docstrings.
        Requires the autodox library, which is included in the optional
        "docs" dependencies.
    """
    data = {}
    aliases = _get_op_aliases()
    alias_lists = {
        opname: 'Aliases:\n- ' + '\n- '.join(aliases[opname])
        for opname in aliases
    }

    for opname in opcodes_inverse:
        number = opcodes_inverse[opname][0]
        doc = opcodes_inverse[opname][1].__doc__
        data[number] = (opname, doc, aliases[opname])

    nop_doc = None
    min_nop_number, max_nop_number = 255, 0
    for nopname in nopcodes_inverse:
        if nop_doc is None:
            nop_doc = nopcodes_inverse[nopname][1].__doc__
        number = nopcodes_inverse[nopname][0]
        min_nop_number = number if number < min_nop_number else min_nop_number
        max_nop_number = number if number > max_nop_number else max_nop_number
    nop_code_snippet = f"{min_nop_number}-{max_nop_number} " + \
        f"(x{min_nop_number.to_bytes(1, 'big').hex().upper()}-" + \
        f"{max_nop_number.to_bytes(1, 'big').hex().upper()})"
    nop_doc = f"Codes in {nop_code_snippet}\n" + nop_doc

    paragraphs = [
        '# OPs\n\n'
        'Each `OP_` function has an alias that excludes the `OP_` prefix.\n\n'
        'All `OP_` functions have the following signature:\n\n'
        '```python\n'
        'def OP_WHATEVER(tape: Tape, stack: Stack, cache: dict) -> None:\n'
        '    ...\n```\n\n'
        'All OPs advance the Tape pointer by the amount they read.\n'
    ]

    for number in data:
        line = f'\n## {data[number][0]} - {number} - x{number.to_bytes(1, "big").hex().upper()}\n\n'
        docstring = _format_docstring(data[number][1])
        paragraphs.append(line + docstring + f'\n\n{alias_lists[data[number][0]]}\n')

    paragraphs.append(f"\n## NOP Codes - {nop_code_snippet}\n\n" +
                      _format_docstring(nop_doc) + '\n')

    paragraphs.append('\n\n# Other interpreter functions')
    paragraphs.append(_format_function_doc(run_script))
    paragraphs.append(_format_function_doc(run_tape))
    paragraphs.append(_format_function_doc(run_auth_script))
    paragraphs.append(_format_function_doc(add_opcode))
    paragraphs.append(_format_function_doc(add_contract))
    paragraphs.append(_format_function_doc(remove_contract))
    paragraphs.append(_format_function_doc(add_contract_interface))
    paragraphs.append(_format_function_doc(remove_contract_interface))
    paragraphs.append('\n\n# Parsing functions')
    paragraphs.append(_format_function_doc(get_symbols))
    paragraphs.append(_format_function_doc(parse_comptime))
    paragraphs.append(_format_function_doc(assemble))
    paragraphs.append(_format_function_doc(compile_script))
    paragraphs.append(_format_function_doc(decompile_script))
    paragraphs.append(_format_function_doc(add_opcode_parsing_handlers))
    paragraphs.append('\n\n# Tools\n\n')
    paragraphs.append(_format_class_doc(Script))
    paragraphs.append(_format_class_doc(ScriptLeaf))
    paragraphs.append(_format_class_doc(ScriptNode))
    paragraphs.append(_format_function_doc(repl))
    paragraphs.append(_format_function_doc(make_script_tree_prioritized))
    paragraphs.append(_format_function_doc(make_merklized_script_prioritized))
    paragraphs.append(_format_function_doc(make_script_tree_balanced))
    paragraphs.append(_format_function_doc(make_merklized_script_balanced))
    paragraphs.append(_format_function_doc(make_adapter_lock_pub))
    paragraphs.append(_format_function_doc(make_adapter_lock_prv))
    paragraphs.append(_format_function_doc(make_single_sig_lock))
    paragraphs.append(_format_function_doc(make_single_sig_lock2))
    paragraphs.append(_format_function_doc(make_single_sig_witness))
    paragraphs.append(_format_function_doc(make_single_sig_witness2))
    paragraphs.append(_format_function_doc(make_multisig_lock))
    paragraphs.append(_format_function_doc(make_adapter_locks_pub))
    paragraphs.append(_format_function_doc(make_adapter_decrypt))
    paragraphs.append(_format_function_doc(decrypt_adapter))
    paragraphs.append(_format_function_doc(make_adapter_locks_prv))
    paragraphs.append(_format_function_doc(make_adapter_witness))
    paragraphs.append(_format_function_doc(make_delegate_key_lock))
    paragraphs.append(_format_function_doc(make_delegate_key_cert))
    paragraphs.append(_format_function_doc(make_delegate_key_witness))
    paragraphs.append(_format_function_doc(make_delegate_key_chain_witness))
    paragraphs.append(_format_function_doc(make_htlc_sha256_lock))
    paragraphs.append(_format_function_doc(make_htlc_shake256_lock))
    paragraphs.append(_format_function_doc(make_htlc_witness))
    paragraphs.append(_format_function_doc(make_htlc2_sha256_lock))
    paragraphs.append(_format_function_doc(make_htlc2_shake256_lock))
    paragraphs.append(_format_function_doc(make_htlc2_witness))
    paragraphs.append(_format_function_doc(make_ptlc_lock))
    paragraphs.append(_format_function_doc(make_ptlc_witness))
    paragraphs.append(_format_function_doc(make_ptlc_refund_witness))
    paragraphs.append(_format_function_doc(make_taproot_lock))
    paragraphs.append(_format_function_doc(make_taproot_witness_keyspend))
    paragraphs.append(_format_function_doc(make_taproot_witness_scriptspend))
    paragraphs.append(_format_function_doc(make_nonnative_taproot_lock))
    paragraphs.append(_format_function_doc(make_graftap_lock))
    paragraphs.append(_format_function_doc(make_graftap_witness_keyspend))
    paragraphs.append(_format_function_doc(make_graftap_witness_scriptspend))
    paragraphs.append(_format_function_doc(setup_amhl))
    paragraphs.append(_format_function_doc(release_left_amhl_lock))
    paragraphs.append(_format_function_doc(add_soft_fork))
    paragraphs.append(_format_function_doc(generate_docs) + '\n\n')

    with open('tapescript/notes.md', 'r') as f:
        paragraphs.append(f.read())

    return paragraphs

def add_soft_fork(code: int, name: str, op: Callable) -> None:
    """Adds a soft fork, adding the op to the interpreter and handlers
        for compiling and decompiling.
    """
    tert(callable(op), 'op must be callable')

    def compiler_handler(
            opname: str, symbols: list[str], symbols_to_advance: int,
            symbol_index: int
        ) -> tuple[int, tuple[bytes]]:
        """Handler for compiling a soft-forked opcode, which will always
            have the form `OP_SOMETHING d<8 count>` or `x<u8 count>`.
        """
        symbols_to_advance += 1
        val = symbols[0]
        yert(val[0] in ('d', 'x'),
            f'{opname} - argument must be prefaced with d or x - symbol {symbol_index}')
        match val[0]:
            case 'd':
                val = int(val[1:])
                yert(0 <= val < 256,
                    f'{opname} - argument must be between 0-255 - symbol {symbol_index}')
                val = val.to_bytes(1, 'big')
            case 'x':
                val = bytes.fromhex(val[1:])
                yert(len(val) == 1,
                    f'{opname} - argument must be 1 byte - symbol {symbol_index}')
        return (symbols_to_advance, (val,))

    def decompiler_handler(opname: str, tape: Tape) -> list[str]:
        """Handler for compiling a soft-forked opcode, which will always
            have the form `OP_SOMETHING d<8 count>`.
        """
        val = tape.read(1)[0]
        return [f'{opname} d{val}']

    add_opcode(code, name, op)
    add_opcode_parsing_handlers(name, compiler_handler, decompiler_handler)

def make_scripthash_lock(script: Script, hashsize: int = 26) -> Script:
    """Makes a lock that commits to a script. When executed, the lock
        verifies that the committed script has been provided and then
        executes it. Locking script will be hashsize + 7 bytes long (33
        with default options). Committed script must have length less
        than `Stack.max_item_size`, else it cannot be pushed onto the
        stack, checked, and verified.
    """
    return Script.from_src(f'''
        dup shake256 d{hashsize}
        push ~! {{ push x{script.bytes.hex()} shake256 d{hashsize} }}
        equal_verify
        eval
    ''')

def make_scripthash_witness(script: Script) -> Script:
    """Makes a witness that pushes a script onto the stack."""
    return Script.from_src(f'push x{script.bytes.hex()}')

def make_adapter_lock_pub(
        pubkey: bytes, tweak_point: bytes, sigflags: str = '00') -> Script:
    """Make an adapter locking script that verifies a sig adapter,
        decrypts it, and then verifies the decrypted signature.
        DEPRECATED: use `make_adapter_locks_pub` instead.
    """
    return Script.from_src(f'''
        # required push by unlocking script: tweak scalar t #
        # required push by unlocking script: signature adapter sa #
        # required push by unlocking script: nonce point R #
        @= R 1
        @= sa 1
        @= t 1

        # verify adapter sig #
        @sa @R
        get_message x{sigflags}
        push x{tweak_point.hex()}
        push x{pubkey.hex()}
        check_adapter_sig verify

        # decrypt adapter sig #
        @sa @R @t decrypt_adapter_sig
        concat

        # check sig #
        push x{pubkey.hex()}
        check_sig x{sigflags}
    ''')

def make_adapter_lock_prv(
        pubkey: bytes, tweak: bytes, sigflags: str = '00') -> Script:
    """Make an adapter locking script that verifies a sig adapter,
        decrypts it, and then verifies the decrypted signature.
        DEPRECATED: use `make_adapter_locks_prv` instead.
    """
    t = clamp_scalar(tweak)
    T = derive_point_from_scalar(t)
    return make_adapter_lock_pub(pubkey, T, sigflags)

def make_single_sig_lock(pubkey: bytes, sigflags: str = '00') -> Script:
    """Make a locking Script that requires a valid signature from a
        single key to unlock.
    """
    return Script.from_src(f'push x{pubkey.hex()} check_sig x{sigflags}')

def make_single_sig_lock2(pubkey: bytes, sigflags: str = '00') -> Script:
    """Make a locking Script that commits to and requires a public key
        and then valid signature from the pubkey to unlock. Saves 8
        bytes in locking script at expense of an additional 33 bytes in
        the witness.
    """
    return Script.from_src(f'''
        dup shake256 d20
        push ~! {{ push x{pubkey.hex()} shake256 d20 }}
        equal_verify
        check_sig x{sigflags}
    ''')

def make_single_sig_witness(
        prvkey: bytes, sigfields: dict[str, bytes], sigflags: str = '00',
        sign_script_prefix: str = ''
    ) -> Script:
    """Make an unlocking script that validates for a single sig locking
        script by signing the sigfields. Returns Script that pushes the
        signature onto the stack. Passing a `sign_script_prefix` will
        prefix the signing operation with the given script source.
    """
    _, stack, _ = run_script(
        compile_script(f'{sign_script_prefix} push x{prvkey.hex()} sign x{sigflags}'),
        {**sigfields}
    )
    sig = stack.get()
    return Script.from_src(f'push x{sig.hex()}')

def make_single_sig_witness2(
        prvkey: bytes, sigfields: dict[str, bytes], sigflags: str = '00',
        sign_script_prefix: str = ''
    ) -> Script:
    """Make an unlocking script that validates for a single sig locking
        script by signing the sigfields. Returns a Script that pushes
        the signature and pubkey onto the stack. 33 bytes larger witness
        than `make_single_sig_witness` to save 8 bytes in the locking
        script. Passing a `sign_script_prefix` will prefix the signing
        operation with the given script source.
    """
    _, stack, _ = run_script(
        compile_script(f'''
            {sign_script_prefix}
            push x{prvkey.hex()}
            dup derive_scalar derive_point
            swap2 sign x{sigflags}
        '''),
        {**sigfields}
    )
    sig = stack.get()
    pubkey = stack.get()
    return Script.from_src(f'push x{sig.hex()} push x{pubkey.hex()}')

def make_multisig_lock(
        pubkeys: list[bytes], quorum_size: int, sigflags: str = '00') -> Script:
    """Make a locking Script that requires quorum_size valid signatures
        from unique keys within the pubkeys list. Can be unlocked by
        joining the results of quorum_size calls to
        `make_single_sig_witness` by different key holders. The
        quorum_size argument must be less than or equal to the number of
        unique public keys.
    """
    vert(quorum_size <= len(set(pubkeys)),
         'quorum_size must be <= number of unique pubkeys')
    src = ''
    for pk in pubkeys:
        src += f'push x{pk.hex()}\n'
    src += f'check_multisig x{sigflags} d{quorum_size} d{len(pubkeys)}'
    return Script.from_src(src)

def make_adapter_locks_pub(
        pubkey: bytes, tweak_point: bytes, sigflags: str = '00') -> tuple[Script, Script]:
    """Make adapter locking scripts using a public key and a tweak
        point. Returns 2 Scripts: one that checks if a sig adapter is
        valid, and one that verifies the decrypted signature.
    """
    script1 = Script.from_src(f'''
        # required push by unlocking script: signature adapter sa #
        # required push by unlocking script: nonce point R #
        get_message x{sigflags}
        push x{tweak_point.hex()}
        push x{pubkey.hex()}
        check_adapter_sig
    ''')
    script2 = Script.from_src(f'''
        # required push by unlocking script: decrypted signature #
        {make_single_sig_lock(pubkey, sigflags).src}
    ''')
    return (script1, script2)

def make_adapter_decrypt(tweak: bytes) -> Script:
    """Make adapter decryption script from a tweak scalar."""
    t = clamp_scalar(tweak)
    return Script.from_src(f'''
        push x{t.hex()}
        decrypt_adapter_sig
    ''')

def decrypt_adapter(adapter_witness: bytes|ScriptProtocol, tweak: bytes) -> bytes:
    """Decrypt an adapter signature with the given tweak scalar,
        returning the decrypted signature.
    """
    tert(type(adapter_witness) is bytes or isinstance(adapter_witness, ScriptProtocol),
         'adapter_witness must be bytes or ScriptProtocol')
    adapter_witness = bytes(adapter_witness)
    _, stack, _ = run_script(
        adapter_witness +
        make_adapter_decrypt(tweak).bytes
    )
    s = stack.get()
    RT = stack.get()
    return RT + s

def make_adapter_locks_prv(
        pubkey: bytes, tweak: bytes, sigflags: str = '00'
    ) -> tuple[Script, Script, Script]:
    """Make adapter locking scripts using a public key and a tweak
        scalar. Returns a tuple of 3 Scripts: one that checks if a sig
        adapter is valid, one that decrypts the signature, and one that
        verifies the decrypted signature.
    """
    t = clamp_scalar(tweak)
    T = derive_point_from_scalar(t)
    script1, script3 = make_adapter_locks_pub(pubkey, T, sigflags)
    script2 = make_adapter_decrypt(tweak)
    return (script1, script2, script3)

def make_adapter_witness(
        prvkey: bytes, tweak_point: bytes, sigfields: dict, sigflags: str = '00',
        sign_script_prefix: str = ''
    ) -> Script:
    """Make an adapter signature witness using a private key and a tweak
        point. Returns a Script that pushes the adapter signature and
        nonce point onto the stack. Passing a `sign_script_prefix` will
        prefix the signing operation with the given script source.
    """
    assert 'sigfield1' in sigfields or 'sigfield2' in sigfields or \
        'sigfield3' in sigfields or 'sigfield4' in sigfields or \
        'sigfield5' in sigfields or 'sigfield6' in sigfields or \
        'sigfield7' in sigfields or 'sigfield8' in sigfields, \
        'at least one sigfield[1-8] must be included'

    _, stack, _ = run_script(
        compile_script(f'''
            {sign_script_prefix}
            push x{prvkey.hex()}
            get_message x{sigflags}
            push x{tweak_point.hex()}
            make_adapter_sig_public
        '''),
        {**sigfields}
    )
    sa = stack.get()
    R = stack.get()

    return Script.from_src(f'''
        push x{sa.hex()}
        push x{R.hex()}
    ''')

def make_delegate_key_lock(root_pubkey: bytes, sigflags: str = '00') -> Script:
    """Takes a root_pubkey and returns a locking Script that is unlocked
        with a signature from the delegate key and a signed certificate
        from the root key authorizing the delegate key.
    """
    return Script.from_src(f'''
        # required push: signature from delegate key #
        # required push: cert of form: delegate public key + begin ts + end ts + can + sig #
        push d41 split @= s 1 # sig #
        dup
        push d40 split pop0 # can #
        push d36 split @= e 1 # end ts #
        push d32 split @= b 1 @= d 1 # begin ts and delegate pubkey #

        # prove the timestamp is within the cert bounds #
        val s"timestamp" dup @b less verify
        @e swap2 less verify

        @s swap2
        push x{root_pubkey.hex()} check_sig_stack verify

        @d check_sig x{sigflags}
    ''')

def make_delegate_key_chain_lock(root_pubkey: bytes, sigflags: str = '00') -> Script:
    """Takes a root_pubkey and returns a locking Script that is unlocked
        with a signature from the delegate key, the delegated public key,
        and a certificate from the root key committing to the delegate
        public key and validity time constraints. This delegate key can
        be used to recursively authorize another public key and cert if
        they are added to the stack, otherwise it will expect to sign
        the sigfields. The delegate key cert chain can extend until
        tapescript runtime constraints are hit (either stack size or
        callstack limit).
    """
    return Script.from_src(f'''
        def 0 {{
            # required push: signature from delegate key or additional cert #
            # required push: cert of form: delegate public key + begin ts + end ts ts + can + sig #
            # required push: authorizing pubkey #
            @= r 1 # authorizing pubkey #
            push d41 split @= s 1 # sig #
            dup
            push d40 split @= c 1 # can delegate further #
            push d36 split @= e 1 # end ts ts #
            push d32 split @= b 1 @= d 1 # begin ts and delegate pubkey #

            # prove the timestamp is within the cert bounds #
            val s"timestamp" dup @b less verify
            @e swap2 less verify

            @s swap2 @r check_sig_stack verify
            if ( @c and ) {{
                @d call d0
            }} else {{
                @d check_sig x{sigflags}
            }}
        }}
        push x{root_pubkey.hex()} call d0
    ''')

def make_delegate_key_cert(
        root_skey: bytes, delegate_pubkey: bytes, begin_ts: int, end_ts: int,
        can_further_delegate: bool = True
    ) -> bytes:
    """Returns a signed key delegation cert. By default, this cert will
        authorize the delegate_pubkey holder to create further delegate
        certs, allowing authorization by a chain of certs. To disable
        this behavior and create a terminal cert, pass `False` as the
        can_further_delegate argument.
    """
    # cert form: delegate key + begin ts + end ts + sig + can #
    _, stack, _ = run_script(compile_script(f'''
        push x{delegate_pubkey.hex()}
        push d{begin_ts} concat
        push d{end_ts} concat
        {'true' if can_further_delegate else 'false'} concat
        dup
        push x{root_skey.hex()} sign_stack
        concat
    '''))
    assert len(stack) == 1
    return stack.get()

def make_delegate_key_witness(
        prvkey: bytes, cert: bytes, sigfields: dict,
        sigflags: str = '00', sign_script_prefix: str = ''
    ) -> Script:
    """Returns an unlocking (witness) Script including a signature from
        the delegate key as well as the delegation certificate. Passing a
        `sign_script_prefix` will prefix the signing operation with the
        given script source.
    """
    _, stack, _ = run_script(
        compile_script(f'{sign_script_prefix} push x{prvkey.hex()} sign x{sigflags}'),
        sigfields
    )
    assert len(stack) == 1
    sig = stack.get()
    return Script.from_src(f'''
        push x{sig.hex()}
        push x{cert.hex()}
    ''')

def make_delegate_key_chain_witness(
        prvkey: bytes, certs: list[bytes], sigfields: dict,
        sigflags: str = '00', sign_script_prefix: str = ''
    ) -> Script:
    """Returns an unlocking (witness) Script including a signature from
        the delegate key as well as the chain of delegation certificates
        ordered from the one authorizing this key down to the first cert
        authorized by the root. Passing a `sign_script_prefix` will prefix
        the signing operation with the given script source.
    """
    _, stack, _ = run_script(
        compile_script(f'{sign_script_prefix} push x{prvkey.hex()} sign x{sigflags}'),
        sigfields
    )
    assert len(stack) == 1
    sig = stack.get()
    return Script.from_src(
        f'push x{sig.hex()} false\npush ' +
        ' true\npush '.join([f'x{c.hex()}' for c in certs])
    )

def make_graftroot_lock(pubkey: bytes, sigflags: str = '00') -> Script:
    """Creates a locking script which requires either a signature from
        the pubkey or a surrogate script signed by the pubkey. If the
        top item in the stack is `true`, the next will be parsed as
        a signed surrogate script; the signature will be verified; and
        then the surrogate script will be executed. If the top item in
        the stack is `false`, then `OP_CHECK_SIG` will be called.
    """
    return Script.from_src(
        f'''
        @= k [ x{pubkey.hex()} ]
        if {{
            dup
            swap d1 d2
            @k check_sig_stack verify
            eval
        }} else {{
            @k check_sig x{sigflags}
        }}'''
    )

def make_graftroot_witness_keyspend(
        prvkey: bytes, sigfields: dict[str, bytes], sigflags: str = '00',
        sign_script_prefix: str = ''
    ) -> Script:
    """Creates a graftroot witness via signature and not by surrogate
        script. Passing a `sign_script_prefix` will prefix the signing
        operation with the given script source.
    """
    return make_single_sig_witness(prvkey, sigfields, sigflags, sign_script_prefix) + \
        Script.from_src('false')

def make_graftroot_witness_surrogate(prvkey: bytes, script: str|Script) -> Script:
    """Creates a graftroot witness consisting of a signed surrogate script."""
    script = Script.from_src(script) if type(script) is str else script
    return Script.from_src(f'''
        push ~! {{
            push x{script.bytes.hex()}
            push x{prvkey.hex()} sign_stack
        }}
        push x{script.bytes.hex()}
        true
    ''')

def make_htlc_sha256_lock(
        receiver_pubkey: bytes, preimage: bytes, refund_pubkey: bytes,
        timeout: int = 60*60*24, sigflags: str = '00'
    ) -> Script:
    """Returns an HTLC that can be unlocked either with the preimage and
        a signature matching receiver_pubkey or with a signature
        matching the refund_pubkey after the timeout has expired.
        Suitable only for systems with guaranteed causal ordering and
        non-repudiation of transactions. Preimage should be at least 16
        random bytes but not more than 32.
    """
    return Script.from_src(f'''
        sha256
        push x{sha256(preimage).digest().hex()}
        equal
        if {{
            push x{receiver_pubkey.hex()}
        }} else {{
            push d{int(time())+timeout}
            check_timestamp_verify
            push x{refund_pubkey.hex()}
        }}
        check_sig x{sigflags}
    ''')

def make_htlc_shake256_lock(
        receiver_pubkey: bytes, preimage: bytes, refund_pubkey: bytes,
        hash_size: int = 20, timeout: int = 60*60*24, sigflags: str = '00'
    ) -> Script:
    """Returns an HTLC that can be unlocked either with the preimage and
        a signature matching receiver_pubkey or with a signature
        matching the refund_pubkey after the timeout has expired.
        Suitable only for systems with guaranteed causal ordering and
        non-repudiation of transactions. Using a hash_size of 20 saves
        11 bytes compared to the sha256 version with a 96 bit reduction
        in security (remaining 160 bits) for the hash lock. Preimage
        should be at least 16 random bytes but not more than 32.
    """
    return Script.from_src(f'''
        shake256 d{hash_size}
        push ~! {{ push x{preimage.hex()} shake256 d{hash_size} }}
        equal
        if {{
            push x{receiver_pubkey.hex()}
        }} else {{
            push d{int(time())+timeout}
            check_timestamp_verify
            push x{refund_pubkey.hex()}
        }}
        check_sig x{sigflags}
    ''')

def make_htlc_witness(
        prvkey: bytes, preimage: bytes, sigfields: dict, sigflags: str = '00',
        sign_script_prefix: str = ''
    ) -> Script:
    """Returns a witness to unlock either the hash lock or the time lock
        path of an HTLC, depending upon whether or not the preimage
        matches. To use the time lock path, pass a preimage of 1 byte to
        save space in the witness. Passing a `sign_script_prefix` will
        prefix the signing operation with the given script source.
    """
    _, stack, _ = run_script(
        compile_script(f'{sign_script_prefix} push x{prvkey.hex()} sign x{sigflags}'),
        {**sigfields}
    )
    sig = stack.get()
    return Script.from_src(f'''
        push x{sig.hex()}
        push x{preimage.hex()}
    ''')

def make_htlc2_sha256_lock(
        receiver_pubkey: bytes, preimage: bytes, refund_pubkey: bytes,
        timeout: int = 60*60*24, sigflags: str = '00') -> Script:
    """Returns an HTLC that can be unlocked either with the preimage and
        a signature matching receiver_pubkey or with a signature
        matching the refund_pubkey after the timeout has expired.
        Suitable only for systems with guaranteed causal ordering and
        non-repudiation of transactions. This version is optimized for
        smaller locking script size (-18 bytes) at the expense of larger
        witnesses (+33 bytes) for larger overall txn size (+15 bytes).
        Which to use will depend upon the intended use case: for public
        blockchains where all nodes must hold a UTXO set in memory and
        can trim witness data after consensus, the lock script size
        reduction is significant and useful; for other use cases, in
        particular systems where witness data cannot be trimmed, the
        other version is more appropriate.
    """
    return Script.from_src(f'''
        sha256
        push x{sha256(preimage).digest().hex()}
        equal
        if {{
            dup shake256 d20
            push ~! {{ push x{receiver_pubkey.hex()} shake256 d20 }}
        }} else {{
            push d{int(time())+timeout}
            check_timestamp_verify
            dup shake256 d20
            push ~! {{ push x{refund_pubkey.hex()} shake256 d20 }}
        }}
        equal_verify
        check_sig x{sigflags}
    ''')

def make_htlc2_shake256_lock(
        receiver_pubkey: bytes, preimage: bytes, refund_pubkey: bytes,
        hash_size: int = 20, timeout: int = 60*60*24, sigflags: str = '00'
    ) -> Script:
    """Returns an HTLC that can be unlocked either with the preimage and
        a signature matching receiver_pubkey or with a signature
        matching the refund_pubkey after the timeout has expired.
        Suitable only for systems with guaranteed causal ordering and
        non-repudiation of transactions. Using a hash_size of 20 saves
        11 bytes compared to the sha256 version with a 96 bit reduction
        in security (remaining 160 bits) for the hash lock. This version
        is optimized for smaller locking script size (-18 bytes) at the
        expense of larger witnesses (+33 bytes) for larger overall txn
        size (+15 bytes). Which to use will depend upon the intended use
        case: for public blockchains where all nodes must hold a UTXO
        set in memory and can trim witness data after consensus, the
        lock script size reduction is significant and useful; for other
        use cases, in particular systems where witness data cannot be
        trimmed, the other version is more appropriate.
    """
    return Script.from_src(f'''
        shake256 d{hash_size}
        push ~! {{ push x{preimage.hex()} shake256 d{hash_size} }}
        equal
        if {{
            dup shake256 d{hash_size}
            push ~! {{ push x{receiver_pubkey.hex()} shake256 d{hash_size} }}
        }} else {{
            push d{int(time())+timeout}
            check_timestamp_verify
            dup shake256 d{hash_size}
            push ~! {{ push x{refund_pubkey.hex()} shake256 d{hash_size} }}
        }}
        equal_verify
        check_sig x{sigflags}
    ''')

def make_htlc2_witness(
        prvkey: bytes, preimage: bytes, sigfields: dict, sigflags: str = '00',
        sign_script_prefix: str = ''
    ) -> Script:
    """Returns a witness Script to unlock either the hash lock or the
        time lock path of an HTLC, depending upon whether or not the
        preimage matches. This version is optimized for smaller locking
        script size (-18 bytes) at the expense of larger witnesses (+33
        bytes) for larger overall txn size (+15 bytes). Which to use
        will depend upon the intended use case: for public blockchains
        where all nodes must hold a UTXO set in memory and can trim
        witness data after consensus, the lock script size reduction is
        significant and useful; for other use cases, in particular
        systems where witness data cannot be trimmed or in which witness
        size should be minimized, the other version is more appropriate.
        Passing a `sign_script_prefix` will prefix the signing operation
        with the given script source.
    """
    _, stack, _ = run_script(
        compile_script(f'''
            {sign_script_prefix}
            push x{prvkey.hex()}
            dup derive_scalar derive_point
            swap2 sign x{sigflags}
        '''),
        {**sigfields}
    )
    sig = stack.get()
    pubkey = stack.get()
    return Script.from_src(f'''
        push x{sig.hex()}
        push x{pubkey.hex()}
        push x{preimage.hex()}
    ''')

def make_ptlc_lock(
        receiver_pubkey: bytes, refund_pubkey: bytes, tweak_point: bytes = None,
        timeout: int = 60*60*24, sigflags: str = '00') -> Script:
    """Returns a Point Time Locked Contract (PTLC) Script that can be
        unlocked with either a signature matching the receiver_pubkey or
        with a signature matching the refund_pubkey after the timeout has
        expired. Suitable only for systems with guaranteed causal ordering
        and non-repudiation of transactions. If a tweak_point is passed,
        use tweak_point+receiver_pubkey as the point lock.
    """
    if type(tweak_point) is bytes:
        receiver_pubkey = aggregate_points([receiver_pubkey, tweak_point])
    return Script.from_src(f'''
        if {{
            push x{receiver_pubkey.hex()}
        }} else {{
            push d{int(time())+timeout}
            check_timestamp_verify
            push x{refund_pubkey.hex()}
        }}
        check_sig x{sigflags}
    ''')

def make_ptlc_witness(
        prvkey: bytes, sigfields: dict, tweak_scalar: bytes = None,
        sigflags: str = '00', sign_script_prefix: str = ''
    ) -> Script:
    """Returns a PTLC witness unlocking the main branch. If a
        tweak_scalar is passed, add tweak_scalar to x within signature
        generation to unlock the point corresponding to
        `derive_point(tweak_scalar) + derive_point(x)`. Passing a
        `sign_script_prefix` will prefix the signing operation with the
        given script source.
    """
    if tweak_scalar:
        # create signature manually
        _, stack, _ = run_script(
            compile_script(f'{sign_script_prefix} get_message x{sigflags}'),
            {**sigfields}
        )
        m = stack.get()
        x = aggregate_scalars([derive_key_from_seed(prvkey), tweak_scalar])
        sig = sign_with_scalar(x, m)
        return Script.from_src(f'push x{sig.hex()}{sigflags} true')
    return make_single_sig_witness(prvkey, sigfields, sigflags, sign_script_prefix) \
        + Script.from_src('true')

def make_ptlc_refund_witness(
        prvkey: bytes, sigfields: dict, sigflags: str = '00',
        sign_script_prefix: str = ''
    ) -> Script:
    """Returns a PTLC witness unlocking the time locked refund branch.
        Passing a `sign_script_prefix` will prefix the signing operation
        with the given script source.
    """
    return make_single_sig_witness(prvkey, sigfields, sigflags, sign_script_prefix) \
        + Script.from_src('false')

def make_taproot_lock(
        pubkey: bytes, script: Script = None, script_commitment: bytes = None,
        sigflags: str = '00'
    ) -> Script:
    """Returns a Script for a taproot locking script that can either be
        unlocked with a signature that validates using the taproot root
        commitment as a public key or by supplying both the committed
        script and the committed public key to execute the committed
        script.
    """
    tert(isinstance(script, Script) or type(script_commitment) is bytes,
         'must supply either committed_script or script_commitment')
    script_commitment = script_commitment or script.commitment()
    vert(len(script_commitment) == 32, 'script_commitment must be 32 bytes')
    X = derive_point_from_scalar(clamp_scalar(sha256(pubkey + script_commitment).digest()))
    root = aggregate_points((pubkey, X))
    return Script.from_src(f'push x{root.hex()} tr x{sigflags}')

def make_taproot_witness_keyspend(
        prvkey: bytes, sigfields: dict, committed_script: Script = None,
        script_commitment: bytes = None, sigflags: str = '00',
        sign_script_prefix: str = ''
    ) -> Script:
    """Returns a Script witness for a taproot keyspend. Passing a
        `sign_script_prefix` will prefix the signing operation with the
        given script source.
    """
    tert(type(prvkey) is bytes, 'prvkey must be the 32 byte prvkey seed')
    vert(len(prvkey) == 32, 'prvkey must be the 32 byte prvkey seed')
    tert(isinstance(sigfields, dict), 'must supply sigfields dict')
    tert(isinstance(committed_script, Script) or type(script_commitment) is bytes,
         'must supply either committed_script or script_commitment')
    vert(sigflags != 'ff', 'cannot use sigflag xFF; must sign at least 1 sigfield')

    script_commitment = script_commitment or committed_script.commitment()
    x = derive_key_from_seed(prvkey)
    X = derive_point_from_scalar(x)
    t = clamp_scalar(sha256(X + script_commitment).digest())
    _, stack, _ = run_script(
        Script.from_src(f'{sign_script_prefix} msg x{sigflags}'), sigfields
    )
    message = stack.get()
    sig = sign_with_scalar(aggregate_scalars((x, t)), message)

    if sigflags != '00':
        sig += bytes.fromhex(sigflags)
    return Script.from_src(f'push x{sig.hex()}')

def make_taproot_witness_scriptspend(
        pubkey: bytes, committed_script: Script) -> Script:
    """Returns a Script witness for a taproot scriptspend, i.e. a
        witness that causes the committed script to be executed.
    """
    tert(type(pubkey) is bytes, 'pubkey must be the 32 byte committed pubkey')
    vert(len(pubkey) == 32, 'pubkey must be the 32 byte committed pubkey')
    tert(isinstance(committed_script, ScriptProtocol), 'committed_script must be ScriptProtocol')
    return Script.from_src(f'push x{committed_script.bytes.hex()} push x{pubkey.hex()}')

def make_nonnative_taproot_lock(
        pubkey: bytes, script: Script = None, script_commitment: bytes = None,
        sigflags: str = '00'
    ) -> Script:
    """Returns a locking Script for non-native taproot. This Script
        exists primarily to compare against the native taproot lock and
        the nonnative graftroot lock.
    """
    tert(isinstance(script, Script) or type(script_commitment) is bytes,
         'must supply either committed_script or script_commitment')
    script_commitment = script_commitment or script.commitment()
    vert(len(script_commitment) == 32, 'script_commitment must be 32 bytes')
    X = derive_point_from_scalar(clamp_scalar(sha256(pubkey + script_commitment).digest()))
    root = aggregate_points((pubkey, X))
    return Script.from_src(f'''
        def 0 {{ push x{root.hex()} }}
        if ( dup size push d32 equal ) {{
            # stack: script, internal pubkey #
            dup swap d0 d2
            dup swap d1 d3
            sha256 cat sha256 clamp_scalar x00 derive_point
            add_points d2
            call d0 eqv eval
        }} else {{
            # stack: signature #
            call d0 check_sig x{sigflags}
        }}
    ''')

def _make_graftap_committed_script(pubkey: bytes) -> Script:
    """Returns the tapescript source for a graftroot lock."""
    return Script.from_src(f'''
        dup
        swap d1 d2
        push x{pubkey.hex()} check_sig_stack verify
        eval
    ''')

def make_graftap_lock(pubkey: bytes) -> Script:
    """Make a taproot lock committing to the (internal) pubkey and a
        graftroot lock.
    """
    return make_taproot_lock(pubkey, _make_graftap_committed_script(pubkey))

def make_graftap_witness_keyspend(
        prvkey: bytes, sigfields: dict, sigflags: str = '00',
        sign_script_prefix: str = ''
    ) -> Script:
    """Make a Script witness for a taproot keyspend, providing the
        committed graftroot lock hash and a signature. Passing a
        `sign_script_prefix` will prefix the signing operation with the
        given script source.
    """
    pubkey = derive_point_from_scalar(derive_key_from_seed(prvkey))
    return make_taproot_witness_keyspend(
        prvkey, sigfields, _make_graftap_committed_script(pubkey),
        sigflags=sigflags, sign_script_prefix=sign_script_prefix
    )

def make_graftap_witness_scriptspend(
        prvkey: bytes, surrogate_script: Script
    ) -> Script:
    """Make a Script witness for a taproot scriptspend, providing the
        committed graftroot lock, the internal pubkey, and the graftroot
        surrogate witness script.
    """
    pubkey = derive_point_from_scalar(derive_key_from_seed(prvkey))
    return Script.from_src(f'''
        push ~! {{
            push x{surrogate_script.bytes.hex()}
            push x{prvkey.hex()} sign_stack
        }}
        push x{surrogate_script.bytes.hex()}
    ''') + make_taproot_witness_scriptspend(
        pubkey, _make_graftap_committed_script(pubkey)
    )

def setup_amhl(
        seed: bytes, pubkeys: tuple[bytes]|list[bytes], sigflags: str = '00',
        refund_pubkeys: dict[bytes] = None, timeout: int = 60*60*24
    ) -> dict[bytes|str, bytes|tuple[Script|bytes, ...]]:
    """Sets up an annoymous multi-hop lock for a sorted list of pubkeys.
        Returns a dict mapping each public key to a tuple containing the
        tuple of scripts returned by make_adapter_locks_pub and the
        tweak point for the hop, and mapping the key 'key' to the first
        tweak scalar needed to unlock the last hop in the AMHL and begin
        the cascade back to the funding source. The order of pubkeys
        must start with the originator and end with the correspondent
        of the receiver. If refund_pubkeys dict is passed, then for any
        pk in pubkeys that is also a key in the refund_pubkeys dict, the
        single sig lock (2nd value) will be replaced with a PTLC.
    """
    tert(type(seed) is bytes, 'seed must be bytes')
    tert(type(pubkeys) in (tuple, list), 'pubkeys must be tuple[bytes]')
    tert(all([type(pk) is bytes for pk in pubkeys]),
         'pubkeys must be tuple[bytes]')
    n = len(pubkeys)
    setup = AMHL.setup(n, seed)
    result = {}
    for i in range(n):
        s = AMHL.setup_for(setup, i)
        T = s[1] if len(s) > 1 else AMHL.oneway(s[0])
        k = s[-1] if len(s) > 0 else s[0]
        pk = pubkeys[i]
        result[pk] = [*make_adapter_locks_pub(pk, T, sigflags), T, k]
        if type(refund_pubkeys) is dict and pk in refund_pubkeys:
            result[pk][1] = make_ptlc_lock(
                pk, refund_pubkeys[pk], timeout=timeout, sigflags=sigflags)
        result[pk] = tuple(result[pk])
    result['key'] = AMHL.setup_for(setup, n)[-1]
    return result

def release_left_amhl_lock(
        adapter_witness: bytes|ScriptProtocol, signature: bytes, y: bytes) -> bytes:
    """Release the next lock using an adapter witness and a decrypted
        signature from right lock. Returns the tweak scalar used to
        decrypt the left adapter signature.
    """
    tert(type(adapter_witness) is bytes or isinstance(adapter_witness, ScriptProtocol),
         'adapter_witness must be bytes or ScriptProtocol of bytes len 66')
    adapter_witness = bytes(adapter_witness)
    vert(len(adapter_witness) == 68, 'adapter_witness must be bytes of len 68')
    tert(type(signature) is bytes, 'signature must be bytes of len 64 or 65')
    vert(len(signature) == 64, 'signature must be bytes of len 64')
    sa = adapter_witness[2:34]
    s = signature[32:]
    t = nacl.bindings.crypto_core_ed25519_scalar_sub(s, sa) # s = sa + t
    return AMHL.release(t, y)

def cli_help() -> str:
    """Return CLI help text."""
    name = argv[0]
    return '\n'.join([
        f'Usage: {name} [method] [options]',
        '\trepl [cache_file] -- interactive -- i -- invokes the REPL; default '
        'behavior if no method is passed',
        '\tcompile src_file bin_file -- compiles the source code into bytecode '
        'and writes it to bin_file',
        '\tdecompile bin_file -- decompiles the bytecode and outputs to stdout',
        '\trun bin_file [cache_file] -- runs tapescript bytecode and prints the '
        'resulting cache and stack',
        '\tauth bin_file [cache_file] -- runs tapescript bytecode as auth script'
        ' and prints true if it was successful or false otherwise',
        '\tversion -- print current tapescript version',
        '',
        'The optional cache_file parameter must be a json file with the '
        'following format:',
        '{',
            '\t"type:name": [type, value]',
        '}',
        '',
        'The type must be one of "string", "str", "number", "bytes". All bytes '
        'values must be hexadecimal strings. For example:',
        '{', '\t"number:78": ["bytes", "d13f398b5bacf525"]', '}'
    ])

def _clert(condition: bool, message: str = ''):
    """CLI assert: print error message and exit if condition fails."""
    if not condition:
        message = f'{message}\n{cli_help()}' if message else cli_help()
        print(message)
        exit(1)

def _parse_cache_json_part(part: list, errmsg: str):
    match part[0]:
        case 'string'|'str':
            _clert(type(part[1]) is str, errmsg)
            return part[1]
        case 'number':
            _clert(type(part[1]) in (int, float), errmsg)
            return part[1]
        case 'bytes':
            _clert(type(part[1]) is str and is_hex(part[1]), errmsg)
            return bytes.fromhex(part[1])

def _parse_cache_json(fname: str) -> dict:
    errmsg = 'JSON file format is {"type:name": ["type", value], ...}. ' + \
        'The type must be "string", "str", "number", or "bytes". Bytes ' + \
        'values must be hexadecimal. If type is "string" or "str", the ' + \
        'associated name or value must be a string. If type is "number", ' + \
        'the associated name or value must be a number. Each key and each ' + \
        'value must have a type, but they do not have to match.'
    with open(fname, 'r') as f:
        cache = {}
        data: dict = json.loads(f.read())
        _clert(type(data) is dict, errmsg)
        for k, v in data.items():
            k = k.split(':')
            k = [k[0], ':'.join(k[1:])] if len(k) > 2 else k
            _clert(type(k) is list and len(k) == 2, f'{k} is invalid. {errmsg}')
            _clert(k[0] in ('string', 'str', 'number', 'bytes'), f'{k[0]} is invalid. {errmsg}')
            _clert(type(v) is list and len(v) == 2, f'{v} is invalid. {errmsg}')
            _clert(v[0] in ('string', 'str', 'number', 'bytes'), f'{v[0]} is invalid. {errmsg}')
            key = _parse_cache_json_part(k, errmsg)
            value = _parse_cache_json_part(v, errmsg)
            cache[key] = value
        return cache

def run_cli() -> None:
    """Run the simple CLI tool. More advanced functionality requires
        programmatic access.
    """
    method = argv[1] if len(argv) > 1 else 'repl'
    match method:
        case 'version' | '--version':
            print(version())
        case 'help' | '--help' | '?' | '-?' | '-h':
            print(cli_help())
        case 'i' | 'repl':
            cache = {}
            if len(argv) > 2:
                cache = _parse_cache_json(argv[2])
            repl(cache)
        case 'compile':
            _clert(len(argv) >= 4, 'Must supply src_file and bin_file parameters.')
            src_fname = argv[2]
            bin_fname = argv[3]
            data = b''
            with open(src_fname, 'r') as f:
                data = compile_script(f.read())
            with open(bin_fname, 'wb') as f:
                f.write(data)
        case 'decompile':
            _clert(len(argv) >= 3, 'Missing bin_file parameter.')
            bin_fname = argv[2]
            with open(bin_fname, 'rb') as f:
                data = f.read()
                print(decompile_script(data))
        case 'run':
            _clert(len(argv) >= 3, 'Must supply bin_file parameter.')
            bin_fname, script, cache = argv[2], b'', {}
            with open(bin_fname, 'rb') as f:
                script = f.read()
            if len(argv) > 3:
                cache = _parse_cache_json(argv[3])
            _, stack, cache = run_script(script, cache)
            items = []
            while len(stack):
                items.append(stack.get().hex())
            items.reverse()
            cache = {
                (f'bytes:{k.hex()}' if type(k) is bytes else k):
                f'bytes:{v.hex()}' if type(v) is bytes else v
                for k, v in cache.items()
            }
            print(f'stack:\n' + '\n'.join(items))
            print(f'cache:\n{cache}')
        case 'auth':
            _clert(len(argv) >= 3, 'Must supply bin_file parameter.')
            bin_fname, script, cache = argv[2], b'', {}
            with open(bin_fname, 'rb') as f:
                script = f.read()
            if len(argv) > 3:
                cache = _parse_cache_json(argv[3])
            print('true' if run_auth_script(script, cache) else 'false')
