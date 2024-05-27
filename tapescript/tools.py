from __future__ import annotations
from .AMHL import AMHL
from .classes import Tape
from .errors import tert, vert, yert
from .parsing import (
    compile_script,
    decompile_script,
    add_opcode_parsing_handlers,
    is_hex,
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
    H_big,
    H_small,
    xor,
)
from dataclasses import dataclass, field
from hashlib import sha256, shake_256
from sys import argv
from time import time
from typing import Callable
import nacl.bindings
import json


@dataclass
class Script:
    """Represent a script as a pairing of source and byte code."""
    src: str = field()
    bytes: bytes = field()

    @classmethod
    def from_src(cls, src: str) -> Script:
        return cls(src, compile_script(src))

    @classmethod
    def from_bytes(cls, code: bytes) -> Script:
        return cls(decompile_script(code), code)

    def commitment(self) -> bytes:
        return sha256(self.bytes).digest()


@dataclass
class ScriptLeaf:
    """A leaf in a Merklized script tree."""
    hash: bytes = field()
    script: Script|None = field(default=None)
    parent: ScriptNode = field(default=None)

    @classmethod
    def from_script(cls, script: Script) -> ScriptLeaf:
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
        return self.hash

    def unlocking_script(self) -> Script:
        """Calculate an unlocking script recursively, traveling up the
            parents. Returns a Script with the source and byte codes.
        """
        vert(self.parent is not None,
             'leaf must be part of a tree to generate an unlocking script')
        other = self.parent.right if self.parent.left is self else self.parent.left
        commitment = other.commitment()
        src = f'push x{commitment.hex()}\npush x{self.script.bytes.hex()}'
        script = Script.from_src(src)

        previous = self.parent.unlocking_script()
        return Script(f'{script.src}\n{previous.src}', script.bytes + previous.bytes)


class ScriptNode:
    """A node in a Merklized script tree."""
    left: ScriptLeaf|ScriptNode
    right: ScriptLeaf|ScriptNode
    parent: ScriptNode

    def __init__(self, left: ScriptLeaf|ScriptNode, right: ScriptLeaf|ScriptNode) -> None:
        left.parent = self
        right.parent = self
        self.left = left
        self.right = right
        self.parent = None

    def root(self) -> bytes:
        """Calculate and return the local root between the two branches."""
        return xor(
            sha256(self.left.commitment()).digest(),
            sha256(self.right.commitment()).digest()
        )

    def locking_script(self) -> Script:
        """Calculates the locking script for the node. Returns a tuple
            with the source and byte codes.
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


def create_script_tree_prioritized(leaves: list[str], tree: ScriptNode = None) -> ScriptNode:
    """Construct a script tree from the leaves using a ScriptLeaf for
        each leaf script, combining the last two into a ScriptNode and
        then recursively combining a ScriptLeaf for the last of the
        remaining script leaves with the previously generated ScriptNode
        until all leaves have been included, priorizing the lower index
        leaf scripts with smaller unlocking script sizes.
    """
    tert(type(leaves) in (list, tuple), 'leaves must be list or tuple of str')
    for branch in leaves:
        tert(type(branch) is str, 'leaves must be list or tuple of str')
        vert(len(branch) > 0, 'leaves must not be empty')
    vert(len(leaves) >= 1, 'must be at least 1 branch')

    if tree:
        node = ScriptNode(
            ScriptLeaf.from_src(leaves.pop()),
            tree
        )
        if len(leaves):
            return create_script_tree_prioritized(leaves, node)
        return node

    if len(leaves) == 1:
        leaves.append('false') # filler branch

    # combine final 2 leaves
    node = ScriptNode(
        right=ScriptLeaf.from_src(leaves.pop()),
        left=ScriptLeaf.from_src(leaves.pop())
    )

    if len(leaves):
        return create_script_tree_prioritized(leaves, node)
    return node

def create_merklized_script_prioritized(leaves: list[str]) -> tuple[Script, list[Script]]:
    """Produces a Merklized, branching script structure with one leaf
        and one node at every level except for the last node, which is
        balanced. Returns a tuple of root locking script and list of
        unlocking scripts. The tree is unbalanced; execution is
        optimized for earlier branches (lower index leaf scripts), and
        execution is linearly worse for each subsequent branch.
    """
    tree = create_script_tree_prioritized(leaves)
    lock = tree.locking_script()
    scripts = [tree.left.unlocking_script()]
    while type(tree.right) is ScriptNode:
        tree = tree.right
        scripts.append(tree.left.unlocking_script())
    scripts.append(tree.right.unlocking_script())
    return (lock, scripts)

def _format_docstring(docstring: str) -> str:
    """Takes a docstring, tokenizes it, and returns a str formatted to
        80 chars or fewer per line without splitting tokens.
    """
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

    return_annotation = function.__annotations__['return'] or 'unseen_return_value'
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
    return dox_a_class(cls, {'header_level': 2})

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
    """Generates the docs file using annotations and docstrings."""
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
    paragraphs.append(_format_function_doc(compile_script))
    paragraphs.append(_format_function_doc(decompile_script))
    paragraphs.append(_format_function_doc(add_opcode_parsing_handlers))
    paragraphs.append('\n\n# Tools')
    paragraphs.append(_format_class_doc(ScriptLeaf))
    paragraphs.append(_format_class_doc(ScriptNode))
    paragraphs.append(_format_function_doc(create_script_tree_prioritized))
    paragraphs.append(_format_function_doc(create_merklized_script_prioritized))
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
    paragraphs.append(_format_function_doc(make_delegate_key_cert_sig))
    paragraphs.append(_format_function_doc(make_delegate_key_unlock))
    paragraphs.append(_format_function_doc(make_htlc_sha256_lock))
    paragraphs.append(_format_function_doc(make_htlc_shake256_lock))
    paragraphs.append(_format_function_doc(make_htlc_witness))
    paragraphs.append(_format_function_doc(make_htlc2_sha256_lock))
    paragraphs.append(_format_function_doc(make_htlc2_shake256_lock))
    paragraphs.append(_format_function_doc(make_htlc2_witness))
    paragraphs.append(_format_function_doc(make_ptlc_lock))
    paragraphs.append(_format_function_doc(make_ptlc_witness))
    paragraphs.append(_format_function_doc(make_ptlc_refund_witness))
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
        val = tape.read(1)[0]
        return [f'{opname} d{val}']

    add_opcode(code, name, op)
    add_opcode_parsing_handlers(name, compiler_handler, decompiler_handler)

def make_adapter_lock_pub(
        pubkey: bytes, tweak_point: bytes, sigflags: str = '00') -> str:
    """Make an adapter locking script that verifies a sig adapter,
        decrypts it, and then verifies the decrypted signature.
    """
    return f'''
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
    '''

def make_adapter_lock_prv(
        pubkey: bytes, tweak: bytes, sigflags: str = '00') -> str:
    """Make an adapter locking script that verifies a sig adapter,
        decrypts it, and then verifies the decrypted signature.
    """
    t = clamp_scalar(tweak)
    T = derive_point_from_scalar(t)
    return make_adapter_lock_pub(pubkey, T, sigflags)

def make_single_sig_lock(pubkey: bytes, sigflags: str = '00') -> str:
    """Make a locking script that requires a valid signature from a
        single key to unlock. Returns tapescript source code.
    """
    return f'push x{pubkey.hex()} check_sig x{sigflags}'

def make_single_sig_lock2(pubkey: bytes, sigflags: str = '00') -> str:
    """Make a locking script that requires a valid signature from a
        single key to unlock. Returns tapescript source code. Saves 8
        bytes in locking script at expense of an additional 33 bytes in
        the witness.
    """
    return f'''
        dup shake256 d20
        push x{shake_256(pubkey).digest(20).hex()}
        equal_verify
        check_sig x{sigflags}
    '''

def make_single_sig_witness(
        prvkey: bytes, sigfields: dict[str, bytes], sigflags: str = '00') -> str:
    """Make an unlocking script that validates for a single sig locking
        script by signing the sigfields. Returns tapescript source code.
    """
    _, stack, _ = run_script(
        compile_script(f'push x{prvkey.hex()} sign x{sigflags}'),
        {**sigfields}
    )
    sig = stack.get()
    return f'push x{sig.hex()}'

def make_single_sig_witness2(
        prvkey: bytes, sigfields: dict[str, bytes], sigflags: str = '00') -> str:
    """Make an unlocking script that validates for a single sig locking
        script by signing the sigfields. Returns tapescript source code.
        33 bytes larger witness than make_single_sig_witness to save 8
        bytes in the locking script.
    """
    _, stack, _ = run_script(
        compile_script(f'''
            push x{prvkey.hex()}
            dup derive_scalar derive_point
            swap2 sign x{sigflags}
        '''),
        {**sigfields}
    )
    sig = stack.get()
    pubkey = stack.get()
    return f'push x{sig.hex()} push x{pubkey.hex()}'

def make_multisig_lock(
        pubkeys: list[bytes], quorum_size: int, sigflags: str = '00') -> str:
    """Make a locking script that requires quorum_size valid signatures
        from unique keys within the pubkeys list. Returns tapescript
        source code. Can be unlocked by joining the results of
        quorum_size calls to make_single_sig_witness by different key
        holders.
    """
    src = ''
    for pk in pubkeys:
        src += f'push x{pk.hex()}\n'
    src += f'check_multisig x{sigflags} d{quorum_size} d{len(pubkeys)}'
    return src

def make_adapter_locks_pub(
        pubkey: bytes, tweak_point: bytes, sigflags: str = '00') -> tuple[str]:
    """Make adapter locking scripts using a public key and a tweak
        scalar. Returns the source for 2 tapescripts: one that checks if
        a sig adapter is valid, and one that verifies the decrypted
        signature.
    """
    script1 = f'''
        # required push by unlocking script: signature adapter sa #
        # required push by unlocking script: nonce point R #
        get_message x{sigflags}
        push x{tweak_point.hex()}
        push x{pubkey.hex()}
        check_adapter_sig
    '''
    script2 = f'''
        # required push by unlocking script: decrypted signature #
        {make_single_sig_lock(pubkey, sigflags)}
    '''
    return (script1, script2)

def make_adapter_decrypt(tweak: bytes) -> str:
    """Make adapter decryption script."""
    t = clamp_scalar(tweak)
    return f'''
        push x{t.hex()}
        decrypt_adapter_sig
    '''

def decrypt_adapter(adapter_witness: bytes, tweak: bytes) -> bytes:
    """Decrypt an adapter signature, returning the decrypted signature."""
    _, stack, _ = run_script(
        adapter_witness +
        compile_script(make_adapter_decrypt(tweak))
    )
    s = stack.get()
    RT = stack.get()
    return RT + s

def make_adapter_locks_prv(
        pubkey: bytes, tweak: bytes, sigflags: str = '00') -> tuple[str]:
    """Make adapter locking scripts using a public key and a tweak
        scalar. Returns the source for 3 tapescripts: one that checks if
        a sig adapter is valid, one that decrypts the signature, and one
        that verifies the decrypted signature.
    """
    t = clamp_scalar(tweak)
    T = derive_point_from_scalar(t)
    script1, script3 = make_adapter_locks_pub(pubkey, T, sigflags)
    script2 = make_adapter_decrypt(tweak)
    return (script1, script2, script3)

def make_adapter_witness(
        prvkey: bytes, tweak_point: bytes, sigfields: dict,
        sigflags: str = '00') -> str:
    """Make an adapter signature witness using a private key and a tweak
        point. Returns tapescript src code.
    """
    assert 'sigfield1' in sigfields or 'sigfield2' in sigfields or \
        'sigfield3' in sigfields or 'sigfield4' in sigfields or \
        'sigfield5' in sigfields or 'sigfield6' in sigfields or \
        'sigfield7' in sigfields or 'sigfield8' in sigfields, \
        'at least one sigfield[1-8] must be included'

    _, stack, _ = run_script(
        compile_script(f'''
            push x{prvkey.hex()}
            get_message x{sigflags}
            push x{tweak_point.hex()}
            make_adapter_sig_public
        '''),
        {**sigfields}
    )
    sa = stack.get()
    R = stack.get()

    return f'''
        push x{sa.hex()}
        push x{R.hex()}
    '''

def make_delegate_key_lock(root_pubkey: bytes, sigflags: str = '00') -> str:
    """Takes a root_pubkey and returns the tapescript source for a
        locking script that is unlocked with a signature from the
        delegate key, the delegated public key, and a certificate from
        the root key committing to the delegate public key and validity
        time constraints.
    """
    return f'''
        # required push: signature from delegate key #
        # required push: delegate public key #
        # required push: delegation begin ts #
        # required push: delegation expiry ts #
        # required push: signature from root key #
        @= crt 1
        @= exp 1
        @= bgn 1
        @= dpk 1

        # prove the timestamp is within the cert bounds #
        @exp val s"timestamp" less verify
        val s"timestamp" @bgn less verify

        # cert form: delegate key + begin ts + expiry #
        @crt
        @dpk @bgn concat @exp concat
        push x{root_pubkey.hex()} check_sig_stack verify

        @dpk check_sig x{sigflags}
    '''

def make_delegate_key_cert_sig(
        root_skey: bytes, delegate_pubkey: bytes, begin_ts: int, end_ts: int
    ) -> bytes:
    """Returns a signature for a key delegation cert."""
    # cert form: delegate key + begin ts + expiry #
    _, stack, _ = run_script(compile_script(f'''
        push x{delegate_pubkey.hex()}
        push d{begin_ts} concat
        push d{end_ts} concat
        push x{root_skey.hex()} sign_stack
    '''))
    assert len(stack) == 1
    return stack.get()

def make_delegate_key_unlock(
        prvkey: bytes, pubkey: bytes, begin_ts: int, end_ts: int,
        cert_sig: bytes, sigfields: dict, sigflags: str = '00'
    ) -> str:
    _, stack, _ = run_script(
        compile_script(f'push x{prvkey.hex()} sign x{sigflags}'),
        sigfields
    )
    assert len(stack) == 1
    sig = stack.get()
    return f'''
        push x{sig.hex()}
        push x{pubkey.hex()}
        push d{begin_ts}
        push d{end_ts}
        push x{cert_sig.hex()}
    '''

def make_htlc_sha256_lock(
        receiver_pubkey: bytes, preimage: bytes, refund_pubkey: bytes,
        timeout: int = 60*60*24, sigflags: str = '00') -> str:
    """Returns an HTLC that can be unlocked either with the preimage and
        a signature matching receiver_pubkey or with a signature
        matching the refund_pubkey after the timeout has expired.
        Suitable only for systems with guaranteed causal ordering and
        non-repudiation of transactions.
    """
    return f'''
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
    '''

def make_htlc_shake256_lock(
        receiver_pubkey: bytes, preimage: bytes, refund_pubkey: bytes,
        hash_size: int = 20, timeout: int = 60*60*24, sigflags: str = '00') -> str:
    """Returns an HTLC that can be unlocked either with the preimage and
        a signature matching receiver_pubkey or with a signature
        matching the refund_pubkey after the timeout has expired.
        Suitable only for systems with guaranteed causal ordering and
        non-repudiation of transactions. Using a hash_size of 20 saves
        11 bytes compared to the sha256 version with a 96 bit reduction
        in security (remaining 160 bits) for the hash lock.
    """
    return f'''
        shake256 d{hash_size}
        push x{shake_256(preimage).digest(20).hex()}
        equal
        if {{
            push x{receiver_pubkey.hex()}
        }} else {{
            push d{int(time())+timeout}
            check_timestamp_verify
            push x{refund_pubkey.hex()}
        }}
        check_sig x{sigflags}
    '''

def make_htlc_witness(
        prvkey: bytes, preimage: bytes, sigfields: dict, sigflags: str = '00'
    ) -> str:
    """Returns the tapescript source for a witness to unlock either the
        hash lock or the time lock path of an HTLC, depending upon
        whether or not the preimage matches.
    """
    _, stack, _ = run_script(
        compile_script(f'push x{prvkey.hex()} sign x{sigflags}'),
        {**sigfields}
    )
    sig = stack.get()
    return f'''
        push x{sig.hex()}
        push x{preimage.hex()}
    '''

def make_htlc2_sha256_lock(
        receiver_pubkey: bytes, preimage: bytes, refund_pubkey: bytes,
        timeout: int = 60*60*24, sigflags: str = '00') -> str:
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
    return f'''
        sha256
        push x{sha256(preimage).digest().hex()}
        equal
        if {{
            dup shake256 d20
            push x{shake_256(receiver_pubkey).digest(20).hex()}
        }} else {{
            push d{int(time())+timeout}
            check_timestamp_verify
            dup shake256 d20
            push x{shake_256(refund_pubkey).digest(20).hex()}
        }}
        equal_verify
        check_sig x{sigflags}
    '''

def make_htlc2_shake256_lock(
        receiver_pubkey: bytes, preimage: bytes, refund_pubkey: bytes,
        hash_size: int = 20, timeout: int = 60*60*24, sigflags: str = '00'
    ) -> str:
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
    return f'''
        shake256 d{hash_size}
        push x{shake_256(preimage).digest(20).hex()}
        equal
        if {{
            dup shake256 d20
            push x{shake_256(receiver_pubkey).digest(20).hex()}
        }} else {{
            push d{int(time())+timeout}
            check_timestamp_verify
            dup shake256 d20
            push x{shake_256(refund_pubkey).digest(20).hex()}
        }}
        equal_verify
        check_sig x{sigflags}
    '''

def make_htlc2_witness(
        prvkey: bytes, preimage: bytes, sigfields: dict, sigflags: str = '00'
    ) -> str:
    """Returns the tapescript source for a witness to unlock either the
        hash lock or the time lock path of an HTLC, depending upon
        whether or not the preimage matches. This version is optimized
        for smaller locking script size (-18 bytes) at the expense of
        larger witnesses (+33 bytes) for larger overall txn size (+15
        bytes). Which to use will depend upon the intended use case: for
        public blockchains where all nodes must hold a UTXO set in
        memory and can trim witness data after consensus, the lock
        script size reduction is significant and useful; for other use
        cases, in particular systems where witness data cannot be
        trimmed, the other version is more appropriate.
    """
    _, stack, _ = run_script(
        compile_script(f'''
            push x{prvkey.hex()}
            dup derive_scalar derive_point
            swap2 sign x{sigflags}
        '''),
        {**sigfields}
    )
    sig = stack.get()
    pubkey = stack.get()
    return f'''
        push x{sig.hex()}
        push x{pubkey.hex()}
        push x{preimage.hex()}
    '''

def make_ptlc_lock(
        receiver_pubkey: bytes, refund_pubkey: bytes, tweak_point: bytes = None,
        timeout: int = 60*60*24, sigflags: str = '00') -> str:
    """Returns the tapescript source for a Point Time Locked Contract
        that can be unlcoked with either a signature matching the
        receiver_pubkey or with a signature matching the refund_pubkey
        after the timeout has expired. Suitable only for systems with
        guaranteed causal ordering and non-repudiation of transactions.
        If a tweak_point is passed, use tweak_point+receiver_pubkey as
        the point lock.
    """
    if type(tweak_point) is bytes:
        receiver_pubkey = aggregate_points([receiver_pubkey, tweak_point])
    return f'''
        if {{
            push x{receiver_pubkey.hex()}
        }} else {{
            push d{int(time())+timeout}
            check_timestamp_verify
            push x{refund_pubkey.hex()}
        }}
        check_sig x{sigflags}
    '''

def make_ptlc_witness(
        prvkey: bytes, sigfields: dict, tweak_scalar: bytes = None,
        sigflags: str = '00') -> str:
    '''Returns the tapescript source for a PTLC witness unlocking the
        main branch. If a tweak_scalar is passed, add tweak_scalar to x
        within signature generation to unlock the point corresponding to
        derive_point(tweak_scalar)+derive_point(x).
    '''
    if tweak_scalar:
        # create signature manually
        _, stack, _ = run_script(compile_script(f'get_message x{sigflags}'), {**sigfields})
        m = stack.get()
        x = aggregate_scalars([derive_key_from_seed(prvkey), tweak_scalar])
        X = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(x) # G^x
        r = clamp_scalar(H_small(H_big(prvkey)[32:], m))
        R = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(r) # G^r
        c = clamp_scalar(H_small(R, X, m)) # clamp(H(R || X || m))
        s = nacl.bindings.crypto_core_ed25519_scalar_add(
            r, nacl.bindings.crypto_core_ed25519_scalar_mul(c, x)
        )
        return f'push x{R.hex() + s.hex()}{sigflags} true'
    return f'{make_single_sig_witness(prvkey, sigfields, sigflags)} true'

def make_ptlc_refund_witness(prvkey: bytes, sigfields: dict, sigflags: str = '00') -> str:
    '''Returns the tapescript source for a PTLC witness unlcoking the
        time locked refund branch.
    '''
    return f'{make_single_sig_witness(prvkey, sigfields, sigflags)} false'

def setup_amhl(
        seed: bytes, pubkeys: tuple[bytes]|list[bytes], sigflags: str = '00',
        refund_pubkeys: dict[bytes] = None, timeout: int = 60*60*24
    ) -> dict[bytes|str, bytes|tuple[str|bytes]]:
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

def release_left_amhl_lock(adapter_witness: bytes, signature: bytes, y: bytes) -> bytes:
    """Release the next lock using an adapter witness and a decrypted
        signature from right lock. Returns the tweak scalar used to
        decrypt the left adapter signature.
    """
    tert(type(adapter_witness) is bytes, 'adapter_witness must be bytes of len 66')
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
        '\tcompile src_file bin_file -- compiles the source code into bytecode '
        'and writes it to bin_file',
        '\tdecompile bin_file -- decompiles the bytecode and outputs to stdout',
        '\trun bin_file [cache_file] -- runs tapescript bytecode and prints the '
        'resulting cache and stack',
        '\tauth bin_file [cache_file] -- runs tapescript bytecode as auth script'
        ' and prints true if it was successful or false otherwise\n',
        'The optional cache_file parameter must be a json file with the '
        'following format:',
        '{', '\t"type:name": [type, value]', '}\n',
        'The type must be one of "string", "str", "number", "bytes". All bytes '
        'values must be hexadecimal strings. For example:',
        '{', '\t["number", 78]: ["bytes", "d13f398b5bacf525"]', '}'
    ])

def _clert(condition: bool, message: str = ''):
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
    errmsg = 'JSON file format is {"type:name": [type, value], ...}. ' + \
        'The type must be "string", "str", "number", or "bytes". Bytes ' + \
        'values must be hexadecimal. If type is "string" or "str", the ' + \
        'associated name or value must be a string. If type is "number", ' + \
        'the associated name or value must be a number.'
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
    _clert(len(argv) >= 2)
    method = argv[1]
    match method:
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
