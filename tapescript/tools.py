from .AMHL import AMHL
from .classes import Tape
from .errors import tert, vert, yert
from .parsing import (
    compile_script,
    decompile_script,
    add_opcode_parsing_handlers
)
from .functions import (
    opcodes_inverse,
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
    derive_point_from_scalar,
)
from hashlib import sha256, shake_256
from time import time
from typing import Callable


def _combine_two(branch_a: str, branch_b: str) -> list[str]:
    """Takes two script branches, hashes them, and returns a root script
        using OP_MERKLEVAL and two unlocking scripts that execute the
        supplied branches after the locking script executes.
    """
    compiled_a = compile_script(branch_a)
    compiled_b = compile_script(branch_b)
    hash_a = sha256(compiled_a).digest()
    hash_b = sha256(compiled_b).digest()
    root = sha256(hash_a + hash_b).digest()

    root_script = f'OP_MERKLEVAL x{root.hex()}\n'
    script_a = f'OP_PUSH x{hash_b.hex()}\nOP_PUSH x{compiled_a.hex()}\nOP_TRUE\n'
    script_b = f'OP_PUSH x{hash_a.hex()}\nOP_PUSH x{compiled_b.hex()}\nOP_FALSE\n'

    return [root_script, script_a, script_b]

def _format_scripts(levels: list) -> tuple[str, list[str]]:
    """Turns a list of script levels into a top-level locking script and
        the unlocking scripts for each branch.
    """
    locking_script = levels[0][0]
    branches = [levels[0][1]]
    partial = levels[0][2]

    for i in range(1, len(levels)):
        branches.append(levels[i][1] + partial)
        partial = levels[i][2] + partial

    branches.append(partial)

    return (locking_script, branches)

def create_merklized_script(branches: list[str], levels: list = None) -> tuple[str, list[str]]:
    """Produces a Merklized, branching script structure with a branch on
        the left at every level. Returns a tuple of root script and list
        of branch execution scripts.
    """
    tert(type(branches) in (list, tuple), 'branches must be list or tuple of str')
    for branch in branches:
        tert(type(branch) is str, 'branches must be list or tuple of str')
        vert(len(branch) > 0, 'branches must not be empty')
    vert(len(branches) >= 1, 'must be at least 1 branch')

    if len(branches) == 1:
        branches.append('OP_FALSE') # filler branch
    levels = [] if not levels else levels

    # combine final 2 branches
    scripts = _combine_two(branches[-2], branches[-1])
    levels.append(scripts)
    remaining_branches = [*branches[:-2], scripts[0]]

    if len(remaining_branches) == 1:
        levels.reverse()
        return _format_scripts(levels)

    return create_merklized_script(remaining_branches, levels)

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

def _format_function_doc(function: Callable) -> str:
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

    val = '\n\n## `'
    val += name
    val += '('
    val += annotations
    val += '): -> '
    val += return_annotation
    val += f'`\n\n{docstring}'
    return val

def generate_docs() -> list[str]:
    """Generates the docs file using annotations and docstrings."""
    data = {}

    for opname in opcodes_inverse:
        number = opcodes_inverse[opname][0]
        doc = opcodes_inverse[opname][1].__doc__
        data[number] = (opname, doc)

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
        'def OP_WHATEVER(tape: Tape, queue: LifoQueue, cache: dict) -> None:\n'
        '    ...\n```\n'
    ]

    for number in data:
        line = f'\n## {data[number][0]} - {number} - x{number.to_bytes(1, "big").hex().upper()}\n\n'
        docstring = _format_docstring(data[number][1])
        paragraphs.append(line + docstring + '\n')

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
    paragraphs.append(_format_function_doc(create_merklized_script))
    paragraphs.append(_format_function_doc(generate_docs))
    paragraphs.append(_format_function_doc(add_soft_fork) + '\n\n')

    with open('notes.md', 'r') as f:
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

def make_single_sig_witness(
        prvkey: bytes, sigfields: dict[str, bytes], sigflags: str = '00',
        contracts: dict = {}) -> str:
    """Make an unlocking script that validates for a single sig locking
        script by signing the sigfields. Returns tapescript source code.
    """
    _, queue, _ = run_script(
        compile_script(f'push x{prvkey.hex()} sign x{sigflags}'),
        {**sigfields},
        {**contracts}
    )
    s = queue.get(False)
    return f'push x{s.hex()}{sigflags}'

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
    script2 = f'''
        push x{t.hex()}
        decrypt_adapter_sig
    '''
    return (script1, script2, script3)

def make_adapter_witness(
        prvkey: bytes, tweak_point: bytes, sigfields: dict,
        sigflags: str = '00', contracts: dict[bytes, object] = {}) -> str:
    """Make an adapter signature witness using a private key and a tweak
        point. Returns tapescript src code.
    """
    assert 'sigfield1' in sigfields or 'sigfield2' in sigfields or \
        'sigfield3' in sigfields or 'sigfield4' in sigfields or \
        'sigfield5' in sigfields or 'sigfield6' in sigfields or \
        'sigfield7' in sigfields or 'sigfield8' in sigfields, \
        'at least one sigfield[1-8] must be included'

    _, queue, _ = run_script(
        compile_script(f'''
            push x{prvkey.hex()}
            get_message x{sigflags}
            push x{tweak_point.hex()}
            make_adapter_sig_public
        '''),
        {**sigfields},
        {**contracts}
    )
    sa = queue.get(False)
    R = queue.get(False)

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
        @= sig 1

        # prove the timestamp is within the cert bounds #
        @exp val s"timestamp" less verify
        val s"timestamp" @bgn less verify

        # cert form: delegate key + begin ts + expiry #
        @exp @bgn concat @dpk concat
        @crt push x{root_pubkey.hex()} check_sig_queue verify

        @sig @dpk check_sig x{sigflags}
    '''

def make_delegate_key_cert_sig(
        root_skey: bytes, delegate_pubkey: bytes, begin_ts: int, end_ts: int
    ) -> bytes:
    """Returns a signature for a key delegation cert."""
    _, queue, _ = run_script(compile_script(f'''
        push d{end_ts} push d{begin_ts} concat
        push x{delegate_pubkey.hex()} concat
        push x{root_skey.hex()} sign_queue
    '''))
    assert queue.qsize() == 1
    return queue.get(False)

def make_delegate_key_unlock(
        prvkey: bytes, pubkey: bytes, begin_ts: int, end_ts: int,
        cert_sig: bytes, sigfields: dict, sigflags: str = '00'
    ) -> str:
    _, queue, _ = run_script(
        compile_script(f'push x{prvkey.hex()} sign x{sigflags}'),
        sigfields
    )
    assert queue.qsize() == 1
    sig = queue.get(False)
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
            check_sig x{sigflags}
        }} else {{
            push d{int(time())+timeout}
            check_timestamp_verify
            push x{refund_pubkey.hex()}
            check_sig x{sigflags}
        }}
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
            check_sig x{sigflags}
        }} else {{
            push d{int(time())+timeout}
            check_timestamp_verify
            push x{refund_pubkey.hex()}
            check_sig x{sigflags}
        }}
    '''

def make_htlc_witness(
        prvkey: bytes, preimage: bytes, sigfields: dict, sigflags: str = '00') -> str:
    """Returns the tapescript source for a witness to unlock either the
        hash lock or the time lock path of an HTLC, depending upon
        whether or not the preimage matches.
    """
    _, queue, _ = run_script(
        compile_script(f'push x{prvkey.hex()} sign x{sigflags}'),
        sigfields
    )
    sig = queue.get(False)
    return f'''
        push x{sig.hex()}
        push x{preimage.hex()}
    '''
