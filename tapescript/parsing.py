from .errors import yert, vert, SyntaxError
from .classes import Tape
from .functions import (
    bytes_to_int,
    int_to_bytes,
    opcodes,
    opcodes_inverse,
    opcode_aliases,
    nopcodes,
    nopcodes_inverse,
    run_script,
)
from math import ceil, log2
from typing import Any, Callable
import struct


def is_hex(s: str) -> bool:
    """Checks if a string is made of valid hexadecimal chars."""
    try:
        bytes.fromhex(f'0{s}' if len(s) % 2 else s)
        return True
    except:
        return False

def get_symbols(script: str) -> list[str]:
    """Split the script source into symbols. Raises SyntaxError for
        unterminated string values.
    """
    splits = [s for s in script.split()]
    splits.reverse()
    symbols = []

    while len(splits):
        token = splits.pop()
        if token[:2] in ('s"', "s'"):
            quote = token[1]
            # match to end of string value
            found = quote in token[3:]
            parts = [token]
            while not found and len(splits):
                next = splits.pop()
                parts.append(next)
                if quote in next:
                    found = True
            yert(found, 'unterminated string encountered')
            token = ' '.join(parts)
            symbols.append(token)
        elif token[0] not in ('s', 'd', 'x', '!', '@'):
            symbols.append(token.upper())
        elif token[0] == 'd' and not token[1:].isnumeric():
            symbols.append(token.upper())
        elif token[0] == 'x' and not is_hex(token[1:]):
            symbols.append(token.upper())
        elif token[0] == 's' and token[1] not in ('"', "'"):
            symbols.append(token.upper())
        elif token[:2] in ('@=', '!='):
            symbols.append(token)
            symbols.append(splits.pop())
        else:
            symbols.append(token)

    return symbols


additional_opcodes = {}
_special_symbols = ('END_IF', 'END_DEF', 'ELSE', '(',')','{','}')

def define_macro(symbols: list[str], macros: dict = {}) -> int:
    """Defines a macro. Code syntax is `!= name [ args ] { statements }`.
        Returns the number by which to advance the symbol index.
    """
    yert(symbols[0] == '!=', 'macro definition must begin with !=')
    name = symbols[1].lower()
    yert(name.isalnum(), 'macro name must be alphanumeric')
    yert(symbols[2] == '[',
         'macro definition must be of form != name [ args ] { statements }')
    closing_brace_index = _find_matching_brace(symbols, '[', ']')
    args = symbols[3:closing_brace_index]
    for arg in args:
        yert(arg.isalnum(), f'macro arg names must be alphanumeric, not {arg}')
    yert(symbols[closing_brace_index+1] == '{',
         'macro definition must be of form != name [ args ] { statements }')
    open_brace_index = closing_brace_index+1
    closing_brace_index = _find_matching_brace(
        symbols, '{', '}'
    )
    statement_symbols = symbols[open_brace_index+1:closing_brace_index]

    macros[name] = {
        'args': args,
        'template': statement_symbols,
    }
    return closing_brace_index + 1

def invoke_macro(symbols: list[str], macros: dict = {}) -> tuple[int, tuple[bytes]]:
    """Invokes a macro, returning the number by which to advance the
        symbol index and the compiled bytecode. May raise a SyntaxError.
    """
    yert(symbols[0][0] == '!', f'macro call must start with !, not {symbols[0][0]}')
    name = symbols[0][1:].lower()
    yert(name in macros, f'cannot call undefined macro: {name}')
    yert(symbols[1] == '[', 'macro call must take form !name [ args ]')
    closing_brace_index = _find_matching_brace(symbols, '[', ']')
    args = symbols[2:closing_brace_index]
    yert(len(args) == len(macros[name]['args']),
         f'call to macro {name} must have args {macros[name]["args"]}')
    args = zip(macros[name]['args'], args)
    args = { a:v for a,v in args }

    src = [*macros[name]['template']]
    for i in range(len(src)):
        if src[i] in args:
            src[i] = args[src[i]]

    code = compile_script(' '.join(src))
    return (closing_brace_index+1, (code,))

def set_variable(symbols: list[str]) -> tuple[int, tuple[bytes]]:
    """Expand syntactic sugar of `@= name [ vals ]` into proper OPs,
        then compile and return the number to advance the symbol index
        and the bytecode.
    """
    yert(symbols[0] == '@=',
         f'set_variable statement must start with @=, not {symbols[0]}')
    name = symbols[1]
    yert(name.isalnum(), f'set_variable name must be alphanumeric, not {name}')
    yert(symbols[2] == '[' or symbols[2].isnumeric(),
         'set_variable statement must be of form @= name [ vals ] or @= name int')

    if symbols[2].isnumeric():
        count = int(symbols[2])
        src = ['WRITE_CACHE']
        src.append('x' + bytes(name, 'utf-8').hex())
        src.append('d' + str(count))
        code = compile_script(' '.join(src))
        return (
            3,
            (code,)
        )

    closing_brace_index = _find_matching_brace(symbols, '[', ']')
    vals = symbols[3:closing_brace_index]

    src = []
    for val in vals:
        src.extend(['PUSH', val])

    src.append('WRITE_CACHE')
    src.append('x' + bytes(name, 'utf-8').hex())
    src.append('d' + str(len(vals)))

    code = compile_script(' '.join(src))

    return (
        closing_brace_index + 1,
        (code,)
    )

def load_variable(symbols: list[str]) -> tuple[int, tuple[bytes]]:
    """Expand the syntactic sugar of `@name` into proper OPs, then
        compile and return the number to advance the symbol index and
        the bytecode.
    """
    yert(symbols[0][0] == '@',
         f"load_variable statement must be of form @name, not {symbols[0]}")
    name = symbols[0][1:]
    yert(name.isalnum(), f'load_variable name must be alphanumeric, not {name}')

    src = "READ_CACHE x" + bytes(name, 'utf-8').hex()
    return (1, (compile_script(src),))

def add_opcode_parsing_handlers(
        opname: str, compiler_handler: Callable, decompiler_handler: Callable
    ) -> None:
    """Adds the handlers for parsing a new OP. The opname should start
        with OP_. The compiler_handler should have this annotation: (
        opname: str, symbols: list[str], symbols_to_advance: int,
        symbol_index: int) -> tuple[int, tuple[bytes]]. The
        decompiler_handler should have this annotation: (op_name: str,
        tape: Tape) -> list[str]. The OP implementation must be added
        to the interpreter via the add_opcode function, else parsing
        will fail.
    """
    additional_opcodes[opname] = (compiler_handler, decompiler_handler)

def _get_additional_opcode_args(
        opname: str, symbols: list[str], symbols_to_advance: int,
        symbol_index: int
    ) -> tuple[int, tuple[bytes]]:
    vert(opname in additional_opcodes, f'unrecognized opname {opname}')
    return additional_opcodes[opname][0](opname, symbols, symbols_to_advance, symbol_index)

def _get_OP_PUSH_args(
        opname: str, symbols: list[str], symbols_to_advance: int, index: int
    ) -> tuple[int, tuple[bytes]]:
    args = []
    symbols_to_advance += 1
    val = symbols[0]
    yert(val[0].lower() in ('d', 'x', 's'),
        f'Symbol {index}: values for OP_PUSH must be prefaced with d, x, or s')

    match val[0].lower():
        case 'd':
            vert(val[1:].isnumeric() or (val[1] == '-' and val[2:].isnumeric()),
                'value prefaced by d must be decimal int')
            val = int(val[1:].split('.')[0])
            val = int_to_bytes(val)
        case 'x':
            val = bytes.fromhex(val[1:])
        case 's':
            if val[1] == '"' and '"' in val[2:]:
                last_idx = val[2:].index('"')
                val = bytes(val[2:last_idx+2], 'utf-8')
            elif val[1] == "'" and "'" in val[2:]:
                last_idx = val[2:].index("'")
                val = bytes(val[2:last_idx+2], 'utf-8')
            else:
                val = bytes(val[1:], 'utf-8')

    if len(val) == 1:
        ...
    elif 1 < len(val) < 256:
        # tape syntax of OP_PUSH1 [size 0-255] [val]
        # human-readable decompiled syntax of OP_PUSH1 val
        args.append(len(val).to_bytes(1, 'big'))
    elif 255 < len(val) < 65_536:
        # tape syntax of OP_PUSH2 [size 0-65_535] [val]
        # human-readable decompiled syntax of OP_PUSH2 val
        args.append(len(val).to_bytes(2, 'big'))
    else:
        raise ValueError(f'size of value invalid for OP_PUSH: {len(val)}')
    args.append(val)
    return (symbols_to_advance, args)

def _get_OP_WRITE_CACHE_args(
        opname: str, symbols: list[str], symbols_to_advance: int
    ) -> tuple[int, tuple[bytes]]:
    symbols_to_advance += 2
    cache_key = symbols[0]
    count = symbols[1]
    yert(cache_key[0].lower() in ('d', 'x', 's'),
        'cache_key for OP_WRITE_CACHE must be prefaced with d, x, or s')
    yert(count[0].lower() in ('d', 'x'),
        'count for OP_WRITE_CACHE must be prefaced with d or x')

    match cache_key[0].lower():
        case 'd':
            vert(cache_key[1:].isnumeric(),
                'value prefaced by d must be decimal int')
            if '.' in cache_key:
                cache_key = int(cache_key[1:].split('.')[0])
            else:
                cache_key = int(cache_key[1:])
            size = ceil(log2(cache_key+1)/8) or 1
            cache_key = cache_key.to_bytes(size, 'big')
        case 'x':
            cache_key = bytes.fromhex(cache_key[1:])
        case 's':
            if cache_key[1] == '"' and '"' in cache_key[2:]:
                last_idx = cache_key[2:].index('"')
                cache_key = bytes(cache_key[2:last_idx+2], 'utf-8')
            elif cache_key[1] == "'" and "'" in cache_key[2:]:
                last_idx = cache_key[2:].index("'")
                cache_key = bytes(cache_key[2:last_idx+2], 'utf-8')
            else:
                cache_key = bytes(cache_key[1:], 'utf-8')

    match count[0].lower():
        case 'd':
            vert(count[1:].isnumeric(),
                'value prefaced by d must be decimal int')
            if '.' in count:
                count = int(count[1:].split('.')[0])
            else:
                count = int(count[1:])
        case 'x':
            count = int.from_bytes(bytes.fromhex(count[1:]), 'big')

    size = len(cache_key)
    yert(size < 256, 'cache_key max length of 255 exceeded for OP_WRITE_CACHE')
    yert(count < 256, 'count max size of 255 exceeded for OP_WRITE_CACHE')

    return (symbols_to_advance, [size.to_bytes(1, 'big'), cache_key, count.to_bytes(1, 'big')])

def _get_OP_PUSH0_type_args(
        opname: str, symbols: list[str], symbols_to_advance: int, symbol_index: int
    ) -> tuple[int, tuple[bytes]]:
    args = []
    symbols_to_advance += 1
    val = symbols[0]
    yert(val[0].lower() in ('d', 'x'),
        f'{opname} - numeric args must be prefaced with d or x; {val} is invalid - symbol {symbol_index}')

    match val[0].lower():
        case 'd':
            vert(val[1:].lstrip('+-').isnumeric(),
                f'{opname} - value prefaced by d must be decimal int; {val} is invalid - symbol {symbol_index}')
            val = int_to_bytes(int(val[1:].split('.')[0]))
            assert len(val) == 1, 'value overflow'
            args.append(val)
        case 'x':
            vert(len(val[1:]) <= 2,
                f'{opname} - value must be at most 1 byte long; {val} is invalid - symbol {symbol_index}')
            val = bytes.fromhex(val[1:])
            args.append(val if len(val) == 1 else b'\x00')
    return (symbols_to_advance, args)

def _get_OP_PUSH1_type_args(
        opname: str, symbols: list[str], symbols_to_advance: int,
        symbol_index: int
    ) -> tuple[int, tuple[bytes]]:
    args = []
    val = None

    if opname == 'OP_PUSH1':
        # human-readable syntax of OP_PUSH1 [size] [val] or OP_PUSH1 [val]
        if (len(symbols[1]) < 3 or symbols[1][:3] != 'OP_') and \
            symbols[1] not in opcodes_inverse and symbols[1] not in nopcodes_inverse and \
            symbols[1] not in opcode_aliases and symbols[1] not in _special_symbols:
            symbols_to_advance += 2
            val = symbols[1]
        else:
            symbols_to_advance += 1
            val = symbols[0]
    else:
        # human-readable syntax of OP_[whatever] [key]
        symbols_to_advance += 1
        val = symbols[0]

    yert(val[0].lower() in ('d', 'f', 'x', 's'),
        f'values for {opname} must be prefaced with d, x, or s; {val} is invalid'
        f' - symbol {symbol_index}')
    match val[0].lower():
        case 'd':
            vert(val[1:].lstrip('+-').replace('.','').isnumeric(),
                f'{opname} - value prefaced by d must be decimal int; '
                f'{val} is invalid - symbol {symbol_index}')
            val = int_to_bytes(int(val[1:].split('.')[0]))
            args.append(len(val).to_bytes(1, 'big'))
            args.append(val)
        case 'f':
            vert(val[1:].lstrip('+-').replace('.','').isnumeric(),
                f'{opname} - value prefaced by f must be decimal float; '
                f'{val} is invalid - symbol {symbol_index}')
            args.append((4).to_bytes(1, 'big'))
            args.append(struct.pack('!f', float(val[1:])))
        case 'x':
            val = bytes.fromhex(val[1:])
            args.append(len(val).to_bytes(1, 'big'))
            args.append(val)
        case 's':
            if val[1] == '"' and '"' in val[2:]:
                last_idx = val[2:].index('"')
                val = bytes(val[2:last_idx+2], 'utf-8')
            elif val[1] == "'" and "'" in val[2:]:
                last_idx = val[2:].index("'")
                val = bytes(val[2:last_idx+2], 'utf-8')
            else:
                val = bytes(val[1:], 'utf-8')
            args.append(len(val).to_bytes(1, 'big'))
            args.append(val)
    return (symbols_to_advance, args)

def _get_OP_PUSH2_args(
        opname: str, symbols: list[str], symbols_to_advance: int,
        symbol_index: int
    ) -> tuple[int, tuple[bytes]]:
    args = []
    val = None

    if opname == 'OP_PUSH2':
        # human-readable syntax of OP_PUSH2 [size] [val] or OP_PUSH2 [val]
        if (len(symbols[1]) < 3 or symbols[1][:3] != 'OP_') and \
            symbols[1] not in opcodes_inverse and symbols[1] not in nopcodes_inverse and \
            symbols[1] not in opcode_aliases and symbols[1] not in _special_symbols:
            symbols_to_advance += 2
            val = symbols[1]
        else:
            symbols_to_advance += 1
            val = symbols[0]
    else:
        # human-readable syntax of OP_[whatever] [key]
        symbols_to_advance += 1
        val = symbols[0]

    yert(val[0].lower() in ('d', 'f', 'x', 's'),
        f'{opname} - values for OP_PUSH2 must be prefaced with d, f, x, or s; '
        f'{val} is invalid - symbol {symbol_index}')

    match val[0].lower():
        case 's':
            if val[1] == '"' and '"' in val[2:]:
                last_idx = val[2:].index('"')
                val = bytes(val[2:last_idx+2], 'utf-8')
            elif val[1] == "'" and "'" in val[2:]:
                last_idx = val[2:].index("'")
                val = bytes(val[2:last_idx+2], 'utf-8')
            else:
                val = bytes(val[1:], 'utf-8')
        case 'd':
            vert(val[1:].lstrip('+-').isnumeric(),
                f'{opname} - value prefaced by d must be decimal int; {val} is '
                f'invalid - symbol {symbol_index}')
            val = int_to_bytes(int(val[1:].split('.')[0]))
            vert(len(val) < 65_536, f'OP_PUSH2 value overflow; {bytes_to_int(val)}'
                 f' is invalid - symbol {symbol_index}')
        case 'f':
            vert(val[1:].lstrip('+-').replace('.','').isnumeric(),
                f'{opname} - value prefaced by f must be decimal float; '
                f'{val} is invalid - symbol {symbol_index}')
            args.append((4).to_bytes(1, 'big'))
            args.append(struct.pack('!f', float(val[1:])))
        case 'x':
            val = bytes.fromhex(val[1:])
            vert(len(val) < 65_536,
                f'x-value for OP_PUSH2 must be at most 65_535 bytes long - '
                f'symbol {symbol_index}')
    args.append(len(val).to_bytes(2, 'big'))
    args.append(val)
    return (symbols_to_advance, args)

def _get_OP_DIV_FLOAT_args(
        opname: str, symbols: list[str], symbols_to_advance: int,
        symbol_index: int
    ) -> tuple[int, tuple[bytes]]:
    args = []
    symbols_to_advance += 1
    val = symbols[0]
    yert(val[0].lower() in ('f', 'x'),
        f'{opname} - numeric args must be prefaced with f or x; {val} is invalid - symbol {symbol_index}')

    match val[0].lower():
        case 'f':
            vert(val[1:].lstrip('+-').isnumeric(),
                f'{opname} - value prefaced by f must be decimal float; {val} is invalid - symbol {symbol_index}')
            args.append(struct.pack('!f', float(val[1:])))
        case 'x':
            vert(len(val[1:]) == 8,
                f'{opname} - value prefaced by x must be 8 long (4 bytes); {val} is invalid - symbol {symbol_index}')
            args.append(bytes.fromhex(val[1:]))
    return (symbols_to_advance, args)

def _get_OP_SWAP_type_args(
        opname: str, symbols: list[str], symbols_to_advance: int,
        symbol_index: int
    ) -> tuple[int, tuple[bytes]]:
    args = []
    symbols_to_advance += 2
    vals = symbols[:2]

    for val in vals:
        yert(val[0].lower() in ('d', 'x'),
            f'{opname} - numeric args must be prefaced with d or x; {val} is invalid - symbol {symbol_index}')

        match val[0].lower():
            case 'd':
                vert(val[1:].isnumeric(),
                    f'{opname} - value prefaced by d must be decimal int; {val} is invalid - symbol {symbol_index}')
                if '.' in val:
                    val = int(val[1:].split('.')[0])
                else:
                    val = int(val[1:])
                yert(0 <= val < 256, f'{opname} - index overflow - symbol {symbol_index}')
                args.append(val.to_bytes(1, 'big'))
            case 'x':
                vert(len(val[1:]) == 2,
                    f'{opname} - value prefaced by x must be 2 long (1 byte); {val} is invalid - symbol {symbol_index}')
                args.append(bytes.fromhex(val[1:]))
    return (symbols_to_advance, args)

def _get_OP_CHECK_MULTISIG_args(
        opname: str, symbols: list[str], symbols_to_advance: int,
        symbol_index: int
    ) -> tuple[int, tuple[bytes]]:
    args = []
    symbols_to_advance += 3
    vals = symbols[:3]

    for val in vals:
        yert(val[0].lower() in ('d', 'x'),
            f'{opname} - numeric args must be prefaced with d or x; {val} is invalid - symbol {symbol_index}')

        match val[0].lower():
            case 'd':
                vert(val[1:].isnumeric(),
                    f'{opname} - value prefaced by d must be decimal int; {val} is invalid - symbol {symbol_index}')
                if '.' in val:
                    val = int(val[1:].split('.')[0])
                else:
                    val = int(val[1:])
                yert(0 <= val < 256, f'{opname} - index overflow - symbol {symbol_index}')
                args.append(val.to_bytes(1, 'big'))
            case 'x':
                vert(len(val[1:]) == 2,
                    f'{opname} - value prefaced by x must be 2 long (1 byte); {val} is invalid - symbol {symbol_index}')
                args.append(bytes.fromhex(val[1:]))
    return (symbols_to_advance, args)

def _get_OP_MERKLEVAL_args(
        opname: str, symbols: list[str], symbols_to_advance: int,
        symbol_index: int
    ) -> tuple[int, tuple[bytes]]:
    args = []
    symbols_to_advance += 1
    val = symbols[0]
    yert(val[0].lower() == 'x', f'OP_MERKLEVAL - arg must be hexadecimal hash; {val} is invalid - symbol {symbol_index}')
    yert(len(val) == 65, f'OP_MERKLEVAL - arg must be hexadecimal hash; {val} is invalid - symbol {symbol_index}')
    args.append(bytes.fromhex(val[1:]))
    return (symbols_to_advance, args)

def _get_nopcode_args(
        opname: str, symbols: list[str], symbols_to_advance: int,
        symbol_index: int
    ) -> tuple[int, tuple[bytes]]:
    return _get_OP_PUSH0_type_args(opname, symbols, symbols_to_advance, symbol_index)

def get_args(
        opname: str, symbols: list[str], symbol_index: int
    ) -> tuple[int, tuple[bytes]]:
    """Get the number of symbols to advance and args for an op."""
    symbols_to_advance = 1
    args = []

    match opname:
        case 'OP_FALSE' | 'OP_TRUE' | 'OP_POP0' | 'OP_SIZE' | \
            'OP_READ_CACHE_STACK' | 'OP_READ_CACHE_STACK_SIZE' | 'OP_DIV_INTS' | \
            'OP_MOD_INTS' | 'OP_DIV_FLOATS' | 'OP_MOD_FLOATS' | 'OP_DUP' | \
            'OP_SHA256' | 'OP_VERIFY' | 'OP_EQUAL' | 'OP_EQUAL_VERIFY' | \
            'OP_CHECK_TIMESTAMP' | 'OP_CHECK_TIMESTAMP_VERIFY' | \
            'OP_CHECK_EPOCH' | 'OP_CHECK_EPOCH_VERIFY' | 'OP_EVAL' | \
            'OP_RANDOM' | 'OP_NOT' | 'OP_RETURN' | 'OP_DEPTH' | 'OP_SWAP2' | \
            'OP_CONCAT' | 'OP_CONCAT_STR' | 'OP_CHECK_TRANSFER' | 'OP_LESS' | \
            'OP_LESS_OR_EQUAL' | 'OP_FLOAT_LESS' | 'OP_FLOAT_LESS_OR_EQUAL' | \
            'OP_INT_TO_FLOAT' | 'OP_FLOAT_TO_INT' | 'OP_SIGN_STACK' | \
            'OP_CHECK_SIG_STACK' | 'OP_DERIVE_SCALAR' | 'OP_DERIVE_POINT' | \
            'OP_MAKE_ADAPTER_SIG_PUBLIC' | 'OP_MAKE_ADAPTER_SIG_PRIVATE' | \
            'OP_CHECK_ADAPTER_SIG' | 'OP_DECRYPT_ADAPTER_SIG' | 'OP_INVOKE' | \
            'OP_SPLIT' | 'OP_SPLIT_STR' | 'OP_XOR' | 'OP_OR' | 'OP_AND':
            # ops that have no arguments on the tape
            # human-readable syntax of OP_[whatever]
            pass
        case 'OP_PUSH':
            # special case: OP_PUSH is a short hand for OP_PUSH[0,1,2,4]
            return _get_OP_PUSH_args(opname, symbols, symbols_to_advance, symbol_index)
        case 'OP_WRITE_CACHE':
            # op with tape arguments of form [size 0-255] [val] [count 0-255]
            return _get_OP_WRITE_CACHE_args(opname, symbols, symbols_to_advance)
        case 'OP_PUSH1' | 'OP_READ_CACHE' | \
            'OP_READ_CACHE_SIZE' | 'OP_DIV_INT' | \
            'OP_MOD_INT' | 'OP_SET_FLAG' | 'OP_UNSET_FLAG' | 'OP_GET_VALUE':
            # ops that have tape arguments of form [size 0-255] [val]
            return _get_OP_PUSH1_type_args(opname, symbols, symbols_to_advance, symbol_index)
        case 'OP_PUSH0' | 'OP_POP1' | 'OP_ADD_INTS' | 'OP_SUBTRACT_INTS' | \
            'OP_MULT_INTS' | 'OP_ADD_FLOATS' | \
            'OP_SUBTRACT_FLOATS' | 'OP_ADD_POINTS' | 'OP_CALL' | \
            'OP_COPY' | 'OP_SHAKE256' | 'OP_REVERSE' | \
            'OP_CHECK_SIG' | 'OP_SIGN' | \
            'OP_CHECK_SIG_VERIFY' | 'OP_CLAMP_SCALAR' | 'OP_ADD_SCALARS' | \
            'OP_SUBTRACT_SCALARS' | 'OP_SUBTRACT_POINTS' | \
            'OP_GET_MESSAGE' | 'OP_CHECK_TEMPLATE' | 'OP_CHECK_TEMPLATE_VERIFY':
            # ops that have tape argument of form [-128 to 127]
            # human-readable syntax of OP_[whatever] [int]
            return _get_OP_PUSH0_type_args(opname, symbols, symbols_to_advance, symbol_index)
        case 'OP_PUSH2':
            # ops that have tape argument of form [0-65535] [val]
            # human-readable syntax of simply OP_PUSH2 [val]
            return _get_OP_PUSH2_args(opname, symbols, symbols_to_advance, symbol_index)
        case 'OP_DIV_FLOAT' | 'OP_MOD_FLOAT':
            # ops that have tape argument of form [4-byte float]
            # human-readable syntax of OP_[DIV|MOD]_FLOAT [val]
            return _get_OP_DIV_FLOAT_args(opname, symbols, symbols_to_advance, symbol_index)
        case 'OP_SWAP':
            # ops that have tape arguments of form [0-255] [0-255]
            # human-readable syntax of OP_SWAP [idx1] [idx2]
            return _get_OP_SWAP_type_args(opname, symbols, symbols_to_advance, symbol_index)
        case 'OP_CHECK_MULTISIG' | 'OP_CHECK_MULTISIG_VERIFY':
            return _get_OP_CHECK_MULTISIG_args(opname, symbols, symbols_to_advance, symbol_index)
        case 'OP_MERKLEVAL' | 'OP_TAPROOT':
            # op has tape argument of form [32-byte val]
            return _get_OP_MERKLEVAL_args(opname, symbols, symbols_to_advance, symbol_index)
        case _:
            if opname[:3] == 'NOP':
                return _get_nopcode_args(opname, symbols, symbols_to_advance, symbol_index)
            return _get_additional_opcode_args(opname, symbols, symbols_to_advance, symbol_index)

    return (symbols_to_advance, tuple(args))


def parse_def(symbols: list[str], symbol_index: int, macros: dict = {}) -> tuple[int, tuple[bytes]]:
    yert(len(symbols) > 0, f'missing OP_DEF clause contents at symbol {symbol_index}')
    vert(symbols[0] in ('OP_DEF', 'DEF'), f'malformed OP_DEF clause: must begin OP_DEF not {symbols[0]}' +
         f' at symbol {symbol_index}')
    code = []
    def_code = b''
    index = 0
    name = symbols[1]
    yert(name.isnumeric() or name[0] in ('d', 'x'), 'def number must be numeric')
    if name[0] == 'd':
        name = int(name[1:])
        vert(0 <= name < 256, 'def number must be in d0-d255')
    elif name[0] == 'x':
        vert(len(name[1:]) < 3, 'def number must be in x00-xff')
        name = bytes.fromhex(name[1:])[0]
    else:
        name = int(name)
        vert(0 <= name < 256, 'def number must be in 0-255')

    if symbols[2] == '{':
        # case 1: OP_DEF number { match }
        yert('}' in symbols, 'missing matching }')
        search_idx = index + _find_matching_brace(symbols[2:], '{', '}') + 2
        index = 3
    else:
        # case 2: find END_DEF
        yert('END_DEF' in symbols[index:], 'missing END_DEF')
        search_idx = symbols.index('END_DEF')
        index = 2

    # add OP_DEF to code
    code.append(opcodes_inverse['OP_DEF'][0].to_bytes(1, 'big'))

    while index <= search_idx:
        current_symbol = symbols[index]
        # ignore comments (symbols between matching #, ', or ")
        if current_symbol in ('"', "'", '#'):
            # skip forward past the matching symbol
            try:
                index = symbols.index(current_symbol, index+1) + 1
            except ValueError:
                raise SyntaxError(f'unterminated comment starting with {current_symbol}') from None
            continue
        if current_symbol in opcode_aliases:
            current_symbol = 'OP_' + current_symbol
        yert(current_symbol != 'OP_DEF',
            f'cannot use OP_DEF within OP_DEF body - symbol {index}')
        if current_symbol in ('}', 'END_DEF'):
            index += 1
            break
        else:
            advance, parts = parse_next(current_symbol, symbols, symbol_index, index, macros)
            index += advance
            def_code += b''.join(parts)

    # add def handle to code
    code.append(name.to_bytes(1, 'big'))

    # add def size to code
    def_size = len(def_code)
    yert(def_size < 2**16, 'def size limit exceeded')
    code.append(def_size.to_bytes(2, 'big'))

    # add def code to code
    code.append(def_code)

    return (search_idx+1, tuple(code))


def parse_if(symbols: list[str], symbol_index: int, macros: dict = {}) -> tuple[int, tuple[bytes]]:
    """Parses a statement starting with OP_IF. Returns tuple (int
        advance, tuple[bytes] parts). Called recursively to handle nested
        conditional clauses. The first element of tuple[bytes] will be
        the proper op code for the if statement.
    """
    yert(len(symbols) > 0, f'missing OP_IF clause contents - symbol {symbol_index}')
    vert(symbols[0] in ('OP_IF', 'IF'), f'malformed OP_IF: must begin OP_IF not {symbols[0]}'+
         f' at symbol {symbol_index}')
    opcode = 'OP_IF'
    code = []
    index = 1
    else_len = 0
    hoist_advance, hoist_code = 0, b''

    if symbols[1] == '(':
        # handle hoisting
        hoist_advance = _find_matching_brace(symbols, '(', ')')
        condition = symbols[2:hoist_advance]
        hoist_code = assemble(condition, macros)
        symbols = [symbols[0], *symbols[hoist_advance+1:]]

    if symbols[1] == '{':
        # case 1: OP_IF { statements }
        yert('}' in symbols[1:], f'unterminated OP_IF: missing matching {"}"} - symbol {symbol_index}')
        index += 1
    else:
        # case 2: OP_IF statements END_IF
        yert('END_IF' in symbols[1:], f'missing END_IF - symbol {symbol_index}')

    while index < len(symbols):
        current_symbol = symbols[index]

        if current_symbol == '}':
            if len(symbols) < index+2 or symbols[index+1] != 'ELSE':
                index += 1
                break
            index += 1
            continue
        elif current_symbol == 'END_IF':
            index += 2
            break
        elif current_symbol == 'ELSE':
            opcode = 'OP_IF_ELSE'
            advance, parts = parse_else(symbols[index:], symbol_index+index, macros)
            index += advance
            code.extend(parts)
            else_len = len(b''.join(parts))
            break
        else:
            advance, parts = parse_next(current_symbol, symbols, symbol_index, index, macros)
            index += advance
            code.extend(parts)

    code = b''.join(code)

    return (
        index + hoist_advance,
        (
            hoist_code,
            opcodes_inverse[opcode][0].to_bytes(1, 'big'),
            (len(code) - else_len).to_bytes(2, 'big'),
            code
        )
    )


def parse_else(symbols: list[str], symbol_index: int, macros: dict = {}) -> tuple[int, tuple[bytes]]:
    """Parses an ELSE clause. Returns tuple (int advance, tuple[bytes]
        parts). Recursively calls parse_if to handle nested conditional
        clauses.
    """
    yert(len(symbols) > 0, f'missing ELSE clause contents - symbol {symbol_index}')
    vert(symbols[0] == 'ELSE', f'malformed ELSE clause: must begin ELSE not {symbols[0]}' +
         f' at symbol {symbol_index}')
    code = []
    index = 1

    if symbols[1] == '{':
        # case 1: ELSE { statements }
        yert('}' in symbols[1:],
             f'unterminated ELSE: missing matching {"}"} - starting symbol {symbol_index}')
        index = 2
    else:
        yert('END_IF' in symbols[1:], f'missing END_IF - starting symbol {symbol_index}')

    while index < len(symbols):
        current_symbol = symbols[index]

        if current_symbol in ('}', 'END_IF'):
            index += 1
            break
        else:
            advance, parts = parse_next(current_symbol, symbols, symbol_index, index, macros)
            index += advance
            code.extend(parts)

    code = b''.join(code)
    return (
        index,
        (
            len(code).to_bytes(2, 'big'),
            code
        )
    )


def parse_try(symbols: list[str], symbol_index: int, macros: dict = {}) -> tuple[int, tuple[bytes]]:
    """Parses a statement starting with OP_TRY. Returns tuple (int
        advance, tuple[bytes] parts). Called recursively to handle
        nested try clauses.
    """
    yert(len(symbols) > 0, f'missing OP_TRY clause contents - symbol {symbol_index}')
    vert(symbols[0] in ('OP_TRY', 'TRY'), f'malformed OP_TRY clause: must begin OP_TRY not {symbols[0]}' +
         f' at symbol {symbol_index}')
    code = []
    index = 1
    except_len = 0

    if symbols[1] == '{':
        # case 1: OP_TRY { statements }
        yert('}' in symbols[1:], f'unterminated OP_TRY: missing matching }} - symbol {symbol_index}')
        index = 2
    else:
        # case 2: OP_TRY statements END_TRY
        # case 3: OP_TRY statements EXCEPT
        yert('END_TRY' in symbols[1:] or 'EXCEPT' in symbols[1:],
             f'missing END_TRY or EXCEPT - starting symbol {symbol_index}')

    while index < len(symbols):
        current_symbol = symbols[index]

        if current_symbol == '}':
            index += 1
            if len(symbols) < index+2 or symbols[index] != 'EXCEPT':
                break
        elif current_symbol == 'EXCEPT':
            advance, parts = parse_except(symbols[index:], symbol_index+index, macros)
            index += advance
            code.extend(parts)
            except_len = len(b''.join(parts))
            break
        else:
            advance, parts = parse_next(current_symbol, symbols, symbol_index, index, macros)
            index += advance
            code.extend(parts)

    code = b''.join(code)

    if except_len == 0:
        code += except_len.to_bytes(2, 'big')
        except_len = 2

    return (
        index,
        (
            opcodes_inverse['OP_TRY_EXCEPT'][0].to_bytes(1, 'big'),
            (len(code) - except_len).to_bytes(2, 'big'),
            code
        )
    )


def parse_except(symbols: list[str], symbol_index: int, macros: dict = {}) -> tuple[int, tuple[bytes]]:
    """Parses an EXCEPT clause. Returns tuple (int advance, tuple[bytes]
        parts). Recursively calls parse_try to handle nested exception
        handling clauses.
    """
    yert(len(symbols) > 0, f'missing EXCEPT clause contents - symbol {symbol_index}')
    yert(symbols[0] == 'EXCEPT', f'malformed EXCEPT: must begin EXCEPT not {symbols[0]}'+
         f'at symbol {symbol_index}')
    code = []
    index = 1

    if symbols[1] == '{':
        # case 1: EXCEPT { statements }
        yert('}' in symbols[1:], f'unterminated EXCEPT: missing matching {"}"} - symbol {symbol_index}')
        index = 2
    else:
        yert('END_EXCEPT' in symbols[1:], f'missing END_EXCEPT - symbol {symbol_index}')

    while index < len(symbols):
        current_symbol = symbols[index]
        if current_symbol in ('}', 'END_EXCEPT'):
            index += 1
            break
        elif current_symbol == 'EXCEPT':
            raise SyntaxError('cannot have multiple EXCEPT clauses')
        advance, parts = parse_next(current_symbol, symbols, symbol_index, index, macros)
        index += advance
        code.extend(parts)

    code = b''.join(code)
    return (
        index,
        (
            len(code).to_bytes(2, 'big'),
            code
        )
    )


def parse_loop(symbols: list[str], symbol_index: int, macros: dict = {}) -> tuple[int, tuple[bytes]]:
    """Parses an OP_LOOP clause. Returns tuple (int advance, tuple[bytes]
        parts). Recursively calls parse_* functions to handle nested
        control flow clauses.
    """
    yert(len(symbols) > 0, f'missing OP_LOOP clause contents - symbol {symbol_index}')
    vert(symbols[0] in ('OP_LOOP', 'LOOP'), f'malformed OP_LOOP clause: must begin OP_LOOP not {symbols[0]}' +
         f' at symbol {symbol_index}')
    code = []
    index = 1

    if symbols[1] == '{':
        # case 1: LOOP { statements }
        yert('}' in symbols[1:], f'unterminated LOOP: missing matching {"}"} - symbol {symbol_index}')
        index = 2
    else:
        yert('END_LOOP' in symbols[1:], f'missing END_LOOP - symbol {symbol_index}')

    while index < len(symbols):
        current_symbol = symbols[index]

        if current_symbol in ('}', 'END_LOOP'):
            index += 1
            break

        advance, parts = parse_next(current_symbol, symbols, symbol_index, index, macros)
        index += advance
        code.extend(parts)

    code = b''.join(code)
    return (
        index,
        (
            opcodes_inverse['OP_LOOP'][0].to_bytes(1, 'big'),
            len(code).to_bytes(2, 'big'),
            code
        )
    )


def parse_next(
        current_symbol: str, symbols: list[str], symbol_index: int, index: int,
        macros: dict = {}) -> tuple[int, tuple[bytes]]:
    """Parse the next statement. Return the number by which to advance
        the index and a tuple of code bytes.
    """
    advance, parts = 0, []

    if current_symbol in ('"', "'", '#'):
        # skip forward past the matching symbol
        try:
            advance = symbols.index(current_symbol, index+1) + 1 - index
            return (advance, parts)
        except ValueError:
            raise SyntaxError(f'unterminated comment starting with {current_symbol}') from None

    if current_symbol in opcode_aliases:
        current_symbol = opcode_aliases[current_symbol]
    if current_symbol in ('PUSH', 'TRY', 'DEF', 'IF'):
        current_symbol = 'OP_' + current_symbol

    yert(current_symbol in opcodes_inverse or current_symbol in nopcodes_inverse
            or current_symbol in ('OP_PUSH', 'OP_TRY', '@=', '!=') or
            (current_symbol[0] in ('!', '@') and current_symbol[1:].isalnum()),
            f'unrecognized symbol: {current_symbol} at symbol {index}' +
            (f' (after {symbols[index-1]})' if index > 0 else '') +
            (f' (before {symbols[index+1]})' if index < len(symbols)-1 else ''))

    if current_symbol == '@=':
        advance, parts = set_variable(symbols[index:])
    elif current_symbol[0] == '@':
        advance, parts = load_variable(symbols[index:])
    elif current_symbol == '!=':
        advance = define_macro(symbols[index:], macros=macros)
    elif current_symbol[0] == '!':
        advance, parts = invoke_macro(symbols[index:], macros=macros)
    elif current_symbol == 'OP_IF':
        advance, parts = parse_if(symbols[index:], symbol_index+index, macros)
    elif current_symbol == 'OP_DEF':
        advance, parts = parse_def(symbols[index:], symbol_index+index, macros)
    elif current_symbol == 'OP_TRY':
        advance, parts = parse_try(symbols[index:], symbol_index+index, macros)
    elif current_symbol == 'OP_LOOP':
        advance, parts = parse_loop(symbols[index:], symbol_index+index, macros)
    else:
        vert(current_symbol in opcodes_inverse or current_symbol in nopcodes_inverse
                or current_symbol == 'OP_PUSH',
            f'unrecognized opcode: {current_symbol} - symbol {symbol_index+index}')
        advance, args = get_args(current_symbol, symbols[index+1:], symbol_index+index)
        if current_symbol in ('OP_PUSH', 'PUSH'):
            if len(args) < 2:
                parts.append(opcodes_inverse['OP_PUSH0'][0].to_bytes(1, 'big'))
            elif len(args[0]) == 1:
                parts.append(opcodes_inverse['OP_PUSH1'][0].to_bytes(1, 'big'))
            elif len(args[0]) == 2:
                parts.append(opcodes_inverse['OP_PUSH2'][0].to_bytes(1, 'big'))
        elif current_symbol[:3] == 'NOP':
            parts.append(nopcodes_inverse[current_symbol][0].to_bytes(1, 'big'))
        else:
            parts.append(opcodes_inverse[current_symbol][0].to_bytes(1, 'big'))
        parts.append(b''.join(args))
    return (advance, parts)


def _find_matching_brace(symbols: list[str], open_brace: str, close_brace: str) -> int:
    """Finds the index of the matching closing brace, adjusting for any
        additional open braces encountered before the closing brace.
    """
    index = symbols.index(close_brace)

    while index < len(symbols):
        n_opens = symbols[:index].count(open_brace)
        n_closes = symbols[:index+1].count(close_brace)
        if n_closes >= n_opens and symbols[index] == close_brace:
            break
        index += symbols[index+1:].index(close_brace) or 1

    return index


def compile_script(script: str) -> bytes:
    """Compile the given human-readable script into byte code. Bubbles
        any SyntaxError or ValueError raised by assemble.
    """
    vert(type(script) is str, 'input script must be str')
    macros = {}
    symbols = get_symbols(script)
    return assemble(symbols, macros=macros)

def parse_comptime(symbols: list[str], macros: dict = {}) -> list[str]:
    """Preparses a list of symbols, replacing any comptime blocks with
        the compiled byte code of the block as a hex value symbol or the
        top stack item as a hex value symbol by compiling and executing
        the contents of the block. Returns a modified list of symbols in
        which all comptime blocks have been replaced.
    """
    new_symbols = []
    index = 0

    while index < len(symbols):
        symbol = symbols[index]
        if symbol == '!=':
            advance = define_macro(symbols[index:], macros=macros)
            index += advance
            continue
        if symbol not in ("~", "~!"):
            new_symbols.append(symbol)
            index += 1
            continue
        yert(symbols[index+1] == "{",
                f'Error at symbol {index}: comptime syntax is `~ {{ ops }}`')
        end = _find_matching_brace(symbols[index:], "{", "}")
        if symbol == "~":
            new_symbols.append(f'x{assemble(symbols[index+2:index+end], macros).hex()}')
        else:
            _, stack, _ = run_script(assemble(symbols[index+2:index+end], macros))
            if not stack.empty():
                new_symbols.append(f'x{stack.get().hex()}')
        index += end + 1

    return new_symbols

def assemble(symbols: list[str], macros: dict = {}) -> bytes:
    """Assemble the symbols into bytecode. Raises SyntaxError and
        ValueError for invalid syntax or values.
    """
    index = 0
    code = []
    symbols = parse_comptime(symbols, macros)

    while index < len(symbols):
        symbol = symbols[index]
        advance, parts = parse_next(symbol, symbols, 0, index, macros)
        index += advance
        code.extend(parts)

    return b''.join(code)


def decompile_script(script: bytes, indent: int = 0) -> list[str]:
    """Decompile the byte code into human-readable script."""
    vert(type(script) is bytes, 'input script must be bytes')
    tape = Tape(script)
    code_lines = []

    def add_line(line: str):
        code_lines.append(''.join(['    ' for _ in range(indent)]) + line)

    def add_lines(lines: list[str]):
        for line in lines:
            add_line(line)

    while not tape.has_terminated():
        op_code = tape.read(1)[0]
        vert(op_code in opcodes or op_code in nopcodes, f'unrecognized opcode {op_code}')
        op_name = opcodes[op_code][0] if op_code in opcodes else nopcodes[op_code][0]

        match op_name:
            case 'OP_DEF':
                def_handle = tape.read(1)[0]
                def_length = int.from_bytes(tape.read(2), 'big')
                def_body = tape.read(def_length)
                def_lines = decompile_script(def_body, indent+1)
                add_line(f'OP_DEF {def_handle}' + ' {')
                code_lines.extend(def_lines)
                add_line('}')
            case 'OP_IF':
                if_len = int.from_bytes(tape.read(2), 'big')
                if_body = tape.read(if_len)
                if_lines = decompile_script(if_body, indent+1)
                add_line('OP_IF {')
                code_lines.extend(if_lines)
                add_line('}')
            case 'OP_IF_ELSE':
                if_len = int.from_bytes(tape.read(2), 'big')
                if_body = tape.read(if_len)
                if_lines = decompile_script(if_body, indent+1)
                else_len = int.from_bytes(tape.read(2), 'big')
                else_body = tape.read(else_len)
                else_lines = decompile_script(else_body, indent+1)
                add_line('OP_IF {')
                code_lines.extend(if_lines)
                add_line('} ELSE {')
                code_lines.extend(else_lines)
                add_line('}')
            case 'OP_TRY_EXCEPT':
                try_len = int.from_bytes(tape.read(2), 'big')
                try_body = tape.read(try_len)
                try_lines = decompile_script(try_body, indent+1)
                except_len = int.from_bytes(tape.read(2), 'big')
                except_body = tape.read(except_len)
                except_lines = decompile_script(except_body, indent+1)
                add_line('OP_TRY {')
                code_lines.extend(try_lines)
                if except_lines:
                    add_line('} EXCEPT {')
                    code_lines.extend(except_lines)
                add_line('}')
            case 'OP_LOOP':
                loop_len = int.from_bytes(tape.read(2), 'big')
                lop_body = tape.read(loop_len)
                loop_lines = decompile_script(lop_body, indent+1)
                add_line('OP_LOOP {')
                code_lines.extend(loop_lines)
                add_line('}')
            case 'OP_FALSE' | 'OP_TRUE' | 'OP_POP0' | 'OP_SIZE' | \
                'OP_READ_CACHE_STACK' | 'OP_READ_CACHE_STACK_SIZE' | 'OP_DIV_INTS' | \
                'OP_MOD_INTS' | 'OP_DIV_FLOATS' | 'OP_MOD_FLOATS' | 'OP_DUP' | \
                'OP_SHA256' | 'OP_VERIFY' | 'OP_EQUAL' | 'OP_EQUAL_VERIFY' | \
                'OP_CHECK_TIMESTAMP' | 'OP_CHECK_TIMESTAMP_VERIFY' | \
                'OP_CHECK_EPOCH' | 'OP_CHECK_EPOCH_VERIFY' | 'OP_EVAL' | \
                'OP_RANDOM' | 'OP_NOT' | 'OP_RETURN' | 'OP_DEPTH' | 'OP_SWAP2' | \
                'OP_CONCAT' | 'OP_CONCAT_STR' | 'OP_CHECK_TRANSFER' | \
                'OP_LESS' | 'OP_LESS_OR_EQUAL' | 'OP_FLOAT_LESS' | \
                'OP_FLOAT_LESS_OR_EQUAL' | 'OP_INT_TO_FLOAT' | \
                'OP_FLOAT_TO_INT' | 'OP_SIGN_STACK' | 'OP_CHECK_SIG_STACK' | \
                'OP_DERIVE_SCALAR' | 'OP_DERIVE_POINT' | \
                'OP_MAKE_ADAPTER_SIG_PUBLIC' | 'OP_MAKE_ADAPTER_SIG_PRIVATE' | \
                'OP_CHECK_ADAPTER_SIG' | 'OP_DECRYPT_ADAPTER_SIG' | 'OP_XOR' | \
                'OP_INVOKE' | 'OP_OR' | 'OP_AND' | 'OP_SPLIT' | 'OP_SPLIT_STR':
                # ops that have no arguments on the tape
                # human-readable syntax of OP_[whatever]
                add_line(op_name)
            case 'OP_PUSH1':
                # ops that have tape arguments of form [size 0-255] [val]
                size = tape.read(1)[0]
                val = tape.read(size)
                add_line(f'{op_name} d{size} x{val.hex()}')
            case 'OP_READ_CACHE' | 'OP_READ_CACHE_SIZE' | \
                'OP_SET_FLAG' | 'OP_UNSET_FLAG' | 'OP_GET_VALUE':
                # ops that have tape arguments of form [size 0-255] [val]
                size = tape.read(1)[0]
                val = tape.read(size)
                add_line(f'{op_name} x{val.hex()}')
            case 'OP_DIV_INT' | 'OP_MOD_INT':
                # ops that have tape arguments of form [size 0-255] [val]
                size = tape.read(1)[0]
                val = tape.read(size)
                add_line(f'{op_name} d{bytes_to_int(val)}')
            case 'OP_WRITE_CACHE':
                # op has tape arguments of form [size 0-255] [val] [count 0-255]
                size = tape.read(1)[0]
                val = tape.read(size)
                count = tape.read(1)[0]
                add_line(f'{op_name} x{val.hex()} d{count}')
            case 'OP_PUSH0' | 'OP_POP1' | 'OP_ADD_INTS' | 'OP_SUBTRACT_INTS' | \
                'OP_MULT_INTS' | 'OP_ADD_FLOATS' | \
                'OP_SUBTRACT_FLOATS' | 'OP_ADD_POINTS' | 'OP_CALL' | \
                'OP_COPY' | 'OP_SHAKE256' | 'OP_REVERSE' | \
                'OP_CLAMP_SCALAR' | \
                'OP_ADD_SCALARS' | 'OP_SUBTRACT_SCALARS' | 'OP_SUBTRACT_POINTS':
                # ops that have tape argument of form [0-255]
                # human-readable syntax of OP_[whatever] [int]
                val = bytes_to_int(tape.read(1))
                add_line(f'{op_name} d{val}')
            case 'OP_CHECK_SIG' | 'OP_CHECK_SIG_VERIFY' | 'OP_SIGN' | \
                'OP_GET_MESSAGE' | 'OP_CHECK_TEMPLATE' | 'OP_CHECK_TEMPLATE_VERIFY':
                # ops that have tape argument of form x[00-ff]
                # human-readable syntax of OP_[whatever] x[00-ff]
                val = tape.read(1)
                add_line(f'{op_name} x{val.hex()}')
            case 'OP_PUSH2':
                # ops that have tape argument of form [0-65535] [val]
                # human-readable syntax of simply OP_PUSH2 [val]
                size = bytes_to_int(tape.read(2))
                val = tape.read(size)
                add_line(f'{op_name} d{size} x{val.hex()}')
            case 'OP_DIV_FLOAT' | 'OP_MOD_FLOAT':
                # ops that have tape argument of form [4-byte float]
                # human-readable syntax of OP_[DIV|MOD]_FLOAT [val]
                val = tape.read(4)
                add_line(f'{op_name} x{val.hex()}')
            case 'OP_SWAP':
                # ops that have tape arguments of form [0-255] [0-255]
                # human-readable syntax of OP_SWAP [idx1] [idx2]
                idx1 = tape.read(1)[0]
                idx2 = tape.read(1)[0]
                add_line(f'{op_name} d{idx1} d{idx2}')
            case 'OP_CHECK_MULTISIG' | 'OP_CHECK_MULTISIG_VERIFY':
                # ops that have tape arguments of form [0-255] [0-255]
                # human-readable syntax of OP_SWAP [idx1] [idx2]
                flag = tape.read(1).hex()
                idx1 = tape.read(1)[0]
                idx2 = tape.read(1)[0]
                add_line(f'{op_name} x{flag} d{idx1} d{idx2}')
            case 'OP_MERKLEVAL' | 'OP_TAPROOT':
                # op has tape argument of form [32-byte val]
                digest = tape.read(32)
                add_line(f'{op_name} x{digest.hex()}')
            case _:
                if op_name[:3] == 'NOP':
                    val = tape.read(1)[0]
                    add_line(f'{op_name} d{val}')
                else:
                    lines = additional_opcodes[op_name][1](op_name, tape)
                    add_lines(lines)

    return code_lines
