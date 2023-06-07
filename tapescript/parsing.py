from .errors import yert, vert, SyntaxError
from .classes import Tape
from .functions import int_to_bytes, opcodes, opcodes_inverse, nopcodes
from math import ceil, log2
from typing import Any, Callable
import struct


def get_symbols(script: str) -> list[str]:
    """Split the script source into symbols."""
    splits = [s for s in script.split()]
    splits.reverse()
    symbols = []

    while len(splits):
        token = splits.pop()
        if token[:2] in ('s"', "s'"):
            # match to end of string value
            found = '"' in token[3:] or "'" in token[3:]
            parts = [token]
            while not found and len(splits):
                next = splits.pop()
                parts.append(next)
                if '"' in next or "'" in next:
                    found = True
            yert(found, 'unterminated string encountered')
            token = ' '.join(parts)
            symbols.append(token)
        elif token[0] not in ('s', 'd', 'x'):
            symbols.append(token.upper())
        else:
            symbols.append(token)

    return symbols


additional_opcodes = {}

def add_opcode_parsing_handlers(opname: str, compiler_handler: Callable, decompiler_handler: Callable) -> None:
    additional_opcodes[opname] = (compiler_handler, decompiler_handler)

def _get_additional_opcode_args(opname: str, symbols: list[str], symbols_to_advance: int) -> tuple[int, tuple[bytes]]:
    vert(opname in additional_opcodes, f'unrecognized opname {opname}')
    return additional_opcodes[opname][0](opname, symbols, symbols_to_advance)

def _get_OP_PUSH_args(opname: str, symbols: list[str], symbols_to_advance: int) -> tuple[int, tuple[bytes]]:
    args = []
    symbols_to_advance += 1
    val = symbols[0]
    yert(val[0].lower() in ('d', 'x', 's'),
        'values for OP_PUSH must be prefaced with d, x, or s')

    match val[0].lower():
        case 'd':
            vert(val[1:].isnumeric(),
                'value prefaced by d must be decimal int')
            if '.' in val:
                val = int(val[1:].split('.')[0])
            else:
                val = int(val[1:])
            size = ceil(log2(val+1)/8) or 1
            val = val.to_bytes(size, 'big')
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

    if 1 < len(val) < 256:
        # tape syntax of OP_PUSH1 [size 0-255] [val]
        # human-readable decompiled syntax of OP_PUSH1 val
        args.append(len(val).to_bytes(1, 'big'))
    elif 255 < len(val) < 65_536:
        # tape syntax of OP_PUSH2 [size 0-65_535] [val]
        # human-readable decompiled syntax of OP_PUSH2 val
        args.append(len(val).to_bytes(2, 'big'))
    elif 65_535 < len(val) < 4_294_967_296:
        # tape syntax of OP_PUSH4 [size 0-4_294_967_295] [val]
        # human-readable decompiled syntax of OP_PUSH4 val
        args.append(len(val).to_bytes(4, 'big'))
    args.append(val)
    return (symbols_to_advance, args)

def _get_OP_PUSH0_type_args(opname: str, symbols: list[str], symbols_to_advance: int) -> tuple[int, tuple[bytes]]:
    args = []
    symbols_to_advance += 1
    val = symbols[0]
    yert(val[0].lower() in ('d', 'x'),
        'numeric args must be prefaced with d or x')

    match val[0].lower():
        case 'd':
            vert(val[1:].isnumeric(),
                'value prefaced by d must be decimal int')
            if '.' in val:
                args.append(int(val[1:].split('.')[0]).to_bytes(1, 'big'))
            else:
                args.append(int(val[1:]).to_bytes(1, 'big'))
        case 'x':
            vert(len(val[1:]) <= 2,
                'value must be at most 1 byte long')
            val = bytes.fromhex(val[1:])
            args.append(val if len(val) == 1 else b'\x00')
    return (symbols_to_advance, args)

def _get_OP_PUSH1_type_args(opname: str, symbols: list[str], symbols_to_advance: int) -> tuple[int, tuple[bytes]]:
    args = []
    if opname == 'OP_WRITE_CACHE':
        # human-readable syntax of OP_WRITE_CACHE [key] [number]
        symbols_to_advance += 2
        vals = symbols[:2]
    else:
        # human-readable syntax of OP_[whatever] [key]
        symbols_to_advance += 1
        vals = (symbols[0])

    for val in vals:
        yert(val[0].lower() in ('d', 'x', 's'),
            f'values for {opname} must be prefaced with d, x, or s')
        match val[0].lower():
            case 'd':
                vert(val[1:].isnumeric(),
                    'value prefaced by d must be decimal int or float')
                if '.' in val:
                    args.append((4).to_bytes(1, 'big'))
                    args.append(struct.pack('!f', float(val[1:])))
                else:
                    val = int_to_bytes(int(val[1:]))
                    args.append(len(val).to_bytes(1, 'big'))
                    args.append(val)
            case 'x':
                val = bytes.fromhex(val[1:])
                args.append(len(val).to_bytes(1, 'big'))
                args.append(val)
            case 's':
                if val[1] == '"' and '"' in val[2:]:
                    last_idx = val[2:].index('"')
                    val = bytes(val[1:last_idx+2], 'utf-8')
                elif val[1] == "'" and "'" in val[2:]:
                    last_idx = val[2:].index("'")
                    val = bytes(val[1:last_idx+2], 'utf-8')
                else:
                    val = bytes(val[1:], 'utf-8')
                args.append(len(val).to_bytes(1, 'big'))
                args.append(val)
    return (symbols_to_advance, args)

def _get_OP_PUSH2_args(opname: str, symbols: list[str], symbols_to_advance: int) -> tuple[int, tuple[bytes]]:
    args = []
    symbols_to_advance += 1
    val = symbols[0]
    yert(val[0].lower() in ('d', 'x', 's'),
        'values for OP_PUSH2 must be prefaced with d, x, or s')

    match val[0].lower():
        case 's':
            if val[1] == '"' and '"' in val[2:]:
                last_idx = val[2:].index('"')
                val = bytes(val[1:last_idx+2], 'utf-8')
            elif val[1] == "'" and "'" in val[2:]:
                last_idx = val[2:].index("'")
                val = bytes(val[1:last_idx+2], 'utf-8')
            else:
                val = bytes(val[1:], 'utf-8')
        case 'd':
            vert(val[1:].isnumeric(),
                'value prefaced by d must be decimal int')
            if '.' in val:
                val = int_to_bytes(int(val[1:].split('.')[0]))
            else:
                val = int_to_bytes(int(val[1:]))
            vert(len(val) < 65_536, 'OP_PUSH2 value overflow')
        case 'x':
            val = bytes.fromhex(val[1:])
            vert(len(val) < 65_536,
                'x-value for OP_PUSH2 must be at most 65_535 bytes long')
    args.append(len(val).to_bytes(2, 'big'))
    args.append(val)
    return (symbols_to_advance, args)

def _get_OP_PUSH4_args(opname: str, symbols: list[str], symbols_to_advance: int) -> tuple[int, tuple[bytes]]:
    args = []
    symbols_to_advance += 1
    val = symbols[0]
    yert(val[0].lower() in ('d', 'x', 's'), \
        'values for OP_PUSH4 must be prefaced with d, x, or s')

    match val[0].lower():
        case 's':
            if val[1] == '"' and '"' in val[2:]:
                last_idx = val[2:].index('"')
                val = bytes(val[1:last_idx+2], 'utf-8')
            elif val[1] == "'" and "'" in val[2:]:
                last_idx = val[2:].index("'")
                val = bytes(val[1:last_idx+2], 'utf-8')
            else:
                val = bytes(val[1:], 'utf-8')
            vert(len(val) < 2**32,
                's-value for OP_PUSH2 must be at most 4_294_967_295 bytes long')
        case 'd':
            vert(val[1:].isnumeric(),
                'value prefaced by d must be decimal int')
            if '.' in val:
                val = int_to_bytes(int(val[1:].split('.')[0]))
            else:
                val = int_to_bytes(int(val[1:]))
        case 'x':
            val = bytes.fromhex(val[1:])
            vert(len(val) < 2**32,
                'x-value for OP_PUSH2 must be at most 4_294_967_295 bytes long')
    args.append(len(val).to_bytes(4, 'big'))
    args.append(val)
    return (symbols_to_advance, args)

def _get_OP_DIV_FLOAT_args(opname: str, symbols: list[str], symbols_to_advance: int) -> tuple[int, tuple[bytes]]:
    args = []
    symbols_to_advance += 1
    val = symbols[0]
    yert(val[0].lower() in ('d', 'x'),
        'numeric args must be prefaced with d or x')

    match val[0].lower():
        case 'd':
            vert(val[1:].isnumeric(),
                f'{opname} value prefaced by d must be decimal float')
            args.append(struct.pack('!f', float(val[1:])))
        case 'x':
            vert(len(val[1:]) == 8,
                f'{opname} value prefaced by x must be 8 long (4 bytes)')
            args.append(bytes.fromhex(val[1:]))
    return (symbols_to_advance, args)

def _get_OP_SWAP_args(opname: str, symbols: list[str], symbols_to_advance: int) -> tuple[int, tuple[bytes]]:
    args = []
    symbols_to_advance += 2
    vals = symbols[:2]

    for val in vals:
        yert(val[0].lower() in ('d', 'x'),
            'numeric args must be prefaced with d or x')

        match val[0].lower():
            case 'd':
                vert(val[1:].isnumeric(),
                    'OP_SWAP value prefaced by d must be decimal int')
                if '.' in val:
                    val = int(val[1:].split('.')[0])
                else:
                    val = int(val[1:])
                yert(0 <= val < 256, 'OP_SWAP index overflow')
                args.append(val.to_bytes(1, 'big'))
            case 'x':
                vert(len(val[1:]) == 2,
                    'OP_SWAP value prefaced by x must be 2 long (1 byte)')
                args.append(bytes.fromhex(val[1:]))
    return (symbols_to_advance, args)

def _get_OP_MERKLEVAL_args(opname: str, symbols: list[str], symbols_to_advance: int) -> tuple[int, tuple[bytes]]:
    args = []
    symbols_to_advance += 1
    val = symbols[0]
    yert(val[0].lower() == 'x', 'OP_MERKLEVAL arg must be hexadecimal hash')
    yert(len(val) == 65, 'OP_MERKLEVAL arg must be hexadecimal hash')
    args.append(bytes.fromhex(val[1:]))
    return (symbols_to_advance, args)

def get_args(opname: str, symbols: list[str]) -> tuple[int, tuple[bytes]]:
    """Get the number of symbols to advance and args for an op."""
    symbols_to_advance = 1
    args = []

    match opname:
        case 'OP_FALSE' | 'OP_TRUE' | 'OP_POP0' | 'OP_SIZE' | \
            'OP_READ_CACHE_Q' | 'OP_READ_CACHE_Q_SIZE' | 'OP_DIV_INTS' | \
            'OP_MOD_INTS' | 'OP_DIV_FLOATS' | 'OP_MOD_FLOATS' | 'OP_DUP' | \
            'OP_SHA256' | 'OP_VERIFY' | 'OP_EQUAL' | 'OP_EQUAL_VERIFY' | \
            'OP_CHECK_TIMESTAMP' | 'OP_CHECK_TIMESTAMP_VERIFY' | \
            'OP_CHECK_EPOCH' | 'OP_CHECK_EPOCH_VERIFY' | 'OP_EVAL' | \
            'OP_NOT' | 'OP_RETURN' | 'OP_DEPTH' | 'OP_SWAP2' | \
            'OP_CONCAT' | 'OP_CONCAT_STR':
            # ops that have no arguments on the tape
            # human-readable syntax of OP_[whatever]
            pass
        case 'OP_PUSH':
            # special case: OP_PUSH is a short hand for OP_PUSH[0,1,2,4]
            return _get_OP_PUSH_args(opname, symbols, symbols_to_advance)
        case 'OP_PUSH1' | 'OP_WRITE_CACHE' | 'OP_READ_CACHE' | \
            'OP_READ_CACHE_SIZE' | 'OP_DIV_INT' | \
            'OP_MOD_INT' | 'OP_SET_FLAG' | 'OP_UNSET_FLAG':
            # ops that have tape arguments of form [size 0-255] [val]
            return _get_OP_PUSH1_type_args(opname, symbols, symbols_to_advance)
        case 'OP_PUSH0' | 'OP_POP1' | 'OP_ADD_INTS' | 'OP_SUBTRACT_INTS' | \
            'OP_MULT_INTS' | 'OP_ADD_FLOATS' | 'OP_CHECK_TRANSFER' | \
            'OP_SUBTRACT_FLOATS' | 'OP_ADD_POINTS' | 'OP_CALL' | \
            'OP_COPY' | 'OP_SHAKE256' | 'OP_RANDOM' | 'OP_REVERSE' | \
            'OP_SPLIT' | 'OP_SPLIT_STR' | 'OP_CHECK_SIG' | 'OP_CHECK_SIG_VERIFY':
            # ops that have tape argument of form [0-255]
            # human-readable syntax of OP_[whatever] [int]
            return _get_OP_PUSH0_type_args(opname, symbols, symbols_to_advance)
        case 'OP_PUSH2':
            # ops that have tape argument of form [0-65535] [val]
            # human-readable syntax of simply OP_PUSH2 [val]
            return _get_OP_PUSH2_args(opname, symbols, symbols_to_advance)
        case 'OP_PUSH4':
            # ops that have tape argument of form [0-4_294_967_295] [val]
            # human-readable syntax of simply OP_PUSH4 [val]
            return _get_OP_PUSH4_args(opname, symbols, symbols_to_advance)
        case 'OP_DIV_FLOAT' | 'OP_MOD_FLOAT':
            # ops that have tape argument of form [4-byte float]
            # human-readable syntax of OP_[DIV|MOD]_FLOAT [val]
            return _get_OP_DIV_FLOAT_args(opname, symbols, symbols_to_advance)
        case 'OP_SWAP':
            # ops that have tape arguments of form [0-255] [0-255]
            # human-readable syntax of OP_SWAP [idx1] [idx2]
            return _get_OP_SWAP_args(opname, symbols, symbols_to_advance)
        case 'OP_MERKLEVAL':
            # op has tape argument of form [val]
            return _get_OP_MERKLEVAL_args(opname, symbols, symbols_to_advance)
        case _:
            return _get_additional_opcode_args(opname, symbols, symbols_to_advance)

    return (symbols_to_advance, tuple(args))


def parse_if(symbols: list[str]) -> tuple[int, tuple[bytes]]:
    """Parses a statement starting with OP_IF. Returns tuple (int
        advance, tuple[bytes] parts). Called recursively to handle nested
        conditional clauses. The first element of tuple[bytes] will be
        the proper op code for the if statement.
    """
    yert(len(symbols) > 0, 'missing OP_IF clause contents')
    opcode = 'OP_IF'
    code = []
    index = 0
    else_len = 0

    if symbols[0] == '(':
        # case 1: OP_IF ( statements )
        yert(')' in symbols[1:], 'unterminated OP_IF: missing matching )')
        index += 1
    else:
        # case 2: OP_IF statements END_IF
        yert('END_IF' in symbols[1:], 'missing END_IF')

    has_else = 'ELSE' in symbols
    while index < len(symbols):
        current_symbol = symbols[index]

        if current_symbol in (')', 'END_IF') and not has_else:
            index += 2
            break
        elif current_symbol in (')', 'END_IF'):
            index += 1
            continue
        elif current_symbol == 'ELSE':
            opcode = 'OP_IF_ELSE'
            advance, parts = parse_else(symbols[index+1:])
            has_else = False
            index += advance
            code.extend(parts)
            else_len = len(b''.join(parts))
        elif current_symbol == 'OP_IF':
            advance, parts = parse_if(symbols[index+1:])
            index += advance
            has_else = 'ELSE' in symbols[index:]
            code.extend(parts)
        else:
            yert(current_symbol in opcodes_inverse or current_symbol == 'OP_PUSH',
                f'unrecognized opcode: {current_symbol}')
            advance, args = get_args(current_symbol, symbols[index+1:])
            if current_symbol == 'OP_PUSH':
                if len(args) < 2:
                    code.append(opcodes_inverse['OP_PUSH0'][0].to_bytes(1, 'big'))
                elif len(args[0]) == 1:
                    code.append(opcodes_inverse['OP_PUSH1'][0].to_bytes(1, 'big'))
                elif len(args[0]) == 2:
                    code.append(opcodes_inverse['OP_PUSH2'][0].to_bytes(1, 'big'))
                elif len(args[0]) == 4:
                    code.append(opcodes_inverse['OP_PUSH4'][0].to_bytes(1, 'big'))
            else:
                code.append(opcodes_inverse[current_symbol][0].to_bytes(1, 'big'))
            code.append(b''.join(args))
            index += advance

    code = b''.join(code)

    return (
        index,
        (
            opcodes_inverse[opcode][0].to_bytes(1, 'big'),
            (len(code) - else_len).to_bytes(3, 'big'),
            code
        )
    )


def parse_else(symbols: list[str]) -> tuple[int, tuple[bytes]]:
    """Parses an ELSE clause. Returns tuple (int advance, tuple[bytes]
        parts). Called recursively to handle nested conditional clauses.
    """
    yert(len(symbols) > 0, 'missing ELSE clause contents')
    code = []
    index = 0

    if symbols[0] == '(':
        # case 1: ELSE ( statements )
        yert(')' in symbols[1:], 'unterminated ELSE: missing matching )')
        index = 1
    else:
        yert('END_IF' in symbols[1:], 'missing END_IF')

    while index < len(symbols):
        current_symbol = symbols[index]

        if current_symbol in (')', 'END_IF'):
            index += 2
            break
        elif current_symbol == 'ELSE':
            raise SyntaxError('cannot have multiple ELSE clauses')
        elif current_symbol == 'OP_IF':
            advance, parts = parse_if(symbols[index+1:])
            index += advance
            code.extend(parts)
        else:
            yert(current_symbol in opcodes_inverse or current_symbol == 'OP_PUSH',
                f'unrecognized opcode: {current_symbol}')
            advance, args = get_args(current_symbol, symbols[index+1:])
            index += advance
            if current_symbol == 'OP_PUSH':
                if len(args) < 2:
                    code.append(opcodes_inverse['OP_PUSH0'][0].to_bytes(1, 'big'))
                elif len(args[0]) == 1:
                    code.append(opcodes_inverse['OP_PUSH1'][0].to_bytes(1, 'big'))
                elif len(args[0]) == 2:
                    code.append(opcodes_inverse['OP_PUSH2'][0].to_bytes(1, 'big'))
                elif len(args[0]) == 4:
                    code.append(opcodes_inverse['OP_PUSH4'][0].to_bytes(1, 'big'))
            else:
                code.append(opcodes_inverse[current_symbol][0].to_bytes(1, 'big'))
            code.append(b''.join(args))

    code = b''.join(code)
    return (
        index,
        (
            len(code).to_bytes(3, 'big'),
            code
        )
    )


def compile_script(script: str) -> bytes:
    """Compile the given human-readable script into byte code."""
    vert(type(script) is str, 'input script must be str')

    # setup
    code = []

    # get a list of symbols
    symbols = get_symbols(script)
    index = 0

    while index < len(symbols):
        symbol = symbols[index]

        # ignore comments (symbols between matchin #, ', or ")
        if symbol in ('"', "'", '#'):
            # skip forward past the matching symbol
            try:
                index = symbols.index(symbol, index+1) + 1
            except ValueError:
                raise SyntaxError(f'unterminated comment starting with {symbol}') from None
            continue

        vert(symbol in opcodes_inverse or symbol == 'OP_PUSH',
             f'unrecognized opcode: {symbol}')

        # handle definition
        if symbol == 'OP_DEF':
            def_code = b''
            name = symbols[index + 1]
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

            if symbols[index + 2] == '{':
                # case 1: OP_DEF number { match }
                yert('}' in symbols[index:], 'missing matching }')
                search_idx = symbols.index('}', index)
                index += 2
            else:
                # case 2: find END_DEF
                yert('END_DEF' in symbols[index:], 'missing END_DEF')
                search_idx = symbols.index('END_DEF')
                index += 1

            # add OP_DEF to code
            code.append(opcodes_inverse['OP_DEF'][0].to_bytes(1, 'big'))

            i = index + 1
            while i < search_idx:
                current_symbol = symbols[i]
                yert(current_symbol[:3] == 'OP_' or (current_symbol == '}'),
                     'statements must begin with valid op code')
                yert(current_symbol != 'OP_DEF',
                    'cannot use OP_DEF within OP_DEF body')

                if current_symbol == 'OP_IF':
                    advance, parts = parse_if(symbols[i+1:])
                    i += advance
                    def_code += b''.join(parts)
                else:
                    advance, args = get_args(current_symbol, symbols[i+1:])
                    i += advance
                    if current_symbol == 'OP_PUSH':
                        if len(args) < 2:
                            def_code += opcodes_inverse['OP_PUSH0'][0].to_bytes(1, 'big')
                        elif len(args[0]) == 1:
                            def_code += opcodes_inverse['OP_PUSH1'][0].to_bytes(1, 'big')
                        elif len(args[0]) == 2:
                            def_code += opcodes_inverse['OP_PUSH2'][0].to_bytes(1, 'big')
                        elif len(args[0]) == 4:
                            def_code += opcodes_inverse['OP_PUSH4'][0].to_bytes(1, 'big')
                    else:
                        def_code += opcodes_inverse[current_symbol][0].to_bytes(1, 'big')
                    def_code += b''.join(args)

            # add def handle to code
            code.append(name.to_bytes(1, 'big'))

            # add def size to code
            def_size = len(def_code)
            yert(def_size < 2**24, 'def size limit exceeded')
            code.append(def_size.to_bytes(3, 'big'))

            # add def code to code
            code.append(def_code)

            # advance the index
            index = search_idx + 1
        elif symbol == 'OP_IF':
            advance, parts = parse_if(symbols[index+1:])
            index += advance + 1
            code.append(b''.join(parts))
        else:
            advance, args = get_args(symbol, symbols[index+1:])
            index += advance
            if symbol == 'OP_PUSH':
                if len(args) < 2:
                    code.append(opcodes_inverse['OP_PUSH0'][0].to_bytes(1, 'big'))
                elif len(args[0]) == 1:
                    code.append(opcodes_inverse['OP_PUSH1'][0].to_bytes(1, 'big'))
                elif len(args[0]) == 2:
                    code.append(opcodes_inverse['OP_PUSH2'][0].to_bytes(1, 'big'))
                elif len(args[0]) == 4:
                    code.append(opcodes_inverse['OP_PUSH4'][0].to_bytes(1, 'big'))
            else:
                code.append(opcodes_inverse[symbol][0].to_bytes(1, 'big'))
            code.append(b''.join(args))

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
                def_length = int.from_bytes(tape.read(3), 'big')
                def_body = tape.read(def_length)
                def_lines = decompile_script(def_body, indent+1)
                add_line(f'OP_DEF {def_handle}' + ' {')
                code_lines.extend(def_lines)
                add_line('}')
            case 'OP_IF':
                if_len = int.from_bytes(tape.read(3), 'big')
                if_body = tape.read(if_len)
                if_lines = decompile_script(if_body, indent+1)
                add_line('OP_IF (')
                code_lines.extend(if_lines)
                add_line(')')
            case 'OP_IF_ELSE':
                if_len = int.from_bytes(tape.read(3), 'big')
                if_body = tape.read(if_len)
                if_lines = decompile_script(if_body, indent+1)
                else_len = int.from_bytes(tape.read(3), 'big')
                else_body = tape.read(else_len)
                else_lines = decompile_script(else_body, indent+1)
                add_line('OP_IF (')
                code_lines.extend(if_lines)
                add_line(') ELSE (')
                code_lines.extend(else_lines)
                add_line(')')
            case 'OP_FALSE' | 'OP_TRUE' | 'OP_POP0' | 'OP_SIZE' | \
                'OP_READ_CACHE_Q' | 'OP_READ_CACHE_Q_SIZE' | 'OP_DIV_INTS' | \
                'OP_MOD_INTS' | 'OP_DIV_FLOATS' | 'OP_MOD_FLOATS' | 'OP_DUP' | \
                'OP_SHA256' | 'OP_VERIFY' | 'OP_EQUAL' | 'OP_EQUAL_VERIFY' | \
                'OP_CHECK_TIMESTAMP' | 'OP_CHECK_TIMESTAMP_VERIFY' | \
                'OP_CHECK_EPOCH' | 'OP_CHECK_EPOCH_VERIFY' | 'OP_EVAL' | \
                'OP_NOT' | 'OP_RETURN' | 'OP_DEPTH' | 'OP_SWAP2' | \
                'OP_CONCAT' | 'OP_CONCAT_STR':
                # ops that have no arguments on the tape
                # human-readable syntax of OP_[whatever]
                add_line(op_name)
            case 'OP_PUSH1' | 'OP_WRITE_CACHE' | 'OP_READ_CACHE' | \
                'OP_READ_CACHE_SIZE' | 'OP_DIV_INT' | \
                'OP_MOD_INT' | 'OP_SET_FLAG' | 'OP_UNSET_FLAG':
                # ops that have tape arguments of form [size 0-255] [val]
                size = tape.read(1)[0]
                val = tape.read(size)
                add_line(f'{op_name} d{size} x{val.hex()}')
            case 'OP_PUSH0' | 'OP_POP1' | 'OP_ADD_INTS' | 'OP_SUBTRACT_INTS' | \
                'OP_MULT_INTS' | 'OP_ADD_FLOATS' | 'OP_CHECK_TRANSFER' | \
                'OP_SUBTRACT_FLOATS' | 'OP_ADD_POINTS' | 'OP_CALL' | \
                'OP_COPY' | 'OP_SHAKE256' | 'OP_RANDOM' | 'OP_REVERSE' | \
                'OP_SPLIT' | 'OP_SPLIT_STR':
                # ops that have tape argument of form [0-255]
                # human-readable syntax of OP_[whatever] [int]
                val = tape.read(1)[0]
                add_line(f'{op_name} d{val}')
            case 'OP_CHECK_SIG' | 'OP_CHECK_SIG_VERIFY':
                # ops that have tape argument of form [0-255]
                # human-readable syntax of OP_[whatever] [int]
                val = tape.read(1)
                add_line(f'{op_name} x{val.hex()}')
            case 'OP_PUSH2':
                # ops that have tape argument of form [0-65535] [val]
                # human-readable syntax of simply OP_PUSH2 [val]
                size = int.from_bytes(tape.read(2), 'big')
                val = tape.read(size)
                add_line(f'{op_name} d{size} x{val.hex()}')
            case 'OP_PUSH4':
                # ops that have tape argument of form [0-4_294_967_295] [val]
                # human-readable syntax of simply OP_PUSH4 [val]
                size = int.from_bytes(tape.read(4), 'big')
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
                add_line(f'OP_SWAP d{idx1} d{idx2}')
            case 'OP_MERKLEVAL':
                # op has tape argument of form [32-byte val]
                digest = tape.read(32)
                add_line(f'OP_MERKLEVAL x{digest.hex()}')
            case _:
                lines = additional_opcodes[op_name][1](op_name, tape)
                add_lines(lines)

    return code_lines
