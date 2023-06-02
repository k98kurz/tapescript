from .errors import yert, vert
from .functions import int_to_bytes, opcodes_inverse
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
            found = False
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


def compile_script(script: str) -> bytes:
    """Compile the given human-readable script into byte code."""
    vert(type(script) is str, 'input script must be str')

    def get_args(opcode: str, symbols: list[str]) -> tuple[int, bytes]:
        """Get the number of symbols to advance and args for an op."""
        symbols_to_advance = 1
        args = []

        match opcode:
            case 'OP_FALSE' | 'OP_TRUE' | 'OP_POP0' | 'OP_SIZE' | \
                'OP_READ_CACHE_Q' | 'OP_READ_CACHE_Q_SIZE' | 'OP_DIV_INTS' | \
                'OP_MOD_INTS' | 'OP_DIV_FLOATS' | 'OP_MOD_FLOATS' | 'OP_DUP' | \
                'OP_SHA256' | 'OP_VERIFY' | 'OP_EQUAL' | 'OP_EQUAL_VERIFY' | \
                'OP_CHECK_TIMESTAMP' | 'OP_CHECK_TIMESTAMP_VERIFY' | \
                'OP_CHECK_EPOCH' | 'OP_CHECK_EPOCH_VERIFY' | 'OP_EVAL' | \
                'OP_NOT' | 'OP_RETURN' | 'OP_DEPTH' | 'OP_SWAP2' | \
                'OP_CONCAT' | 'OP_CONCAT_STR' | 'OP_DIV_INTS':
                # ops that have no arguments on the tape
                # human-readable syntax of OP_[whatever]
                pass
            case 'OP_PUSH':
                # special case: OP_PUSH is a short hand for OP_PUSH[0,1,2,4]
                # @todo prety sure this is wrong
                symbols_to_advance += 1
                val = symbols[0]
                yert(val[0].lower() in ('d', 'x'),
                    'numeric args must be prefaced with d or x')

                match val[0].lower():
                    case 'd':
                        vert(val[1:].isnumeric(),
                            'value prefaced by d must be decimal int')
                        if '.' in val:
                            val = int(val[1:].split('.')[0])
                        else:
                            val = int(val[1:])
                        size = 1 if val < 256 else 2 if val < 65536 else 4
                        val = val.to_bytes(size, 'big')
                    case 'x':
                        vert(len(val[1:]) <= 8,
                            'value must be at most 4 bytes long')
                        val = bytes.fromhex(val[1:])

                if 1 < len(val) < 256:
                    args.append(len(val).to_bytes(1, 'big'))
                elif 255 < len(val) < 65_536:
                    args.append(len(val).to_bytes(2, 'big'))
                elif 65_535 < len(val) < 4_294_967_296:
                    args.append(len(val).to_bytes(4, 'big'))
                args.append(val)
            case 'OP_PUSH1' | 'OP_WRITE_CACHE' | 'OP_READ_CACHE' | \
                'OP_READ_CACHE_SIZE' | 'OP_DIV_INT' | \
                'OP_MOD_INT' | 'OP_SET_FLAG' | 'OP_UNSET_FLAG':
                # ops that have tape arguments of form [size 0-255] [val]
                if opcode == 'OP_WRITE_CACHE':
                    # human-readable syntax of OP_WRITE_CACHE [key] [number]
                    symbols_to_advance += 2
                    vals = symbols[:2]
                else:
                    # human-readable syntax of OP_[whatever] [key]
                    symbols_to_advance += 1
                    vals = (symbols[0])

                for val in vals:
                    yert(val[0].lower() in ('d', 'x', 's'),
                        f'values for {opcode} must be prefaced with d, x, or s')
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
            case 'OP_PUSH0' | 'OP_POP1' | 'OP_ADD_INTS' | 'OP_SUBTRACT_INTS' | \
                'OP_MULT_INTS' | 'OP_ADD_FLOATS' | \
                'OP_SUBTRACT_FLOATS' | 'OP_ADD_POINTS' | 'OP_CALL' | \
                'OP_COPY' | 'OP_SHAKE256' | 'OP_RANDOM' | 'OP_REVERSE' | \
                'OP_SPLIT' | 'OP_SPLIT_STR' | 'OP_CHECK_SIG' | 'OP_CHECK_SIG_VERIFY':
                # ops that have tape argument of form [0-255]
                # human-readable syntax of OP_[whatever] [int]
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
            case 'OP_PUSH2':
                # ops that have tape argument of form [0-65535] [val]
                # human-readable syntax of simply OP_PUSH2 [val]
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
            case 'OP_PUSH4':
                # ops that have tape argument of form [0-4_294_967_295] [val]
                # human-readable syntax of simply OP_PUSH4 [val]
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
            case 'OP_DIV_FLOAT' | 'OP_MOD_FLOAT':
                # ops that have tape argument of form [4-byte float]
                # human-readable syntax of OP_[DIV|MOD]_FLOAT [val]
                symbols_to_advance += 1
                val = symbols[0]
                yert(val[0].lower() in ('d', 'x'),
                    'numeric args must be prefaced with d or x')

                match val[0].lower():
                    case 'd':
                        vert(val[1:].isnumeric(),
                            f'{opcode} value prefaced by d must be decimal float')
                        args.append(struct.pack('!f', float(val[1:])))
                    case 'x':
                        vert(len(val[1:]) == 8,
                            f'{opcode} value prefaced by x must be 8 long (4 bytes)')
                        args.append(bytes.fromhex(val[1:]))
            case 'OP_SWAP':
                # ops that have tape arguments of form [0-255] [0-255]
                # human-readable syntax of OP_SWAP [idx1] [idx2]
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
            case _:
                pass

        return (symbols_to_advance, tuple(args))

    # setup
    code = []
    in_def, if_depth = False, 0
    defs = {}
    if_codes = []

    # get a list of symbols
    symbols = get_symbols(script)
    index = 0

    while index < len(symbols):
        symbol = symbols[index]

        # ignore comments (symbols between matchin #, ', or ")
        if symbol in ('"', "'", '#'):
            # skip forward past the matching symbol
            index = symbols.index(symbol, index) + 1
            continue

        vert(symbols[0] in opcodes_inverse, 'unrecognized opcode')

        # handle definition
        if symbol == 'OP_DEF':
            def_code = b''
            name = symbols[index + 1]
            yert(name.isnumeric(), 'def number must be numeric')
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
                    ...
                else:
                    advance, args = get_args(current_symbol, symbols[i+1:])
                    i += advance
                    def_code += b''.join(args)

            # add def handle to code
            code.append(name.to_bytes(1, 'big'))

            # add def size to code
            def_size = len(def_code)
            assert 0 < def_size < 2**24, 'def size limit exceeded'
            code.append(def_size.to_bytes(3, 'big'))

            # add def code to code
            code.append(def_code)

            # advance the index
            index += search_idx


def decompile_script(script: bytes) -> str:
    """Decompile the byte code into human-readable script."""
    # @todo write decompiler once compiler finished
    ...
