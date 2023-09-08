from context import classes, errors, functions, parsing
from queue import LifoQueue
import unittest


class TestParsing(unittest.TestCase):
    tape: classes.Tape
    queue: LifoQueue
    cache: dict

    def setUp(self) -> None:
        self.tape = classes.Tape(b'')
        self.queue = LifoQueue()
        self.cache = {}
        return super().setUp()

    def test_get_symbols_raises_error_for_unterminated_string(self):
        with self.assertRaises(errors.SyntaxError) as e:
            parsing.get_symbols("OP_PUSH s'unterminated should error")
        assert str(e.exception) == 'unterminated string encountered'

    def test_get_symbols_parses_properly(self):
        symbols = parsing.get_symbols('OP_WHATEVER s"some string should be one symbol" OP_SOMETHING d123')
        assert symbols == [
            'OP_WHATEVER',
            's"some string should be one symbol"',
            'OP_SOMETHING',
            'd123'
        ]
        symbols = parsing.get_symbols('OP_DEF 0 { OP_PUSH x1234 }')
        assert symbols == [
            'OP_DEF',
            '0',
            '{',
            'OP_PUSH',
            'x1234',
            '}'
        ]
        symbols = parsing.get_symbols('OP_PUSH s"word"')
        assert symbols == [
            'OP_PUSH',
            's"word"'
        ]

    def test_get_symbols_converts_any_whitespace_to_single_space(self):
        symbols = parsing.get_symbols('s"should   be\nseparated\tby\njust    1 space"')
        assert symbols == ['s"should be separated by just 1 space"']

    def test_parse_if_errors_on_incomplete_OP_IF(self):
        with self.assertRaises(errors.SyntaxError) as e:
            parsing.parse_if(['OP_IF', '(', 'OP_POP0'], 0)
        assert str(e.exception) == 'unterminated OP_IF: missing matching ) - symbol 0'

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.parse_if(['OP_IF', 'OP_POP0'], 0)
        assert 'missing END_IF' in str(e.exception)

    def test_compile_script_errors_on_nonstr_input(self):
        with self.assertRaises(ValueError) as e:
            parsing.compile_script(b'not a str')
        assert str(e.exception) == 'input script must be str'

    def test_compile_script_errors_on_invalid_opcode(self):
        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_WTF d1')
        assert 'unrecognized symbol: OP_WTF' in str(e.exception)

    def test_compile_script_errors_on_invalid_opcode_use_syntax(self):
        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF notnumeric OP_DEF 1 OP_PUSH x01 END_DEF END_DEF')
        assert 'def number must be numeric' in str(e.exception)

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF x123 OP_DEF 1 OP_PUSH x01 END_DEF END_DEF')
        assert 'def number must be in x00-xff' in str(e.exception)

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 2000 OP_DEF 1 OP_PUSH x01 END_DEF END_DEF')
        assert 'def number must be in 0-255' in str(e.exception)

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF d2000 OP_DEF 1 OP_PUSH x01 END_DEF END_DEF')
        assert 'def number must be in d0-d255' in str(e.exception)

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 1 { OP_PUSH x01')
        assert 'missing matching }' in str(e.exception)

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 1 OP_PUSH x01')
        assert 'missing END_DEF' in str(e.exception)

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 0 OP_DEF 1 OP_PUSH x01 END_DEF END_DEF')
        assert 'cannot use OP_DEF within OP_DEF body' in str(e.exception)

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 0 { d123 }')
        assert 'statements must begin with valid op code, not d123' in str(e.exception)

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH 123 }')
        assert str(e.exception) == 'values for OP_PUSH must be prefaced with d, x, or s'

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH dabc }')
        assert str(e.exception) == 'value prefaced by d must be decimal int'

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH1 asd }')
        assert 'values for OP_PUSH1 must be prefaced with d, x, or s' in str(e.exception)

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH1 dnotnumeric }')
        assert 'value prefaced by d must be decimal int or float' in str(e.exception)

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH0 asd }')
        assert 'numeric args must be prefaced with d or x' in str(e.exception)

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH0 dnotnumeric }')
        assert 'value prefaced by d must be decimal int' in str(e.exception)

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH0 x1234 }')
        assert 'value must be at most 1 byte long' in str(e.exception)

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH2 asd }')
        assert 'values for OP_PUSH2 must be prefaced with d, x, or s' in str(e.exception)

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH2 dnotnumeric }')
        assert 'value prefaced by d must be decimal int' in str(e.exception)

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH4 asd }')
        assert 'values for OP_PUSH4 must be prefaced with d, x, or s' in str(e.exception)

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH4 dnotnumeric }')
        assert 'value prefaced by d must be decimal int' in str(e.exception)

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 0 { OP_DIV_FLOAT asd }')
        assert 'numeric args must be prefaced with d or x' in str(e.exception)

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_DIV_FLOAT dnotnumeric }')
        assert 'value prefaced by d must be decimal float' in str(e.exception)

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_MOD_FLOAT x123456 }')
        assert 'value prefaced by x must be 8 long (4 bytes)' in str(e.exception)

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 0 { OP_SWAP asd d123 }')
        assert 'numeric args must be prefaced with d or x' in str(e.exception)

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_SWAP dnotnumeric x1234 }')
        assert 'value prefaced by d must be decimal int' in str(e.exception)

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_SWAP x1234 d123 }')
        assert 'value prefaced by x must be 2 long (1 byte)' in str(e.exception)

    def test_compile_script_errors_on_unterminated_comment(self):
        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('" unterminated comment')
        str(e.exception) == 'unterminated comment starting with "'

    def test_compile_script_ignores_comments(self):
        code1 = parsing.compile_script('OP_POP0')
        code2 = parsing.compile_script('# ignored # OP_POP0')
        assert code1 == code2 == functions.opcodes_inverse['OP_POP0'][0].to_bytes(1, 'big')

    def test_compile_script_errors_on_incomplete_OP_IF(self):
        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_IF ( OP_POP0')
        assert 'unterminated OP_IF: missing matching )' in str(e.exception)

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_IF OP_POP0')
        assert 'missing END_IF' in str(e.exception)

    def test_compile_script_returns_bytes(self):
        code = parsing.compile_script('OP_POP0')
        assert type(code) is bytes
        assert len(code) == 1

    def test_compile_script_e2e_vectors(self):
        vector_files = {
            '1.src': '1.hex',
            '2.src': '2.hex',
            '3.src': '3.hex',
            '4.src': '4.hex',
            '5.src': '5.hex',
            '6.src': '6.hex',
            'p2pk_locking_script.src': 'p2pk_locking_script.hex',
            'p2pk_unlocking_script1.src': 'p2pk_unlocking_script1.hex',
            'p2pk_unlocking_script2.src': 'p2pk_unlocking_script2.hex',
            'p2sh_committed_script.src': 'p2sh_committed_script.hex',
            'p2sh_unlocking_script.src': 'p2sh_unlocking_script.hex',
            'p2sh_locking_script.src': 'p2sh_locking_script.hex',
            'cds_committed_script.src': 'cds_committed_script.hex',
            'cds_locking_script.src': 'cds_locking_script.hex',
            'cds_unlocking_script1.src': 'cds_unlocking_script1.hex',
            'cds_unlocking_script2.src': 'cds_unlocking_script2.hex',
            'cds_unlocking_script3.src': 'cds_unlocking_script3.hex',
            'correspondent_committed_script.src': 'correspondent_committed_script.hex',
            'correspondent_locking_script.src': 'correspondent_locking_script.hex',
            'correspondent_unlocking_script1.src': 'correspondent_unlocking_script1.hex',
            'correspondent_unlocking_script2.src': 'correspondent_unlocking_script2.hex',
            'merkleval_committed_script_a.src': 'merkleval_committed_script_a.hex',
            'merkleval_committed_script_b.src': 'merkleval_committed_script_b.hex',
            'merkleval_committed_script_ba.src': 'merkleval_committed_script_ba.hex',
            'merkleval_committed_script_bb.src': 'merkleval_committed_script_bb.hex',
            'merkleval_locking_script.src': 'merkleval_locking_script.hex',
            'merkleval_unlocking_script_a.src': 'merkleval_unlocking_script_a.hex',
            'merkleval_unlocking_script_ba.src': 'merkleval_unlocking_script_ba.hex',
            'merkleval_unlocking_script_bb.src': 'merkleval_unlocking_script_bb.hex',
            'omega_e2e.src': 'omega_e2e.hex',
            'omega_e2e_aliases.src': 'omega_e2e.hex',
            'branching_e2e.src': 'branching_e2e.hex',
            'trydef.src': 'trydef.hex',
            'try_in_if.src': 'try_in_if.hex',
        }
        vectors = {}
        names = {}
        errors = []

        for src_fname, hex_fname in vector_files.items():
            with open(f'tests/vectors/{src_fname}', 'r') as fsrc:
                with open(f'tests/vectors/{hex_fname}', 'r') as fhex:
                    src = fsrc.read()
                    hex = ''.join(fhex.read().split())
                    vectors[src] = hex
                    names[hex] = src_fname

        for src, hex in vectors.items():
            expected = hex
            current = names[hex]
            try:
                observed = parsing.compile_script(src).hex()
            except BaseException as e:
                errors.append(f"\ntest_compile_script_e2e_vector: error with {current}: {e}")
                continue
            if expected != observed:
                # just to make it easier to step through the broken test vectors
                print(f"{names[hex]} compilation failed")
                observed = parsing.compile_script(src).hex()
                print(expected)
                print(observed)
                diff = ''
                if len(observed) > len(expected):
                    for i in range(len(observed)):
                        if i >= len(expected):
                            diff += '+'
                        else:
                            diff += ' ' if expected[i] == observed[i] else '^'
                if len(expected) >= len(observed):
                    for i in range(len(expected)):
                        if i >= len(observed):
                            diff += '-'
                        else:
                            diff += ' ' if expected[i] == observed[i] else '^'
                if len(expected) < 200 and len(observed) < 200:
                    print(diff)
                else:
                    print(
                        self.bytes_xor(
                            bytes.fromhex(expected),
                            bytes.fromhex(observed)
                        ).hex()
                    )
            assert expected == observed

        assert len(errors) == 0, f'errors encountered: {errors}'
        print(f'{len(vectors.items())} vectors tested for compile_script')

    def test_decompile_script_returns_list_of_str(self):
        code = parsing.decompile_script(b'\x00')
        assert type(code) is list
        assert code == ['OP_FALSE']

    def test_decompile_script_e2e_vectors(self):
        vector_files = {
            '1.hex': '1.src',
            '2.hex': '2_decompiled.src',
            '3.hex': '3_decompiled.src',
            '4.hex': '4_decompiled.src',
            '5.hex': '5_decompiled.src',
            '6.hex': '6_decompiled.src',
            'cds_committed_script.hex': 'cds_committed_script_decompiled.src',
            'cds_locking_script.hex': 'cds_locking_script_decompiled.src',
            'cds_unlocking_script1.hex': 'cds_unlocking_script1_decompiled.src',
            'cds_unlocking_script2.hex': 'cds_unlocking_script2_decompiled.src',
            'cds_unlocking_script3.hex': 'cds_unlocking_script3_decompiled.src',
            'correspondent_committed_script.hex': 'correspondent_committed_script_decompiled.src',
            'correspondent_locking_script.hex': 'correspondent_locking_script_decompiled.src',
            'correspondent_unlocking_script1.hex': 'correspondent_unlocking_script1_decompiled.src',
            'correspondent_unlocking_script2.hex': 'correspondent_unlocking_script2_decompiled.src',
            'merkleval_committed_script_a.hex': 'merkleval_committed_script_a_decompiled.src',
            'merkleval_committed_script_b.hex': 'merkleval_committed_script_b.src',
            'merkleval_committed_script_ba.hex': 'merkleval_committed_script_ba_decompiled.src',
            'merkleval_committed_script_bb.hex': 'merkleval_committed_script_bb_decompiled.src',
            'merkleval_locking_script.hex': 'merkleval_locking_script.src',
            'merkleval_unlocking_script_a.hex': 'merkleval_unlocking_script_a_decompiled.src',
            'merkleval_unlocking_script_ba.hex': 'merkleval_unlocking_script_ba_decompiled.src',
            'merkleval_unlocking_script_bb.hex': 'merkleval_unlocking_script_bb_decompiled.src',
            'p2pk_locking_script.hex': 'p2pk_locking_script_decompiled.src',
            'p2pk_unlocking_script1.hex': 'p2pk_unlocking_script1_decompiled.src',
            'p2pk_unlocking_script2.hex': 'p2pk_unlocking_script2_decompiled.src',
            'p2sh_committed_script.hex': 'p2sh_committed_script_decompiled.src',
            'p2sh_locking_script.hex': 'p2sh_locking_script_decompiled.src',
            'p2sh_unlocking_script.hex': 'p2sh_unlocking_script_decompiled.src',
            'omega_e2e.hex': 'omega_e2e_decompiled.src',
            'branching_e2e.hex': 'branching_e2e_decompiled.src',
            'trydef.hex': 'trydef.src',
            'try_in_if.hex': 'try_in_if.src',
        }
        vectors = {}
        names = {}

        for hex_fname, src_fname in vector_files.items():
            with open(f'tests/vectors/{src_fname}', 'r') as fsrc:
                with open(f'tests/vectors/{hex_fname}', 'r') as fhex:
                    src = fsrc.read()
                    hex = ''.join(fhex.read().split())
                    src_lines = src.split('\n')
                    # keep only non-empty lines
                    vectors[hex] = [line for line in src_lines if line != '']
                    names[hex] = src_fname

        for hex, src in vectors.items():
            expected = src
            observed = parsing.decompile_script(bytes.fromhex(hex))
            if expected != observed:
                # just to make it easier to step through the broken test vectors
                observed = parsing.decompile_script(bytes.fromhex(hex))
                print(f'\n{names[hex]} failed')
                print('\ndifferences:')
                if len(expected) > len(observed):
                    for i in range(len(expected)):
                        if i >= len(observed):
                            print(f'expected line {i+1}: {expected[i]}')
                        elif observed[i] != expected[i]:
                            print(f'expected line {i+1}: {expected[i]}')
                            print(f'observed line {i+1}: {observed[i]}')
                else:
                    for i in range(len(observed)):
                        if i >= len(expected):
                            print(f'observed line {i+1}: {observed[i]}')
                        elif observed[i] != expected[i]:
                            print(f'expected line {i+1}: {expected[i]}')
                            print(f'observed line {i+1}: {observed[i]}')
            assert expected == observed

        print(f'{len(vectors.items())} vectors tested for decompile_script')

    def test_compile_decompiled_script_e2e_vectors(self):
        vector_files = {
            '2_decompiled.src': '2.hex',
            '3_decompiled.src': '3.hex',
            '4_decompiled.src': '4.hex',
            '5_decompiled.src': '5.hex',
            '6_decompiled.src': '6.hex',
            'cds_committed_script_decompiled.src': 'cds_committed_script.hex',
            'cds_locking_script_decompiled.src': 'cds_locking_script.hex',
            'cds_unlocking_script1_decompiled.src': 'cds_unlocking_script1.hex',
            'cds_unlocking_script2_decompiled.src': 'cds_unlocking_script2.hex',
            'cds_unlocking_script3_decompiled.src': 'cds_unlocking_script3.hex',
            'correspondent_committed_script_decompiled.src': 'correspondent_committed_script.hex',
            'correspondent_locking_script_decompiled.src': 'correspondent_locking_script.hex',
            'correspondent_unlocking_script1_decompiled.src': 'correspondent_unlocking_script1.hex',
            'correspondent_unlocking_script2_decompiled.src': 'correspondent_unlocking_script2.hex',
            'merkleval_committed_script_a_decompiled.src': 'merkleval_committed_script_a.hex',
            'merkleval_committed_script_b.src': 'merkleval_committed_script_b.hex',
            'merkleval_committed_script_ba_decompiled.src': 'merkleval_committed_script_ba.hex',
            'merkleval_committed_script_bb_decompiled.src': 'merkleval_committed_script_bb.hex',
            'merkleval_locking_script.src': 'merkleval_locking_script.hex',
            'merkleval_unlocking_script_a_decompiled.src': 'merkleval_unlocking_script_a.hex',
            'merkleval_unlocking_script_ba_decompiled.src': 'merkleval_unlocking_script_ba.hex',
            'merkleval_unlocking_script_bb_decompiled.src': 'merkleval_unlocking_script_bb.hex',
            'p2pk_locking_script_decompiled.src': 'p2pk_locking_script.hex',
            'p2pk_unlocking_script1_decompiled.src': 'p2pk_unlocking_script1.hex',
            'p2pk_unlocking_script2_decompiled.src': 'p2pk_unlocking_script2.hex',
            'p2sh_committed_script_decompiled.src': 'p2sh_committed_script.hex',
            'p2sh_locking_script_decompiled.src': 'p2sh_locking_script.hex',
            'p2sh_unlocking_script_decompiled.src': 'p2sh_unlocking_script.hex',
            'omega_e2e_decompiled.src': 'omega_e2e.hex',
            'branching_e2e_decompiled.src': 'branching_e2e.hex',
        }
        vectors = {}
        names = {}
        errors = []

        for src_fname, hex_fname in vector_files.items():
            with open(f'tests/vectors/{src_fname}', 'r') as fsrc:
                with open(f'tests/vectors/{hex_fname}', 'r') as fhex:
                    src = fsrc.read()
                    hex = ''.join(fhex.read().split())
                    vectors[src] = hex
                    names[hex] = src_fname

        for src, hex in vectors.items():
            try:
                expected = hex
                observed = parsing.compile_script(src).hex()
                if expected != observed:
                    # just to make it easier to step through the broken test vectors
                    observed = parsing.compile_script(src).hex()
                    print(expected)
                    print(observed)
                    diff = ''
                    if len(observed) > len(expected):
                        for i in range(len(observed)):
                            if i >= len(expected):
                                diff += '+'
                            else:
                                diff += ' ' if expected[i] == observed[i] else '^'
                    if len(expected) >= len(observed):
                        for i in range(len(expected)):
                            if i >= len(observed):
                                diff += '-'
                            else:
                                diff += ' ' if expected[i] == observed[i] else '^'
                    if len(expected) < 200 and len(observed) < 200:
                        print(diff)
                    else:
                        print(
                            self.bytes_xor(
                                bytes.fromhex(expected),
                                bytes.fromhex(observed)
                            ).hex()
                        )
                assert expected == observed
            except BaseException as e:
                errors.append(f'\ntest_compile_decompiled_script_e2e_vector: error with {names[hex]}: {e}')
                continue

        assert len(errors) == 0, f'errors encountered: {errors}'
        print(f'{len(vectors.items())} vectors tested for compiling decompiled scripts')

    def test_add_opcode_parsing_handlers_e2e(self):
        original_opcodes = {**functions.opcodes}
        original_opcodes_inverse = {**functions.opcodes_inverse}

        OP_GRAB_INT = lambda tape, queue, cache: tape.read(1)[0]
        functions.opcodes[255] = ('OP_GRAB_INT', OP_GRAB_INT)
        functions.opcodes_inverse['OP_GRAB_INT'] = (255, OP_GRAB_INT)

        def compiler(opname: str, symbols: list[str], symbols_to_advance: int,
                     symbol_index: int):
            symbols_to_advance += 1
            val = int(symbols[0][1:]).to_bytes(1, 'big')
            return (symbols_to_advance, (val,))

        def decompiler(opname: str, tape: classes.Tape):
            val = tape.read(1)[0]
            return [f'{opname} d{val}']

        parsing.add_opcode_parsing_handlers('OP_GRAB_INT', compiler, decompiler)
        compiled = parsing.compile_script('OP_GRAB_INT d2')
        assert compiled == b'\xff\x02'
        decompiled = parsing.decompile_script(compiled)
        assert decompiled == ['OP_GRAB_INT d2']

        assert functions.opcodes != original_opcodes
        assert functions.opcodes_inverse != original_opcodes_inverse
        del functions.opcodes[255]
        del functions.opcodes_inverse['OP_GRAB_INT']

    def test_define_macro_and_invoke_macro_e2e(self):
        defsrc = '!= test [ arg1 arg2 ] { PUSH arg1 PUSH arg2 EQUAL_VERIFY }'
        callsrc = '!test [ d12 d23 ]'
        symbols = parsing.get_symbols(defsrc)
        macros = {}

        assert len(macros) == 0
        index = parsing.define_macro(symbols, macros)
        assert type(index) is int and index == len(symbols)
        assert len(macros) == 1
        assert 'test' in macros, f"{macros=}"
        assert 'args' in macros['test']
        assert 'template' in macros['test']

        symbols = parsing.get_symbols(callsrc)
        result = parsing.invoke_macro(symbols, macros)
        assert type(result) is tuple
        assert len(result) == 2
        assert type(result[0]) is int
        assert result[0] == len(symbols)
        assert type(result[1]) is tuple
        assert len(result[1]) == 1
        assert type(result[1][0]) is bytes

        src = defsrc + ' ' + callsrc
        result = parsing.compile_script(src)
        assert type(result) is bytes
        print(result.hex())
        assert len(result) == 5

    def test_variables_e2e(self):
        setsrc = '@= test [ d123 ]'
        result = parsing.set_variable(parsing.get_symbols(setsrc))
        assert type(result) is tuple
        assert len(result) == 2
        assert result[0] == len(parsing.get_symbols(setsrc))
        assert type(result[1]) is tuple
        assert len(result[1]) == 1
        assert type(result[1][0]) is bytes

        getsrc = '@test'
        result = parsing.load_variable([getsrc])
        assert type(result) is tuple
        assert len(result) == 2
        assert result[0] == len(parsing.get_symbols(getsrc))
        assert type(result[1]) is tuple
        assert len(result[1]) == 1
        assert type(result[1][0]) is bytes

        src = '@= test [ d123 ] @test PUSH d123 EQUAL'
        code = parsing.compile_script(src)
        assert type(code) is bytes
        assert len(code) == 18

    def bytes_xor(self, first: bytes, second: bytes) -> bytes:
        while len(first) > len(second):
            second = second + b'\x00'
        while len(first) < len(second):
            first = first + b'\x00'

        result = bytearray(len(first))
        for i in range(len(first)):
            result[i] = first[i] ^ second[i]

        return bytes(result)

    def line_diff(self, first: str, second: str) -> None:
        diff = ''
        if len(first) > len(second):
            for i in range(len(first)):
                if i >= len(second):
                    diff += first[i]


if __name__ == '__main__':
    unittest.main()
