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
            parsing.parse_if(['(', 'OP_POP0'])
        assert str(e.exception) == 'unterminated OP_IF: missing matching )'

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.parse_if(['OP_POP0'])
        assert str(e.exception) == 'missing END_IF'

    def test_compile_script_errors_on_nonstr_input(self):
        with self.assertRaises(ValueError) as e:
            parsing.compile_script(b'not a str')
        assert str(e.exception) == 'input script must be str'

    def test_compile_script_errors_on_invalid_opcode(self):
        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_WTF d1')
        assert str(e.exception) == 'unrecognized opcode: OP_WTF'

    def test_compile_script_errors_on_invalid_opcode_use_syntax(self):
        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF notnumeric OP_DEF 1 OP_PUSH x01 END_DEF END_DEF')
        assert str(e.exception) == 'def number must be numeric'

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF x123 OP_DEF 1 OP_PUSH x01 END_DEF END_DEF')
        assert str(e.exception) == 'def number must be in x00-xff'

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 2000 OP_DEF 1 OP_PUSH x01 END_DEF END_DEF')
        assert str(e.exception) == 'def number must be in 0-255'

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF d2000 OP_DEF 1 OP_PUSH x01 END_DEF END_DEF')
        assert str(e.exception) == 'def number must be in d0-d255'

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 1 { OP_PUSH x01')
        assert str(e.exception) == 'missing matching }'

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 1 OP_PUSH x01')
        assert str(e.exception) == 'missing END_DEF'

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 0 OP_DEF 1 OP_PUSH x01 END_DEF END_DEF')
        assert str(e.exception) == 'cannot use OP_DEF within OP_DEF body'

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 0 { d123 }')
        assert str(e.exception) == 'statements must begin with valid op code'

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH 123 }')
        assert str(e.exception) == 'values for OP_PUSH must be prefaced with d, x, or s'

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH dabc }')
        assert str(e.exception) == 'value prefaced by d must be decimal int'

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH1 asd }')
        assert str(e.exception) == 'values for OP_PUSH1 must be prefaced with d, x, or s'

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH1 dnotnumeric }')
        assert str(e.exception) == 'value prefaced by d must be decimal int or float'

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH0 asd }')
        assert str(e.exception) == 'numeric args must be prefaced with d or x'

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH0 dnotnumeric }')
        assert str(e.exception) == 'value prefaced by d must be decimal int'

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH0 x1234 }')
        assert str(e.exception) == 'value must be at most 1 byte long'

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH2 asd }')
        assert str(e.exception) == 'values for OP_PUSH2 must be prefaced with d, x, or s'

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH2 dnotnumeric }')
        assert str(e.exception) == 'value prefaced by d must be decimal int'

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH4 asd }')
        assert str(e.exception) == 'values for OP_PUSH4 must be prefaced with d, x, or s'

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH4 dnotnumeric }')
        assert str(e.exception) == 'value prefaced by d must be decimal int'

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 0 { OP_DIV_FLOAT asd }')
        assert str(e.exception) == 'numeric args must be prefaced with d or x'

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_DIV_FLOAT dnotnumeric }')
        assert str(e.exception) == 'OP_DIV_FLOAT value prefaced by d must be decimal float'

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_MOD_FLOAT x123456 }')
        assert str(e.exception) == 'OP_MOD_FLOAT value prefaced by x must be 8 long (4 bytes)'

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF 0 { OP_SWAP asd d123 }')
        assert str(e.exception) == 'numeric args must be prefaced with d or x'

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_SWAP dnotnumeric x1234 }')
        assert str(e.exception) == 'OP_SWAP value prefaced by d must be decimal int'

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_SWAP x1234 d123 }')
        assert str(e.exception) == 'OP_SWAP value prefaced by x must be 2 long (1 byte)'

    def test_compile_script_errors_on_unterminated_comment(self):
        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('" unterminated comment')
        str(e.exception) == 'unterminated comment starting with "'

    def test_compile_script_ignores_comments(self):
        code1 = parsing.compile_script('OP_POP0')
        code2 = parsing.compile_script('# ignored # OP_POP0')
        assert code1 == code2 == functions.opcodes_inverse['OP_POP0'][0].to_bytes(1)

    def test_compile_script_errors_on_incomplete_OP_IF(self):
        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_IF ( OP_POP0')
        assert str(e.exception) == 'unterminated OP_IF: missing matching )'

        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_IF OP_POP0')
        assert str(e.exception) == 'missing END_IF'

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
        }
        vectors = {}

        for src_fname, hex_fname in vector_files.items():
            with open(f'tests/vectors/{src_fname}', 'r') as fsrc:
                with open(f'tests/vectors/{hex_fname}', 'r') as fhex:
                    src = fsrc.read()
                    hex = ''.join(fhex.read().split())
                    vectors[src] = hex

        for src, hex in vectors.items():
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

        print(f'{len(vectors.items())} vectors tested')

    def bytes_xor(self, first: bytes, second: bytes) -> bytes:
        while len(first) > len(second):
            second = second + b'\x00'
        while len(first) < len(second):
            first = first + b'\x00'

        result = bytearray(len(first))
        for i in range(len(first)):
            result[i] = first[i] ^ second[i]

        return bytes(result)


if __name__ == '__main__':
    unittest.main()
