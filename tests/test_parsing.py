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

    def test_get_symbols_converts_any_whitespace_to_single_space(self):
        symbols = parsing.get_symbols('s"should   be\nseparated\tby\njust    1 space"')
        assert symbols == ['s"should be separated by just 1 space"']

    def test_compile_script_errors_on_nonstr_input(self):
        with self.assertRaises(ValueError) as e:
            parsing.compile_script(b'not a str')
        assert str(e.exception) == 'input script must be str'

    def test_compile_script_errors_on_invalid_opcode(self):
        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_WTF d1')
        assert str(e.exception) == 'unrecognized opcode'

    def test_compile_script_errors_on_invalid_opcode_use_syntax(self):
        with self.assertRaises(errors.SyntaxError) as e:
            parsing.compile_script('OP_DEF notnumeric OP_DEF 1 OP_PUSH x01 END_DEF END_DEF')
        assert str(e.exception) == 'def number must be numeric'

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 2000 OP_DEF 1 OP_PUSH x01 END_DEF END_DEF')
        assert str(e.exception) == 'def number must be in 0-255'

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
        assert str(e.exception) == 'numeric args must be prefaced with d or x'

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH dabc }')
        assert str(e.exception) == 'value prefaced by d must be decimal int'

        with self.assertRaises(ValueError) as e:
            parsing.compile_script('OP_DEF 0 { OP_PUSH xabcd12345d }')
        assert str(e.exception) == 'value must be at most 4 bytes long'

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

    def test_compile_script_ignores_comments(self):
        ...


if __name__ == '__main__':
    unittest.main()
