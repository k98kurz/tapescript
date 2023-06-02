from context import classes, functions
from hashlib import sha256, sha3_256
from random import randint
import unittest


class TestFunctions(unittest.TestCase):
    def test_bytes_to_int_raises_errors_for_invalid_input(self):
        with self.assertRaises(TypeError) as e:
            functions.bytes_to_int('not bytes')
        assert str(e.exception) == 'number must be bytes'
        with self.assertRaises(ValueError) as e:
            functions.bytes_to_int(b'')
        assert str(e.exception) == 'number must not be empty'

    def test_bytes_to_int_returns_int(self):
        number = functions.bytes_to_int(b'0')
        assert type(number) is int
        assert number == int.from_bytes(b'0', 'big')

    def test_int_to_bytes_raises_TypeError_for_nonint(self):
        with self.assertRaises(TypeError) as e:
            functions.int_to_bytes('not int')
        assert str(e.exception) == 'number must be int'

    def test_int_to_bytes_returns_bytes(self):
        number = functions.int_to_bytes(123)
        assert type(number) is bytes
        number = functions.int_to_bytes(-123)
        assert type(number) is bytes

    def test_int_to_bytes_bytes_to_int_e2e(self):
        number = 200
        converted = functions.int_to_bytes(number)
        reconverted = functions.bytes_to_int(converted)
        assert reconverted == number

        number = -200
        converted = functions.int_to_bytes(number)
        reconverted = functions.bytes_to_int(converted)
        assert reconverted == number

    def test_bytes_to_bool_raises_TypeError_for_invalid_input(self):
        with self.assertRaises(TypeError) as e:
            functions.bytes_to_bool('not bytes')
        assert str(e.exception) == "cannot convert 'str' object to bytes"

    def test_bytes_to_bool_returns_bool(self):
        assert functions.bytes_to_bool(b'') is False
        assert functions.bytes_to_bool(b'1') is True


if __name__ == '__main__':
    unittest.main()
