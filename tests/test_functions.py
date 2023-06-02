from context import classes, functions
from hashlib import sha256, sha3_256
from queue import LifoQueue
from random import randint
import unittest


class TestFunctions(unittest.TestCase):
    tape: classes.Tape
    queue: LifoQueue
    cache: dict

    def setUp(self) -> None:
        self.tape = classes.Tape(b'')
        self.queue = LifoQueue()
        self.cache = {}
        return super().setUp()

    # helper functions
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

    # ops
    def test_OP_FALSE_puts_null_byte_onto_queue(self):
        assert self.queue.empty()
        assert not len(self.cache.keys())
        functions.OP_FALSE(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        assert not len(self.cache.keys())
        assert self.queue.get() == b'\x00'

    def test_OP_TRUE_puts_nonnull_byte_onto_queue(self):
        assert self.queue.empty()
        assert not len(self.cache.keys())
        functions.OP_TRUE(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        assert not len(self.cache.keys())
        assert self.queue.get() == b'\x01'

    def test_OP_PUSH0_puts_next_byte_from_tape_onto_queue(self):
        self.tape = classes.Tape(b'123')
        assert self.queue.empty()
        assert not len(self.cache.keys())
        functions.OP_PUSH0(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        assert not len(self.cache.keys())
        assert self.queue.get() == b'1'

    def test_OP_PUSH1_reads_next_byte_as_int_and_puts_that_many_from_tape_onto_queue(self):
        self.tape = classes.Tape(functions.int_to_bytes(11) + b'hello world')
        assert self.queue.empty()
        assert not len(self.cache.keys())
        functions.OP_PUSH1(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        assert not len(self.cache.keys())
        assert self.queue.get() == b'hello world'

    def test_OP_PUSH2_reads_next_2_bytes_as_int_and_puts_that_many_from_tape_onto_queue(self):
        self.tape = classes.Tape(b'\x00' + functions.int_to_bytes(11) + b'hello world')
        assert self.queue.empty()
        assert not len(self.cache.keys())
        functions.OP_PUSH2(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        assert not len(self.cache.keys())
        assert self.queue.get() == b'hello world'

    def test_OP_PUSH4_reads_next_4_bytes_as_int_and_puts_that_many_from_tape_onto_queue(self):
        self.tape = classes.Tape(b'\x00\x00\x00' + functions.int_to_bytes(11) + b'hello world')
        assert self.queue.empty()
        assert not len(self.cache.keys())
        functions.OP_PUSH4(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        assert not len(self.cache.keys())
        assert self.queue.get() == b'hello world'

    def test_OP_POP0_moves_one_item_from_queue_into_cache(self):
        self.queue.put(b'1234')
        assert not self.queue.empty()
        assert not len(self.cache.keys())
        functions.OP_POP0(self.tape, self.queue, self.cache)
        assert self.queue.empty()
        assert len(self.cache.keys())
        assert b'P' in self.cache
        assert self.cache[b'P'] == [b'1234']

    def test_OP_POP1_reads_next_bytes_from_tape_then_puts_that_many_items_from_queue_to_cache(self):
        assert self.queue.empty()
        self.queue.put(b'12')
        self.queue.put(b'34')
        self.tape = classes.Tape(functions.int_to_bytes(2))
        assert not self.queue.empty()
        assert b'P' not in self.cache
        functions.OP_POP1(self.tape, self.queue, self.cache)
        assert self.queue.empty()
        assert b'P' in self.cache
        assert self.cache[b'P'] == [b'34', b'12']

    def test_OP_POP1_interprets_negative_ints_as_positive(self):
        assert self.queue.empty()
        for i in range(136):
            self.queue.put(functions.int_to_bytes(i))
        self.tape = classes.Tape(functions.int_to_bytes(-120))
        functions.OP_POP1(self.tape, self.queue, self.cache)
        assert self.queue.empty()
        assert b'P' in self.cache
        assert len(self.cache[b'P']) == 136

    def test_OP_SIZE_pulls_item_from_queue_and_puts_its_length_onto_queue(self):
        assert self.queue.empty()
        self.queue.put(b'123')
        functions.OP_SIZE(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        item = self.queue.get(False)
        assert item == functions.int_to_bytes(3)


if __name__ == '__main__':
    unittest.main()
