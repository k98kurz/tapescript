from context import classes, functions
from hashlib import sha256, shake_256
from nacl.signing import SigningKey, VerifyKey
from queue import LifoQueue
from random import randint
from secrets import token_bytes
import nacl.bindings
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

    def test_bytes_to_float_raises_errors_for_invalid_input(self):
        with self.assertRaises(TypeError) as e:
            functions.bytes_to_float('not bytes')
        assert str(e.exception) == 'number must be 4 bytes'

        with self.assertRaises(ValueError) as e:
            functions.bytes_to_float(b'not 4 bytes')
        assert str(e.exception) == 'number must be 4 bytes'

    def test_bytes_to_float_returns_float(self):
        number = functions.bytes_to_float(b'2222')
        assert type(number) is float

    def test_float_to_bytes_raises_TypeError_for_invalid_input(self):
        with self.assertRaises(TypeError) as e:
            functions.float_to_bytes('not a float')
        assert str(e.exception) == 'number must be float'

    def test_float_to_bytes_returns_bytes(self):
        number = functions.float_to_bytes(123.0394)
        assert type(number) is bytes

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

    def test_OP_PUSH1_reads_next_byte_as_uint_and_puts_that_many_from_tape_onto_queue(self):
        self.tape = classes.Tape(functions.int_to_bytes(11) + b'hello world')
        assert self.queue.empty()
        assert not len(self.cache.keys())
        functions.OP_PUSH1(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        assert not len(self.cache.keys())
        assert self.queue.get() == b'hello world'

    def test_OP_PUSH2_reads_next_2_bytes_as_uint_and_puts_that_many_from_tape_onto_queue(self):
        self.tape = classes.Tape(b'\x00' + functions.int_to_bytes(11) + b'hello world')
        assert self.queue.empty()
        assert not len(self.cache.keys())
        functions.OP_PUSH2(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        assert not len(self.cache.keys())
        assert self.queue.get() == b'hello world'

    def test_OP_PUSH4_reads_next_4_bytes_as_uint_and_puts_that_many_from_tape_onto_queue(self):
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

    def test_OP_POP1_reads_uint_from_tape_then_puts_that_many_items_from_queue_to_cache(self):
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

    def test_OP_WRITE_CACHE_reads_cache_key_and_int_from_tape_and_moves_from_queue_to_cache(self):
        self.tape = classes.Tape(
            functions.int_to_bytes(4) +
            b'test' +
            functions.int_to_bytes(2)
        )
        assert self.queue.empty()
        assert not len(self.cache.keys())
        self.queue.put(b'1')
        self.queue.put(b'2')
        functions.OP_WRITE_CACHE(self.tape, self.queue, self.cache)
        assert self.queue.empty()
        assert b'test' in self.cache
        assert self.cache[b'test'] == [b'2', b'1']

    def test_OP_READ_CACHE_reads_cache_key_from_tape_and_moves_values_from_cache_to_queue(self):
        self.cache[b'test'] = [b'2', b'1']
        self.tape = classes.Tape(functions.int_to_bytes(4) + b'test')
        assert self.queue.empty()
        functions.OP_READ_CACHE(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        assert self.cache[b'test'] == [b'2', b'1']
        items = [self.queue.get(False), self.queue.get(False)]
        assert items == [b'1', b'2']

    def test_OP_READ_CACHE_SIZE_reads_cache_key_from_tape_and_puts_size_of_cache_on_queue(self):
        self.cache[b'test'] = [b'2', b'1']
        self.tape = classes.Tape(functions.int_to_bytes(4) + b'test')
        assert self.queue.empty()
        functions.OP_READ_CACHE_SIZE(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        assert self.cache[b'test'] == [b'2', b'1']
        item = self.queue.get(False)
        assert self.queue.empty()
        assert item == functions.int_to_bytes(2)

    def test_OP_READ_CACHE_Q_reads_cache_key_from_queue_and_moves_items_from_cache_to_queue(self):
        self.cache[b'test'] = [b'2', b'1']
        assert self.queue.empty()
        self.queue.put(b'test')
        functions.OP_READ_CACHE_Q(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        assert self.cache[b'test'] == [b'2', b'1']
        items = [self.queue.get(False), self.queue.get(False)]
        assert self.queue.empty()
        assert items == [b'1', b'2']

    def test_OP_READ_CACHE_Q_SIZE_reads_cache_key_from_queue_and_puts_size_of_cache_on_queue(self):
        self.cache[b'test'] = [b'2', b'1']
        assert self.queue.empty()
        self.queue.put(b'test')
        functions.OP_READ_CACHE_Q_SIZE(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        assert self.cache[b'test'] == [b'2', b'1']
        item = self.queue.get(False)
        assert self.queue.empty()
        assert item == functions.int_to_bytes(2)

    def test_OP_ADD_INTS_reads_uint_from_tape_pulls_that_many_ints_from_queue_and_puts_sum_on_queue(self):
        self.tape = classes.Tape(functions.int_to_bytes(3))
        assert self.queue.empty()
        self.queue.put(functions.int_to_bytes(2))
        self.queue.put(functions.int_to_bytes(5))
        self.queue.put(functions.int_to_bytes(-3))
        functions.OP_ADD_INTS(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        item = self.queue.get(False)
        assert self.queue.empty()
        assert not self.cache
        assert functions.bytes_to_int(item) == 4

    def test_OP_SUBTRACT_INTS_reads_uint_from_tape_pulls_that_many_ints_from_queue_and_puts_difference_on_queue(self):
        self.tape = classes.Tape(functions.int_to_bytes(3))
        assert self.queue.empty()
        self.queue.put(functions.int_to_bytes(-3))
        self.queue.put(functions.int_to_bytes(2))
        self.queue.put(functions.int_to_bytes(5))
        functions.OP_SUBTRACT_INTS(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        item = self.queue.get(False)
        assert self.queue.empty()
        assert not self.cache
        assert functions.bytes_to_int(item) == 6

    def test_OP_MULT_INTS_reads_uint_from_tape_pulls_that_many_ints_from_queue_and_puts_product_on_queue(self):
        self.tape = classes.Tape(functions.int_to_bytes(4))
        assert self.queue.empty()
        self.queue.put(functions.int_to_bytes(3))
        self.queue.put(functions.int_to_bytes(2))
        self.queue.put(functions.int_to_bytes(-2))
        self.queue.put(functions.int_to_bytes(5))
        functions.OP_MULT_INTS(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        item = self.queue.get(False)
        assert self.queue.empty()
        assert not self.cache
        assert functions.bytes_to_int(item) == -60

    def test_OP_DIV_INT_pulls_int_from_queue_reads_signed_int_from_tape_and_puts_quotient_on_queue(self):
        self.tape = classes.Tape(functions.int_to_bytes(1) + functions.int_to_bytes(-2))
        assert self.queue.empty()
        self.queue.put(functions.int_to_bytes(-60))
        functions.OP_DIV_INT(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        item = self.queue.get(False)
        assert self.queue.empty()
        assert not self.cache
        assert functions.bytes_to_int(item) == 30

    def test_OP_DIV_INTS_pulls_two_ints_from_queue_and_puts_quotient_on_queue(self):
        assert self.queue.empty()
        self.queue.put(functions.int_to_bytes(12))
        self.queue.put(functions.int_to_bytes(-132))
        functions.OP_DIV_INTS(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        item = self.queue.get(False)
        assert self.queue.empty()
        assert not self.cache
        assert functions.bytes_to_int(item) == -11

    def test_OP_MOD_INT_reads_uint_from_tape_pulls_int_from_queue_and_puts_modulus_on_queue(self):
        assert self.queue.empty()
        self.tape = classes.Tape(functions.int_to_bytes(1) + functions.int_to_bytes(17))
        self.queue.put(functions.int_to_bytes(1258))
        functions.OP_MOD_INT(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        item = self.queue.get(False)
        assert self.queue.empty()
        assert not self.cache
        assert functions.bytes_to_int(item) == (1258%17)

    def test_OP_MOD_INT_pulls_two_ints_from_queue_and_puts_modulus_on_queue(self):
        assert self.queue.empty()
        self.queue.put(functions.int_to_bytes(17))
        self.queue.put(functions.int_to_bytes(1258))
        functions.OP_MOD_INTS(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        item = self.queue.get(False)
        assert self.queue.empty()
        assert not self.cache
        assert functions.bytes_to_int(item) == (1258%17)

    def test_OP_ADD_FLOATS_reads_uint_from_tape_pulls_that_many_floats_from_queue_put_sum_on_queue(self):
        assert self.queue.empty()
        self.tape = classes.Tape(functions.int_to_bytes(3))
        self.queue.put(functions.float_to_bytes(0.01))
        self.queue.put(functions.float_to_bytes(0.1))
        self.queue.put(functions.float_to_bytes(1.0))

        expected = functions.bytes_to_float(functions.float_to_bytes(0.01))
        expected += functions.bytes_to_float(functions.float_to_bytes(0.1))
        expected += functions.bytes_to_float(functions.float_to_bytes(1.0))

        functions.OP_ADD_FLOATS(self.tape, self.queue, self.cache)
        assert not self.cache
        assert not self.queue.empty()
        item = self.queue.get(False)
        item = functions.bytes_to_float(item)
        assert self.queue.empty()
        assert str(item)[:5] == str(expected)[:5]

    def test_OP_SUBTRACT_FLOATS_reads_uint_from_tape_pulls_that_many_floats_from_queue_put_difference_on_queue(self):
        assert self.queue.empty()
        self.tape = classes.Tape(functions.int_to_bytes(3))
        self.queue.put(functions.float_to_bytes(0.01))
        self.queue.put(functions.float_to_bytes(0.1))
        self.queue.put(functions.float_to_bytes(1.0))

        expected = functions.bytes_to_float(functions.float_to_bytes(1.0))
        expected -= functions.bytes_to_float(functions.float_to_bytes(0.01))
        expected -= functions.bytes_to_float(functions.float_to_bytes(0.1))

        functions.OP_SUBTRACT_FLOATS(self.tape, self.queue, self.cache)
        assert not self.cache
        assert not self.queue.empty()
        item = self.queue.get(False)
        item = functions.bytes_to_float(item)
        assert self.queue.empty()
        assert str(item)[:5] == str(expected)[:5]

    def test_OP_DIV_FLOAT_reads_float_from_tape_pulls_float_from_queue_put_quotient_on_queue(self):
        assert self.queue.empty()
        self.tape = classes.Tape(functions.float_to_bytes(0.01))
        self.queue.put(functions.float_to_bytes(0.1))

        expected = functions.bytes_to_float(functions.float_to_bytes(0.1))
        expected /= functions.bytes_to_float(functions.float_to_bytes(0.01))

        functions.OP_DIV_FLOAT(self.tape, self.queue, self.cache)
        assert not self.cache
        assert not self.queue.empty()
        item = self.queue.get(False)
        item = functions.bytes_to_float(item)
        assert self.queue.empty()
        assert (item-expected)/expected < 0.000001

    def test_OP_DIV_FLOATS_pulls_two_floats_from_queue_put_quotient_on_queue(self):
        assert self.queue.empty()
        self.queue.put(functions.float_to_bytes(0.01))
        self.queue.put(functions.float_to_bytes(0.1))

        expected = functions.bytes_to_float(functions.float_to_bytes(0.1))
        expected /= functions.bytes_to_float(functions.float_to_bytes(0.01))

        functions.OP_DIV_FLOATS(self.tape, self.queue, self.cache)
        assert not self.cache
        assert not self.queue.empty()
        item = self.queue.get(False)
        item = functions.bytes_to_float(item)
        assert self.queue.empty()
        assert (item-expected)/expected < 0.000001

    def test_OP_MOD_FLOAT_reads_float_from_tape_pulls_float_from_queue_put_modulus_on_queue(self):
        assert self.queue.empty()
        self.tape = classes.Tape(functions.float_to_bytes(13.0))
        self.queue.put(functions.float_to_bytes(131.1))

        expected = functions.bytes_to_float(functions.float_to_bytes(131.1))
        expected = expected % functions.bytes_to_float(functions.float_to_bytes(13.0))

        functions.OP_MOD_FLOAT(self.tape, self.queue, self.cache)
        assert not self.cache
        assert not self.queue.empty()
        item = self.queue.get(False)
        item = functions.bytes_to_float(item)
        assert self.queue.empty()
        assert (item-expected)/expected < 0.000001

    def test_OP_MOD_FLOATS_pulls_two_floats_from_queue_put_modulus_on_queue(self):
        assert self.queue.empty()
        self.queue.put(functions.float_to_bytes(131.1))
        self.queue.put(functions.float_to_bytes(13.0))

        expected = functions.bytes_to_float(functions.float_to_bytes(131.1))
        expected = expected % functions.bytes_to_float(functions.float_to_bytes(13.0))

        functions.OP_MOD_FLOATS(self.tape, self.queue, self.cache)
        assert not self.cache
        assert not self.queue.empty()
        item = self.queue.get(False)
        item = functions.bytes_to_float(item)
        assert self.queue.empty()
        assert (item-expected)/expected < 0.000001

    def test_OP_ADD_POINTS_reads_uint_from_tape_pulls_that_many_points_from_queue_puts_sum_on_queue(self):
        assert self.queue.empty()
        self.tape = classes.Tape(functions.int_to_bytes(2))
        point1 = bytes(SigningKey(token_bytes(32)).verify_key)
        point2 = bytes(SigningKey(token_bytes(32)).verify_key)
        expected = nacl.bindings.crypto_core_ed25519_add(point1, point2)
        self.queue.put(point1)
        self.queue.put(point2)
        functions.OP_ADD_POINTS(self.tape, self.queue, self.cache)
        assert not self.cache
        assert not self.queue.empty()
        item = self.queue.get(False)
        assert item == bytes(expected)

    def test_OP_COPY_reads_uint_from_tape_and_copies_top_queue_value_that_many_times(self):
        assert self.queue.empty()
        n_copies = randint(1, 255)
        self.queue.put(b'1')
        self.tape = classes.Tape(n_copies.to_bytes(1, 'big'))
        functions.OP_COPY(self.tape, self.queue, self.cache)
        expected = n_copies + 1
        observed = 0
        while not self.queue.empty():
            observed += 1
            assert self.queue.get(False) == b'1'
        assert observed == expected

    def test_OP_DUP_duplicates_top_queue_item(self):
        assert self.queue.empty()
        self.queue.put(b'1')
        functions.OP_DUP(self.tape, self.queue, self.cache)
        assert self.queue.get(False) == b'1'
        assert self.queue.get(False) == b'1'
        assert self.queue.empty()

    def test_OP_SHA256_pulls_value_from_queue_and_puts_its_sha256_on_queue(self):
        assert self.queue.empty()
        preimage = b'123232'
        self.queue.put(preimage)
        functions.OP_SHA256(self.tape, self.queue, self.cache)
        expected = sha256(preimage).digest()
        assert self.queue.get(False) == expected
        assert self.queue.empty()

    def test_OP_SHAKE256_reads_uint_from_tape_pulls_value_from_queue_and_puts_its_shake256_on_queue(self):
        assert self.queue.empty()
        self.tape = classes.Tape((20).to_bytes(1, 'big'))
        preimage = b'123232'
        self.queue.put(preimage)
        functions.OP_SHAKE256(self.tape, self.queue, self.cache)
        expected = shake_256(preimage).digest(20)
        assert self.queue.get(False) == expected
        assert self.queue.empty()

    def test_OP_VERIFY_raises_error_only_if_top_queue_item_is_not_true(self):
        self.queue.put(b'\x00')
        with self.assertRaises(AssertionError) as e:
            functions.OP_VERIFY(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_VERIFY check failed'

        self.queue.put(b'\x01')
        functions.OP_VERIFY(self.tape, self.queue, self.cache)
        self.queue.put(b'12323')
        functions.OP_VERIFY(self.tape, self.queue, self.cache)

    def test_OP_EQUAL_compares_two_values_from_queue_and_puts_bool_on_queue(self):
        self.queue.put(b'123')
        self.queue.put(b'123')
        functions.OP_EQUAL(self.tape, self.queue, self.cache)
        assert self.queue.get(False) == b'\x01'

        self.queue.put(b'321')
        self.queue.put(b'123')
        functions.OP_EQUAL(self.tape, self.queue, self.cache)
        assert self.queue.get(False) == b'\x00'

    def test_OP_EQUAL_VERIFY_runs_OP_EQUAL_then_OP_VERIFY(self):
        assert self.queue.empty()
        self.queue.put(b'123')
        self.queue.put(b'123')
        functions.OP_EQUAL_VERIFY(self.tape, self.queue, self.cache)
        assert self.queue.empty()

        self.queue.put(b'321')
        self.queue.put(b'123')
        with self.assertRaises(AssertionError) as e:
            functions.OP_EQUAL_VERIFY(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_VERIFY check failed'
        assert self.queue.empty()


if __name__ == '__main__':
    unittest.main()
