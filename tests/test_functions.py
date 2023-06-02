from context import classes, errors, functions
from hashlib import sha256, shake_256
from nacl.signing import SigningKey, VerifyKey
from queue import LifoQueue
from random import randint
from secrets import token_bytes
from time import time
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
        with self.assertRaises(errors.ScriptExecutionError) as e:
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
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_EQUAL_VERIFY(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_VERIFY check failed'
        assert self.queue.empty()

    def test_OP_CHECK_SIG_pulls_VerifyKey_and_signature_from_queue_and_checks_against_cache(self):
        body = b'hello world'
        skey = SigningKey(token_bytes(32))
        vkey = skey.verify_key
        smsg = skey.sign(body)
        sig = smsg[:64]
        self.tape = classes.Tape(b'\x00')
        assert self.queue.empty()
        self.queue.put(sig)
        self.queue.put(bytes(vkey))
        self.cache['sigfield1'] = body
        functions.OP_CHECK_SIG(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        assert self.queue.get(False) == b'\x01'
        assert self.queue.empty()

    def test_OP_CHECK_SIG_sigflag_omits_sigfields(self):
        field1 = b'hello'
        field3 = b' '
        field8 = b'world'
        body = field1 + field3 + field8
        sigflag = 0b00000001 | 0b00000100 | 0b10000000
        sigflag = (~sigflag) & 255
        self.tape = classes.Tape(sigflag.to_bytes(1, 'big'))
        skey = SigningKey(token_bytes(32))
        vkey = skey.verify_key
        smsg = skey.sign(body)
        sig = smsg[:64] + sigflag.to_bytes(1, 'big')
        assert self.queue.empty()
        self.queue.put(sig)
        self.queue.put(bytes(vkey))
        self.cache['sigfield1'] = field1
        self.cache['sigfield2'] = b'should be ignored'
        self.cache['sigfield3'] = field3
        self.cache['sigfield4'] = b'should be ignored'
        self.cache['sigfield5'] = b'should be ignored'
        self.cache['sigfield6'] = b'should be ignored'
        self.cache['sigfield7'] = b'should be ignored'
        self.cache['sigfield8'] = field8
        functions.OP_CHECK_SIG(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        assert self.queue.get(False) == b'\x01'
        assert self.queue.empty()

    def test_OP_CHECK_SIG_errors_on_disallowed_sigflag(self):
        field1 = b'hello'
        body = field1
        allowed_sigflags = 0b00000100 | 0b10000000
        allowed_sigflags = (~allowed_sigflags) & 255
        self.tape = classes.Tape(allowed_sigflags.to_bytes(1, 'big'))
        attempted_sigflags = 0b10000000
        attempted_sigflags = (~attempted_sigflags) & 255
        skey = SigningKey(token_bytes(32))
        vkey = skey.verify_key
        smsg = skey.sign(body)
        sig = smsg[:64] + attempted_sigflags.to_bytes(1, 'big')
        assert self.queue.empty()
        self.queue.put(sig)
        self.queue.put(bytes(vkey))

        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_SIG(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'disallowed sigflag'
        assert self.queue.empty()

    def test_OP_CHECK_SIG_VERIFY_runs_OP_CHECK_SIG_then_OP_VERIFY(self):
        body = b'hello world'
        skey = SigningKey(token_bytes(32))
        vkey = skey.verify_key
        smsg = skey.sign(body)
        sig = smsg[:64]
        self.tape = classes.Tape(b'\x00')
        assert self.queue.empty()
        self.queue.put(sig)
        self.queue.put(bytes(vkey))
        self.cache['sigfield1'] = body
        functions.OP_CHECK_SIG_VERIFY(self.tape, self.queue, self.cache)
        assert self.queue.empty()

        sig = smsg[:64]
        self.tape = classes.Tape(b'\x00')
        assert self.queue.empty()
        self.queue.put(sig)
        self.queue.put(bytes(vkey))
        self.cache['sigfield1'] = b'not body'
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_SIG_VERIFY(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_VERIFY check failed'
        assert self.queue.empty()

    def test_OP_CHECK_TIMESTAMP_raises_error_for_invalid_constraint(self):
        assert self.queue.empty()
        self.queue.put(b'')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TIMESTAMP(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_CHECK_TIMESTAMP malformed constraint encountered'

    def test_OP_CHECKTIMESTAMP_raises_errors_for_invalid_cache_timestamp(self):
        assert self.queue.empty()
        self.queue.put(b'xxxx')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TIMESTAMP(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_CHECK_TIMESTAMP cache missing timestamp'

        assert self.queue.empty()
        self.queue.put(b'xxxx')
        self.cache['timestamp'] = 'not an int'
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TIMESTAMP(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_CHECK_TIMESTAMP malformed cache timestamp'

    def test_OP_CHECKTIMESTAMP_raises_errors_for_invalid_ts_threshold_tape_flag(self):
        assert self.queue.empty()
        self.queue.put(b'xxxx')
        self.cache['timestamp'] = 3
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TIMESTAMP(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_CHECK_TIMESTAMP missing ts_threshold flag'

        assert self.queue.empty()
        self.queue.put(b'xxxx')
        self.cache['timestamp'] = 3
        self.tape.flags['ts_threshold'] = 'not an int'
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TIMESTAMP(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_CHECK_TIMESTAMP malformed ts_threshold flag'

    def test_OP_CHECK_TIMESTAMP_compares_top_queue_int_to_cache_timestamp(self):
        assert self.queue.empty()
        self.tape.flags['ts_threshold'] = 10
        self.cache['timestamp'] = int(time())
        self.queue.put(int(time()).to_bytes(4, 'big'))
        functions.OP_CHECK_TIMESTAMP(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        assert self.queue.get(False) == b'\x01'

        assert self.queue.empty()
        self.cache['timestamp'] = int(time())-1
        self.queue.put(int(time()).to_bytes(4, 'big'))
        functions.OP_CHECK_TIMESTAMP(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        item = self.queue.get(False)
        assert item == b'\x00'

        assert self.queue.empty()
        self.cache['timestamp'] = int(time())+12
        self.queue.put(int(time()).to_bytes(4, 'big'))
        functions.OP_CHECK_TIMESTAMP(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        item = self.queue.get(False)
        assert item == b'\x00'

        assert self.queue.empty()
        self.tape.flags['ts_threshold'] = 100
        self.cache['timestamp'] = int(time())+12
        self.queue.put(int(time()).to_bytes(4, 'big'))
        functions.OP_CHECK_TIMESTAMP(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        item = self.queue.get(False)
        assert item == b'\x01'

    def test_OP_CHECK_TIMESTAMP_VERIFY_runs_OP_CHECK_TIMESTAMP_then_OP_VERIFY(self):
        assert self.queue.empty()
        self.tape = classes.Tape(b'', flags={'ts_threshold': 10})
        self.cache['timestamp'] = int(time())
        self.queue.put(int(time()).to_bytes(4, 'big'))
        functions.OP_CHECK_TIMESTAMP_VERIFY(self.tape, self.queue, self.cache)
        assert self.queue.empty()

        assert self.queue.empty()
        self.cache['timestamp'] = int(time())-1
        self.queue.put(int(time()).to_bytes(4, 'big'))
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TIMESTAMP_VERIFY(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_VERIFY check failed'
        assert self.queue.empty()

        assert self.queue.empty()
        self.cache['timestamp'] = int(time())+12
        self.queue.put(int(time()).to_bytes(4, 'big'))
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TIMESTAMP_VERIFY(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_VERIFY check failed'
        assert self.queue.empty()

    def test_OP_CHECK_EPOCH_raises_error_for_invalid_constraint(self):
        assert self.queue.empty()
        self.queue.put(b'')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_EPOCH(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_CHECK_EPOCH malformed constraint encountered'

    def test_OP_CHECK_EPOCH_raises_errors_for_invalid_epoch_threshold_tape_flag(self):
        assert self.queue.empty()
        self.queue.put(b'x')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_EPOCH(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_CHECK_EPOCH missing epoch_threshold flag'

        assert self.queue.empty()
        self.queue.put(b'x')
        self.tape.flags['epoch_threshold'] = 'not an int'
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_EPOCH(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_CHECK_EPOCH malformed epoch_threshold flag'

        assert self.queue.empty()
        self.queue.put(b'x')
        self.tape.flags['epoch_threshold'] = -1
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_EPOCH(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_CHECK_EPOCH malformed epoch_threshold flag'

    def test_OP_CHCECK_EPOCH_compares_current_time_to_constraint(self):
        assert self.queue.empty()
        self.tape.flags['epoch_threshold'] = 0
        self.queue.put(int(time()-10).to_bytes(4, 'big'))
        functions.OP_CHECK_EPOCH(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        assert self.queue.get(False) == b'\x01'

        assert self.queue.empty()
        self.queue.put(int(time()+10).to_bytes(4, 'big'))
        functions.OP_CHECK_EPOCH(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        item = self.queue.get(False)
        assert item == b'\x00'

        assert self.queue.empty()
        self.tape.flags['epoch_threshold'] = 100
        self.queue.put(int(time()+10).to_bytes(4, 'big'))
        functions.OP_CHECK_EPOCH(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        item = self.queue.get(False)
        assert item == b'\x01'

    def test_OP_CHECK_EPOCH_VERIFY_runs_OP_CHECK_EPOCH_then_OP_VERIFY(self):
        assert self.queue.empty()
        self.tape.flags['epoch_threshold'] = 0
        self.queue.put(int(time()-10).to_bytes(4, 'big'))
        functions.OP_CHECK_EPOCH_VERIFY(self.tape, self.queue, self.cache)
        assert self.queue.empty()

        assert self.queue.empty()
        self.queue.put(int(time()+10).to_bytes(4, 'big'))
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_EPOCH_VERIFY(self.tape, self.queue, self.cache)
        assert self.queue.empty()

        assert self.queue.empty()
        self.tape.flags['epoch_threshold'] = 100
        self.queue.put(int(time()+10).to_bytes(4, 'big'))
        functions.OP_CHECK_EPOCH_VERIFY(self.tape, self.queue, self.cache)
        assert self.queue.empty()

    def test_OP_DEF_creates_subtape_definition(self):
        assert self.queue.empty()
        self.tape = classes.Tape(b'\x00\x00\x00\x0bhello world')
        assert not self.tape.definitions
        functions.OP_DEF(self.tape, self.queue, self.cache)
        assert b'\x00' in self.tape.definitions
        assert isinstance(self.tape.definitions[b'\x00'], classes.Tape)
        assert self.tape.definitions[b'\x00'].data == b'hello world'
        assert self.queue.empty()

    def test_OP_NOT_inverts_bool_value_of_top_queue_value(self):
        assert self.queue.empty()
        self.queue.put(b'\x01')
        functions.OP_NOT(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        assert self.queue.get(False) == b'\x00'

        assert self.queue.empty()
        self.queue.put(b'\x00')
        functions.OP_NOT(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        assert self.queue.get(False) == b'\x01'
        assert self.queue.empty()

    def test_OP_RANDOM_puts_random_bytes_on_queue(self):
        assert self.queue.empty()
        n_bytes = randint(1, 250)
        self.tape = classes.Tape(n_bytes.to_bytes(1, 'big'))
        functions.OP_RANDOM(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        item = self.queue.get(False)
        assert type(item) is bytes
        assert len(item) == n_bytes
        assert self.queue.empty()

    def test_OP_RETURN_advances_tape_pointer_to_end(self):
        self.tape = classes.Tape(b'asdkjhk123')
        assert self.tape.pointer == 0
        functions.OP_RETURN(self.tape, self.queue, self.cache)
        assert self.tape.pointer == len(self.tape.data)
        with self.assertRaises(errors.ScriptExecutionError) as e:
            self.tape.read(1)

    def test_OP_SET_FLAG_raises_error_for_unrecognized_flag(self):
        self.tape = classes.Tape(b'\x03abc')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_SET_FLAG(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_SET_FLAG unrecognized flag'

    def test_OP_SET_FLAG_sets_tape_flag_to_default_value(self):
        original_flags = functions.flags
        functions.flags = {**original_flags, b'dummy_flag': 1}
        self.tape = classes.Tape(b'\x0adummy_flag')
        assert b'dummy_flag' not in self.tape.flags
        functions.OP_SET_FLAG(self.tape, self.queue, self.cache)
        assert b'dummy_flag' in self.tape.flags
        functions.flags = original_flags

    def test_OP_UNSET_FLAG_unsets_tape_flag(self):
        self.tape = classes.Tape(b'\x0adummy_flag')
        self.tape.flags[b'dummy_flag'] = 1
        assert b'dummy_flag' in self.tape.flags
        functions.OP_UNSET_FLAG(self.tape, self.queue, self.cache)
        assert b'dummy_flag' not in self.tape.flags

    def test_OP_DEPTH_puts_queue_size_onto_queue(self):
        assert self.queue.empty()
        self.queue.put(b'123')
        self.queue.put(b'321')
        self.queue.put(b'asd')
        functions.OP_DEPTH(self.tape, self.queue, self.cache)
        assert not self.queue.empty()
        item = self.queue.get(False)
        assert functions.bytes_to_int(item) == 3
        items = []
        while not self.queue.empty():
            items.append(self.queue.get(False))
        assert items == [b'asd', b'321', b'123']

    def test_OP_SWAP_swaps_order_of_queue_items_given_indices_from_tape(self):
        assert self.queue.empty()
        self.tape = classes.Tape(b'\x00\x02')
        self.queue.put(b'bottom')
        self.queue.put(b'middle')
        self.queue.put(b'top')
        functions.OP_SWAP(self.tape, self.queue, self.cache)
        items = []
        while not self.queue.empty():
            items.append(self.queue.get(False))
        assert items == [b'bottom', b'middle', b'top']

    def test_OP_SWAP2_swaps_top_two_queue_items(self):
        self.queue.put(b'second')
        self.queue.put(b'first')
        functions.OP_SWAP2(self.tape, self.queue, self.cache)
        assert self.queue.get(False) == b'second'
        assert self.queue.get(False) == b'first'

    def test_OP_REVERSE_reads_uint_from_tape_and_reverses_order_of_that_many_queue_items(self):
        assert self.queue.empty()
        self.queue.put(4)
        self.queue.put(3)
        self.queue.put(2)
        self.queue.put(1)
        self.tape = classes.Tape(b'\x03')
        functions.OP_REVERSE(self.tape, self.queue, self.cache)
        items = []
        while not self.queue.empty():
            items.append(self.queue.get(False))
        assert items == [3,2,1,4]

    def test_OP_CONCAT_concatenates_top_two_items_from_queue(self):
        self.queue.put(b'123')
        self.queue.put(b'321')
        functions.OP_CONCAT(self.tape, self.queue, self.cache)
        assert self.queue.get(False) == b'321123'
        assert self.queue.empty()

    def test_OP_SPLIT_splits_top_queue_item_at_uint_index_read_from_tape(self):
        self.tape = classes.Tape(b'\x02')
        self.queue.put(b'12345')
        functions.OP_SPLIT(self.tape, self.queue, self.cache)
        assert self.queue.get(False) == b'345'
        assert self.queue.get(False) == b'12'

    def test_OP_CONCAT_STR_concatenates_top_two_utf8_str_items_from_queue(self):
        self.queue.put(bytes('123', 'utf-8'))
        self.queue.put(bytes('abc', 'utf-8'))
        functions.OP_CONCAT_STR(self.tape, self.queue, self.cache)
        item = self.queue.get(False)
        assert str(item, 'utf-8') == 'abc123'
        assert self.queue.empty()

    def test_OP_SPLIT_STR_splits_top_queue_utf8_str_at_uint_index_read_from_tape(self):
        self.tape = classes.Tape(b'\x02')
        self.queue.put(bytes('12345', 'utf-8'))
        functions.OP_SPLIT_STR(self.tape, self.queue, self.cache)
        assert str(self.queue.get(False), 'utf-8') == '345'
        assert str(self.queue.get(False), 'utf-8') == '12'

    def test_NOP_reads_uint_from_tape_and_pulls_that_many_items_from_queue(self):
        assert self.queue.empty()
        self.queue.put(1)
        self.queue.put(2)
        self.queue.put(3)
        self.tape = classes.Tape(b'\x02')
        functions.NOP(self.tape, self.queue, self.cache)
        assert self.queue.get(False) == 1
        assert self.queue.empty()

    def test_OP_CHECK_TRANSFER_errors_on_missing_or_invalid_contract_or_params(self):
        def setup_transfer():
            self.tape = classes.Tape(b'\x01')
            self.queue.put(b'txn_proof')
            self.queue.put(b'source')
            self.queue.put(b'destination')
            self.queue.put(b'constraint')
            self.queue.put(b'amount')
            self.queue.put(b'contractid')

        valid_contract = {
            'verify_txn_proof': lambda txn_proof: True,
            'verify_transfer': lambda txn_proof, source, destination: True,
            'verify_txn_constraint': lambda txn_proof, constraint: True,
            'calc_txn_aggregates': lambda proofs, scope: {b'destination': 10}
        }

        setup_transfer()
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TRANSFER(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_CHECK_TRANSFER missing contract'

        setup_transfer()
        self.tape.contracts[b'contractid'] = {}
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TRANSFER(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_CHECK_TRANSFER contract missing verify_txn_proof'

        setup_transfer()
        self.tape.contracts[b'contractid'] = {'verify_txn_proof': 1}
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TRANSFER(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_CHECK_TRANSFER malformed contract'

        setup_transfer()
        self.tape.contracts[b'contractid'] = {
            'verify_txn_proof': valid_contract['verify_txn_proof']
        }
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TRANSFER(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_CHECK_TRANSFER contract missing verify_transfer'

        setup_transfer()
        self.tape.contracts[b'contractid'] = {
            'verify_txn_proof': valid_contract['verify_txn_proof'],
            'verify_transfer': 1
        }
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TRANSFER(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_CHECK_TRANSFER malformed contract'

        setup_transfer()
        self.tape.contracts[b'contractid'] = {
            'verify_txn_proof': valid_contract['verify_txn_proof'],
            'verify_transfer': valid_contract['verify_transfer']
        }
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TRANSFER(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_CHECK_TRANSFER contract missing verify_txn_constraint'

        setup_transfer()
        self.tape.contracts[b'contractid'] = {
            'verify_txn_proof': valid_contract['verify_txn_proof'],
            'verify_transfer': valid_contract['verify_transfer'],
            'verify_txn_constraint': 1
        }
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TRANSFER(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_CHECK_TRANSFER malformed contract'

        setup_transfer()
        self.tape.contracts[b'contractid'] = {
            'verify_txn_proof': valid_contract['verify_txn_proof'],
            'verify_transfer': valid_contract['verify_transfer'],
            'verify_txn_constraint': valid_contract['verify_txn_constraint']
        }
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TRANSFER(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_CHECK_TRANSFER contract missing calc_txn_aggregates'

        setup_transfer()
        self.tape.contracts[b'contractid'] = {
            'verify_txn_proof': valid_contract['verify_txn_proof'],
            'verify_transfer': valid_contract['verify_transfer'],
            'verify_txn_constraint': valid_contract['verify_txn_constraint'],
            'calc_txn_aggregates': 1
        }
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TRANSFER(self.tape, self.queue, self.cache)
        assert str(e.exception) == 'OP_CHECK_TRANSFER malformed contract'

    def test_OP_CHECK_TRANSFER_works(self):
        def setup_transfer():
            self.tape = classes.Tape(b'\x01')
            self.queue.put(b'txn_proof')
            self.queue.put(b'source')
            self.queue.put(b'destination')
            self.queue.put(b'constraint')
            self.queue.put((10).to_bytes(1, 'big')) # amount
            self.queue.put(b'contractid')

        amount = 10
        valid_contract = {
            'verify_txn_proof': lambda txn_proof: True,
            'verify_transfer': lambda txn_proof, source, destination: True,
            'verify_txn_constraint': lambda txn_proof, constraint: True,
            'calc_txn_aggregates': lambda proofs, scope: {b'destination': amount}
        }

        setup_transfer()
        self.tape.contracts[b'contractid'] = valid_contract
        functions.OP_CHECK_TRANSFER(self.tape, self.queue, self.cache)
        assert self.queue.get(False) == b'\x01'
        assert self.queue.empty()

        amount = 9
        setup_transfer()
        self.tape.contracts[b'contractid'] = valid_contract
        functions.OP_CHECK_TRANSFER(self.tape, self.queue, self.cache)
        assert self.queue.get(False) == b'\x00'
        assert self.queue.empty()

        amount = 11
        setup_transfer()
        self.tape.contracts[b'contractid'] = valid_contract
        functions.OP_CHECK_TRANSFER(self.tape, self.queue, self.cache)
        assert self.queue.get(False) == b'\x01'
        assert self.queue.empty()

    def test_opcodes_is_dict_mapping_ints_to_tuple_str_function(self):
        assert isinstance(functions.opcodes, dict)
        for key, value in functions.opcodes.items():
            assert type(key) is int
            assert type(value) is tuple
            assert len(value) == 2
            assert type(value[0]) is str
            assert callable(value[1])

    def test_opcodes_inverse_is_dict_mapping_strs_to_tuple_int_function(self):
        assert isinstance(functions.opcodes_inverse, dict)
        for key, value in functions.opcodes_inverse.items():
            assert type(key) is str
            assert type(value) is tuple
            assert len(value) == 2
            assert type(value[0]) is int
            assert callable(value[1])

    def test_nopcodes_is_dict_mapping_ints_to_tuple_str_function(self):
        assert isinstance(functions.nopcodes, dict)
        for key, value in functions.nopcodes.items():
            assert type(key) is int
            assert type(value) is tuple
            assert len(value) == 2
            assert type(value[0]) is str
            assert callable(value[1])

    def test_nopcodes_inverse_is_dict_mapping_strs_to_tuple_int_function(self):
        assert isinstance(functions.nopcodes_inverse, dict)
        for key, value in functions.nopcodes_inverse.items():
            assert type(key) is str
            assert type(value) is tuple
            assert len(value) == 2
            assert type(value[0]) is int
            assert callable(value[1])

    def test_compile_script_errors_on_nonstr_input(self):
        with self.assertRaises(ValueError) as e:
            functions.compile_script(b'not a str')
        assert str(e.exception) == 'input script must be str'

    def test_compile_script_errors_on_invalid_opcode(self):
        with self.assertRaises(ValueError) as e:
            functions.compile_script('OP_WTF d1')
        assert str(e.exception) == 'unrecognized opcode'

    def test_compile_script_errors_on_invalid_syntax(self):
        with self.assertRaises(errors.SyntaxError) as e:
            functions.compile_script('OP_DEF notnumeric OP_DEF 1 OP_PUSH x01 END_DEF END_DEF')
        assert str(e.exception) == 'def number must be numeric'

        with self.assertRaises(ValueError) as e:
            functions.compile_script('OP_DEF 2000 OP_DEF 1 OP_PUSH x01 END_DEF END_DEF')
        assert str(e.exception) == 'def number must be in 0-255'

        with self.assertRaises(errors.SyntaxError) as e:
            functions.compile_script('OP_DEF 1 { OP_PUSH x01')
        assert str(e.exception) == 'missing matching }'

        with self.assertRaises(errors.SyntaxError) as e:
            functions.compile_script('OP_DEF 1 OP_PUSH x01')
        assert str(e.exception) == 'missing END_DEF'

        with self.assertRaises(errors.SyntaxError) as e:
            functions.compile_script('OP_DEF 0 OP_DEF 1 OP_PUSH x01 END_DEF END_DEF')
        assert str(e.exception) == 'cannot use OP_DEF within OP_DEF body'

    def test_compile_script_ignores_comments(self):
        ...

    # skip OP_CALL test until run_tape tested
    # skip OP_IF test until OP_CALL tested
    # skip OP_IF_ELSE test until OP_CALL tested
    # skip OP_EVAL test until OP_CALL tested


if __name__ == '__main__':
    unittest.main()
