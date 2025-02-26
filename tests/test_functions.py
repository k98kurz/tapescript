from __future__ import annotations
from context import classes, errors, functions, interfaces
from hashlib import sha256
from nacl.signing import SigningKey
from random import randint
from time import time
from typing import Protocol, runtime_checkable
import nacl.bindings
import unittest

try:
    from hashlib import shake_256
except ImportError:
    from warnings import warn

    class Shake256Replacement:
        def __init__(self, preimage: bytes):
            self.preimage = preimage
        def copy(self) -> Shake256Replacement:
            return Shake256Replacement(self.preimage)
        def digest(self, size: int):
            val = sha256(self.preimage).digest()
            while len(val) < size:
                val += sha256(val).digest()
            return val[:size]
        def hexdigest(self, size: int) -> str:
            return self.digest(size).hex()
        def update(self, data: bytes) -> Shake256Replacement:
            self.preimage += data
            return self
        @property
        def block_size(self) -> int:
            return 136
        @property
        def digest_size(self) -> int:
            return 0
        @property
        def name(self) -> str:
            return 'shake_256'

    def shake_256(preimage: bytes):
        warn('shake_256 is not available on this system; this replacement will not give correct outputs')
        return Shake256Replacement(preimage)

try:
    from secrets import token_bytes
except ImportError:
    from os import urandom
    def token_bytes(count: int) -> bytes:
        return urandom(count)


class ValidContract:
    amount: int
    def __init__(self, amount: int) -> None:
        self.amount = amount
    def verify_txn_proof(self, proof: bytes) -> bool:
        return True
    def verify_transfer(self, proof: bytes, source: bytes, destination: bytes) -> bool:
        return True
    def verify_txn_constraint(self, proof: bytes, constraint: bytes) -> bool:
        return True
    def calc_txn_aggregates(self, proofs: list[bytes], scope: bytes = None) -> dict:
        return {scope: self.amount}

class InvalidContract:
    amount: int
    def __init__(self, amount: int) -> None:
        self.amount = amount

@runtime_checkable
class CanDoThing(Protocol):
    def does_thing(self):
        ...

class DoesThing:
    def does_thing(self):
        ...

def merkleval_root(commitment1: bytes, commitment2: bytes) -> bytes:
    return functions.xor(
        sha256(commitment1).digest(),
        sha256(commitment2).digest(),
    )

class TestFunctions(unittest.TestCase):
    tape: classes.Tape
    stack: classes.Stack
    cache: dict
    original_opcodes: dict
    original_nopcodes: dict
    original_opcodes_inverse: dict
    original_nopcodes_inverse: dict
    original_contract_interfaces: dict

    def setUp(self) -> None:
        self.tape = classes.Tape(b'')
        self.stack = classes.Stack()
        self.cache = {}
        self.original_opcodes = {**functions.opcodes}
        self.original_opcodes_inverse = {**functions.opcodes_inverse}
        self.original_nopcodes = {**functions.nopcodes}
        self.original_nopcodes_inverse = {**functions.nopcodes_inverse}
        self.original_contract_interfaces = {**functions._contract_interfaces}
        return super().setUp()

    def tearDown(self) -> None:
        functions.opcodes = self.original_opcodes
        functions.opcodes_inverse = self.original_opcodes_inverse
        functions.nopcodes = self.original_nopcodes
        functions.nopcodes_inverse = self.original_nopcodes_inverse
        functions._contracts = {}
        functions._contract_interfaces = self.original_contract_interfaces

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
    def test_OP_FALSE_puts_null_byte_onto_stack(self):
        assert self.stack.empty()
        assert not len(self.cache.keys())
        functions.OP_FALSE(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert not len(self.cache.keys())
        assert self.stack.get() == b'\x00'

    def test_OP_TRUE_puts_nonnull_byte_onto_stack(self):
        assert self.stack.empty()
        assert not len(self.cache.keys())
        functions.OP_TRUE(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert not len(self.cache.keys())
        assert functions.bytes_to_bool(self.stack.get())

    def test_OP_PUSH0_puts_next_byte_from_tape_onto_stack(self):
        self.tape = classes.Tape(b'123')
        assert self.stack.empty()
        assert not len(self.cache.keys())
        functions.OP_PUSH0(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert not len(self.cache.keys())
        assert self.stack.get() == b'1'

    def test_OP_PUSH1_reads_next_byte_as_uint_and_puts_that_many_from_tape_onto_stack(self):
        self.tape = classes.Tape(functions.int_to_bytes(11) + b'hello world')
        assert self.stack.empty()
        assert not len(self.cache.keys())
        functions.OP_PUSH1(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert not len(self.cache.keys())
        assert self.stack.get() == b'hello world'

    def test_OP_PUSH2_reads_next_2_bytes_as_uint_and_puts_that_many_from_tape_onto_stack(self):
        self.tape = classes.Tape(b'\x00' + functions.int_to_bytes(11) + b'hello world')
        assert self.stack.empty()
        assert not len(self.cache.keys())
        functions.OP_PUSH2(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert not len(self.cache.keys())
        assert self.stack.get() == b'hello world'

    def test_OP_POP0_moves_one_item_from_stack_into_cache(self):
        self.stack.put(b'1234')
        assert not self.stack.empty()
        assert not len(self.cache.keys())
        functions.OP_POP0(self.tape, self.stack, self.cache)
        assert self.stack.empty()
        assert len(self.cache.keys())
        assert b'P' in self.cache
        assert self.cache[b'P'] == [b'1234']

    def test_OP_POP1_reads_uint_from_tape_then_puts_that_many_items_from_stack_to_cache(self):
        assert self.stack.empty()
        self.stack.put(b'12')
        self.stack.put(b'34')
        self.tape = classes.Tape(functions.int_to_bytes(2))
        assert not self.stack.empty()
        assert b'P' not in self.cache
        functions.OP_POP1(self.tape, self.stack, self.cache)
        assert self.stack.empty()
        assert b'P' in self.cache
        assert self.cache[b'P'] == [b'34', b'12']

    def test_OP_POP1_interprets_negative_ints_as_positive(self):
        assert self.stack.empty()
        for i in range(136):
            self.stack.put(functions.int_to_bytes(i))
        self.tape = classes.Tape(functions.int_to_bytes(-120))
        functions.OP_POP1(self.tape, self.stack, self.cache)
        assert self.stack.empty()
        assert b'P' in self.cache
        assert len(self.cache[b'P']) == 136

    def test_OP_SIZE_pulls_item_from_stack_and_puts_its_length_onto_stack(self):
        assert self.stack.empty()
        self.stack.put(b'123')
        functions.OP_SIZE(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        item = self.stack.get()
        assert item == functions.int_to_bytes(3)

    def test_OP_WRITE_CACHE_reads_cache_key_and_int_from_tape_and_moves_from_stack_to_cache(self):
        self.tape = classes.Tape(
            functions.int_to_bytes(4) +
            b'test' +
            functions.int_to_bytes(2)
        )
        assert self.stack.empty()
        assert not len(self.cache.keys())
        self.stack.put(b'1')
        self.stack.put(b'2')
        functions.OP_WRITE_CACHE(self.tape, self.stack, self.cache)
        assert self.stack.empty()
        assert b'test' in self.cache
        assert self.cache[b'test'] == [b'2', b'1']

    def test_OP_READ_CACHE_reads_cache_key_from_tape_and_moves_values_from_cache_to_stack(self):
        self.cache[b'test'] = [b'2', b'1']
        self.tape = classes.Tape(functions.int_to_bytes(4) + b'test')
        assert self.stack.empty()
        functions.OP_READ_CACHE(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert self.cache[b'test'] == [b'2', b'1']
        items = [self.stack.get(), self.stack.get()]
        assert items == [b'1', b'2']

    def test_OP_READ_CACHE_raises_ScriptExecutionError_for_missing_cache_key(self):
        self.tape = classes.Tape(functions.int_to_bytes(4) + b'test')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_READ_CACHE(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_READ_CACHE key not in cache'

    def test_OP_READ_CACHE_SIZE_reads_cache_key_from_tape_and_puts_size_of_cache_on_stack(self):
        self.cache[b'test'] = [b'2', b'1']
        self.tape = classes.Tape(functions.int_to_bytes(4) + b'test')
        assert self.stack.empty()
        functions.OP_READ_CACHE_SIZE(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert self.cache[b'test'] == [b'2', b'1']
        item = self.stack.get()
        assert self.stack.empty()
        assert item == functions.int_to_bytes(2)

    def test_OP_READ_CACHE_STACK_reads_cache_key_from_stack_and_moves_items_from_cache_to_stack(self):
        self.cache[b'test'] = [b'2', b'1']
        assert self.stack.empty()
        self.stack.put(b'test')
        functions.OP_READ_CACHE_STACK(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert self.cache[b'test'] == [b'2', b'1']
        items = [self.stack.get(), self.stack.get()]
        assert self.stack.empty()
        assert items == [b'1', b'2']

    def test_OP_READ_CACHE_STACK_raises_ScriptExecutionError_for_missing_cache_key(self):
        self.stack.put(b'test')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_READ_CACHE_STACK(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_READ_CACHE_STACK key not in cache'

    def test_OP_READ_CACHE_STACK_SIZE_reads_cache_key_from_stack_and_puts_size_of_cache_on_stack(self):
        self.cache[b'test'] = [b'2', b'1']
        assert self.stack.empty()
        self.stack.put(b'test')
        functions.OP_READ_CACHE_STACK_SIZE(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert self.cache[b'test'] == [b'2', b'1']
        item = self.stack.get()
        assert self.stack.empty()
        assert item == functions.int_to_bytes(2)

    def test_OP_ADD_INTS_reads_uint_from_tape_pulls_that_many_ints_from_stack_and_puts_sum_on_stack(self):
        self.tape = classes.Tape(functions.int_to_bytes(3))
        assert self.stack.empty()
        self.stack.put(functions.int_to_bytes(2))
        self.stack.put(functions.int_to_bytes(5))
        self.stack.put(functions.int_to_bytes(-3))
        functions.OP_ADD_INTS(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        item = self.stack.get()
        assert self.stack.empty()
        assert not self.cache
        assert functions.bytes_to_int(item) == 4

    def test_OP_SUBTRACT_INTS_reads_uint_from_tape_pulls_that_many_ints_from_stack_and_puts_difference_on_stack(self):
        self.tape = classes.Tape(functions.int_to_bytes(3))
        assert self.stack.empty()
        self.stack.put(functions.int_to_bytes(-3))
        self.stack.put(functions.int_to_bytes(2))
        self.stack.put(functions.int_to_bytes(5))
        functions.OP_SUBTRACT_INTS(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        item = self.stack.get()
        assert self.stack.empty()
        assert not self.cache
        assert functions.bytes_to_int(item) == 6

    def test_OP_MULT_INTS_reads_uint_from_tape_pulls_that_many_ints_from_stack_and_puts_product_on_stack(self):
        self.tape = classes.Tape(functions.int_to_bytes(4))
        assert self.stack.empty()
        self.stack.put(functions.int_to_bytes(3))
        self.stack.put(functions.int_to_bytes(2))
        self.stack.put(functions.int_to_bytes(-2))
        self.stack.put(functions.int_to_bytes(5))
        functions.OP_MULT_INTS(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        item = self.stack.get()
        assert self.stack.empty()
        assert not self.cache
        assert functions.bytes_to_int(item) == -60

    def test_OP_DIV_INT_pulls_int_from_stack_reads_signed_int_from_tape_and_puts_quotient_on_stack(self):
        self.tape = classes.Tape(functions.int_to_bytes(1) + functions.int_to_bytes(-2))
        assert self.stack.empty()
        self.stack.put(functions.int_to_bytes(-60))
        functions.OP_DIV_INT(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        item = self.stack.get()
        assert self.stack.empty()
        assert not self.cache
        assert functions.bytes_to_int(item) == 30

    def test_OP_DIV_INTS_pulls_two_ints_from_stack_and_puts_quotient_on_stack(self):
        assert self.stack.empty()
        divisor = 12
        dividend = -132
        self.stack.put(functions.int_to_bytes(divisor))
        self.stack.put(functions.int_to_bytes(dividend))
        functions.OP_DIV_INTS(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        item = self.stack.get()
        assert self.stack.empty()
        assert not self.cache
        assert functions.bytes_to_int(item) == dividend / divisor

    def test_OP_MOD_INT_reads_uint_from_tape_pulls_int_from_stack_and_puts_modulus_on_stack(self):
        assert self.stack.empty()
        self.tape = classes.Tape(functions.uint_to_bytes(1) + functions.int_to_bytes(17))
        self.stack.put(functions.int_to_bytes(1258))
        functions.OP_MOD_INT(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        item = self.stack.get()
        assert self.stack.empty()
        assert not self.cache
        assert functions.bytes_to_int(item) == (1258%17)

    def test_OP_MOD_INTS_pulls_two_ints_from_stack_and_puts_modulus_on_stack(self):
        assert self.stack.empty()
        dividend = 1258
        divisor = 17
        self.stack.put(functions.int_to_bytes(divisor))
        self.stack.put(functions.int_to_bytes(dividend))
        functions.OP_MOD_INTS(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        item = self.stack.get()
        assert self.stack.empty()
        assert not self.cache
        assert functions.bytes_to_int(item) == (dividend%divisor)

    def test_OP_ADD_FLOATS_reads_uint_from_tape_pulls_that_many_floats_from_stack_put_sum_on_stack(self):
        assert self.stack.empty()
        self.tape = classes.Tape(functions.int_to_bytes(3))
        floats = [
            functions.float_to_bytes(0.01),
            functions.float_to_bytes(0.1),
            functions.float_to_bytes(1.0)
        ]
        self.stack.put(floats[0])
        self.stack.put(floats[1])
        self.stack.put(floats[2])

        expected = functions.bytes_to_float(floats[0])
        expected += functions.bytes_to_float(floats[1])
        expected += functions.bytes_to_float(floats[2])

        functions.OP_ADD_FLOATS(self.tape, self.stack, self.cache)
        assert not self.cache
        assert not self.stack.empty()
        item = self.stack.get()
        item = functions.bytes_to_float(item)
        assert self.stack.empty()
        assert str(item)[:5] == str(expected)[:5]

    def test_OP_ADD_FLOATS_raises_errors_for_invalid_floats(self):
        self.tape = classes.Tape(functions.int_to_bytes(2))
        assert self.stack.empty()
        self.stack.put(functions.float_to_bytes(0.01)+b'000')
        self.stack.put(functions.float_to_bytes(0.1))
        with self.assertRaises(TypeError) as e:
            functions.OP_ADD_FLOATS(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_ADD_FLOATS malformed float'

        self.tape = classes.Tape(functions.int_to_bytes(2))
        self.stack.put(functions.float_to_bytes(float('NaN')))
        self.stack.put(functions.float_to_bytes(0.1))
        with self.assertRaises(ValueError) as e:
            functions.OP_ADD_FLOATS(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_ADD_FLOATS nan encountered'

    def test_OP_SUBTRACT_FLOATS_reads_uint_from_tape_pulls_that_many_floats_from_stack_put_difference_on_stack(self):
        assert self.stack.empty()
        minuend = functions.float_to_bytes(1.0)
        subtrahend1 = functions.float_to_bytes(0.01)
        subtrahend2 = functions.float_to_bytes(0.1)
        self.tape = classes.Tape(functions.int_to_bytes(3))
        self.stack.put(subtrahend1)
        self.stack.put(subtrahend2)
        self.stack.put(minuend)

        expected = functions.bytes_to_float(minuend)
        expected -= functions.bytes_to_float(subtrahend1)
        expected -= functions.bytes_to_float(subtrahend2)

        functions.OP_SUBTRACT_FLOATS(self.tape, self.stack, self.cache)
        assert not self.cache
        assert not self.stack.empty()
        item = self.stack.get()
        item = functions.bytes_to_float(item)
        assert self.stack.empty()
        assert str(item)[:5] == str(expected)[:5]

    def test_OP_SUBTRACT_FLOATS_raises_errors_for_invalid_floats(self):
        self.tape = classes.Tape(functions.int_to_bytes(2))
        self.stack.put(functions.float_to_bytes(0.01)+b'000')
        self.stack.put(functions.float_to_bytes(0.1))
        with self.assertRaises(TypeError) as e:
            functions.OP_SUBTRACT_FLOATS(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_SUBTRACT_FLOATS malformed float'

        self.tape = classes.Tape(functions.int_to_bytes(2))
        self.stack.put(functions.float_to_bytes(float('NaN')))
        self.stack.put(functions.float_to_bytes(0.1))
        with self.assertRaises(ValueError) as e:
            functions.OP_SUBTRACT_FLOATS(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_SUBTRACT_FLOATS nan encountered'

    def test_OP_DIV_FLOAT_reads_float_from_tape_pulls_float_from_stack_put_quotient_on_stack(self):
        assert self.stack.empty()
        dividend = functions.float_to_bytes(0.1)
        divisor = functions.float_to_bytes(0.01)
        self.tape = classes.Tape(divisor)
        self.stack.put(dividend)

        expected = functions.bytes_to_float(dividend)
        expected /= functions.bytes_to_float(divisor)

        functions.OP_DIV_FLOAT(self.tape, self.stack, self.cache)
        assert not self.cache
        assert not self.stack.empty()
        item = self.stack.get()
        item = functions.bytes_to_float(item)
        assert self.stack.empty()
        error_ratio = abs(item-expected)/expected
        assert error_ratio < 0.000001, f'error ratio: {error_ratio}'

    def test_OP_DIV_FLOAT_raises_errors_for_invalid_float(self):
        self.tape = classes.Tape(functions.float_to_bytes(0.01))
        self.stack.put(functions.float_to_bytes(0.1) + b'xx')
        with self.assertRaises(TypeError) as e:
            functions.OP_DIV_FLOAT(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_DIV_FLOAT malformed float'

        self.tape = classes.Tape(functions.float_to_bytes(float('NaN')))
        self.stack.put(functions.float_to_bytes(0.1))
        with self.assertRaises(ValueError) as e:
            functions.OP_DIV_FLOAT(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_DIV_FLOAT nan encountered'

    def test_OP_DIV_FLOATS_pulls_two_floats_from_stack_put_quotient_on_stack(self):
        assert self.stack.empty()
        dividend = functions.float_to_bytes(0.1)
        divisor = functions.float_to_bytes(0.01)
        self.stack.put(divisor)
        self.stack.put(dividend)

        expected = functions.bytes_to_float(dividend)
        expected /= functions.bytes_to_float(divisor)

        functions.OP_DIV_FLOATS(self.tape, self.stack, self.cache)
        assert not self.cache
        assert not self.stack.empty()
        item = self.stack.get()
        item = functions.bytes_to_float(item)
        assert self.stack.empty()
        # assert item == expected
        error_ratio = abs(item-expected)/expected
        assert error_ratio < 0.000001, f'error ratio: {error_ratio}'

    def test_OP_DIV_FLOATS_raises_errors_for_invalid_floats(self):
        self.stack.put(functions.float_to_bytes(0.01)+b'1212')
        with self.assertRaises(TypeError) as e:
            functions.OP_DIV_FLOATS(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_DIV_FLOATS malformed float'

        self.stack.put(functions.float_to_bytes(0.1))
        self.stack.put(functions.float_to_bytes(0.01)+b'1212')
        with self.assertRaises(TypeError) as e:
            functions.OP_DIV_FLOATS(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_DIV_FLOATS malformed float'

        self.stack.put(functions.float_to_bytes(float('NaN')))
        self.stack.put(functions.float_to_bytes(0.1))
        with self.assertRaises(ValueError) as e:
            functions.OP_DIV_FLOATS(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_DIV_FLOATS nan encountered'

    def test_OP_MOD_FLOAT_reads_float_from_tape_pulls_float_from_stack_put_modulus_on_stack(self):
        assert self.stack.empty()
        divisor = functions.float_to_bytes(13.0)
        dividend = functions.float_to_bytes(131.1)
        self.tape = classes.Tape(divisor)
        self.stack.put(dividend)

        expected = functions.bytes_to_float(dividend)
        expected = expected % functions.bytes_to_float(divisor)

        functions.OP_MOD_FLOAT(self.tape, self.stack, self.cache)
        assert not self.cache
        assert not self.stack.empty()
        item = self.stack.get()
        item = functions.bytes_to_float(item)
        assert self.stack.empty()
        assert item == expected
        # assert abs(item-expected)/expected < 0.000001

    def test_OP_MOD_FLOAT_raises_errors_for_invalid_floats(self):
        self.tape = classes.Tape(functions.float_to_bytes(1.1))
        self.stack.put(functions.float_to_bytes(0.1) + b'12')
        with self.assertRaises(TypeError) as e:
            functions.OP_MOD_FLOAT(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_MOD_FLOAT malformed float'

        self.tape = classes.Tape(functions.float_to_bytes(float('NaN')))
        self.stack.put(functions.float_to_bytes(0.1))
        with self.assertRaises(ValueError) as e:
            functions.OP_MOD_FLOAT(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_MOD_FLOAT nan encountered'

    def test_OP_MOD_FLOATS_pulls_two_floats_from_stack_put_modulus_on_stack(self):
        assert self.stack.empty()
        divisor = functions.float_to_bytes(13.0)
        dividend = functions.float_to_bytes(131.1)
        self.stack.put(divisor)
        self.stack.put(dividend)

        expected = functions.bytes_to_float(divisor)
        expected = expected % functions.bytes_to_float(dividend)

        functions.OP_MOD_FLOATS(self.tape, self.stack, self.cache)
        assert not self.cache
        assert not self.stack.empty()
        item = self.stack.get()
        item = functions.bytes_to_float(item)
        assert self.stack.empty()
        assert item == expected
        # assert abs(item-expected)/expected < 0.000001

    def test_OP_MOD_FLOATS_raises_errors_for_invalid_floats(self):
        self.stack.put(functions.float_to_bytes(0.1) + b'x')
        with self.assertRaises(TypeError) as e:
            functions.OP_MOD_FLOATS(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_MOD_FLOATS malformed float'

        self.stack.put(functions.float_to_bytes(0.1))
        self.stack.put(functions.float_to_bytes(0.1) + b'x')
        with self.assertRaises(TypeError) as e:
            functions.OP_MOD_FLOATS(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_MOD_FLOATS malformed float'

        self.stack.put(functions.float_to_bytes(0.1))
        self.stack.put(functions.float_to_bytes(float('NaN')))
        with self.assertRaises(ValueError) as e:
            functions.OP_MOD_FLOATS(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_MOD_FLOATS nan encountered'

    def test_OP_ADD_POINTS_reads_uint_from_tape_pulls_that_many_points_from_stack_puts_sum_on_stack(self):
        assert self.stack.empty()
        self.tape = classes.Tape(functions.int_to_bytes(2))
        point1 = bytes(SigningKey(token_bytes(32)).verify_key)
        point2 = bytes(SigningKey(token_bytes(32)).verify_key)
        expected = nacl.bindings.crypto_core_ed25519_add(point1, point2)
        self.stack.put(point1)
        self.stack.put(point2)
        functions.OP_ADD_POINTS(self.tape, self.stack, self.cache)
        assert not self.cache
        assert not self.stack.empty()
        item = self.stack.get()
        assert item == bytes(expected)

    def test_OP_ADD_POINTS_raises_errors_for_invalid_points(self):
        self.tape = classes.Tape(b'\x02')
        self.stack.put(b''.join([b'\xff' for _ in range(32)]))
        self.stack.put(b''.join([b'\xff' for _ in range(32)]))
        with self.assertRaises(ValueError) as e:
            functions.OP_ADD_POINTS(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_ADD_POINTS invalid point encountered'

    def test_OP_COPY_reads_uint_from_tape_and_copies_top_stack_value_that_many_times(self):
        assert self.stack.empty()
        n_copies = randint(1, 255)
        self.stack.put(b'1')
        self.tape = classes.Tape(n_copies.to_bytes(1, 'big'))
        functions.OP_COPY(self.tape, self.stack, self.cache)
        expected = n_copies + 1
        observed = 0
        while not self.stack.empty():
            observed += 1
            assert self.stack.get() == b'1'
        assert observed == expected

    def test_OP_DUP_duplicates_top_stack_item(self):
        assert self.stack.empty()
        self.stack.put(b'1')
        functions.OP_DUP(self.tape, self.stack, self.cache)
        assert self.stack.get() == b'1'
        assert self.stack.get() == b'1'
        assert self.stack.empty()

    def test_OP_SHA256_pulls_value_from_stack_and_puts_its_sha256_on_stack(self):
        assert self.stack.empty()
        preimage = b'123232'
        self.stack.put(preimage)
        functions.OP_SHA256(self.tape, self.stack, self.cache)
        expected = sha256(preimage).digest()
        assert self.stack.get() == expected
        assert self.stack.empty()

    def test_OP_SHAKE256_reads_uint_from_tape_pulls_value_from_stack_and_puts_its_shake256_on_stack(self):
        assert self.stack.empty()
        self.tape = classes.Tape((20).to_bytes(1, 'big'))
        preimage = b'123232'
        self.stack.put(preimage)
        functions.OP_SHAKE256(self.tape, self.stack, self.cache)
        expected = shake_256(preimage).digest(20)
        assert self.stack.get() == expected
        assert self.stack.empty()

    def test_OP_VERIFY_raises_error_only_if_top_stack_item_is_not_true(self):
        self.stack.put(b'\x00')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_VERIFY(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_VERIFY check failed'

        self.stack.put(b'\x01')
        functions.OP_VERIFY(self.tape, self.stack, self.cache)
        self.stack.put(b'12323')
        functions.OP_VERIFY(self.tape, self.stack, self.cache)

    def test_OP_EQUAL_compares_two_values_from_stack_and_puts_bool_on_stack(self):
        self.stack.put(b'123')
        self.stack.put(b'123')
        functions.OP_EQUAL(self.tape, self.stack, self.cache)
        assert self.stack.get() == b'\xff'

        self.stack.put(b'321')
        self.stack.put(b'123')
        functions.OP_EQUAL(self.tape, self.stack, self.cache)
        assert self.stack.get() == b'\x00'

    def test_OP_EQUAL_VERIFY_runs_OP_EQUAL_then_OP_VERIFY(self):
        assert self.stack.empty()
        self.stack.put(b'123')
        self.stack.put(b'123')
        functions.OP_EQUAL_VERIFY(self.tape, self.stack, self.cache)
        assert self.stack.empty()

        self.stack.put(b'321')
        self.stack.put(b'123')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_EQUAL_VERIFY(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_VERIFY check failed'
        assert self.stack.empty()

    def test_OP_CHECK_SIG_pulls_VerifyKey_and_signature_from_stack_and_checks_against_cache(self):
        body = b'hello world'
        skey = SigningKey(token_bytes(32))
        vkey = skey.verify_key
        smsg = skey.sign(body)
        sig = smsg[:64]
        self.tape = classes.Tape(b'\x00')
        assert self.stack.empty()
        self.stack.put(sig)
        self.stack.put(bytes(vkey))
        self.cache['sigfield1'] = body
        functions.OP_CHECK_SIG(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert self.stack.get() == b'\xff'
        assert self.stack.empty()

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
        assert self.stack.empty()
        self.stack.put(sig)
        self.stack.put(bytes(vkey))
        self.cache['sigfield1'] = field1
        self.cache['sigfield2'] = b'should be ignored'
        self.cache['sigfield3'] = field3
        self.cache['sigfield4'] = b'should be ignored'
        self.cache['sigfield5'] = b'should be ignored'
        self.cache['sigfield6'] = b'should be ignored'
        self.cache['sigfield7'] = b'should be ignored'
        self.cache['sigfield8'] = field8
        functions.OP_CHECK_SIG(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert self.stack.get() == b'\xff'
        assert self.stack.empty()

    def test_OP_CHECK_SIG_errors_on_invalid_vkey_or_sig(self):
        self.tape = classes.Tape(b'\x00')
        self.stack.put(b''.join(b'\xff' for _ in range(64)))
        self.stack.put(b'not a valid vkey')
        with self.assertRaises(ValueError) as e:
            functions.OP_CHECK_SIG(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_CHECK_SIG invalid vkey encountered'

        self.tape = classes.Tape(b'\x00')
        self.stack.put(b'not a valid sig')
        self.stack.put(b''.join(b'\xff' for _ in range(32)))
        with self.assertRaises(ValueError) as e:
            functions.OP_CHECK_SIG(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_CHECK_SIG invalid sig encountered'

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
        assert self.stack.empty()
        self.stack.put(sig)
        self.stack.put(bytes(vkey))

        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_SIG(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'disallowed sigflag'
        assert self.stack.empty()

    def test_OP_CHECK_SIG_VERIFY_runs_OP_CHECK_SIG_then_OP_VERIFY(self):
        body = b'hello world'
        skey = SigningKey(token_bytes(32))
        vkey = skey.verify_key
        smsg = skey.sign(body)
        sig = smsg[:64]
        self.tape = classes.Tape(b'\x00')
        assert self.stack.empty()
        self.stack.put(sig)
        self.stack.put(bytes(vkey))
        self.cache['sigfield1'] = body
        functions.OP_CHECK_SIG_VERIFY(self.tape, self.stack, self.cache)
        assert self.stack.empty()

        sig = smsg[:64]
        self.tape = classes.Tape(b'\x00')
        assert self.stack.empty()
        self.stack.put(sig)
        self.stack.put(bytes(vkey))
        self.cache['sigfield1'] = b'not body'
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_SIG_VERIFY(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_VERIFY check failed'
        assert self.stack.empty()

    def test_OP_CHECK_TIMESTAMP_raises_error_for_invalid_constraint(self):
        assert self.stack.empty()
        self.stack.put(b'')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TIMESTAMP(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_CHECK_TIMESTAMP malformed constraint encountered'

    def test_OP_CHECKTIMESTAMP_raises_errors_for_invalid_cache_timestamp(self):
        assert self.stack.empty()
        self.stack.put(b'xxxx')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TIMESTAMP(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_CHECK_TIMESTAMP cache missing timestamp'

        assert self.stack.empty()
        self.stack.put(b'xxxx')
        self.cache['timestamp'] = 'not an int'
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TIMESTAMP(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_CHECK_TIMESTAMP malformed cache timestamp'

    def test_OP_CHECKTIMESTAMP_raises_errors_for_invalid_ts_threshold_tape_flag(self):
        assert self.stack.empty()
        self.stack.put(b'xxxx')
        self.cache['timestamp'] = 3
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TIMESTAMP(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_CHECK_TIMESTAMP missing ts_threshold flag'

        assert self.stack.empty()
        self.stack.put(b'xxxx')
        self.cache['timestamp'] = 3
        self.tape.flags['ts_threshold'] = 'not an int'
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TIMESTAMP(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_CHECK_TIMESTAMP malformed ts_threshold flag'

    def test_OP_CHECK_TIMESTAMP_compares_top_stack_int_to_cache_timestamp(self):
        assert self.stack.empty()
        self.tape.flags['ts_threshold'] = 10
        self.cache['timestamp'] = int(time())
        self.stack.put(int(time()).to_bytes(4, 'big'))
        functions.OP_CHECK_TIMESTAMP(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert self.stack.get() == b'\xff'

        assert self.stack.empty()
        self.cache['timestamp'] = int(time())-1
        self.stack.put(int(time()).to_bytes(4, 'big'))
        functions.OP_CHECK_TIMESTAMP(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        item = self.stack.get()
        assert item == b'\x00'

        assert self.stack.empty()
        self.cache['timestamp'] = int(time())+12
        self.stack.put(int(time()).to_bytes(4, 'big'))
        functions.OP_CHECK_TIMESTAMP(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        item = self.stack.get()
        assert item == b'\x00'

        assert self.stack.empty()
        self.tape.flags['ts_threshold'] = 100
        self.cache['timestamp'] = int(time())+12
        self.stack.put(int(time()).to_bytes(4, 'big'))
        functions.OP_CHECK_TIMESTAMP(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        item = self.stack.get()
        assert item == b'\xff'

    def test_OP_CHECK_TIMESTAMP_VERIFY_runs_OP_CHECK_TIMESTAMP_then_OP_VERIFY(self):
        assert self.stack.empty()
        self.tape = classes.Tape(b'', flags={'ts_threshold': 10})
        self.cache['timestamp'] = int(time())
        self.stack.put(int(time()).to_bytes(4, 'big'))
        functions.OP_CHECK_TIMESTAMP_VERIFY(self.tape, self.stack, self.cache)
        assert self.stack.empty()

        assert self.stack.empty()
        self.cache['timestamp'] = int(time())-1
        self.stack.put(int(time()).to_bytes(4, 'big'))
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TIMESTAMP_VERIFY(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_VERIFY check failed'
        assert self.stack.empty()

        assert self.stack.empty()
        self.cache['timestamp'] = int(time())+12
        self.stack.put(int(time()).to_bytes(4, 'big'))
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TIMESTAMP_VERIFY(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_VERIFY check failed'
        assert self.stack.empty()

    def test_OP_CHECK_EPOCH_raises_error_for_invalid_constraint(self):
        assert self.stack.empty()
        self.stack.put(b'')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_EPOCH(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_CHECK_EPOCH malformed constraint encountered'

    def test_OP_CHECK_EPOCH_raises_errors_for_invalid_epoch_threshold_tape_flag(self):
        assert self.stack.empty()
        self.stack.put(b'x')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_EPOCH(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_CHECK_EPOCH missing epoch_threshold flag'

        assert self.stack.empty()
        self.stack.put(b'x')
        self.tape.flags['epoch_threshold'] = 'not an int'
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_EPOCH(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_CHECK_EPOCH malformed epoch_threshold flag'

        assert self.stack.empty()
        self.stack.put(b'x')
        self.tape.flags['epoch_threshold'] = -1
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_EPOCH(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_CHECK_EPOCH malformed epoch_threshold flag'

    def test_OP_CHCECK_EPOCH_compares_current_time_to_constraint(self):
        assert self.stack.empty()
        self.tape.flags['epoch_threshold'] = 0
        self.stack.put(int(time()-10).to_bytes(4, 'big'))
        functions.OP_CHECK_EPOCH(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert self.stack.get() == b'\xff'

        assert self.stack.empty()
        self.stack.put(int(time()+10).to_bytes(4, 'big'))
        functions.OP_CHECK_EPOCH(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        item = self.stack.get()
        assert item == b'\x00'

        assert self.stack.empty()
        self.tape.flags['epoch_threshold'] = 100
        self.stack.put(int(time()+10).to_bytes(4, 'big'))
        functions.OP_CHECK_EPOCH(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        item = self.stack.get()
        assert item == b'\xff'

    def test_OP_CHECK_EPOCH_VERIFY_runs_OP_CHECK_EPOCH_then_OP_VERIFY(self):
        assert self.stack.empty()
        self.tape.flags['epoch_threshold'] = 0
        self.stack.put(int(time()-10).to_bytes(4, 'big'))
        functions.OP_CHECK_EPOCH_VERIFY(self.tape, self.stack, self.cache)
        assert self.stack.empty()

        assert self.stack.empty()
        self.stack.put(int(time()+10).to_bytes(4, 'big'))
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_EPOCH_VERIFY(self.tape, self.stack, self.cache)
        assert self.stack.empty()

        assert self.stack.empty()
        self.tape.flags['epoch_threshold'] = 100
        self.stack.put(int(time()+10).to_bytes(4, 'big'))
        functions.OP_CHECK_EPOCH_VERIFY(self.tape, self.stack, self.cache)
        assert self.stack.empty()

    def test_OP_DEF_creates_subtape_definition(self):
        assert self.stack.empty()
        self.tape = classes.Tape(b'\x00\x00\x0bhello world')
        assert not self.tape.definitions
        functions.OP_DEF(self.tape, self.stack, self.cache)
        assert b'\x00' in self.tape.definitions
        assert isinstance(self.tape.definitions[b'\x00'], classes.Tape)
        assert self.tape.definitions[b'\x00'].data == b'hello world'
        assert self.stack.empty()

    def test_OP_NOT_inverts_bool_value_of_top_stack_value(self):
        assert self.stack.empty()
        self.stack.put(b'\xFF')
        functions.OP_NOT(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert self.stack.get() == b'\x00'

        assert self.stack.empty()
        self.stack.put(b'\x00')
        functions.OP_NOT(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert self.stack.get() == b'\xFF'
        assert self.stack.empty()

    def test_OP_NOT_inverts_bytestring_on_top_of_stack(self):
        self.stack.put(b'\xf0\x0f')
        functions.OP_NOT(self.tape, self.stack, self.cache)
        assert self.stack.get() == b'\x0f\xf0'

        data = token_bytes(4)
        self.stack.put(data)
        functions.OP_DUP(self.tape, self.stack, self.cache)
        functions.OP_NOT(self.tape, self.stack, self.cache)
        functions.OP_XOR(self.tape, self.stack, self.cache)
        assert self.stack.get() == b'\xff\xff\xff\xff'

    def test_OP_RANDOM_puts_random_bytes_on_stack(self):
        assert self.stack.empty()
        n_bytes = randint(1, 250)
        self.stack.put(functions.int_to_bytes(n_bytes))
        self.tape = classes.Tape(b'')
        functions.OP_RANDOM(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        item = self.stack.get()
        assert type(item) is bytes
        assert len(item) == n_bytes
        assert self.stack.empty()

    def test_OP_RETURN_advances_tape_pointer_to_end(self):
        self.tape = classes.Tape(b'asdkjhk123')
        assert self.tape.pointer == 0
        functions.OP_RETURN(self.tape, self.stack, self.cache)
        assert self.tape.pointer == len(self.tape.data)
        with self.assertRaises(errors.ScriptExecutionError) as e:
            self.tape.read(1)

    def test_OP_SET_FLAG_raises_error_for_unrecognized_flag(self):
        self.tape = classes.Tape(b'\x03abc')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_SET_FLAG(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_SET_FLAG unrecognized flag'

    def test_OP_SET_FLAG_sets_tape_flag_to_default_value(self):
        original_flags = functions.flags
        functions.flags = {**original_flags, b'dummy_flag': 1}
        self.tape = classes.Tape(b'\x0adummy_flag')
        assert b'dummy_flag' not in self.tape.flags
        functions.OP_SET_FLAG(self.tape, self.stack, self.cache)
        assert b'dummy_flag' in self.tape.flags
        functions.flags = original_flags

    def test_OP_UNSET_FLAG_unsets_tape_flag(self):
        self.tape = classes.Tape(b'\x0adummy_flag')
        self.tape.flags[b'dummy_flag'] = 1
        assert b'dummy_flag' in self.tape.flags
        functions.OP_UNSET_FLAG(self.tape, self.stack, self.cache)
        assert b'dummy_flag' not in self.tape.flags

    def test_OP_DEPTH_puts_stack_size_onto_stack(self):
        assert self.stack.empty()
        self.stack.put(b'123')
        self.stack.put(b'321')
        self.stack.put(b'asd')
        functions.OP_DEPTH(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        item = self.stack.get()
        assert functions.bytes_to_int(item) == 3
        items = []
        while not self.stack.empty():
            items.append(self.stack.get())
        assert items == [b'asd', b'321', b'123']

    def test_OP_SWAP_swaps_order_of_stack_items_given_indices_from_tape(self):
        assert self.stack.empty()
        self.tape = classes.Tape(b'\x00\x02')
        self.stack.put(b'bottom')
        self.stack.put(b'middle')
        self.stack.put(b'top')
        functions.OP_SWAP(self.tape, self.stack, self.cache)
        items = []
        while not self.stack.empty():
            items.append(self.stack.get())
        assert items == [b'bottom', b'middle', b'top']

        self.stack = classes.Stack()
        self.tape = classes.Tape(b'\x00\x01')
        self.stack.put(b'bottom')
        self.stack.put(b'middle')
        self.stack.put(b'top')
        functions.OP_SWAP(self.tape, self.stack, self.cache)
        items = []
        while not self.stack.empty():
            items.append(self.stack.get())
        assert items == [b'middle', b'top', b'bottom']

    def test_OP_SWAP_raises_ScriptExecutionError_for_stack_depth_overflow(self):
        self.stack.put(b'sds')
        self.tape = classes.Tape(b'\x00\xff')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_SWAP(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_SWAP stack size exceeded by index'

        self.tape = classes.Tape(b'\xff\x00')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_SWAP(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_SWAP stack size exceeded by index'

    def test_OP_SWAP2_swaps_top_two_stack_items(self):
        self.stack.put(b'second')
        self.stack.put(b'first')
        functions.OP_SWAP2(self.tape, self.stack, self.cache)
        assert self.stack.get() == b'second'
        assert self.stack.get() == b'first'

    def test_OP_REVERSE_reads_uint_from_tape_and_reverses_order_of_that_many_stack_items(self):
        assert self.stack.empty()
        self.stack.put(b'4')
        self.stack.put(b'3')
        self.stack.put(b'2')
        self.stack.put(b'1')
        self.tape = classes.Tape(b'\x03')
        functions.OP_REVERSE(self.tape, self.stack, self.cache)
        assert self.stack.list() == [b'4',b'1',b'2',b'3'], self.stack.list()

    def test_OP_REVERSE_raises_ScriptExecutionError_for_stack_depth_overflow(self):
        self.stack.put(b'sds')
        self.tape = classes.Tape(b'\xff')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_REVERSE(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_REVERSE stack size exceeded'

    def test_OP_CONCAT_concatenates_top_two_items_from_stack(self):
        self.stack.put(b'321')
        self.stack.put(b'123')
        functions.OP_CONCAT(self.tape, self.stack, self.cache)
        assert self.stack.get() == b'321123'
        assert self.stack.empty()

    def test_OP_SPLIT_splits_top_stack_item_at_uint_index_read_from_tape(self):
        self.stack.put(b'12345')
        self.stack.put(b'\x02')
        functions.OP_SPLIT(self.tape, self.stack, self.cache)
        assert self.stack.get() == b'345'
        assert self.stack.get() == b'12'

    def test_OP_SPLIT_raises_ScriptExecutionError_for_negative_index(self):
        self.stack.put(b'sds')
        self.stack.put(functions.int_to_bytes(-1))
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_SPLIT(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_SPLIT negative index is invalid'

    def test_OP_SPLIT_raises_ScriptExecutionError_for_length_index_overflow(self):
        self.stack.put(b'sds')
        self.stack.put(functions.int_to_bytes(20))
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_SPLIT(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_SPLIT item len exceeded by index'

    def test_OP_SPLIT_and_OP_CONCAT_are_inverse_functions(self):
        first = b'123'
        second = b'abc'
        self.stack.put(first)
        self.stack.put(second)
        functions.OP_CONCAT(self.tape, self.stack, self.cache)
        self.stack.put(b'\x03')
        functions.OP_SPLIT(self.tape, self.stack, self.cache)
        assert self.stack.get() == second
        assert self.stack.get() == first

    def test_OP_CONCAT_STR_concatenates_top_two_utf8_str_items_from_stack(self):
        self.stack.put(bytes('abc', 'utf-8'))
        self.stack.put(bytes('123', 'utf-8'))
        functions.OP_CONCAT_STR(self.tape, self.stack, self.cache)
        item = self.stack.get()
        assert str(item, 'utf-8') == 'abc123'
        assert self.stack.empty()

    def test_OP_SPLIT_STR_splits_top_stack_utf8_str_at_uint_index_read_from_tape(self):
        self.stack.put(bytes('12345', 'utf-8'))
        self.stack.put(b'\x02')
        functions.OP_SPLIT_STR(self.tape, self.stack, self.cache)
        assert str(self.stack.get(), 'utf-8') == '345'
        assert str(self.stack.get(), 'utf-8') == '12'

    def test_OP_SPLIT_STR_raises_ScriptExecutionError_for_negative_index(self):
        self.stack.put(b'sds')
        self.stack.put(functions.int_to_bytes(-1))
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_SPLIT_STR(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_SPLIT_STR negative index is invalid'

    def test_OP_SPLIT_STR_raises_ScriptExecutionError_for_str_length_overflow(self):
        self.stack.put(b'sds')
        self.stack.put(b'\x05')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_SPLIT_STR(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_SPLIT_STR item len exceeded by index'

    def test_NOP_reads_int_from_tape_and_pulls_that_many_items_from_stack(self):
        assert self.stack.empty()
        self.stack.put(b'1')
        self.stack.put(b'2')
        self.stack.put(b'3')
        self.tape = classes.Tape(functions.int_to_bytes(2))
        functions.NOP(self.tape, self.stack, self.cache)
        assert self.stack.get() == b'1'
        assert self.stack.empty()

    def test_NOP_raises_ScriptExecutionError_for_negative_count(self):
        self.tape = classes.Tape(functions.int_to_bytes(-2))
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.NOP(self.tape, self.stack, self.cache)

    def test_OP_CHECK_TRANSFER_errors_on_missing_or_invalid_contract_or_params(self):
        def setup_transfer():
            self.tape = classes.Tape(b'\x01')
            self.stack.put(b'txn_proof')
            self.stack.put(b'source')
            self.stack.put(b'\x01')
            self.stack.put(b'destination')
            self.stack.put(b'constraint')
            self.stack.put(b'amount')
            self.stack.put(b'contractid')

        setup_transfer()
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TRANSFER(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_CHECK_TRANSFER missing contract'

        setup_transfer()
        self.tape.contracts[b'contractid'] = InvalidContract(10)
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_TRANSFER(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'contract must implement the CanCheckTransfer interface'

    def test_OP_CHECK_TRANSFER_works(self):
        def setup_transfer():
            self.tape = classes.Tape(b'\x00')
            self.stack.put(b'txn_proof')
            self.stack.put(b'source')
            self.stack.put((1).to_bytes(1, 'big'))
            self.stack.put(b'destination')
            self.stack.put(b'constraint')
            self.stack.put((10).to_bytes(1, 'big')) # amount
            self.stack.put(b'contractid')

        amount = 10
        setup_transfer()
        self.tape.contracts[b'contractid'] = ValidContract(amount)
        functions.OP_CHECK_TRANSFER(self.tape, self.stack, self.cache)
        assert self.stack.get() == b'\xff'
        assert self.stack.empty()

        amount = 9
        setup_transfer()
        self.tape.contracts[b'contractid'] = ValidContract(amount)
        functions.OP_CHECK_TRANSFER(self.tape, self.stack, self.cache)
        assert self.stack.get() == b'\x00'
        assert self.stack.empty()

        amount = 11
        setup_transfer()
        self.tape.contracts[b'contractid'] = ValidContract(amount)
        functions.OP_CHECK_TRANSFER(self.tape, self.stack, self.cache)
        assert self.stack.get() == b'\xff'
        assert self.stack.empty()

    def test_OP_CALL_reads_uint_from_tape_and_runs_that_definition(self):
        self.tape = classes.Tape(b'\x00')
        self.tape.definitions[b'\x00'] = classes.Tape(b'\x01')
        assert self.stack.empty()
        functions.OP_CALL(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert self.stack.get() == b'\xff'

    def test_OP_CALL_raises_ScriptExecutionError_when_callstack_limit_exceeded(self):
        self.tape.callstack_limit = -1
        self.tape.callstack_count = 1
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CALL(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'callstack limit exceeded'

    def test_OP_CALL_does_not_reset_definition_pointer(self):
        self.tape = classes.Tape(b'\x00')
        subtape = classes.Tape(b'\x2b\x00\x03\x00\x2a\x00\x02\x03')
        self.tape.definitions[b'\x00'] = subtape
        subtape.definitions = self.tape.definitions
        assert self.stack.empty()
        self.stack.put(b'\x01')
        functions.OP_CALL(self.tape, self.stack, self.cache)
        assert self.tape.definitions[b'\x00'].pointer == 0
        assert len(self.stack) == 2
        assert self.stack.get() == b'\x03'
        assert self.stack.get() == b'\x03'

    def test_OP_IF_reads_2uint_length_from_tape_pulls_top_stack_bool_and_executes_if_true(self):
        length = b'\x00\x02'
        op_push0 = b'\x02'
        self.tape = classes.Tape(length + op_push0 + b'X')
        assert self.stack.empty()
        self.stack.put(b'\x01')
        functions.OP_IF(self.tape, self.stack, self.cache)
        assert self.tape.has_terminated()
        assert self.stack.get() == b'X'
        assert self.stack.empty()

        length = b'\x00\x02'
        op_push0 = b'\x02'
        self.tape = classes.Tape(length + op_push0 + b'X')
        assert self.stack.empty()
        self.stack.put(b'\x00')
        functions.OP_IF(self.tape, self.stack, self.cache)
        assert self.tape.has_terminated()
        assert self.stack.empty()

    def test_OP_IF_ELSE_reads_2_definitions_from_tape_and_executes_first_one_if_top_stack_value(self):
        length = b'\x00\x02'
        if_def = b'\x02Y'
        else_def = b'\x02N'
        self.tape = classes.Tape(length + if_def + length + else_def)
        assert self.stack.empty()
        self.stack.put(b'\x01')
        functions.OP_IF_ELSE(self.tape, self.stack, self.cache)
        assert self.tape.has_terminated()
        assert self.stack.get() == b'Y'
        assert self.stack.empty()

        self.tape = classes.Tape(length + if_def + length + else_def)
        assert self.stack.empty()
        self.stack.put(b'\x00')
        functions.OP_IF_ELSE(self.tape, self.stack, self.cache)
        assert self.tape.has_terminated()
        assert self.stack.get() == b'N'
        assert self.stack.empty()

    def test_OP_TRY_EXCEPT_reads_2_definitions_from_tape_executes_properly(self):
        try_len = b'\x00\x02'
        except_len = b'\x00\x01'
        try_def = b'\x00\x20'
        except_def = b'\x01'
        self.tape = classes.Tape(try_len + try_def + except_len + except_def)
        assert self.stack.empty()
        assert b'E' not in self.cache
        functions.OP_TRY_EXCEPT(self.tape, self.stack, self.cache)
        assert self.tape.has_terminated()
        assert b'E' in self.cache
        assert len(self.cache[b'E']) == 1
        exname, exstr = str(self.cache[b'E'][0], 'utf-8').split('|')
        assert exname == 'ScriptExecutionError'
        assert exstr == 'OP_VERIFY check failed'
        assert not self.stack.empty()
        item = self.stack.get()
        assert functions.bytes_to_bool(item)

    def test_OP_EVAL_pulls_value_from_stack_and_runs_as_script(self):
        code = b'\x02F'
        assert self.stack.empty()
        self.stack.put(code)
        functions.OP_EVAL(self.tape, self.stack, self.cache)
        assert self.tape.has_terminated()
        assert not self.stack.empty()
        assert self.stack.get() == b'F'
        assert self.stack.empty()

    def test_OP_EVAL_raises_ScriptExecutionError_if_disallow_OP_EVAL_flag_set(self):
        self.tape.flags['disallow_OP_EVAL'] = True
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_EVAL(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_EVAL disallowed'

    def test_OP_EVAL_raises_ValueError_for_empty_script(self):
        self.stack.put(b'')
        with self.assertRaises(ValueError) as e:
            functions.OP_EVAL(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_EVAL encountered empty script'

    def test_OP_MERKLEVAL_single_branch(self):
        committed_branch_a = b'\x02A'
        committed_branch_b = b'\x02B'
        commitment_a = sha256(committed_branch_a).digest()
        commitment_b = sha256(committed_branch_b).digest()
        commitment_root = merkleval_root(commitment_a, commitment_b)
        self.stack.put(commitment_b)
        self.stack.put(committed_branch_a)
        self.tape = classes.Tape(commitment_root)
        functions.OP_MERKLEVAL(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert self.stack.get() == b'A'
        assert self.stack.empty()

        self.stack.put(commitment_a)
        self.stack.put(committed_branch_b)
        self.tape = classes.Tape(commitment_root)
        functions.OP_MERKLEVAL(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert self.stack.get() == b'B'
        assert self.stack.empty()

    def test_OP_MERKLEVAL_double_branch(self):
        committed_branch_a = b'\x02A'
        committed_branch_ba = b'\x03\x02BA'
        committed_branch_bb = b'\x03\x02BB'
        commitment_a = sha256(committed_branch_a).digest()
        commitment_ba = sha256(committed_branch_ba).digest()
        commitment_bb = sha256(committed_branch_bb).digest()
        commitment_b_root = merkleval_root(commitment_ba, commitment_bb)
        committed_branch_b_root = b'\x3c' + commitment_b_root
        commitment_b = sha256(committed_branch_b_root).digest()

        commitment_root = merkleval_root(commitment_a, commitment_b)
        self.stack.put(commitment_b)
        self.stack.put(committed_branch_a)
        self.tape = classes.Tape(commitment_root)
        functions.OP_MERKLEVAL(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert self.stack.get() == b'A'
        assert self.stack.empty()

        self.stack.put(commitment_bb)
        self.stack.put(committed_branch_ba)
        self.stack.put(commitment_a)
        self.stack.put(committed_branch_b_root)
        self.tape = classes.Tape(commitment_root)
        functions.OP_MERKLEVAL(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert self.stack.get() == b'BA'
        assert self.stack.empty()

        self.stack.put(commitment_ba)
        self.stack.put(committed_branch_bb)
        self.stack.put(commitment_a)
        self.stack.put(committed_branch_b_root)
        self.tape = classes.Tape(commitment_root)
        functions.OP_MERKLEVAL(self.tape, self.stack, self.cache)
        assert not self.stack.empty()
        assert self.stack.get() == b'BB'
        assert self.stack.empty()

    def test_OP_MERKLEVAL_raises_error_on_mismatching_hash(self):
        committed_branch_a = b'\x02A'
        committed_branch_b = b'\x02B'
        commitment_a = sha256(committed_branch_a).digest()
        commitment_b = sha256(committed_branch_b).digest()
        commitment_root = merkleval_root(commitment_a, commitment_b)
        self.stack.put(commitment_b)
        self.stack.put(committed_branch_a + b'uncommitted code')
        self.tape = classes.Tape(commitment_root)

        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_MERKLEVAL(self.tape, self.stack, self.cache)
        assert str(e.exception) == 'OP_VERIFY check failed'

    def test_OP_LESS_pulls_two_ints_from_stack_and_places_bool_on_stack(self):
        val1 = functions.int_to_bytes(123)
        val2 = functions.int_to_bytes(321)
        self.stack.put(val1)
        self.stack.put(val2)
        functions.OP_LESS(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        result = self.stack.get()
        assert result == b'\x00'

        self.stack.put(val1)
        self.stack.put(val1)
        functions.OP_LESS(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        result = self.stack.get()
        assert result == b'\x00'

        self.stack.put(val2)
        self.stack.put(val1)
        functions.OP_LESS(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        result = self.stack.get()
        assert result == b'\xff'

    def test_OP_LESS_OR_EQUAL_pulls_two_ints_from_stack_and_places_bool_on_stack(self):
        val1 = functions.int_to_bytes(123)
        val2 = functions.int_to_bytes(321)
        self.stack.put(val1)
        self.stack.put(val2)
        functions.OP_LESS_OR_EQUAL(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        result = self.stack.get()
        assert result == b'\x00'

        self.stack.put(val1)
        self.stack.put(val1)
        functions.OP_LESS_OR_EQUAL(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        result = self.stack.get()
        assert result == b'\xff'

        self.stack.put(val2)
        self.stack.put(val1)
        functions.OP_LESS_OR_EQUAL(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        result = self.stack.get()
        assert result == b'\xff'

    def test_OP_GET_VALUE_pulls_str_from_tape_and_puts_cache_vals_onto_stack(self):
        key = bytes('test', 'utf-8')
        self.cache['test'] = 123
        self.tape.data = functions.int_to_bytes(len(key)) + key
        functions.OP_GET_VALUE(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        assert self.tape.has_terminated()
        result = self.stack.get()
        assert result == functions.int_to_bytes(123)

        self.cache['test'] = [123, 12.34, 'abc', b'ac']
        assert len(self.stack) == 0
        self.tape.reset_pointer()
        functions.OP_GET_VALUE(self.tape, self.stack, self.cache)
        assert len(self.stack) == 4
        result = [
            self.stack.get(),
            self.stack.get(),
            self.stack.get(),
            self.stack.get(),
        ]
        assert result[0] == b'ac'
        assert result[1] == bytes('abc', 'utf-8')
        assert result[2] == functions.float_to_bytes(12.34)
        assert result[3] == functions.int_to_bytes(123)

    def test_OP_FLOAT_LESS_pulls_two_floats_from_stack_and_places_bool_on_stack(self):
        val1 = functions.float_to_bytes(123.0)
        val2 = functions.float_to_bytes(321.0)
        self.stack.put(val1)
        self.stack.put(val2)
        functions.OP_FLOAT_LESS(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        result = self.stack.get()
        assert result == b'\x00'

        self.stack.put(val1)
        self.stack.put(val1)
        functions.OP_FLOAT_LESS(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        result = self.stack.get()
        assert result == b'\x00'

        self.stack.put(val2)
        self.stack.put(val1)
        functions.OP_FLOAT_LESS(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        result = self.stack.get()
        assert result == b'\xff'

    def test_OP_FLOAT_LESS_OR_EQUAL_pulls_two_floats_from_stack_and_places_bool_on_stack(self):
        val1 = functions.float_to_bytes(123.0)
        val2 = functions.float_to_bytes(321.0)
        self.stack.put(val1)
        self.stack.put(val2)
        functions.OP_FLOAT_LESS_OR_EQUAL(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        result = self.stack.get()
        assert result == b'\x00'

        self.stack.put(val1)
        self.stack.put(val1)
        functions.OP_FLOAT_LESS_OR_EQUAL(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        result = self.stack.get()
        assert result == b'\xff'

        self.stack.put(val2)
        self.stack.put(val1)
        functions.OP_FLOAT_LESS_OR_EQUAL(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        result = self.stack.get()
        assert result == b'\xff'

    def test_OP_INT_TO_FLOAT_works_correctly(self):
        val = functions.int_to_bytes(123)
        self.stack.put(val)
        functions.OP_INT_TO_FLOAT(self.tape, self.stack, self.cache)
        result = self.stack.get()
        assert result == functions.float_to_bytes(123 * 1.0)

    def test_OP_FLOAT_TO_INT_works_correctly(self):
        val = functions.float_to_bytes(123.1)
        self.stack.put(val)
        functions.OP_FLOAT_TO_INT(self.tape, self.stack, self.cache)
        result = self.stack.get()
        assert result == functions.int_to_bytes(123)

    def test_OP_LOOP_raises_error_for_too_many_executions(self):
        self.tape.data = b'\x00\x00'
        self.stack.put(b'\x01')
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_LOOP(self.tape, self.stack, self.cache)
        assert 'OP_LOOP limit exceeded' in str(e.exception)

    def test_OP_LOOP_executes_for_true_top_stack_value(self):
        self.tape.data = b'\x00\x01\x00'
        self.stack.put(b'\x01')
        assert len(self.stack) == 1
        functions.OP_LOOP(self.tape, self.stack, self.cache)
        assert len(self.stack) == 2

    def test_OP_LOOP_skips_execution_for_false_top_stack_value(self):
        self.tape.data = b'\x00\x01\x00'
        self.stack.put(b'\x00')
        assert len(self.stack) == 1
        functions.OP_LOOP(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1

    def test_OP_CHECK_MULTISIG_pulls_m_sigs_from_stack_then_n_vkeys_and_verifies(self):
        # 3-of-3
        self.tape.data = b'\x00\x03\x03'
        msg = b'hi I am a protocol value that is signed'
        self.cache['sigfield1'] = msg
        skeys = [
            SigningKey(token_bytes(32)),
            SigningKey(token_bytes(32)),
            SigningKey(token_bytes(32)),
        ]
        vkeys = [skey.verify_key for skey in skeys]
        sigs = [skey.sign(msg).signature for skey in skeys]
        [self.stack.put(bytes(sig)) for sig in sigs]
        [self.stack.put(bytes(vkey)) for vkey in vkeys]
        functions.OP_CHECK_MULTISIG(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        assert functions.bytes_to_bool(self.stack.get())

        # 2-of-3
        self.tape = classes.Tape(b'\x00\x02\x03')
        [self.stack.put(bytes(sig)) for sig in sigs[:2]]
        [self.stack.put(bytes(vkey)) for vkey in vkeys]
        functions.OP_CHECK_MULTISIG(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        assert functions.bytes_to_bool(self.stack.get())

    def test_OP_CHECK_MULTISIG_puts_false_onto_stack_for_reused_sig(self):
        # 3-of-3
        self.tape.data = b'\x00\x03\x03'
        msg = b'hi I am a protocol value that is signed'
        self.cache['sigfield1'] = msg
        skeys = [
            SigningKey(token_bytes(32)),
            SigningKey(token_bytes(32)),
            SigningKey(token_bytes(32)),
        ]
        vkeys = [skey.verify_key for skey in skeys]
        sigs = [skey.sign(msg).signature for skey in skeys]
        [self.stack.put(bytes(sigs[0])) for _ in sigs]
        [self.stack.put(bytes(vkey)) for vkey in vkeys]
        functions.OP_CHECK_MULTISIG(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        assert not functions.bytes_to_bool(self.stack.get())

    def test_OP_CHECK_MULTISIG_puts_false_onto_stack_for_sig_using_wrong_key(self):
        # 2-of-2
        self.tape.data = b'\x00\x02\x02'
        msg = b'hi I am a protocol value that is signed'
        self.cache['sigfield1'] = msg
        skeys = [
            SigningKey(token_bytes(32)),
            SigningKey(token_bytes(32)),
            SigningKey(token_bytes(32)),
        ]
        vkeys = [skey.verify_key for skey in skeys]
        sigs = [skey.sign(msg).signature for skey in skeys]
        [self.stack.put(bytes(sig)) for sig in sigs[1:]]
        [self.stack.put(bytes(vkey)) for vkey in vkeys[:2]]
        functions.OP_CHECK_MULTISIG(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        assert not functions.bytes_to_bool(self.stack.get())

    def test_OP_CHECK_MULTISIG_VERIFY_executes_without_error_for_good_paths(self):
        # 3-of-3
        self.tape.data = b'\x00\x03\x03'
        msg = b'hi I am a protocol value that is signed'
        self.cache['sigfield1'] = msg
        skeys = [
            SigningKey(token_bytes(32)),
            SigningKey(token_bytes(32)),
            SigningKey(token_bytes(32)),
        ]
        vkeys = [skey.verify_key for skey in skeys]
        sigs = [skey.sign(msg).signature for skey in skeys]
        [self.stack.put(bytes(sig)) for sig in sigs]
        [self.stack.put(bytes(vkey)) for vkey in vkeys]
        functions.OP_CHECK_MULTISIG_VERIFY(self.tape, self.stack, self.cache)
        assert len(self.stack) == 0

        # 2-of-3
        self.tape = classes.Tape(b'\x00\x02\x03')
        [self.stack.put(bytes(sig)) for sig in sigs[:2]]
        [self.stack.put(bytes(vkey)) for vkey in vkeys]
        functions.OP_CHECK_MULTISIG_VERIFY(self.tape, self.stack, self.cache)
        assert len(self.stack) == 0

    def test_OP_CHECK_MULTISIG_VERIFY_raises_error_for_reused_sig(self):
        # 3-of-3
        self.tape.data = b'\x00\x03\x03'
        msg = b'hi I am a protocol value that is signed'
        self.cache['sigfield1'] = msg
        skeys = [
            SigningKey(token_bytes(32)),
            SigningKey(token_bytes(32)),
            SigningKey(token_bytes(32)),
        ]
        vkeys = [skey.verify_key for skey in skeys]
        sigs = [skey.sign(msg).signature for skey in skeys]
        [self.stack.put(bytes(sigs[0])) for _ in sigs]
        [self.stack.put(bytes(vkey)) for vkey in vkeys]
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_MULTISIG_VERIFY(self.tape, self.stack, self.cache)
        assert len(self.stack) == 0

    def test_OP_CHECK_MULTISIG_VERIFY_raises_error_for_sig_using_wrong_key(self):
        # 2-of-2
        self.tape.data = b'\x00\x02\x02'
        msg = b'hi I am a protocol value that is signed'
        self.cache['sigfield1'] = msg
        skeys = [
            SigningKey(token_bytes(32)),
            SigningKey(token_bytes(32)),
            SigningKey(token_bytes(32)),
        ]
        vkeys = [skey.verify_key for skey in skeys]
        sigs = [skey.sign(msg).signature for skey in skeys]
        [self.stack.put(bytes(sig)) for sig in sigs[1:]]
        [self.stack.put(bytes(vkey)) for vkey in vkeys[:2]]
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.OP_CHECK_MULTISIG_VERIFY(self.tape, self.stack, self.cache)
        assert len(self.stack) == 0

    def test_OP_SIGN_creates_valid_signatures(self):
        seed = token_bytes(32)
        self.tape.data = b'\x02'
        self.stack.put(seed)
        self.cache['sigfield1'] = b'hello'
        self.cache['sigfield2'] = b'excluded by sigflag'
        self.cache['sigfield3'] = b'world'
        functions.OP_SIGN(self.tape, self.stack, self.cache)
        sig = self.stack.get()
        assert len(self.stack) == 0
        assert len(sig) == nacl.bindings.crypto_sign_BYTES + 1, 'invalid signature'

        self.stack.put(sig)
        self.stack.put(bytes(SigningKey(seed).verify_key))
        self.tape.reset()
        functions.OP_CHECK_SIG(self.tape, self.stack, self.cache)
        result = self.stack.get()
        assert len(self.stack) == 0
        assert result == b'\xff'

    def test_OP_SIGN_raises_error_for_invalid_key(self):
        seed = b'not a valid key length'
        self.tape.data = b'\x00'
        self.stack.put(seed)
        self.cache['sigfield1'] = b'test'
        with self.assertRaises(ValueError) as e:
            functions.OP_SIGN(self.tape, self.stack, self.cache)
        assert 'invalid' in str(e.exception)

    def test_OP_SIGN_STACK_signs_message_from_stack_using_skey_seed_from_stack(self):
        seed = token_bytes(nacl.bindings.crypto_sign_SEEDBYTES)
        msg = b'hello world'
        self.stack.put(msg)
        self.stack.put(seed)
        functions.OP_SIGN_STACK(self.tape, self.stack, self.cache)
        sig = self.stack.get()
        assert len(sig) == nacl.bindings.crypto_sign_BYTES
        SigningKey(seed).verify_key.verify(msg, sig)

    def test_OP_CHECK_SIG_STACK_raises_correct_errors(self):
        seed = token_bytes(nacl.bindings.crypto_sign_SEEDBYTES)
        msg = b'hello world'
        skey = SigningKey(seed)
        sig = skey.sign(msg).signature

        self.stack.put(sig)
        self.stack.put(msg)
        self.stack.put(bytes(skey.verify_key)[:-1])
        with self.assertRaises(ValueError) as e:
            functions.OP_CHECK_SIG_STACK(self.tape, self.stack, self.cache)
        assert 'invalid vkey' in str(e.exception)

        self.stack.put(sig[:-1])
        self.stack.put(msg)
        self.stack.put(bytes(skey.verify_key))
        with self.assertRaises(ValueError) as e:
            functions.OP_CHECK_SIG_STACK(self.tape, self.stack, self.cache)
        assert 'invalid sig' in str(e.exception)

    def test_OP_CHECK_SIG_STACK_puts_correct_bool_onto_stack(self):
        seed = token_bytes(nacl.bindings.crypto_sign_SEEDBYTES)
        msg = b'hello world'
        skey = SigningKey(seed)
        sig = skey.sign(msg).signature

        self.stack.put(sig)
        self.stack.put(msg)
        self.stack.put(bytes(skey.verify_key))
        functions.OP_CHECK_SIG_STACK(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        assert self.stack.get() == b'\xff'

        self.stack.put(sig[1:] + sig[:1])
        self.stack.put(msg)
        self.stack.put(bytes(skey.verify_key))
        functions.OP_CHECK_SIG_STACK(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        assert self.stack.get() == b'\x00'

    def test_OP_INVOKE_e2e(self):
        contract_id = b'abcdef'
        class ABIContract:
            def abi(self, args: list[bytes]) -> list[bytes]:
                return [b''.join(args)]
        self.stack.put(b'world')
        self.stack.put(b'hello')
        self.stack.put(b'\x02')
        self.stack.put(contract_id)
        self.tape.contracts[contract_id] = ABIContract()
        functions.OP_INVOKE(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        assert self.stack.get() == b'helloworld'

    def test_OP_XOR_takes_two_values_and_puts_XOR_of_them_onto_stack(self):
        item1 = b'hello'
        item2 = b'world'
        expected = []
        for i in range(len(item1)):
            expected.append(item1[i] ^ item2[i])
        expected = bytes(expected)
        self.stack.put(item1)
        self.stack.put(item2)
        functions.OP_XOR(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        observed = self.stack.get()
        assert expected == observed, \
            f'expected {expected.hex()}, observed {observed.hex()}'

    def test_OP_OR_takes_two_values_and_puts_OR_of_them_onto_stack(self):
        item1 = b'\xf0'
        item2 = b'\x01'
        expected = b'\xf1'
        self.stack.put(item1)
        self.stack.put(item2)
        functions.OP_OR(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        observed = self.stack.get()
        assert expected == observed, \
            f'expected {expected.hex()}, observed {observed.hex()}'

    def test_OP_AND_takes_two_values_and_puts_AND_of_them_onto_stack(self):
        item1 = b'\xf0'
        item2 = b'\x01'
        expected = b'\x00'
        self.stack.put(item1)
        self.stack.put(item2)
        functions.OP_AND(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        observed = self.stack.get()
        assert expected == observed, \
            f'expected {expected.hex()}, observed {observed.hex()}'

    def test_OP_DERIVE_SCALAR_creates_32_byte_value_from_seed(self):
        self.stack.put(b'yellow submarine')
        functions.OP_DERIVE_SCALAR(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        result = self.stack.get()
        assert len(result) == 32

    def test_OP_CLAMP_SCALAR_clamps_32_bytes_to_ed25519_scalar(self):
        seed = token_bytes(32)
        self.stack.put(seed)
        self.tape.data = b'\x00'
        functions.OP_CLAMP_SCALAR(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        x1 = self.stack.get()
        assert len(x1) == 32
        assert not (x1[31] & 0b10000000)

        self.tape = classes.Tape(b'\x01')
        self.stack.put(seed)
        functions.OP_CLAMP_SCALAR(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        x2 = self.stack.get()
        assert len(x2) == 32
        assert not (x2[31] & 0b10000000)
        assert not (x2[0] & 0b00000111)
        assert (x2[31] & 0b01000000)

    def test_OP_CLAMP_SCALAR_raises_ValueError_for_invalid_seed_size(self):
        seed = token_bytes(token_bytes(1)[0] % 32) # 31 random bytes
        self.stack.put(seed)
        self.tape.data = b'\x00'
        with self.assertRaises(ValueError) as e:
            functions.OP_CLAMP_SCALAR(self.tape, self.stack, self.cache)

    def test_OP_DERIVE_POINT_replaces_scalar_with_point_on_stack_and_sets_cache(self):
        seed = token_bytes(32)
        x = functions.derive_key_from_seed(seed)
        self.stack.put(x)
        assert b'X' not in self.cache
        functions.set_tape_flags(self.tape)
        functions.OP_DERIVE_POINT(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        assert b'X' in self.cache
        X = self.stack.get()
        assert X != x

    def test_OP_DERIVE_POINT_works_with_CHECK_SIG(self):
        # basically proves it generates a public key
        seed = token_bytes(32)
        x = functions.derive_key_from_seed(seed)
        m = b'hello world'
        self.stack.put(x)
        functions.OP_DERIVE_POINT(self.tape, self.stack, self.cache)
        X = self.stack.get()
        sig = SigningKey(seed).sign(m).signature

        self.tape = classes.Tape(b'\x00')
        self.stack.put(sig)
        self.stack.put(m)
        self.stack.put(X)
        functions.OP_CHECK_SIG_STACK(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        assert self.stack.get() == b'\xff'

    def test_OP_SUBTRACT_POINTS_and_OP_SUBTRACT_SCALARS_work_properly(self):
        seed1 = token_bytes(32)
        seed2 = token_bytes(32)
        x1 = functions.derive_key_from_seed(seed1)
        x2 = functions.derive_key_from_seed(seed2)
        x3 = functions.aggregate_scalars([x1, x2])
        assert x3 not in (x1, x2)

        X1 = functions.derive_point_from_scalar(x1)
        X2 = functions.derive_point_from_scalar(x2)
        X3_1 = functions.aggregate_points([X1, X2])
        X3_2 = functions.derive_point_from_scalar(x3)
        assert X3_1 == X3_2
        assert X3_1 not in (X1, X2)

        self.tape.data = b'\x02'
        self.stack.put(x2)
        self.stack.put(x3)
        functions.OP_SUBTRACT_SCALARS(self.tape, self.stack, self.cache)
        x = self.stack.get()
        X = functions.derive_point_from_scalar(x)
        assert X == X1

        self.tape.reset()
        self.stack.put(X2)
        self.stack.put(X3_1)
        functions.OP_SUBTRACT_POINTS(self.tape, self.stack, self.cache)
        X = self.stack.get()
        assert X == X1

    def test_OP_MAKE_ADAPTER_SIG_PUBLIC_takes_3_from_and_puts_2_on_stack(self):
        seed = token_bytes(32)
        T = functions.derive_point_from_scalar(
            functions.derive_key_from_seed(token_bytes(32))
        )
        m = b'hello world'
        self.stack.put(seed)
        self.stack.put(m)
        self.stack.put(T)
        functions.set_tape_flags(self.tape)
        functions.OP_MAKE_ADAPTER_SIG_PUBLIC(self.tape, self.stack, self.cache)
        assert b'T' in self.cache
        assert b'R' in self.cache
        assert b'sa' in self.cache
        assert len(self.stack) == 2
        sa = self.stack.get()
        R = self.stack.get()
        assert len(sa) == 32 and sa not in (seed, T, m)
        assert len(R) == 32 and R not in (seed, T, m)

    def test_OP_MAKE_ADAPTER_SIG_PRIVATE_takes_3_from_and_puts_3_on_stack(self):
        seed1 = token_bytes(32)
        seed2 = token_bytes(32)
        m = b'hello world'
        self.stack.put(m)
        self.stack.put(seed2)
        self.stack.put(seed1)
        functions.set_tape_flags(self.tape)
        functions.OP_MAKE_ADAPTER_SIG_PRIVATE(self.tape, self.stack, self.cache)
        assert b't' in self.cache
        assert b'T' in self.cache
        assert b'R' in self.cache
        assert b'sa' in self.cache
        assert len(self.stack) == 3
        sa = self.stack.get()
        R = self.stack.get()
        T = self.stack.get()
        assert len(sa) == 32 and sa not in (seed1, seed2, m)
        assert len(T) == 32 and T not in (seed1, seed2, m)
        assert len(R) == 32 and R not in (seed1, seed2, m)

    def test_OP_CHECK_ADAPTER_SIG_takes_5_from_and_puts_1_on_stack(self):
        R = functions.derive_point_from_scalar(
            functions.derive_key_from_seed(token_bytes(32))
        )
        T = functions.derive_point_from_scalar(
            functions.derive_key_from_seed(token_bytes(32))
        )
        # sa = functions.clamp_scalar(token_bytes(32))
        sa = token_bytes(32)
        m = b'hello world'
        X = functions.derive_point_from_scalar(
            functions.derive_key_from_seed(token_bytes(32))
        )
        self.stack.put(sa)
        self.stack.put(R)
        self.stack.put(m)
        self.stack.put(T)
        self.stack.put(X)
        functions.OP_CHECK_ADAPTER_SIG(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        assert self.stack.get() == b'\x00'

    def test_OP_MAKE_ADAPTER_SIG_and_OP_VALIDATE_ADAPTER_SIG_e2e(self):
        seed = token_bytes(32)
        T = functions.derive_point_from_scalar(
            functions.derive_key_from_seed(token_bytes(32))
        )
        X = bytes(SigningKey(seed).verify_key)
        m = b'hello world'
        self.stack.put(seed)
        self.stack.put(m)
        self.stack.put(T)
        functions.OP_MAKE_ADAPTER_SIG_PUBLIC(self.tape, self.stack, self.cache)
        assert len(self.stack) == 2
        sa = self.stack.get()
        R = self.stack.get()

        # positive case
        self.stack.put(sa)
        self.stack.put(R)
        self.stack.put(m)
        self.stack.put(T)
        self.stack.put(X)
        functions.OP_CHECK_ADAPTER_SIG(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        assert self.stack.get() == b'\xff'

        # negative case
        self.stack.put(sa)
        self.stack.put(R)
        self.stack.put(m + b'qws')
        self.stack.put(T)
        self.stack.put(X)
        functions.OP_CHECK_ADAPTER_SIG(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        assert self.stack.get() == b'\x00'

    def test_OP_MAKE_ADAPTER_SIG_and_OP_DECRYPT_ADAPTER_SIG_e2e(self):
        seed1 = token_bytes(32)
        seed2 = token_bytes(32)
        t = functions.clamp_scalar(seed2)
        T = functions.derive_point_from_scalar(t)
        X = bytes(SigningKey(seed1).verify_key)
        m = b'hello world'
        self.stack.put(seed1)
        self.stack.put(m)
        self.stack.put(T)
        functions.set_tape_flags(self.tape)
        functions.OP_MAKE_ADAPTER_SIG_PUBLIC(self.tape, self.stack, self.cache)
        assert len(self.stack) == 2
        sa = self.stack.get()
        R = self.stack.get()

        self.stack.put(sa)
        self.stack.put(R)
        self.stack.put(seed2)
        functions.OP_DECRYPT_ADAPTER_SIG(self.tape, self.stack, self.cache)
        assert len(self.stack) == 2
        assert b's' in self.cache
        assert b'RT' in self.cache
        s = self.stack.get()
        RT = self.stack.get()

        # check signature
        self.cache['sigfield1'] = m
        self.tape = classes.Tape(b'\x00')
        functions.set_tape_flags(self.tape)
        self.stack.put(RT + s)
        self.stack.put(X)
        functions.OP_CHECK_SIG(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        assert self.stack.get() == b'\xff'

    def test_OP_CHECK_TEMPLATE(self):
        self.tape.data = b'\x01'
        template = b'hello world'
        self.stack.put(template)
        self.cache = {'sigfield1': template}

        functions.OP_CHECK_TEMPLATE(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        assert self.stack.get() == b'\xff'

        self.tape.reset_pointer()
        template = b'something else'
        self.stack.put(template)

        functions.OP_CHECK_TEMPLATE(self.tape, self.stack, self.cache)
        assert len(self.stack) == 1
        assert self.stack.get() == b'\x00'

    def test_OP_TAPROOT(self):
        # get keypair
        seed = token_bytes(32)
        skey = functions.derive_key_from_seed(seed)
        pubk = functions.derive_point_from_scalar(skey)

        # setup script
        # script_src = 'true'
        script_bin = b'\x01'
        script_hash = sha256(pubk + sha256(script_bin).digest()).digest()
        script_scalar = functions.clamp_scalar(script_hash)
        script_point = functions.derive_point_from_scalar(script_scalar)

        # combine pubk and script point
        root = functions.aggregate_points([pubk, script_point])

        tape = classes.Tape(b'\x01')
        stack = classes.Stack()
        cache = {'sigfield1': b'nope ', 'sigfield2': b'hello world'}

        # create message and signature
        message = cache['sigfield2']
        sig = functions.sign_with_scalar(functions.aggregate_scalars([skey, script_scalar]), message)

        # test unlock1 (key spend): should result in True value
        tape.reset_pointer()
        assert len(stack) == 0
        stack.put(sig + b'\x01')
        stack.put(root)
        functions.OP_TAPROOT(tape, stack, cache)
        assert len(stack) == 1
        assert stack.get() == b'\xff'

        # test malformed unlock1: should result in False value
        tape.reset_pointer()
        stack.put(bytes(reversed(sig)))
        stack.put(root)
        functions.OP_TAPROOT(tape, stack, cache)
        assert len(stack) == 1
        assert stack.get() == b'\x00'

        # test unlock2 (committed script): should result in True value
        tape.reset_pointer()
        stack.put(script_bin)
        stack.put(pubk)
        stack.put(root)
        functions.OP_TAPROOT(tape, stack, cache)
        assert len(stack) == 1
        assert stack.get() == b'\xff'

        # test malformed unlock2: should result in False value
        tape.reset_pointer()
        stack.put(script_bin + b'\x01')
        stack.put(pubk)
        stack.put(root)
        functions.OP_TAPROOT(tape, stack, cache)
        assert len(stack) == 1
        assert stack.get() == b'\x00'

    # values
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

    # code running functions
    def test_run_tape_executes_ops_until_tape_has_terminated(self):
        code = bytes.fromhex('990099009900990099009900')
        self.tape = classes.Tape(code)
        assert self.stack.empty()
        assert not self.cache
        functions.run_tape(self.tape, self.stack, self.cache)
        assert self.tape.has_terminated()
        assert self.stack.empty()

        code = bytes.fromhex('290000000202012a00')
        self.tape = classes.Tape(code)
        assert self.stack.empty()
        assert not self.cache
        functions.run_tape(self.tape, self.stack, self.cache)
        assert self.tape.has_terminated()
        assert not self.stack.empty()
        item = self.stack.get()
        assert item == b'\xff'
        item = self.stack.get()
        assert item == b'\x02'

    def test_run_script_returns_tuple_of_tape_stack_and_cache(self):
        code = bytes.fromhex('990099009900990099009900')
        result = functions.run_script(code)
        assert isinstance(result, tuple)
        assert len(result) == 3
        assert isinstance(result[0], classes.Tape)
        assert isinstance(result[1], classes.Stack)
        assert isinstance(result[2], dict)
        assert result[0].has_terminated()

    def test_run_auth_script_returns_True_only_if_stack_has_single_True_value(self):
        assert functions.run_auth_script(b'\x00') == False
        assert functions.run_auth_script(b'\x00\x20') == False
        assert functions.run_auth_script(b'\x01') == True
        assert functions.run_auth_script(b'\x01\x01') == False

    def test_OP_RETURN_exits_local_context_and_returns_to_outer_context(self):
        # return from def before adding int false to stack
        code = b'\x29\x00\x00\x02\x30\x00\x2a\x00\x01'
        tape, stack, _ = functions.run_script(code)
        assert tape.has_terminated()
        assert stack.get() == b'\xff'
        assert stack.empty()

        # return from def after adding int false to stack
        code = b'\x29\x00\x00\x02\x00\x30\x2a\x00\x01'
        tape, stack, _ = functions.run_script(code)
        assert tape.has_terminated()
        assert stack.get() == b'\xff'
        assert stack.get() == b'\x00'
        assert stack.empty()

    def test_OP_RETURN_within_OP_IF_exits_outer_context(self):
        # return from def within OP_IF before adding int false to stack
        code = b'\x29\x00\x00\x06\x2b\x00\x02\x30\x00\x01\x01\x2a\x00\x02\x02'
        tape, stack, _ = functions.run_script(code)
        assert tape.has_terminated()
        assert stack.get() == b'\x02'
        assert stack.empty()

    def test_OP_RETURN_within_OP_IF_ELSE_exits_outer_context(self):
        # return from def within OP_IF before adding int false to stack
        code = b'\x29\x00\x00\x08\x2c\x00\x02\x30\x00\x00\x00\x01\x01\x2a\x00\x02\x02'
        tape, stack, _ = functions.run_script(code)
        assert tape.has_terminated()
        assert stack.get() == b'\x02'
        assert stack.empty()

    def test_OP_RETURN_within_OP_TRY_EXCEPT_exits_outer_context(self):
        # return from def within OP_TRY_EXCEPT before adding int false to stack
        code = b'\x29\x00\x00\x07\x3d\x00\x01\x30\x00\x00\x01\x2a\x00\x02\x02'
        tape, stack, _ = functions.run_script(code)
        assert tape.has_terminated()
        assert stack.get() == b'\x02'
        assert stack.empty()

    def test_OP_RETURN_within_OP_EVAL_does_not_exit_outer_context(self):
        # do not return from def within OP_EVAL before adding \xff to stack
        code = b'\x29\x00\x00\x05' + b'\x02\x30\x2d\x02\xff' + b'\x2a\x00'
        tape, stack, _ = functions.run_script(code)
        assert tape.has_terminated()
        assert stack.get() == b'\xff'
        assert stack.empty()

    def test_OP_RETURN_within_OP_EVAL_exits_outer_context_when_eval_return_flag_set(self):
        # return from def within OP_EVAL before adding \xff to stack
        code = b'\x29\x00\x00\x05' + b'\x02\x30\x2d\x02\xff' + b'\x2a\x00'
        tape, stack, _ = functions.run_script(code, additional_flags={'eval_return':True})
        assert tape.has_terminated()
        assert stack.empty()

    def test_add_opcode_raises_errors_for_invalid_input(self):
        function = lambda tape, stack, cache: stack.put('nonsense')
        with self.assertRaises(TypeError) as e:
            functions.add_opcode('not an int', '', function)
        assert str(e.exception) == 'code must be int'
        with self.assertRaises(TypeError) as e:
            functions.add_opcode(255, b'not str', function)
        assert str(e.exception) == 'name must be str'
        with self.assertRaises(TypeError) as e:
            functions.add_opcode(255, 'name', 'not callable')
        assert str(e.exception) == 'function must be callable'
        with self.assertRaises(ValueError) as e:
            functions.add_opcode(0, 'name', function)
        assert str(e.exception) == '0 already assigned to OP_FALSE'
        with self.assertRaises(ValueError) as e:
            functions.add_opcode(256, 'name', function)
        assert str(e.exception) == 'code must be <256'
        with self.assertRaises(ValueError) as e:
            functions.add_opcode(255, 'name', function)
        assert str(e.exception) == 'name must start with OP_'

    def test_add_opcode_adds_function_e2e(self):
        self.stack.put(b'123')
        functions.run_tape(classes.Tape(b'\xff\x01'), self.stack, {})
        assert self.stack.empty()

        functions.add_opcode(255, 'OP_NONSENSE', lambda tape, stack, cache: stack.put(b'nonsense'))
        assert self.original_opcodes != functions.opcodes
        assert self.original_opcodes_inverse != functions.opcodes_inverse

        tape, stack, cache = functions.run_script(b'\xff\x01')
        assert not stack.empty()
        assert stack.get() == b'\xff'
        assert stack.get() == b'nonsense'

    def test_add_contract_raises_error_on_invalid_contract(self):
        assert b'123' not in functions._contracts
        with self.assertRaises(errors.ScriptExecutionError) as e:
            functions.add_contract(b'123', InvalidContract(1))
        assert str(e.exception) == 'contract does not fulfill at least one interface'
        assert b'123' not in functions._contracts

    def test_add_contract_adds_valid_contract(self):
        assert b'123' not in functions._contracts
        contract = ValidContract(10)
        functions.add_contract(b'123', contract)
        assert b'123' in functions._contracts
        assert functions._contracts[b'123'] is contract

    def test_remove_contract_removes_contract_by_id(self):
        functions._contracts[b'123'] = ValidContract(10)
        assert b'123' in functions._contracts
        functions.remove_contract(b'123')
        assert b'123' not in functions._contracts

    def test_added_contracts_added_to_executing_scripts(self):
        contract = ValidContract(10)
        functions.add_contract(b'123', contract)
        tape, stack, cache = functions.run_script(b'\x00')
        assert b'123' in tape.contracts
        assert tape.contracts[b'123'] is contract

    def test_add_contract_interface_raises_TypeError_for_invalid_interface(self):
        with self.assertRaises(TypeError) as e:
            functions.add_contract_interface({})
        assert str(e.exception) == 'interface must be a Protocol'
        with self.assertRaises(TypeError) as e:
            functions.add_contract_interface(ValidContract)
        assert str(e.exception) == 'interface must be a Protocol'

    def test_add_contract_interface_adds_interface_for_type_checking(self):
        functions.add_contract(b'123', ValidContract(10))
        assert b'123' in functions._contracts

        with self.assertRaises(errors.ScriptExecutionError):
            functions.add_contract(b'321', DoesThing())
        functions.add_contract_interface(CanDoThing)
        functions.add_contract(b'321', DoesThing())

    def test_remove_contract_inferface_raises_TypeError_for_invalid_interface(self):
        with self.assertRaises(TypeError) as e:
            functions.remove_contract_interface({})
        assert str(e.exception) == 'interface must be a Protocol'

    def test_remove_contract_interface_removes_interface_for_type_checking(self):
        assert b'123' not in functions._contracts
        with self.assertRaises(errors.ScriptExecutionError):
            functions.add_contract(b'123', DoesThing())
        assert b'123' not in functions._contracts

        functions.remove_contract_interface(interfaces.CanCheckTransfer)
        with self.assertRaises(errors.ScriptExecutionError):
            functions.add_contract(b'321', ValidContract(10))
        assert b'321' not in functions._contracts

    # e2e vectors
    def test_p2pk_e2e(self):
        message = b'spending bitcoinz or something'
        ts = int(time())
        ts_bytes = ts.to_bytes(4, 'big')
        old_ts = (1694791613).to_bytes(4, 'big')
        cache_vals = {
            'sigfield1': message,
            'timestamp': ts,
        }

        with open('tests/vectors/p2pk_locking_script.hex', 'r') as f:
            hexdata = ''.join(f.read().split())
            locking_script = bytes.fromhex(hexdata)
            locking_script = locking_script.replace(old_ts, ts_bytes)

        with open('tests/vectors/p2pk_unlocking_script1.hex', 'r') as f:
            hexdata = ''.join(f.read().split())
            unlocking_script1 = bytes.fromhex(hexdata)
            script = unlocking_script1 + locking_script
            tape, stack, _ = functions.run_script(script, cache_vals)
            assert tape.has_terminated()
            assert not stack.empty()
            item = stack.get()
            assert item == b'\xff'

        with open('tests/vectors/p2pk_unlocking_script2.hex', 'r') as f:
            hexdata = ''.join(f.read().split())
            unlocking_script2 = bytes.fromhex(hexdata)
            script = unlocking_script2 + locking_script
            tape, stack, _ = functions.run_script(script, cache_vals)
            assert tape.has_terminated()
            assert not stack.empty()
            item = stack.get()
            assert item == b'\xff'

    def test_p2sh_e2e(self):
        message = b'spending bitcoinz or something'
        original_flags = {**functions.flags}
        # disable additional time check
        functions.flags['ts_threshold'] = 0
        ts = int(time())
        cache_vals = {
            'sigfield1': message,
            'timestamp': ts,
        }

        with open('tests/vectors/p2sh_locking_script.hex', 'r') as f:
            hexdata = ''.join(f.read().split())
            locking_script = bytes.fromhex(hexdata)

        with open('tests/vectors/p2sh_unlocking_script.hex', 'r') as f:
            hexdata = ''.join(f.read().split())
            unlocking_script = bytes.fromhex(hexdata)
            script = unlocking_script + locking_script
            tape, stack, _ = functions.run_script(script, cache_vals)
            assert tape.has_terminated()
            assert not stack.empty()
            item = stack.get()
            assert item == b'\xff'

        functions.flags = original_flags

    def test_cds_e2e(self):
        original_flags = {**functions.flags}
        # disable additional time check
        functions.flags['ts_threshold'] = 0
        with open('tests/vectors/cds_locking_script.hex', 'r') as f:
            hexdata = ''.join(f.read().split())
            locking_script = bytes.fromhex(hexdata)

        # redemption spending path
        message = b'redeem CDS: proved sending 1000 back to CDS issuer'
        ts = int(time())
        cache_vals = {
            'sigfield1': message,
            'timestamp': ts,
        }
        amount = 1000
        destination = bytes.fromhex('49001a64110769ed9154ecb60799d1b4adabf5f07c93e1d8964ab58bb2449f7f')

        class Contract:
            amount: int
            def __init__(self, amount: int) -> None:
                self.amount = amount
            def verify_txn_proof(self, proof: bytes) -> bool:
                return True
            def verify_transfer(self, proof: bytes, source: bytes, destination: bytes) -> bool:
                return True
            def verify_txn_constraint(self, proof: bytes, constraint: bytes) -> bool:
                return True
            def calc_txn_aggregates(self, proofs: list[bytes], scope: bytes = None) -> dict:
                return {scope: self.amount}

        contract = Contract(amount)
        contract_id = bytes.fromhex('49001a64110769ed9154ecb60799d1b4adabf5f07c93e1d8964ab58bb2449f7f')
        with open('tests/vectors/cds_unlocking_script1.hex', 'r') as f:
            hexdata = ''.join(f.read().split())
            unlocking_script1 = bytes.fromhex(hexdata)
        result = functions.run_auth_script(unlocking_script1 + locking_script, cache_vals, {
            contract_id: contract
        })
        assert result

        # CDS expiration spending path
        message = b'CDS expiration: issuer regains collateral'
        cache_vals['sigfield1'] = message
        with open('tests/vectors/cds_unlocking_script2.hex', 'r') as f:
            hexdata = ''.join(f.read().split())
            unlocking_script2 = bytes.fromhex(hexdata)
        result = functions.run_auth_script(unlocking_script2 + locking_script, cache_vals, {
            contract_id: contract
        })
        assert result

        # CDS transfer spending path
        message = b'CDS transfer'
        cache_vals['sigfield1'] = message
        with open('tests/vectors/cds_unlocking_script3.hex', 'r') as f:
            hexdata = ''.join(f.read().split())
            unlocking_script3 = bytes.fromhex(hexdata)
        result = functions.run_auth_script(unlocking_script3 + locking_script, cache_vals, {
            contract_id: contract
        })
        assert result

        functions.flags = original_flags

    def test_correspondents_e2e(self):
        message = b'spending bitcoinz or something'
        original_flags = {**functions.flags}
        # disable additional time check
        functions.flags['ts_threshold'] = 0
        ts = int(time())
        cache_vals = {
            'sigfield1': message,
            'timestamp': ts,
        }

        with open('tests/vectors/correspondent_locking_script.hex', 'r') as f:
            hexdata = ''.join(f.read().split())
            locking_script = bytes.fromhex(hexdata)

        with open('tests/vectors/correspondent_unlocking_script1.hex', 'r') as f:
            hexdata = ''.join(f.read().split())
            unlocking_script = bytes.fromhex(hexdata)
            script = unlocking_script + locking_script
            tape, stack, _ = functions.run_script(script, cache_vals)
            assert tape.has_terminated()
            assert not stack.empty()
            item = stack.get()
            assert item == b'\xff'

        with open('tests/vectors/correspondent_unlocking_script2.hex', 'r') as f:
            hexdata = ''.join(f.read().split())
            unlocking_script = bytes.fromhex(hexdata)
            script = unlocking_script + locking_script
            tape, stack, _ = functions.run_script(script, cache_vals)
            assert tape.has_terminated()
            assert not stack.empty()
            item = stack.get()
            assert item == b'\xff'

        functions.flags = original_flags

    def test_merkleval_e2e(self):
        message = b'spending some coinz'
        original_flags = {**functions.flags}
        # disable additional time check
        functions.flags['ts_threshold'] = 0
        ts = int(time())
        cache_vals = {
            'sigfield1': message,
            'timestamp': ts,
        }

        with open('tests/vectors/merkleval_locking_script.hex', 'r') as f:
            hexdata = ''.join(f.read().split())
            locking_script = bytes.fromhex(hexdata)

        with open('tests/vectors/merkleval_unlocking_script_a.hex', 'r') as f:
            hexdata = ''.join(f.read().split())
            unlocking_script = bytes.fromhex(hexdata)
            script = unlocking_script + locking_script
            tape, stack, _ = functions.run_script(script, cache_vals)
            assert tape.has_terminated()
            assert not stack.empty()
            item = stack.get()
            assert item == b'\xff'

        with open('tests/vectors/merkleval_unlocking_script_ba.hex', 'r') as f:
            hexdata = ''.join(f.read().split())
            unlocking_script = bytes.fromhex(hexdata)
            script = unlocking_script + locking_script
            tape, stack, _ = functions.run_script(script, cache_vals)
            assert tape.has_terminated()
            assert not stack.empty()
            item = stack.get()
            assert item == b'\xff'

        with open('tests/vectors/merkleval_unlocking_script_bb.hex', 'r') as f:
            hexdata = ''.join(f.read().split())
            unlocking_script = bytes.fromhex(hexdata)
            script = unlocking_script + locking_script
            tape, stack, _ = functions.run_script(script, cache_vals)
            assert tape.has_terminated()
            assert not stack.empty()
            item = stack.get()
            assert item == b'\xff'

        functions.flags = original_flags


if __name__ == '__main__':
    unittest.main()
