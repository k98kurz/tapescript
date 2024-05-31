from __future__ import annotations
from .classes import Tape, Stack
from .errors import tert, vert, sert
from .interfaces import CanCheckTransfer, CanBeInvoked, ScriptProtocol
from hashlib import sha256, shake_256, sha512
from math import ceil, floor, isnan, log2
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from secrets import token_bytes
from time import time
from typing import Any, Callable, _ProtocolMeta
import nacl.bindings
import struct


def bytes_to_int(number: bytes) -> int:
    """Convert from bytes to a signed int."""
    tert(type(number) is bytes, 'number must be bytes')
    vert(len(number) > 0, 'number must not be empty')
    size = len(number) * 8
    number = int.from_bytes(number, 'big')
    negative = number >> (size - 1)

    return number - 2**size if negative else number

def int_to_bytes(number: int) -> bytes:
    """Convert from arbitrarily large signed int to bytes."""
    tert(type(number) is int, 'number must be int')
    negative = number < 0
    number = abs(number)
    n_bits = floor(log2(number)) + 1 if number != 0 else 1
    n_bytes = ceil(n_bits/8)

    if negative:
        if n_bits % 8 == 0 and number > 2**(n_bytes*8-1):
            n_bytes += 1
        number = (1 << (n_bytes * 8 - 1)) + (2**(n_bytes * 8 - 1) - number)
    elif n_bits % 8 == 0:
        n_bytes += 1

    return number.to_bytes(n_bytes, 'big')

def uint_to_bytes(number: int) -> bytes:
    """Convert from arbitrarily large unsigned int to bytes."""
    tert(type(number) is int, 'number must be int')
    n_bits = floor(log2(number)) + 1 if number != 0 else 1
    n_bytes = ceil(n_bits/8)

    return number.to_bytes(n_bytes, 'big')

def bytes_to_bool(val: bytes) -> bool:
    """Return True if any bits set, else False."""
    return int.from_bytes(val, 'big') > 0

def bytes_to_float(number: bytes) -> float:
    """Converts bytes into a 32-bit float."""
    tert(type(number) is bytes, 'number must be 4 bytes')
    vert(len(number) == 4, 'number must be 4 bytes')
    return struct.unpack('!f', number)[0]

def float_to_bytes(number: float) -> bytes:
    """Converts a float into 4 bytes."""
    tert(type(number) is float, 'number must be float')
    return struct.pack('!f', number)

def clamp_scalar(scalar: bytes, from_private_key: bool = False) -> bytes:
    """Make a clamped ed25519 scalar by setting specific bits."""
    if type(scalar) is bytes and len(scalar) >= 32:
        x_i = bytearray(scalar[:32])
    elif type(scalar) is SigningKey:
        x_i = bytearray(sha512(bytes(scalar)).digest()[:32])
        from_private_key = True
    else:
        raise ValueError('not a SigningKey and not 32+ bytes scalar')

    if from_private_key:
        # set bits 0, 1, and 2 to 0
        # nb: lsb is right-indexed
        x_i[0] &= 0b11111000
        # set bit 254 to 1
        x_i[31] |= 0b01000000

    # set bit 255 to 0
    x_i[31] &= 0b01111111

    return bytes(x_i)

def H_big(*parts) -> bytes:
    """The big, 64-byte hash function."""
    return sha512(b''.join(parts)).digest()

def H_small(*parts) -> bytes:
    """The small, 32-byte hash function."""
    return nacl.bindings.crypto_core_ed25519_scalar_reduce(H_big(*parts))

def derive_key_from_seed(seed: bytes) -> bytes:
    """Derive the scalar used for signing from a seed."""
    return clamp_scalar(H_big(seed)[:32], True)

def derive_point_from_scalar(scalar: bytes) -> bytes:
    """Derives an ed25519 point from a scalar."""
    return nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(scalar)

def aggregate_points(points: list[bytes|VerifyKey]) -> bytes:
    """Aggregate points on the Ed25519 curve."""
    # type checking inputs
    for pt in points:
        if type(pt) is not bytes and type(pt) is not VerifyKey:
            raise TypeError('each point must be bytes or VerifyKey')

    # normalize points to bytes
    points = [pt if type(pt) is bytes else bytes(pt) for pt in points]

    # raise an error for invalid points
    for pt in points:
        if not nacl.bindings.crypto_core_ed25519_is_valid_point(pt):
            raise ValueError('each point must be a valid ed25519 point')

    # compute the sum
    sum = points[0]
    for i in range(1, len(points)):
        sum = nacl.bindings.crypto_core_ed25519_add(sum, points[i])

    return sum

def aggregate_scalars(scalars: list[bytes]) -> bytes:
    """Aggregate scalars on the Ed25519 curve."""
    # type checking inputs
    for x in scalars:
        tert(type(x) is bytes, 'each scalar must be bytes')

    # compute the sum
    sum = scalars[0]
    for i in range(1, len(scalars)):
        sum = nacl.bindings.crypto_core_ed25519_scalar_add(sum, scalars[i])

    return sum

def sign_with_scalar(scalar: bytes, message: bytes, seed: bytes = None) -> bytes:
    """Creates a valid signature given an ed25519 scalar that validates
        with the corresponding point.
    """
    tert(type(scalar) is bytes, 'scalar must be bytes')
    tert(type(message) is bytes, 'message must be bytes')

    vert(nacl.bindings.crypto_core_ed25519_SCALARBYTES == len(scalar),
         'scalar must be a valid ed25519 scalar')

    seed = seed or H_small(scalar + message)
    nonce = H_big(seed)[32:]
    x, m = scalar, message
    X = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(x) # G^x
    r = clamp_scalar(H_small(H_big(nonce, m))) # H(nonce || m)
    R = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(r) # G^r
    c = clamp_scalar(H_small(R, X, m)) # H(R + T || X || m)
    s = nacl.bindings.crypto_core_ed25519_scalar_add(
        r, nacl.bindings.crypto_core_ed25519_scalar_mul(c, x)
    ) # r + H(R || X || m) * x
    return R + s

def not_bytes(b1: bytes) -> bytes:
    """Perform a bitwise NOT operation. Implementation is specific to
        the Python memory model.
    """
    n_bits = len(b1)*8
    return ((1 << n_bits) - 1 - int.from_bytes(b1, 'big')).to_bytes(n_bits//8, 'big')

def xor(b1: bytes, b2: bytes) -> bytes:
    """XOR two equal-length byte strings together."""
    b3 = bytearray()
    for i in range(len(b1)):
        b3.append(b1[i] ^ b2[i])

    return bytes(b3)

def or_bytes(b1: bytes, b2: bytes) -> bytes:
    """OR two equal-length byte strings together."""
    b3 = bytearray()
    for i in range(len(b1)):
        b3.append(b1[i] | b2[i])

    return bytes(b3)

def and_bytes(b1: bytes, b2: bytes) -> bytes:
    """AND two equal-length byte strings together."""
    b3 = bytearray()
    for i in range(len(b1)):
        b3.append(b1[i] & b2[i])

    return bytes(b3)

def bytes_are_same(b1: bytes, b2: bytes) -> bool:
    """Timing-attack safe bytes comparison."""
    return len(b1) == len(b2) and int.from_bytes(xor(b1, b2), 'little') == 0


def OP_FALSE(tape: Tape, stack: Stack, cache: dict) -> None:
    """Puts a null byte onto the stack."""
    stack.put(b'\x00')

def OP_TRUE(tape: Tape, stack: Stack, cache: dict) -> None:
    """Puts a 0xFF byte onto the stack."""
    stack.put(b'\xff')

def OP_PUSH0(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape; put it onto the stack.
    """
    stack.put(tape.read(1))

def OP_PUSH1(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        take that many bytes from the tape; put them onto the stack.
    """
    size = int.from_bytes(tape.read(1), 'big')
    stack.put(tape.read(size))

def OP_PUSH2(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next 2 bytes from the tape, interpreting as an unsigned
        int; take that many bytes from the tape; put them onto the
        stack.
    """
    size = int.from_bytes(tape.read(2), 'big')
    stack.put(tape.read(size))

def OP_GET_MESSAGE(tape: Tape, stack: Stack, cache: dict) -> None:
    """Reads a byte from tape as the sigflags; constructs the message
        that will be used by OP_SIGN and OP_CHECK_SIG/_VERIFY from the
        sigfields; puts the result onto the stack. Runs the signature
        extension plugins beforehand.
    """
    run_sig_extensions(tape, stack, cache)
    sig_flag = int.from_bytes(tape.read(1), 'big')

    sig_flag1 = sig_flag & 0b00000001
    sig_flag2 = sig_flag & 0b00000010
    sig_flag3 = sig_flag & 0b00000100
    sig_flag4 = sig_flag & 0b00001000
    sig_flag5 = sig_flag & 0b00010000
    sig_flag6 = sig_flag & 0b00100000
    sig_flag7 = sig_flag & 0b01000000
    sig_flag8 = sig_flag & 0b10000000

    message = b''

    if 'sigfield1' in cache and not sig_flag1:
        message += cache['sigfield1']
    if 'sigfield2' in cache and not sig_flag2:
        message += cache['sigfield2']
    if 'sigfield3' in cache and not sig_flag3:
        message += cache['sigfield3']
    if 'sigfield4' in cache and not sig_flag4:
        message += cache['sigfield4']
    if 'sigfield5' in cache and not sig_flag5:
        message += cache['sigfield5']
    if 'sigfield6' in cache and not sig_flag6:
        message += cache['sigfield6']
    if 'sigfield7' in cache and not sig_flag7:
        message += cache['sigfield7']
    if 'sigfield8' in cache and not sig_flag8:
        message += cache['sigfield8']

    stack.put(message)

def OP_POP0(tape: Tape, stack: Stack, cache: dict) -> None:
    """Remove the first item from the stack and put it in the cache at
        key b'P' (can be put back onto the stack with @P).
    """
    cache[b'P'] = [stack.get()]

def OP_POP1(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        remove that many items from the stack and put them in the cache
        at key b'P' (can be put back onto the stack with @P).
    """
    size = int.from_bytes(tape.read(1), 'big')
    items = []

    for _ in range(size):
        items.append(stack.get())

    cache[b'P'] = items

def OP_SIZE(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pull a value from the stack; put the size of the value onto the
        stack as signed int.
    """
    stack.put(int_to_bytes(len(stack.get())))

def OP_WRITE_CACHE(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        read that many bytes from tape as cache key; read another byte
        from the tape, interpreting as an int; read that many items from
        the stack and write them to the cache.
    """
    size = int.from_bytes(tape.read(1), 'big')
    key = tape.read(size)
    n_items = int.from_bytes(tape.read(1), 'big')
    items = []

    for _ in range(n_items):
        items.append(stack.get())

    cache[key] = items

def OP_READ_CACHE(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        read that many bytes from tape as cache key; read those values
        from the cache and place them onto the stack.
    """
    size = int.from_bytes(tape.read(1), 'big')
    key = tape.read(size)
    sert(key in cache, 'OP_READ_CACHE key not in cache')
    items = cache[key] if type(cache[key]) in (list, tuple) else [cache[key]]

    for item in items:
        stack.put(item)

def OP_READ_CACHE_SIZE(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        read that many bytes from tape as cache key; count how many
        values exist at that point in the cache and place that int onto
        the stack.
    """
    size = int.from_bytes(tape.read(1), 'big')
    key = tape.read(size)

    if key not in cache:
        return stack.put(int_to_bytes(0))

    stack.put(int_to_bytes(len(cache[key])))

def OP_READ_CACHE_STACK(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pull a value from the stack as a cache key; put those values from
        the cache onto the stack.
    """
    key = stack.get()
    sert(key in cache, 'OP_READ_CACHE_STACK key not in cache')
    items = cache[key] if type(cache[key]) in (list, tuple) else [cache[key]]

    for item in items:
        stack.put(item)

def OP_READ_CACHE_STACK_SIZE(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pull a value from the stack as a cache key; count the number of
        values in the cache at that key; put the result onto the stack
        as a signed int.
    """
    key = stack.get()

    if key not in cache:
        return stack.put(int_to_bytes(0))

    stack.put(int_to_bytes(len(cache[key])))

def OP_ADD_INTS(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned
        int; pull that many values from the stack, interpreting them as
        signed ints; add them together; put the result back onto the
        stack.
    """
    size = int.from_bytes(tape.read(1), 'big')
    total = 0

    for _ in range(size):
        total += bytes_to_int(stack.get())

    stack.put(int_to_bytes(total))

def OP_SUBTRACT_INTS(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as uint count;
        pull that many values from the stack, interpreting them as
        signed ints; subtract count-1 of them from the first one; put
        the result onto the stack.
    """
    count = int.from_bytes(tape.read(1), 'big')
    total = bytes_to_int(stack.get())

    for _ in range(count-1):
        item = stack.get()
        number = bytes_to_int(item)
        total -= number

    stack.put(int_to_bytes(total))

def OP_MULT_INTS(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned
        int; pull that many values from the stack, interpreting them as
        signed ints; multiply them together; put the result back onto
        the stack.
    """
    count = int.from_bytes(tape.read(1), 'big')
    total = bytes_to_int(stack.get())

    for _ in range(count-1):
        total *= bytes_to_int(stack.get())

    stack.put(int_to_bytes(total))

def OP_DIV_INT(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned
        int; read that many bytes from the tape, interpreting as a
        signed int divisor (denominator); pull a value from the stack,
        interpreting as a signed int dividend (numerator); divide the
        dividend by the divisor; put the result onto the stack.
    """
    size = int.from_bytes(tape.read(1), 'big')
    divisor = bytes_to_int(tape.read(size))
    dividend = bytes_to_int(stack.get())
    stack.put(int_to_bytes(dividend // divisor))

def OP_DIV_INTS(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pull two values from the stack, interpreting as signed ints;
        divide the first by the second; put the result onto the stack.
    """
    dividend = bytes_to_int(stack.get())
    divisor = bytes_to_int(stack.get())
    stack.put(int_to_bytes(dividend // divisor))

def OP_MOD_INT(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned
        int; read that many bytes from the tape, interpreting as a
        signed int divisor; pull a value from the stack, interpreting
        as a signed int dividend; perform integer modulus: dividend %
        divisor; put the result onto the stack.
    """
    size = int.from_bytes(tape.read(1), 'big')
    divisor = bytes_to_int(tape.read(size))
    dividend = bytes_to_int(stack.get())
    stack.put(int_to_bytes(dividend % divisor))

def OP_MOD_INTS(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pull two values from the stack, interpreting as signed ints;
        perform integer modulus: first % second; put the result onto the
        stack.
    """
    dividend = bytes_to_int(stack.get())
    divisor = bytes_to_int(stack.get())
    stack.put(int_to_bytes(dividend % divisor))

def OP_ADD_FLOATS(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        pull that many values from the stack, interpreting them as
        floats; add them together; put the result back onto the stack.
    """
    count = int.from_bytes(tape.read(1), 'big')
    total = 0.0

    for _ in range(count):
        item = stack.get()
        tert(type(item) is bytes and len(item) == 4,
            'OP_ADD_FLOATS malformed float')
        item, = struct.unpack('!f', item)
        total += item

    vert(not isnan(total), 'OP_ADD_FLOATS nan encountered')

    stack.put(struct.pack('!f', total))

def OP_SUBTRACT_FLOATS(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        pull that many values from the stack, interpreting them as
        floats; subtract them from the first one; put the result back
        onto the stack.
    """
    count = int.from_bytes(tape.read(1), 'big')
    item = stack.get()
    tert(type(item) is bytes and len(item) == 4,
        'OP_SUBTRACT_FLOATS malformed float')
    total = bytes_to_float(item)

    for _ in range(count-1):
        item = stack.get()
        tert(type(item) is bytes and len(item) == 4,
            'OP_SUBTRACT_FLOATS malformed float')
        number = bytes_to_float(item)
        total -= number

    vert(not isnan(total), 'OP_SUBTRACT_FLOATS nan encountered')

    stack.put(struct.pack('!f', total))

def OP_DIV_FLOAT(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next 4 bytes from the tape, interpreting as a float
        divisor; pull a value from the stack, interpreting as a float
        dividend; divide the dividend by the divisor; put the result
        onto the stack.
    """
    divisor = bytes_to_float(tape.read(4))
    item = stack.get()
    tert(type(item) is bytes and len(item) == 4,
        'OP_DIV_FLOAT malformed float')
    dividend = bytes_to_float(item)
    result = dividend / divisor
    vert(not isnan(result), 'OP_DIV_FLOAT nan encountered')
    stack.put(float_to_bytes(result))

def OP_DIV_FLOATS(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pull two values from the stack, interpreting as floats; divide
        the second by the first; put the result onto the stack.
    """
    item = stack.get()
    tert(len(item) == 4, 'OP_DIV_FLOATS malformed float')
    dividend = bytes_to_float(item)

    item = stack.get()
    tert(len(item) == 4, 'OP_DIV_FLOATS malformed float')
    divisor = bytes_to_float(item)

    result = dividend / divisor
    vert(not isnan(result), 'OP_DIV_FLOATS nan encountered')
    stack.put(float_to_bytes(result))

def OP_MOD_FLOAT(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next 4 bytes from the tape, interpreting as a float
        divisor; pull a value from the stack, interpreting as a float
        dividend; perform float modulus: dividend % divisor; put the
        result onto the stack.
    """
    divisor = bytes_to_float(tape.read(4))
    item = stack.get()
    tert(type(item) is bytes and len(item) == 4, 'OP_MOD_FLOAT malformed float')
    dividend = bytes_to_float(item)
    result = dividend % divisor
    vert(not isnan(result), 'OP_MOD_FLOAT nan encountered')
    stack.put(float_to_bytes(result))

def OP_MOD_FLOATS(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pull two values from the stack, interpreting as floats; perform
        float modulus: second % first; put the result onto the stack.
    """
    item = stack.get()
    tert(type(item) is bytes and len(item) == 4, 'OP_MOD_FLOATS malformed float')
    divisor = bytes_to_float(item)

    item = stack.get()
    tert(type(item) is bytes and len(item) == 4, 'OP_MOD_FLOATS malformed float')
    dividend = bytes_to_float(item)

    result = dividend % divisor
    vert(not isnan(result), 'OP_MOD_FLOATS nan encountered')
    stack.put(float_to_bytes(result))

def OP_ADD_POINTS(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        pull that many values from the stack; add them together using
        ed25519 point addition; replace the result onto the stack.
    """
    count = int.from_bytes(tape.read(1), 'big')
    points = []

    for _ in range(count):
        points.append(stack.get())
        tert(type(points[-1]) in (bytes, VerifyKey),
            'OP_ADD_POINTS non-point value encountered')

    # raise an error for invalid points
    for pt in points:
        vert(nacl.bindings.crypto_core_ed25519_is_valid_point(pt),
            'OP_ADD_POINTS invalid point encountered')

    # compute the sum
    sum = aggregate_points(points)

    # put the sum onto the stack
    stack.put(sum)

def OP_COPY(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        pull a value from the stack; place that value and a number of
        copies corresponding to the int from the tape back onto the
        stack.
    """
    n_copies = int.from_bytes(tape.read(1), 'big')
    item = stack.get()

    for _ in range(n_copies + 1):
        stack.put(item)

def OP_DUP(tape: Tape, stack: Stack, cache: dict) -> None:
    """OP_COPY but with only 1 copy and no reading from the tape or
        advancing the pointer. Equivalent to OP_DUP in Bitcoin script.
    """
    item = stack.get()
    stack.put(item)
    stack.put(item)

def OP_SHA256(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pull an item from the stack and put its sha256 hash back onto
        the stack.
    """
    item = stack.get()
    stack.put(sha256(item).digest())

def OP_SHAKE256(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        pull an item from the stack; put its shake_256 hash of the
        spcified length back onto the stack.
    """
    size = int.from_bytes(tape.read(1), 'big')
    item = stack.get()
    stack.put(shake_256(item).digest(size))

def OP_VERIFY(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pull a value from the stack; evaluate it as a bool; and raise a
        ScriptExecutionError if it is False.
    """
    sert(bytes_to_bool(stack.get()), 'OP_VERIFY check failed')

def OP_EQUAL(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pull 2 items from the stack; compare them; put the bool result
        onto the stack.
    """
    item1, item2 = stack.get(), stack.get()
    stack.put(b'\xff' if bytes_are_same(item1, item2) else b'\x00')

def OP_EQUAL_VERIFY(tape: Tape, stack: Stack, cache: dict) -> None:
    """Runs OP_EQUAL then OP_VERIFY."""
    OP_EQUAL(tape, stack, cache)
    OP_VERIFY(tape, stack, cache)

def OP_CHECK_SIG(tape: Tape, stack: Stack, cache: dict) -> None:
    """Take a byte from the tape, interpreting as the encoded allowable
        sigflags; pull a value from the stack, interpreting as a
        VerifyKey; pull a value from the stack, interpreting as a
        signature; check the signature against the VerifyKey and the
        cached sigfields not disabled by a sig flag; put True onto the
        stack if verification succeeds, otherwise put False onto the
        stack. Runs the signature extension plugins beforehand.
    """
    run_sig_extensions(tape, stack, cache)
    allowable_flags = int.from_bytes(tape.read(1), 'big')
    vkey = stack.get()
    sig = stack.get()

    vert((type(vkey) is bytes and len(vkey) == nacl.bindings.crypto_sign_PUBLICKEYBYTES)
        or type(vkey) is VerifyKey,
        'OP_CHECK_SIG invalid vkey encountered')
    vert(type(sig) is bytes and len(sig) in (
        nacl.bindings.crypto_sign_BYTES, nacl.bindings.crypto_sign_BYTES + 1
        ),
        'OP_CHECK_SIG invalid sig encountered')

    vkey = vkey if type(vkey) is VerifyKey else VerifyKey(vkey)
    sig_flag = 0 if len(sig) == nacl.bindings.crypto_sign_BYTES else sig[-1]
    sig = sig if len(sig) == nacl.bindings.crypto_sign_BYTES else sig[:-1]

    sig_flag1 = sig_flag & 0b00000001
    sig_flag2 = sig_flag & 0b00000010
    sig_flag3 = sig_flag & 0b00000100
    sig_flag4 = sig_flag & 0b00001000
    sig_flag5 = sig_flag & 0b00010000
    sig_flag6 = sig_flag & 0b00100000
    sig_flag7 = sig_flag & 0b01000000
    sig_flag8 = sig_flag & 0b10000000

    if sig_flag1:
        sert(allowable_flags & 0b00000001, 'disallowed sigflag')
    if sig_flag2:
        sert(allowable_flags & 0b00000010, 'disallowed sigflag')
    if sig_flag3:
        sert(allowable_flags & 0b00000100, 'disallowed sigflag')
    if sig_flag4:
        sert(allowable_flags & 0b00001000, 'disallowed sigflag')
    if sig_flag5:
        sert(allowable_flags & 0b00010000, 'disallowed sigflag')
    if sig_flag6:
        sert(allowable_flags & 0b00100000, 'disallowed sigflag')
    if sig_flag7:
        sert(allowable_flags & 0b01000000, 'disallowed sigflag')
    if sig_flag8:
        sert(allowable_flags & 0b10000000, 'disallowed sigflag')

    OP_GET_MESSAGE(Tape(sig_flag.to_bytes(1, 'big')), stack, cache)
    message = stack.get()

    try:
        vkey.verify(message, sig)
        stack.put(b'\xff')
    except BadSignatureError:
        stack.put(b'\x00')

def OP_CHECK_SIG_VERIFY(tape: Tape, stack: Stack, cache: dict) -> None:
    """Runs OP_CHECK_SIG, then OP_VERIFY."""
    OP_CHECK_SIG(tape, stack, cache)
    OP_VERIFY(tape, stack, cache)

def OP_CHECK_TIMESTAMP(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pulls a value from the stack, interpreting as an unsigned int;
        gets the timestamp to check from the cache; compares the two
        values; if the cache timestamp is less than the stack time, or
        if current Unix epoch is behind cache timestamp by the flagged
        amount, put False onto the stack; otherwise, put True onto the
        stack. If the ts_threshold flag is <= 0, that check will be
        skipped.
    """
    constraint = stack.get()
    sert(type(constraint) is bytes and len(constraint) > 0,
        'OP_CHECK_TIMESTAMP malformed constraint encountered')
    constraint = int.from_bytes(constraint, 'big')

    sert('timestamp' in cache, 'OP_CHECK_TIMESTAMP cache missing timestamp')
    sert(type(cache['timestamp']) is int,
        'OP_CHECK_TIMESTAMP malformed cache timestamp')

    sert('ts_threshold' in tape.flags,
        'OP_CHECK_TIMESTAMP missing ts_threshold flag')
    sert(type(tape.flags['ts_threshold']) is int,
        'OP_CHECK_TIMESTAMP malformed ts_threshold flag')

    difference = cache['timestamp'] - int(time())
    if cache['timestamp'] < constraint:
        stack.put(b'\x00')
    elif difference >= tape.flags['ts_threshold'] and \
        tape.flags['ts_threshold'] > 0:
        stack.put(b'\x00')
    else:
        stack.put(b'\xff')

def OP_CHECK_TIMESTAMP_VERIFY(tape: Tape, stack: Stack, cache: dict) -> None:
    """Runs OP_CHECK_TIMESTAMP, then OP_VERIFY."""
    OP_CHECK_TIMESTAMP(tape, stack, cache)
    OP_VERIFY(tape, stack, cache)

def OP_CHECK_EPOCH(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pulls a value from the stack, interpreting as an unsigned int;
        gets the current Unix epoch time; compares the two values; if
        current time is less than the stack time, put False onto the
        stack; otherwise, put True onto the stack.
    """
    constraint = stack.get()
    sert(type(constraint) is bytes and len(constraint) > 0,
        'OP_CHECK_EPOCH malformed constraint encountered')
    constraint = int.from_bytes(constraint, 'big')

    sert('epoch_threshold' in tape.flags,
        'OP_CHECK_EPOCH missing epoch_threshold flag')
    sert(type(tape.flags['epoch_threshold']) is int,
        'OP_CHECK_EPOCH malformed epoch_threshold flag')
    sert(tape.flags['epoch_threshold'] >= 0,
        'OP_CHECK_EPOCH malformed epoch_threshold flag')

    if constraint - int(time()) >= tape.flags['epoch_threshold']:
        stack.put(b'\x00')
    else:
        stack.put(b'\xff')

def OP_CHECK_EPOCH_VERIFY(tape: Tape, stack: Stack, cache: dict) -> None:
    """Runs OP_CHECK_EPOCH, then OP_VERIFY."""
    OP_CHECK_EPOCH(tape, stack, cache)
    OP_VERIFY(tape, stack, cache)

def OP_DEF(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape as the definition number; read
        the next 2 bytes from the tape, interpreting as an unsigned int;
        read that many bytes from the tape as the subroutine definition.
    """
    def_handle = tape.read(1)
    def_size = int.from_bytes(tape.read(2), 'big')

    def_data = tape.read(def_size)
    subtape = Tape(
        def_data,
        callstack_limit=tape.callstack_limit,
        contracts=tape.contracts,
        flags=tape.flags
    )
    tape.definitions[def_handle] = subtape
    subtape.definitions = tape.definitions

def OP_CALL(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape as the definition number; call
        run_tape passing that definition tape, the stack, and the cache.
    """
    sert(tape.callstack_count < tape.callstack_limit,
        'callstack limit exceeded')

    def_handle = tape.read(1)
    tape.callstack_count += 1
    subtape = tape.definitions[def_handle]
    init_pointer = subtape.pointer
    subtape.callstack_count = tape.callstack_count

    subtape.pointer = 0
    run_tape(subtape, stack, cache, additional_flags=tape.flags)
    subtape.pointer = init_pointer
    if 'returned' in cache:
        del cache['returned']

def OP_IF(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next 2 bytes from the tape, interpreting as an unsigned
        int; read that many bytes from the tape as a subroutine
        definition; pull a value from the stack and evaluate as a bool;
        if it is true, run the subroutine.
    """
    def_size = int.from_bytes(tape.read(2), 'big')

    def_data = tape.read(def_size)

    if bytes_to_bool(stack.get()):
        subtape = Tape(
            def_data,
            callstack_limit=tape.callstack_limit,
            callstack_count=tape.callstack_count,
            definitions={**tape.definitions},
            contracts=tape.contracts
        )
        run_tape(subtape, stack, cache, additional_flags=tape.flags)
        if 'returned' in cache:
            OP_RETURN(tape, stack, cache)

def OP_IF_ELSE(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next 2 bytes from the tape, interpreting as an unsigned
        int; read that many bytes from the tape as the IF subroutine
        definition; read the next 2 bytes from the tape, interpreting as
        an unsigned int; read that many bytes from the tape as the ELSE
        subroutine definition; pull a value from the stack and evaluate
        as a bool; if it is true, run the IF subroutine; else run the
        ELSE subroutine.
    """
    if_def_size = int.from_bytes(tape.read(2), 'big')
    if_def_data = tape.read(if_def_size)

    else_def_size = int.from_bytes(tape.read(2), 'big')
    else_def_data = tape.read(else_def_size)

    subtape = Tape(
        if_def_data if bytes_to_bool(stack.get()) else else_def_data,
        callstack_limit=tape.callstack_limit,
        callstack_count=tape.callstack_count,
        definitions={**tape.definitions},
        contracts=tape.contracts,
    )
    run_tape(subtape, stack, cache, additional_flags=tape.flags)
    if 'returned' in cache:
        OP_RETURN(tape, stack, cache)

def OP_EVAL(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pulls a value from the stack then attempts to run it as a script.
        OP_EVAL shares a common stack and cache with other ops. Script
        is disallowed from modifying tape.flags or tape.definitions; it
        is executed with callstack_count=tape.callstack_count+1 and
        copies of tape.flags and tape.definitions; it also has access to
        all loaded contracts.
    """
    sert('disallow_OP_EVAL' not in tape.flags, 'OP_EVAL disallowed')
    script = stack.get()
    vert(len(script) > 0, 'OP_EVAL encountered empty script')

    # setup
    subtape = Tape(
        script,
        callstack_count=tape.callstack_count+1,
        callstack_limit=tape.callstack_limit,
        definitions={**tape.definitions},
        contracts=tape.contracts,
        flags={**tape.flags}
    )

    # run
    run_tape(subtape, stack, cache, additional_flags=tape.flags)
    if 'returned' in cache:
        if 'eval_return' in tape.flags and tape.flags['eval_return']:
            OP_RETURN(tape, stack, cache)
        else:
            del cache['returned']

def OP_NOT(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pulls a value from the stack; performs bitwise NOT operation;
        puts result onto the stack.
    """
    item = stack.get()
    stack.put(not_bytes(item))

def OP_RANDOM(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pull an item from the tape, interpreting as a signed int; put
        that many random bytes onto the stack.
    """
    # size = int.from_bytes(tape.read(1), 'big')
    size = bytes_to_int(stack.get())
    stack.put(token_bytes(size))

def OP_RETURN(tape: Tape, stack: Stack, cache: dict) -> None:
    """Ends the script."""
    tape.pointer = len(tape.data)
    cache['returned'] = True

def OP_SET_FLAG(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        read that many bytes from the tape as a flag; set that flag.
    """
    size = int.from_bytes(tape.read(1), 'big')
    flag = tape.read(size)
    sert(flag in flags, 'OP_SET_FLAG unrecognized flag')
    tape.flags[flag] = flags[flag]

def OP_UNSET_FLAG(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        read that many bytes from the tape as a flag; unset that flag.
    """
    size = int.from_bytes(tape.read(1), 'big')
    flag = tape.read(size)
    if flag in tape.flags:
        del tape.flags[flag]

def OP_DEPTH(tape: Tape, stack: Stack, cache: dict) -> None:
    """Put the stack item count onto the stack."""
    stack.put(int_to_bytes(len(stack)))

def OP_SWAP(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next 2 bytes from the tape, interpreting as unsigned
        ints; swap the stack items at those depths.
    """
    first_idx = int.from_bytes(tape.read(1), 'big')
    second_idx = int.from_bytes(tape.read(1), 'big')

    if first_idx == second_idx:
        return

    max_idx = first_idx if first_idx > second_idx else second_idx
    sert(len(stack.deque) > max_idx, 'OP_SWAP stack size exceeded by index')

    length = len(stack.deque)
    first_idx = length - first_idx - 1
    second_idx = length - second_idx - 1

    first = stack.deque[first_idx]
    second = stack.deque[second_idx]
    stack.deque[first_idx] = second
    stack.deque[second_idx] = first

def OP_SWAP2(tape: Tape, stack: Stack, cache: dict) -> None:
    """Swap the order of the top two items of the stack."""
    first = stack.get()
    second = stack.get()
    stack.put(first)
    stack.put(second)

def OP_REVERSE(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        reverse that number of items from the top of the stack.
    """
    count = int.from_bytes(tape.read(1), 'big')
    sert(len(stack.deque) >= count, 'OP_REVERSE stack size exceeded')
    items = [stack.get() for _ in range(count)]
    [stack.put(item) for item in items]

def OP_CONCAT(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pull two items from the stack; concatenate them bottom+top; put
        the result onto the stack.
    """
    second = stack.get()
    first = stack.get()
    stack.put(first + second)

def OP_SPLIT(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int
        index; pull an item from the stack; split the item bytes at the
        index; put the second byte sequence onto the stack, then put the
        first byte sequence onto the stack.
    """
    index = int.from_bytes(tape.read(1), 'big')
    item = stack.get()
    sert(index < len(item), 'OP_SPLIT item len exceeded by index')
    part0 = item[:index]
    part1 = item[index:]
    stack.put(part0)
    stack.put(part1)

def OP_CONCAT_STR(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pull two items from the stack, interpreting as UTF-8 strings;
        concatenate them; put the result onto the stack.
    """
    second = str(stack.get(), 'utf-8')
    first = str(stack.get(), 'utf-8')
    stack.put(bytes(first + second, 'utf-8'))

def OP_SPLIT_STR(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int
        index; pull an item from the stack, interpreting as a UTF-8 str;
        split the item str at the index, then put the first str onto
        the stack; put the second str onto the stack.
    """
    index = int.from_bytes(tape.read(1), 'big')
    item = str(stack.get(), 'utf-8')
    sert(index < len(item), 'OP_SPLIT_STR item len exceeded by index')
    part0 = item[:index]
    part1 = item[index:]
    stack.put(bytes(part0, 'utf-8'))
    stack.put(bytes(part1, 'utf-8'))

def OP_CHECK_TRANSFER(tape: Tape, stack: Stack, cache: dict) -> None:
    """Take an item from the stack as a contract ID; take an item from
        the stack as an amount; take an item from the stack as a
        serialized txn constraint; take an item from the stack as a
        destination (address, locking script hash, etc); take an item
        from the stack, interpreting as an unsigned int count; take
        count number of items from the stack as sources; take the count
        number of items from the stack as transaction proofs; verify
        that the aggregate of the transfers to the destination from the
        sources equals or exceeds the amount; verify that the transfers
        were valid using the proofs and the contract code; verify that
        any constraints were followed; and put True onto the stack if
        successful and False otherwise. Sources and proofs must be in
        corresponding order.
    """
    # get parameters
    contract_id = stack.get()
    amount = bytes_to_int(stack.get())
    constraint = stack.get()
    destination = stack.get()
    count = int.from_bytes(stack.get(), 'big')
    sources = []
    txn_proofs = []
    all_proofs_valid = True

    for _ in range(count):
        sources.append(stack.get())

    for _ in range(count):
        txn_proofs.append(stack.get())

    # check contract is loaded and has required functions
    sert(contract_id in tape.contracts,
        'OP_CHECK_TRANSFER missing contract')
    sert(isinstance(tape.contracts[contract_id], CanCheckTransfer),
         'contract must implement the CanCheckTransfer interface')

    verify_txn_proof = tape.contracts[contract_id].verify_txn_proof
    verify_transfer = tape.contracts[contract_id].verify_transfer
    verify_txn_constraint = tape.contracts[contract_id].verify_txn_constraint
    calc_txn_aggregates = tape.contracts[contract_id].calc_txn_aggregates

    # check each proof
    for i in range(count):
        if not verify_txn_proof(txn_proofs[i]):
            all_proofs_valid = False
        if not verify_transfer(txn_proofs[i], sources[i], destination):
            all_proofs_valid = False
        if len(constraint) and not verify_txn_constraint(txn_proofs[i], constraint):
            all_proofs_valid = False

    # calculate aggregate
    aggregate = calc_txn_aggregates(txn_proofs, scope=destination)[destination]

    stack.put(b'\xff' if all_proofs_valid and amount <= aggregate else b'\x00')

def OP_MERKLEVAL(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read 32 bytes from the tape as the root digest; call OP_DUP then
        OP_SHA256 twice; move stack item at index 2 to the top and call
        OP_SHA256 once; call OP_XOR; call OP_SHA256; push root hash
        onto the stack; call OP_EQUAL_VERIFY; call OP_EVAL.
    """
    root_hash = tape.read(32)
    OP_DUP(tape, stack, cache)
    OP_SHA256(tape, stack, cache)
    OP_SHA256(tape, stack, cache)
    OP_SWAP(Tape(b'\x01\x02'), stack, cache)
    OP_SWAP2(tape, stack, cache)
    OP_SHA256(tape, stack, cache)
    OP_XOR(tape, stack, cache)
    stack.put(root_hash)
    OP_EQUAL_VERIFY(tape, stack, cache)
    OP_EVAL(tape, stack, cache)

def OP_TRY_EXCEPT(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next 2 bytes from the tape, interpreting as an unsigned
        int; read that many bytes from the tape as the TRY subroutine
        definition; read 2 bytes from the tape, interpreting as an
        unsigned int; read that many bytes as the EXCEPT subroutine
        definition; execute the TRY subroutine in a try block; if an
        error occurs, serialize it and put it in the cache then run the
        EXCEPT subroutine.
    """
    try_def_size = int.from_bytes(tape.read(2), 'big')
    try_def_data = tape.read(try_def_size)

    except_def_size = int.from_bytes(tape.read(2), 'big')
    except_def_data = tape.read(except_def_size)

    subtape = Tape(
        try_def_data,
        callstack_limit=tape.callstack_limit,
        callstack_count=tape.callstack_count,
        definitions={**tape.definitions},
        contracts=tape.contracts,
    )

    try:
        run_tape(subtape, stack, cache, additional_flags=tape.flags)
    except BaseException as e:
        serialized = e.__class__.__name__ + '|' + str(e)
        cache[b'E'] = [serialized.encode('utf-8')]
        subtape = Tape(
            except_def_data,
            callstack_limit=tape.callstack_limit,
            callstack_count=tape.callstack_count,
            definitions={**tape.definitions},
            contracts=tape.contracts,
        )
        run_tape(subtape, stack, cache, additional_flags=tape.flags)

    if 'returned' in cache:
        OP_RETURN(tape, stack, cache)

def OP_LESS(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pull two signed ints val1 and val2 from stack; put (v1<v2) onto
        stack.
    """
    val1 = bytes_to_int(stack.get())
    val2 = bytes_to_int(stack.get())
    stack.put(b'\xff' if val1 < val2 else b'\x00')

def OP_LESS_OR_EQUAL(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pull two signed ints val1 and val2 from stack; put (v1<=v2) onto
        stack.
    """
    val1 = bytes_to_int(stack.get())
    val2 = bytes_to_int(stack.get())
    stack.put(b'\xff' if val1 <= val2 else b'\x00')

def OP_GET_VALUE(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read one byte from the tape as uint size; read size bytes from
        the tape, interpreting as utf-8 string; put the read-only cache
        value(s) at that cache key onto the stack, serialized as bytes.
    """
    size = int.from_bytes(tape.read(1), 'big')
    key = str(tape.read(size), 'utf-8')
    sert(key in cache, f'OP_GET_VALUE key "{key}" not in cache')
    items = cache[key] if type(cache[key]) in (list, tuple) else [cache[key]]
    for val in items:
        if type(val) in (bytes, bytearray):
            stack.put(val)
        elif type(val) is str:
            stack.put(bytes(val, 'utf-8'))
        elif type(val) is int:
            stack.put(int_to_bytes(val))
        elif type(val) is float:
            stack.put(float_to_bytes(val))

def OP_FLOAT_LESS(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pull two floats val1 and val2 from stack; put (v1<v2) onto stack."""
    val1 = bytes_to_float(stack.get())
    val2 = bytes_to_float(stack.get())
    stack.put(b'\xff' if val1 < val2 else b'\x00')

def OP_FLOAT_LESS_OR_EQUAL(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pull two floats val1 and val2 from stack; put (v1<=v2) onto stack."""
    val1 = bytes_to_float(stack.get())
    val2 = bytes_to_float(stack.get())
    stack.put(b'\xff' if val1 <= val2 else b'\x00')

def OP_INT_TO_FLOAT(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pull a signed int from the stack and put it back as a float."""
    value = bytes_to_int(stack.get())
    stack.put(float_to_bytes(1.0 * value))

def OP_FLOAT_TO_INT(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pull a float from the stack and put it back as a signed int."""
    value = bytes_to_float(stack.get())
    stack.put(int_to_bytes(int(value)))

def OP_LOOP(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read 2 bytes from the tape as uint len; read that many bytes from
        the tape as the loop definition; run the loop as long as the top
        value of the stack is not false or until a callstack limit
        exceeded error is raised.
    """
    loop_size = int.from_bytes(tape.read(2), 'big')
    loop_def = tape.read(loop_size)
    condition = stack.peek()
    count = 0

    subtape = Tape(
        loop_def, callstack_limit=tape.callstack_limit,
        callstack_count=tape.callstack_count,
        definitions=tape.definitions, flags=tape.flags,
        contracts=tape.contracts
    )

    while bytes_to_bool(condition):
        sert(count < tape.callstack_limit, 'OP_LOOP limit exceeded')
        run_tape(subtape, stack, cache)
        if 'returned' in cache:
            return
        subtape.reset_pointer()
        count += 1
        condition = stack.peek()

def OP_CHECK_MULTISIG(tape: Tape, stack: Stack, cache: dict) -> None:
    """Reads 1 byte from tape as allowable flags; reads 1 byte from tape
        as uint m; reads 1 byte from tape as uint n; pulls n values from
        stack as vkeys; pulls m values from stack as signatures;
        verifies each signature against vkeys; puts false onto the stack
        if any signature fails to validate with one of the vkeys or if
        any vkey is used more than once; puts true onto the stack
        otherwise.
    """
    run_sig_extensions(tape, stack, cache)
    subtape = Tape(tape.read(1))
    m = int.from_bytes(tape.read(1), 'big')
    n = int.from_bytes(tape.read(1), 'big')
    vkeys = [stack.get() for _ in range(n)]
    sigs = [stack.get() for _ in range(m)]
    confirmed = set()

    for sig in sigs:
        for vkey in vkeys:
            subtape.reset_pointer()
            stack.put(sig)
            stack.put(vkey)
            OP_CHECK_SIG(subtape, stack, cache)
            result = bytes_to_bool(stack.get())
            if result:
                vkeys.remove(vkey)
                confirmed.add(sig)
                break

    if len(confirmed) == len(sigs):
        stack.put(b'\xff')
    else:
        stack.put(b'\x00')

def OP_CHECK_MULTISIG_VERIFY(tape: Tape, stack: Stack, cache: dict) -> None:
    """Runs OP_CHECK_MULTISIG then OP_VERIFY."""
    OP_CHECK_MULTISIG(tape, stack, cache)
    OP_VERIFY(tape, stack, cache)

def OP_SIGN(tape: Tape, stack: Stack, cache: dict) -> None:
    """Reads 1 byte from the tape as the sig_flag; pulls a value from
        the stack, interpreting as a SigningKey; creates a signature
        using the correct sigfields; puts the signature onto the stack.
        Raises ValueError for invalid key seed length. Runs the
        signature extension plugins beforehand.
    """
    run_sig_extensions(tape, stack, cache)
    sig_flag = int.from_bytes(tape.read(1), 'big')
    skey_seed = stack.get()
    vert(len(skey_seed) == nacl.bindings.crypto_sign_SEEDBYTES,
         'invalid signing key; must be ' +
         f'{nacl.bindings.crypto_sign_SEEDBYTES} bytes')

    OP_GET_MESSAGE(Tape(sig_flag.to_bytes(1, 'big')), stack, cache)
    message = stack.get()

    skey = SigningKey(skey_seed)
    sig = skey.sign(message).signature
    sig = sig + sig_flag.to_bytes(1, 'big') if sig_flag else sig
    if 9 in tape.flags and tape.flags[9]:
        cache[b's'] = sig
    stack.put(sig)

def OP_SIGN_STACK(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pulls a value from the stack, interpreting as a SigningKey; pulls
        a message from the stack; signs the message with the SigningKey;
        puts the signature onto the stack. Raises ValueError for invalid
        key seed length.
    """
    seed = stack.get()
    msg = stack.get()
    vert(len(seed) == nacl.bindings.crypto_sign_SEEDBYTES)
    skey = SigningKey(seed)
    sig = skey.sign(msg).signature
    if 9 in tape.flags and tape.flags[9]:
        cache[b's'] = sig
    stack.put(sig)

def OP_CHECK_SIG_STACK(tape: Tape, stack: Stack, cache: dict) -> None:
    """Pulls a value from the stack, interpreting as a VerifyKey; pulls
        a message from the stack; pulls a value from the stack,
        interpreting as a signature; puts True onto the stack if the
        signature is valid for the message and the VerifyKey, otherwise
        puts False onto the stack. Raises ValueError for invalid vkey or
        signature.
    """
    vkey = stack.get()
    vert(len(vkey) == nacl.bindings.crypto_core_ed25519_BYTES, 'invalid vkey')
    msg = stack.get()
    sig = stack.get()
    vert(len(sig) == nacl.bindings.crypto_sign_BYTES, 'invalid signature')
    try:
        VerifyKey(vkey).verify(msg, sig)
        OP_TRUE(tape, stack, cache)
    except:
        OP_FALSE(tape, stack, cache)

def OP_DERIVE_SCALAR(tape: Tape, stack: Stack, cache: dict) -> None:
    """Takes a value seed from stack; derives an ed25519 key scalar from
        the seed; puts the key scalar onto the stack. Sets cache key
        b'x' to x if allowed by tape.flags.
    """
    seed = stack.get()
    x = derive_key_from_seed(seed)
    if 1 in tape.flags and tape.flags[1]:
        cache[b'x'] = x
    stack.put(x)

def OP_CLAMP_SCALAR(tape: Tape, stack: Stack, cache: dict) -> None:
    """Reads a byte from the tape, interpreting as a bool is_key; takes
        a value from the stack; clamps it to an ed25519 scalar; puts the
        clamped ed25519 scalar onto the stack. Raises ValueError for
        invalid value.
    """
    is_key = bytes_to_bool(tape.read(1))
    value = stack.get()
    stack.put(clamp_scalar(value, is_key))

def OP_ADD_SCALARS(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        pull that many values from the stack; add them together using
        ed25519 scalar addition; put the sum onto the stack.
    """
    count = int.from_bytes(tape.read(1), 'big')
    scalars = []

    for _ in range(count):
        scalars.append(stack.get())

    # compute the sum
    sum = aggregate_scalars(scalars)

    # put the sum onto the stack
    stack.put(sum)

def OP_SUBTRACT_SCALARS(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as uint count;
        pull that many values from the stack, interpreting them as
        ed25519 scalars; subtract count-1 of them from the first one;
        put the difference onto the stack.
    """
    count = int.from_bytes(tape.read(1), 'big')
    total = stack.get()

    for _ in range(count-1):
        item = stack.get()
        total = nacl.bindings.crypto_core_ed25519_scalar_sub(total, item)

    stack.put(total)

def OP_DERIVE_POINT(tape: Tape, stack: Stack, cache: dict) -> None:
    """Takes an an ed25519 scalar value x from the stack; derives a
        curve point X from scalar value x; puts X onto stack; sets cache
        key b'X' to X if allowed by tape.flags (can be used in code with
        @X).
    """
    x = stack.get()
    X = derive_point_from_scalar(x)
    if 2 in tape.flags and tape.flags[2]:
        cache[b'X'] = X
    stack.put(X)

def OP_SUBTRACT_POINTS(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        pull that many values from the stack, interpreting them as
        ed25519 scalars; subtract them from the first one; put the
        result onto the stack.
    """
    count = int.from_bytes(tape.read(1), 'big')
    total = stack.get()

    for _ in range(count-1):
        item = stack.get()
        total = nacl.bindings.crypto_core_ed25519_sub(total, item)

    stack.put(total)

def OP_MAKE_ADAPTER_SIG_PUBLIC(tape: Tape, stack: Stack, cache: dict) -> None:
    """Takes three items from stack: public tweak point T, message m,
        and prvkey seed; creates a signature adapter sa; puts nonce
        point R onto stack; puts signature adapter sa onto stack; sets
        cache keys b'R' to R, b'T' to T, and b'sa' to sa if allowed by
        tape.flags (can be used in code with @R, @T, and @sa).
    """
    T = stack.get()
    m = stack.get()
    seed = stack.get()
    x = derive_key_from_seed(seed)
    X = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(x) # G^x
    nonce = H_big(seed)[32:]
    r = clamp_scalar(H_small(H_big(nonce, m))) # H(nonce || m)
    R = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(r) # G^r
    RT = aggregate_points((R, T)) # R + t
    ca = clamp_scalar(H_small(RT, X, m)) # H(R + T || X || m)
    sa = nacl.bindings.crypto_core_ed25519_scalar_add(
        r, nacl.bindings.crypto_core_ed25519_scalar_mul(ca, x)
    ) # r + H(R + T || X || m) * x
    if 3 in tape.flags and tape.flags[3]:
        cache[b'r'] = r
    if 4 in tape.flags and tape.flags[4]:
        cache[b'R'] = R
    if 6 in tape.flags and tape.flags[6]:
        cache[b'T'] = T
    if 8 in tape.flags and tape.flags[8]:
        cache[b'sa'] = sa
    stack.put(R)
    stack.put(sa)

def OP_MAKE_ADAPTER_SIG_PRIVATE(tape: Tape, stack: Stack, cache: dict) -> None:
    """Takes three values, seed, t, and message m from the stack;
        derives prvkey x from seed; derives pubkey X from x; derives
        private nonce r from seed and m; derives public nonce point R
        from r; derives public tweak point T from t; creates signature
        adapter sa; puts T, R, and sa onto stack; sets cache keys b't'
        to t if tape.flags[5], b'T' to T if tape.flags[6], b'R' to R if
        tape.flags[4], and b'sa' to sa if tape.flags[8] (can be used in
        code with @t, @T, @R, and @sa). Values seed and t should be 32
        bytes each. Values T, R, and sa are all public 32 byte values
        and necessary for verification; t is used to decrypt the
        signature.
    """
    seed = stack.get()
    t = clamp_scalar(stack.get())
    m = stack.get()
    x = derive_key_from_seed(seed)
    X = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(x) # G^x
    T = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(t) # G^x
    nonce = H_big(seed)[32:]
    r = clamp_scalar(H_small(nonce, m))
    R = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(r) # G^r
    c = clamp_scalar(H_small(R, X, m)) # clamp(H(R || X || m))
    tr = nacl.bindings.crypto_core_ed25519_scalar_add(t, r)
    sa = nacl.bindings.crypto_core_ed25519_scalar_add(
        tr, nacl.bindings.crypto_core_ed25519_scalar_mul(c, x)
    ) # t + r + c*x
    if 4 in tape.flags and tape.flags[4]:
        cache[b'R'] = R
    if 5 in tape.flags and tape.flags[5]:
        cache[b't'] = t
    if 6 in tape.flags and tape.flags[6]:
        cache[b'T'] = T
    if 8 in tape.flags and tape.flags[8]:
        cache[b'sa'] = sa
    stack.put(T)
    stack.put(R)
    stack.put(sa)

def OP_CHECK_ADAPTER_SIG(tape: Tape, stack: Stack, cache: dict) -> None:
    """Takes public key X, tweak point T, message m, nonce point R, and
        signature adapter sa from the stack; puts True onto stack
        if the signature adapter is valid and False otherwise.
    """
    X = stack.get()
    T = stack.get()
    m = stack.get()
    R = stack.get()
    sa = stack.get()
    sa_G = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(sa) # sa_G = G^sa
    RT = aggregate_points((R, T)) # R + T
    ca = clamp_scalar(H_small(RT, X, m)) # H(R + T || X || m)
    caX = nacl.bindings.crypto_scalarmult_ed25519_noclamp(ca, X) # X^H(R + T || X || m)
    RcaX = aggregate_points((R, caX)) # R + X^H(R + T || X || m)
    stack.put(b'\xff' if bytes_are_same(sa_G, RcaX) else b'\x00')

def OP_DECRYPT_ADAPTER_SIG(tape: Tape, stack: Stack, cache: dict) -> None:
    """Takes tweak scalar t, nonce point R, and signature adapter sa
        from stack; calculates nonce RT; decrypts signature s from sa;
        puts RT onto the stack; puts s onto stack; sets cache keys b's'
        to s if tape.flags[9] and b'RT' to RT if tape.flags[7] (can be
        used in code with @s and @RT).
    """
    t = clamp_scalar(stack.get())
    R = stack.get()
    sa = stack.get()
    T = derive_point_from_scalar(t)
    RT = aggregate_points((R, T)) # R + T
    s = nacl.bindings.crypto_core_ed25519_scalar_add(sa, t) # s = sa + t
    if 7 in tape.flags and tape.flags[7]:
        cache[b'RT'] = RT
    if 9 in tape.flags and tape.flags[9]:
        cache[b's'] = s
    stack.put(RT)
    stack.put(s)

def OP_INVOKE(tape: Tape, stack: Stack, cache: dict) -> None:
    """Takes an item from the stack as `contract_id`; takes an int from
        the stack as `argcount`; takes `argcount` items from the stack
        as arguments; tries to invoke the contract's abi method, passing
        it the arguments; puts any return values onto the stack. Raises
        ScriptExecutionError if the argcount is negative, contract is
        missing, or the contract does not implement the `CanBeInvoked`
        interface. Raises TypeError if the return value type is not
        bytes or NoneType. If allowed by tape.flag[0], will put any
        return values into cache at key b'IR'.
    """
    contract_id = stack.get()
    argcount = bytes_to_int(stack.get())
    sert(argcount >= 0, 'OP_INVOKE invalid argcount encountered')
    args = []
    for _ in range(argcount):
        args.append(stack.get())

    sert(contract_id in tape.contracts, 'OP_INVOKE unknown contract')
    contract = tape.contracts[contract_id]
    sert(isinstance(contract, CanBeInvoked),
        'contract must implement the CanBeInvoked interface')
    result = getattr(contract, 'abi')(args)
    tert(type(result) in (tuple, list, type(None)),
         'invalid contract: abi return value must be tuple[bytes] or None')
    if result is not None:
        for r in result:
            tert(type(r) is bytes,
                 'invalid contract: abi return value must be tuple[bytes] or None')
            stack.put(r)
        if 0 in tape.flags and tape.flags[0]:
            cache[b'IR'] = result

def OP_XOR(tape: Tape, stack: Stack, cache: dict) -> None:
    """Takes two values from the stack; XORs them together; puts result
        onto the stack. Pads the shorter length value with x00.
    """
    item1 = stack.get()
    item2 = stack.get()
    while len(item1) < len(item2):
        item1 += b'\x00'
    while len(item1) > len(item2):
        item2 += b'\x00'
    result = xor(item1, item2)
    stack.put(result)

def OP_OR(tape: Tape, stack: Stack, cache: dict) -> None:
    """Takes two values from the stack; ORs them together; puts result
        onto the stack. Pads the shorter length value with x00.
    """
    item1 = stack.get()
    item2 = stack.get()
    while len(item1) < len(item2):
        item1 += b'\x00'
    while len(item1) > len(item2):
        item2 += b'\x00'
    result = or_bytes(item1, item2)
    stack.put(result)

def OP_AND(tape: Tape, stack: Stack, cache: dict) -> None:
    """Takes two values from the stack; ANDs them together; puts result
        onto the stack. Pads the shorter length value with x00.
    """
    item1 = stack.get()
    item2 = stack.get()
    while len(item1) < len(item2):
        item1 += b'\x00'
    while len(item1) > len(item2):
        item2 += b'\x00'
    result = and_bytes(item1, item2)
    stack.put(result)

def OP_CHECK_TEMPLATE(tape: Tape, stack: Stack, cache: dict) -> None:
    """Reads 1 byte from the tape, interpreting as sigflags; pull an
        item from the stack for each indicated sigfield as a template;
        check that all indicated sigfields validate against the template
        using the plugin system; put True onto the stack if every
        sigfield validated against its template by at least one ctv
        plugin function, and False otherwise. Runs the signature
        extension plugins first if tape.flags[10] is set to True, which
        is the default behavior.
    """
    if tape.flags.get(10, True):
        run_sig_extensions(tape, stack, cache)
    sig_flag = int.from_bytes(tape.read(1), 'big')
    all_valid = True

    sig_flags = {
        '1': sig_flag & 0b00000001,
        '2': sig_flag & 0b00000010,
        '3': sig_flag & 0b00000100,
        '4': sig_flag & 0b00001000,
        '5': sig_flag & 0b00010000,
        '6': sig_flag & 0b00100000,
        '7': sig_flag & 0b01000000,
        '8': sig_flag & 0b10000000,
    }

    for i, flag in sig_flags.items():
        if not flag:
            continue
        template = stack.get()
        field = cache[f'sigfield{i}']
        s = Stack()
        s.put(field)
        s.put(template)
        t = Tape(b'', plugins={**tape.plugins}, contracts={**tape.contracts})
        result = run_plugins('check_template', t, s, cache)
        if not len(result):
            all_valid = all_valid and bytes_are_same(template, field)
        else:
            all_valid = all_valid and any(result)

    stack.put(b'\xff' if all_valid else b'\x00')

def OP_CHECK_TEMPLATE_VERIFY(tape: Tape, stack: Stack, cache: dict) -> None:
    """Runs OP_CHECK_TEMPLATE and then OP_VERIFY."""
    OP_CHECK_TEMPLATE(tape, stack, cache)
    OP_VERIFY(tape, stack, cache)

def OP_TAPROOT(tape: Tape, stack: Stack, cache: dict) -> None:
    """Reads 32 bytes from the tape as the root; gets a copy of the top
        stack item (using stack.peek); if the item has length 32, it is
        an ed25519 public key, otherwise it is a signature; if it was a
        public key, then it is executing the committed script; if it is
        a signature, then it is executing the key-spend path. For
        key-spend, pull the sigflags from cache b'trsf' or
        'taproot_sigflags', but replace with 0x00 if it does not
        disallow exclusion of at least one sigfield (i.e. has at least
        one null bit), then run `OP_CHECK_SIG`. For committed script
        execution, first `SWAP2` so the script is on top; then `DUP`;
        `SWAP 1 2` so the pubkey is second from the top; `SHA256` the
        top item to get the script commitment; `CLAMP_SALAR 0x00`,
        `DERIVE_POINT`, and `ADD_POINTS 2` to combine the pubkey and the
        script commitment; if the result was the root, then `OP_EVAL`,
        otherwise remove the script and put 0x00 onto the stack.
    """
    root = tape.read(32)
    pubkey_or_sig = stack.peek()
    is_pubkey = len(pubkey_or_sig) == 32

    if is_pubkey:
        OP_SWAP2(tape, stack, cache)
        OP_DUP(tape, stack, cache)
        OP_SWAP(Tape(uint_to_bytes(1) + uint_to_bytes(2)), stack, cache)
        OP_SHA256(tape, stack, cache)
        OP_CLAMP_SCALAR(Tape(b'\x00'), stack, cache)
        OP_DERIVE_POINT(tape, stack, cache)
        OP_ADD_POINTS(Tape(uint_to_bytes(2)), stack, cache)
        if not bytes_are_same(stack.get(), root):
            _ = stack.get() # remove script
            stack.put(b'\x00')
            return
        OP_EVAL(tape, stack, cache)
    else:
        # take sigflags from cache address b'trsf' or default
        sigflags = cache.get(b'trsf', cache.get('taproot_sigflags', [b'\x00']))[0]
        # ensure that at least one field is not allowed to be excluded (null bit)
        if not bytes_to_bool(not_bytes(sigflags)) or len(sigflags) != 1:
            sigflags = b'\x00'
        stack.put(root)
        OP_CHECK_SIG(Tape(sigflags), stack, cache)

def NOP(tape: Tape, stack: Stack, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as a signed int
        and pull that many values from the stack. Does nothing with the
        values. Useful for later soft-forks by redefining byte codes.
        Raises ScriptExecutionError if count is negative.
    """
    count = bytes_to_int(tape.read(1))
    sert(count >= 0, 'NOP count must not be negative')

    for _ in range(count):
        stack.get()


opcodes = [
    ('OP_FALSE', OP_FALSE),
    ('OP_TRUE', OP_TRUE),
    ('OP_PUSH0', OP_PUSH0),
    ('OP_PUSH1', OP_PUSH1),
    ('OP_PUSH2', OP_PUSH2),
    ('OP_GET_MESSAGE', OP_GET_MESSAGE),
    ('OP_POP0', OP_POP0),
    ('OP_POP1', OP_POP1),
    ('OP_SIZE', OP_SIZE),
    ('OP_WRITE_CACHE', OP_WRITE_CACHE),
    ('OP_READ_CACHE', OP_READ_CACHE),
    ('OP_READ_CACHE_SIZE', OP_READ_CACHE_SIZE),
    ('OP_READ_CACHE_STACK', OP_READ_CACHE_STACK),
    ('OP_READ_CACHE_STACK_SIZE', OP_READ_CACHE_STACK_SIZE),
    ('OP_ADD_INTS', OP_ADD_INTS),
    ('OP_SUBTRACT_INTS', OP_SUBTRACT_INTS),
    ('OP_MULT_INTS', OP_MULT_INTS),
    ('OP_DIV_INT', OP_DIV_INT),
    ('OP_DIV_INTS', OP_DIV_INTS),
    ('OP_MOD_INT', OP_MOD_INT),
    ('OP_MOD_INTS', OP_MOD_INTS),
    ('OP_ADD_FLOATS', OP_ADD_FLOATS),
    ('OP_SUBTRACT_FLOATS', OP_SUBTRACT_FLOATS),
    ('OP_DIV_FLOAT', OP_DIV_FLOAT),
    ('OP_DIV_FLOATS', OP_DIV_FLOATS),
    ('OP_MOD_FLOAT', OP_MOD_FLOAT),
    ('OP_MOD_FLOATS', OP_MOD_FLOATS),
    ('OP_ADD_POINTS', OP_ADD_POINTS),
    ('OP_COPY', OP_COPY),
    ('OP_DUP', OP_DUP),
    ('OP_SHA256', OP_SHA256),
    ('OP_SHAKE256', OP_SHAKE256),
    ('OP_VERIFY', OP_VERIFY),
    ('OP_EQUAL', OP_EQUAL),
    ('OP_EQUAL_VERIFY', OP_EQUAL_VERIFY),
    ('OP_CHECK_SIG', OP_CHECK_SIG),
    ('OP_CHECK_SIG_VERIFY', OP_CHECK_SIG_VERIFY),
    ('OP_CHECK_TIMESTAMP', OP_CHECK_TIMESTAMP),
    ('OP_CHECK_TIMESTAMP_VERIFY', OP_CHECK_TIMESTAMP_VERIFY),
    ('OP_CHECK_EPOCH', OP_CHECK_EPOCH),
    ('OP_CHECK_EPOCH_VERIFY', OP_CHECK_EPOCH_VERIFY),
    ('OP_DEF', OP_DEF),
    ('OP_CALL', OP_CALL),
    ('OP_IF', OP_IF),
    ('OP_IF_ELSE', OP_IF_ELSE),
    ('OP_EVAL', OP_EVAL),
    ('OP_NOT', OP_NOT),
    ('OP_RANDOM', OP_RANDOM),
    ('OP_RETURN', OP_RETURN),
    ('OP_SET_FLAG', OP_SET_FLAG),
    ('OP_UNSET_FLAG', OP_UNSET_FLAG),
    ('OP_DEPTH', OP_DEPTH),
    ('OP_SWAP', OP_SWAP),
    ('OP_SWAP2', OP_SWAP2),
    ('OP_REVERSE', OP_REVERSE),
    ('OP_CONCAT', OP_CONCAT),
    ('OP_SPLIT', OP_SPLIT),
    ('OP_CONCAT_STR', OP_CONCAT_STR),
    ('OP_SPLIT_STR', OP_SPLIT_STR),
    ('OP_CHECK_TRANSFER', OP_CHECK_TRANSFER),
    ('OP_MERKLEVAL', OP_MERKLEVAL),
    ('OP_TRY_EXCEPT', OP_TRY_EXCEPT),
    ('OP_LESS', OP_LESS),
    ('OP_LESS_OR_EQUAL', OP_LESS_OR_EQUAL),
    ('OP_GET_VALUE', OP_GET_VALUE),
    ('OP_FLOAT_LESS', OP_FLOAT_LESS),
    ('OP_FLOAT_LESS_OR_EQUAL', OP_FLOAT_LESS_OR_EQUAL),
    ('OP_INT_TO_FLOAT', OP_INT_TO_FLOAT),
    ('OP_FLOAT_TO_INT', OP_FLOAT_TO_INT),
    ('OP_LOOP', OP_LOOP),
    ('OP_CHECK_MULTISIG', OP_CHECK_MULTISIG),
    ('OP_CHECK_MULTISIG_VERIFY', OP_CHECK_MULTISIG_VERIFY),
    ('OP_SIGN', OP_SIGN),
    ('OP_SIGN_STACK', OP_SIGN_STACK),
    ('OP_CHECK_SIG_STACK', OP_CHECK_SIG_STACK),
    ('OP_DERIVE_SCALAR', OP_DERIVE_SCALAR),
    ('OP_CLAMP_SCALAR', OP_CLAMP_SCALAR),
    ('OP_ADD_SCALARS', OP_ADD_SCALARS),
    ('OP_SUBTRACT_SCALARS', OP_SUBTRACT_SCALARS),
    ('OP_DERIVE_POINT', OP_DERIVE_POINT),
    ('OP_SUBTRACT_POINTS', OP_SUBTRACT_POINTS),
    ('OP_MAKE_ADAPTER_SIG_PUBLIC', OP_MAKE_ADAPTER_SIG_PUBLIC),
    ('OP_MAKE_ADAPTER_SIG_PRIVATE', OP_MAKE_ADAPTER_SIG_PRIVATE),
    ('OP_CHECK_ADAPTER_SIG', OP_CHECK_ADAPTER_SIG),
    ('OP_DECRYPT_ADAPTER_SIG', OP_DECRYPT_ADAPTER_SIG),
    ('OP_INVOKE', OP_INVOKE),
    ('OP_XOR', OP_XOR),
    ('OP_OR', OP_OR),
    ('OP_AND', OP_AND),
    ('OP_CHECK_TEMPLATE', OP_CHECK_TEMPLATE),
    ('OP_CHECK_TEMPLATE_VERIFY', OP_CHECK_TEMPLATE_VERIFY),
    ('OP_TAPROOT', OP_TAPROOT),
]
opcodes: dict[int, tuple[str, Callable]] = {x: opcodes[x] for x in range(len(opcodes))}

nopcodes = {}

for i in range(len(opcodes), 256):
    nopcodes[i] = (f'NOP{i}', NOP)

opcodes_inverse = {
    opcodes[key][0]: (key, opcodes[key][1]) for key in opcodes
}

opcode_aliases = {
    k[3:]: k for k, _ in opcodes_inverse.items()
}

opcode_aliases['OP_RCZ'] = 'OP_READ_CACHE_SIZE'
opcode_aliases['RCZ'] = 'OP_READ_CACHE_SIZE'
opcode_aliases['OP_RCS'] = 'OP_READ_CACHE_STACK'
opcode_aliases['OP_SUBF'] = 'OP_SUBTRACT_FLOATS'
opcode_aliases['SUBF'] = 'OP_SUBTRACT_FLOATS'
opcode_aliases['OP_MODF'] = 'OP_MOD_FLOAT'
opcode_aliases['MODF'] = 'OP_MOD_FLOAT'
opcode_aliases['OP_MODFS'] = 'OP_MOD_FLOATS'
opcode_aliases['MODFS'] = 'OP_MOD_FLOATS'
opcode_aliases['RCS'] = 'OP_READ_CACHE_STACK'
opcode_aliases['OP_RCSZ'] = 'OP_READ_CACHE_STACK_SIZE'
opcode_aliases['RCSZ'] = 'OP_READ_CACHE_STACK_SIZE'
opcode_aliases['OP_LEQ'] = 'OP_LESS_OR_EQUAL'
opcode_aliases['LEQ'] = 'OP_LESS_OR_EQUAL'
opcode_aliases['OP_VAL'] = 'OP_GET_VALUE'
opcode_aliases['VAL'] = 'OP_GET_VALUE'
opcode_aliases['OP_FLESS'] = 'OP_FLOAT_LESS'
opcode_aliases['FLESS'] = 'OP_FLOAT_LESS'
opcode_aliases['OP_FLEQ'] = 'OP_FLOAT_LESS_OR_EQUAL'
opcode_aliases['FLEQ'] = 'OP_FLOAT_LESS_OR_EQUAL'
opcode_aliases['OP_I2F'] = 'OP_INT_TO_FLOAT'
opcode_aliases['I2F'] = 'OP_INT_TO_FLOAT'
opcode_aliases['OP_F2I'] = 'OP_FLOAT_TO_INT'
opcode_aliases['F2I'] = 'OP_FLOAT_TO_INT'
opcode_aliases['OP_CTS'] = 'OP_CHECK_TIMESTAMP'
opcode_aliases['CTS'] = 'OP_CHECK_TIMESTAMP'
opcode_aliases['OP_CTSV'] = 'OP_CHECK_TIMESTAMP_VERIFY'
opcode_aliases['CTSV'] = 'OP_CHECK_TIMESTAMP_VERIFY'
opcode_aliases['OP_CEV'] = 'OP_CHECK_EPOCH_VERIFY'
opcode_aliases['CEV'] = 'OP_CHECK_EPOCH_VERIFY'
opcode_aliases['OP_CSV'] = 'OP_CHECK_SIG_VERIFY'
opcode_aliases['CSV'] = 'OP_CHECK_SIG_VERIFY'
opcode_aliases['OP_CMS'] = 'OP_CHECK_MULTISIG'
opcode_aliases['CMS'] = 'OP_CHECK_MULTISIG'
opcode_aliases['OP_CMSV'] = 'OP_CHECK_MULTISIG_VERIFY'
opcode_aliases['CMSV'] = 'OP_CHECK_MULTISIG_VERIFY'
opcode_aliases['OP_CSS'] = 'OP_CHECK_SIG_STACK'
opcode_aliases['CSS'] = 'OP_CHECK_SIG_STACK'
opcode_aliases['OP_MASU'] = 'OP_MAKE_ADAPTER_SIG_PUBLIC'
opcode_aliases['MASU'] = 'OP_MAKE_ADAPTER_SIG_PUBLIC'
opcode_aliases['OP_MASV'] = 'OP_MAKE_ADAPTER_SIG_PRIVATE'
opcode_aliases['MASV'] = 'OP_MAKE_ADAPTER_SIG_PRIVATE'
opcode_aliases['OP_CAS'] = 'OP_CHECK_ADAPTER_SIG'
opcode_aliases['CAS'] = 'OP_CHECK_ADAPTER_SIG'
opcode_aliases['OP_DAS'] = 'OP_DECRYPT_ADAPTER_SIG'
opcode_aliases['DAS'] = 'OP_DECRYPT_ADAPTER_SIG'
opcode_aliases['OP_MSG'] = 'OP_GET_MESSAGE'
opcode_aliases['MSG'] = 'OP_GET_MESSAGE'
opcode_aliases['OP_CAT'] = 'OP_CONCAT'
opcode_aliases['CAT'] = 'OP_CONCAT'
opcode_aliases['OP_CATS'] = 'OP_CONCAT_STR'
opcode_aliases['CATS'] = 'OP_CONCAT_STR'
opcode_aliases['OP_CT'] = 'OP_CHECK_TEMPLATE'
opcode_aliases['CT'] = 'OP_CHECK_TEMPLATE'
opcode_aliases['OP_CTV'] = 'OP_CHECK_TEMPLATE_VERIFY'
opcode_aliases['CTV'] = 'OP_CHECK_TEMPLATE_VERIFY'
opcode_aliases['OP_TR'] = 'OP_TAPROOT'
opcode_aliases['TR'] = 'OP_TAPROOT'

nopcodes_inverse = {
    nopcodes[key][0]: (key, nopcodes[key][1]) for key in nopcodes
}

# flags are intended to change how specific opcodes function
flags = {
    # TODO: ts_threshold and epoc_threshold should become standard cache items
    'ts_threshold': 60,
    'epoch_threshold': 60,
    0: True,
    1: True,
    2: True,
    3: True,
    4: True,
    5: True,
    6: True,
    7: True,
    8: True,
    9: True,
    10: True,
}

flags_to_set = [
    'ts_threshold',
    'epoch_threshold',
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
]

# contracts are intended for use with OP_CHECK_TRANSFER
_contracts = {}
_contract_interfaces = {
    CanCheckTransfer.__name__: CanCheckTransfer,
    CanBeInvoked.__name__: CanBeInvoked,
}


# plugins
_plugins: dict[str, list[Callable]] = {}

# signature extension plugin funcs are called at the beginning of CHECK_SIG,
# CHECK_MULTISIG, SIGN, and GET_MESSAGE and take the same arguments as an op
_plugins['signature_extensions'] = []

# CTV plugin funcs are called to compare each sigfield against a template, and
# they take the same arguments as an op. However, the tape they get is empty,
# and the stack contains just the sigfield and the template (template on top).
# If no extensions are loaded, a simple equality comparison will be done.
_plugins['check_template'] = []

def _check_contract(contract: object) -> None:
    """Check a contract against required interfaces. Raise
        ScriptExecutionError if it does not match at least one.
    """
    matched = False
    for _, interface in _contract_interfaces.items():
            matched = matched or isinstance(contract, interface)
    sert(matched, f'contract does not fulfill at least one interface')

def add_contract(contract_id: bytes, contract: object) -> None:
    """Add a contract to be loaded on each script execution."""
    tert(type(contract_id) is bytes,
        'contract_id must be bytes and should be sha256 hash of its source code')
    _check_contract(contract)
    _contracts[contract_id] = contract

def remove_contract(contract_id: bytes) -> None:
    """Remove a loaded contract to prevent it from being included on
        script execution.
    """
    tert(type(contract_id) is bytes,
        'contract_id must be bytes and should be sha256 hash of its source code')
    if contract_id in _contracts:
        del _contracts[contract_id]

def add_contract_interface(interface: type) -> None:
    """Adds an interface for type checking contracts. Interface must be
        a runtime_checkable Protocol.
    """
    tert(type(interface) is _ProtocolMeta, 'interface must be a Protocol')
    if interface.__name__ not in _contract_interfaces:
        _contract_interfaces[interface.__name__] = interface

def remove_contract_interface(interface: type) -> None:
    """Removes an interface for type checking contracts."""
    tert(type(interface) is _ProtocolMeta, 'interface must be a Protocol')
    if interface.__name__ in _contract_interfaces:
        del _contract_interfaces[interface.__name__]

def add_opcode(code: int, name: str, function: Callable) -> None:
    """Adds an OP implementation with the code, name, and function."""
    tert(type(code) is int, 'code must be int')
    tert(type(name) is str, 'name must be str')
    tert(callable(function), 'function must be callable')
    if code in opcodes:
        vert(code not in opcodes, f'{code} already assigned to {opcodes[code][0]}')
    vert(code < 256, 'code must be <256')
    vert(name[:3].upper() == 'OP_', 'name must start with OP_')
    name = name.upper()
    opcodes[code] = (name, function)
    opcodes_inverse[name] = (code, function)

    if code in nopcodes:
        nopname = nopcodes[code][0]
        del nopcodes[code]
        del nopcodes_inverse[nopname]

def add_alias(alias: str, op_name: str) -> None:
    """Adds an alias for an OP."""
    tert(type(alias) is str, "alias must be str")
    tert(type(op_name) is str, "op_name must be str")
    alias = alias.upper()
    op_name = op_name.upper()
    vert(op_name in opcodes_inverse,
         f'op_name must be a valid OP name; "{op_name}" unrecognized')
    vert(alias not in opcode_aliases,
         f'alias "{alias}" already in use for {opcode_aliases.get(alias, "")}')
    vert(alias.isalnum(), f'alias must be alphanumeric; "{alias}" is invalid')
    opcode_aliases[alias] = op_name

def add_plugin(scope: str, plugin: Callable[[Tape, Stack, dict], Any]) -> None:
    """Adds a plugin for the given scope."""
    tert(type(scope) is str, 'scope must be str')
    tert(callable(plugin), f'plugin (for {scope}) must be Callable[[Tape, Stack, dict], Any]')

    if scope not in _plugins:
        _plugins[scope] = []

    if plugin not in _plugins[scope]:
        _plugins[scope].append(plugin)

def remove_plugin(scope: str, plugin: Callable[[Tape, Stack, dict], Any]) -> None:
    """Removes a plugin for the given scope."""
    tert(type(scope) is str, 'scope must be str')
    if scope not in _plugins:
        return
    if plugin in _plugins[scope]:
        _plugins[scope].remove(plugin)

def reset_plugins(scope: str) -> None:
    """Removes all plugins for the given scope."""
    tert(type(scope) is str, 'scope must be str')
    if scope not in _plugins:
        return
    [
        remove_plugin(scope, plugin)
        for plugin in _plugins[scope]
    ]

def run_plugins(scope: str, tape: Tape, stack: Stack, cache: dict) -> list:
    """Runs all plugins of the given scope."""
    result = []
    if scope not in tape.plugins:
        return result
    for plugin in tape.plugins[scope]:
        result.append(plugin(tape, stack, cache))
    return result

def add_signature_extension(plugin: Callable[[Tape, Stack, dict], None]) -> None:
    """Adds a signature extension plugin to be run before the following
        ops: CHECK_SIG, CHECK_MULTISIG, SIGN, and GET_MESSAGE.
    """
    add_plugin('signature_extensions', plugin)

def remove_signature_extension(plugin: Callable[[Tape, Stack, dict], None]) -> None:
    """Removes a signature extension plugin from the list of plugins to
        be run before the following ops: CHECK_SIG, CHECK_MULTISIG, SIGN,
        and GET_MESSAGE.
    """
    remove_plugin('signature_extensions', plugin)

def reset_signature_extensions() -> None:
    """Removes all signature extension plugins."""
    reset_plugins('signature_extensions')

def run_sig_extensions(tape: Tape, stack: Stack, cache: dict) -> None:
    """Runs all signature extension plugins."""
    run_plugins('signature_extensions', tape, stack, cache)

def set_tape_flags(tape: Tape, additional_flags: dict = {}) -> Tape:
    """Sets flags included in flags_to_set and any additional_flags for
        the tape.
    """
    for key in flags:
        if type(key) in (str, int):
            tape.flags[key] = flags[key] if key in flags_to_set else False
    for key in additional_flags:
        if type(key) in (str, int):
            tape.flags[key] = additional_flags[key]
    return tape

def run_tape(tape: Tape, stack: Stack, cache: dict,
             additional_flags: dict = {}) -> None:
    """Run the given tape using the stack and cache."""
    tape = set_tape_flags(tape, additional_flags)
    while not tape.has_terminated():
        op_code = int.from_bytes(tape.read(1), 'big')
        if op_code in opcodes:
            op = opcodes[op_code][1]
        else:
            op = nopcodes[op_code][1]
        op(tape, stack, cache)

def run_script(script: bytes|ScriptProtocol, cache_vals: dict = {},
               contracts: dict = {},
               additional_flags: dict = {},
               plugins: dict = {}) -> tuple[Tape, Stack, dict]:
    """Run the given script byte code. Returns a tape, stack, and dict."""
    tert(type(script) is bytes or isinstance(script, ScriptProtocol),
         'script must be bytes or ScriptProtocol implementation')
    script = bytes(script)
    tape = Tape(script)
    stack = Stack()
    cache = {'timestamp': int(time()), **cache_vals}
    tape.contracts = {**_contracts, **contracts}
    tape.plugins = {**_plugins, **plugins}
    run_tape(tape, stack, cache, additional_flags=additional_flags)
    return (tape, stack, cache)

def run_auth_script(script: bytes|ScriptProtocol, cache_vals: dict = {},
                    contracts: dict = {}, plugins: dict = {}) -> bool:
    """Run the given auth script byte code. Returns True iff the stack
        has a single \\xff value after script execution and no errors were
        raised; otherwise, returns False.
    """
    try:
        tape, stack, cache = run_script(script, cache_vals, contracts, plugins=plugins)
        assert tape.has_terminated()
        assert len(stack) == 1
        item = stack.get()
        assert item == b'\xff'
        return True
    except BaseException as e:
        return False
