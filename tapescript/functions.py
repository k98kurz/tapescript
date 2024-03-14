from __future__ import annotations
from .classes import Tape
from .errors import tert, vert, sert
from .interfaces import CanCheckTransfer
from hashlib import sha256, shake_256
from math import ceil, floor, isnan, log2
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from queue import LifoQueue
from secrets import token_bytes
from time import time
from typing import Callable, Protocol, _ProtocolMeta
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

def bytes_to_bool(val: bytes) -> bool:
    """Return True if any bits set, else False."""
    return int.from_bytes(val, 'big') > 0

def bytes_to_float(number: bytes) -> float:
    tert(type(number) is bytes, 'number must be 4 bytes')
    vert(len(number) == 4, 'number must be 4 bytes')
    return struct.unpack('!f', number)[0]

def float_to_bytes(number: float) -> bytes:
    tert(type(number) is float, 'number must be float')
    return struct.pack('!f', number)


def OP_FALSE(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Puts a null byte onto the queue."""
    queue.put(b'\x00')

def OP_TRUE(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Puts a 0x01 byte onto the queue."""
    queue.put(b'\x01')

def OP_PUSH0(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape; put it onto the queue; and
        advance the pointer appropriately.
    """
    queue.put(tape.read(1))

def OP_PUSH1(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        take that many bytes from the tape; put them onto the queue; and
        advance the pointer appropriately.
    """
    size = int.from_bytes(tape.read(1), 'big')
    queue.put(tape.read(size))

def OP_PUSH2(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next 2 bytes from the tape, interpreting as an unsigned
        int; take that many bytes from the tape; put them onto the
        queue; and advance the pointer appropriately.
    """
    size = int.from_bytes(tape.read(2), 'big')
    queue.put(tape.read(size))

def OP_PUSH4(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next 4 bytes from the tape, interpreting as an unsigned
        int; take that many bytes from the tape; put them onto the
        queue; and advance the pointer appropriately.
    """
    size = int.from_bytes(tape.read(4), 'big')
    queue.put(tape.read(size))

def OP_POP0(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Remove the first item from the queue and put it in the cache."""
    cache[b'P'] = [queue.get(False)]

def OP_POP1(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        remove that many items from the queue and put them in the cache;
        advance the pointer appropriately.
    """
    size = int.from_bytes(tape.read(1), 'big')
    items = []

    for _ in range(size):
        items.append(queue.get(False))

    cache[b'P'] = items

def OP_SIZE(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pull a value from the queue; put the size of the value onto the
        queue.
    """
    queue.put(int_to_bytes(len(queue.get(False))))

def OP_WRITE_CACHE(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        read that many bytes from tape as cache key; read another byte
        from the tape, interpreting as an int; read that many items from
        the queue and write them to the cache; advance the pointer
        appropriately.
    """
    size = int.from_bytes(tape.read(1), 'big')
    key = tape.read(size)
    n_items = int.from_bytes(tape.read(1), 'big')
    items = []

    for _ in range(n_items):
        items.append(queue.get(False))

    cache[key] = items

def OP_READ_CACHE(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        read that many bytes from tape as cache key; read those values
        from the cache and place them onto the queue; advance the
        pointer.
    """
    size = int.from_bytes(tape.read(1), 'big')
    key = tape.read(size)
    sert(key in cache, 'OP_READ_CACHE key not in cache')
    items = cache[key] if type(cache[key]) in (list, tuple) else [cache[key]]

    for item in items:
        queue.put(item)

def OP_READ_CACHE_SIZE(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        read that many bytes from tape as cache key; count how many
        values exist at that point in the cache and place that int onto
        the queue; advance the pointer.
    """
    size = int.from_bytes(tape.read(1), 'big')
    key = tape.read(size)

    if key not in cache:
        return queue.put(int_to_bytes(0))

    queue.put(int_to_bytes(len(cache[key])))

def OP_READ_CACHE_Q(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pull a value from the queue as a cache key; put those values from
        the cache onto the queue.
    """
    key = queue.get(False)
    sert(key in cache, 'OP_READ_CACHE_Q key not in cache')
    items = cache[key] if type(cache[key]) in (list, tuple) else [cache[key]]

    for item in items:
        queue.put(item)

def OP_READ_CACHE_Q_SIZE(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pull a value from the queue as a cache key; count the number of
        values in the cache at that key; put the result onto the queue.
    """
    key = queue.get(False)

    if key not in cache:
        return queue.put(int_to_bytes(0))

    queue.put(int_to_bytes(len(cache[key])))

def OP_ADD_INTS(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned
        int; pull that many values from the queue, interpreting them as
        signed ints; add them together; put the result back onto the
        queue; advance the pointer appropriately.
    """
    size = int.from_bytes(tape.read(1), 'big')
    total = 0

    for _ in range(size):
        total += bytes_to_int(queue.get(False))

    queue.put(int_to_bytes(total))

def OP_SUBTRACT_INTS(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        pull that many values from the queue, interpreting them as
        signed ints; subtract them from the first one; put the result
        back onto the queue; advance the pointer appropriately.
    """
    size = int.from_bytes(tape.read(1), 'big')
    total = bytes_to_int(queue.get(False))

    for _ in range(size-1):
        item = queue.get(False)
        number = bytes_to_int(item)
        total -= number

    queue.put(int_to_bytes(total))

def OP_MULT_INTS(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned
        int; pull that many values from the queue, interpreting them as
        signed ints; multiply them together; put the result back onto
        the queue; advance the pointer appropriately.
    """
    size = int.from_bytes(tape.read(1), 'big')
    total = bytes_to_int(queue.get(False))

    for _ in range(size-1):
        total *= bytes_to_int(queue.get(False))

    queue.put(int_to_bytes(total))

def OP_DIV_INT(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned
        int; read that many bytes from the tape, interpreting as a
        signed int divisor (denominator); pull a value from the queue,
        interpreting as a signed int dividend (numerator); divide the
        dividend by the divisor; put the result onto the queue; advance
        the pointer.
    """
    size = int.from_bytes(tape.read(1), 'big')
    divisor = bytes_to_int(tape.read(size))
    dividend = bytes_to_int(queue.get(False))
    queue.put(int_to_bytes(dividend // divisor))

def OP_DIV_INTS(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pull two values from the queue, interpreting as signed ints;
        divide the first by the second; put the result onto the queue.
    """
    dividend = bytes_to_int(queue.get(False))
    divisor = bytes_to_int(queue.get(False))
    queue.put(int_to_bytes(dividend // divisor))

def OP_MOD_INT(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned
        int; read that many bytes from the tape, interpreting as a
        signed int divisor; pull a value from the queue, interpreting
        as a signed int dividend; perform integer modulus: dividend %
        divisor; put the result onto the queue; advance the tape.
    """
    size = int.from_bytes(tape.read(1), 'big')
    divisor = bytes_to_int(tape.read(size))
    dividend = bytes_to_int(queue.get(False))
    queue.put(int_to_bytes(dividend % divisor))

def OP_MOD_INTS(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pull two values from the queue, interpreting as signed ints;
        perform integer modulus: first % second; put the result onto the
        queue.
    """
    dividend = bytes_to_int(queue.get(False))
    divisor = bytes_to_int(queue.get(False))
    queue.put(int_to_bytes(dividend % divisor))

def OP_ADD_FLOATS(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        pull that many values from the queue, interpreting them as
        floats; add them together; put the result back onto the queue;
        advance the pointer appropriately.
    """
    size = int.from_bytes(tape.read(1), 'big')
    total = 0.0

    for _ in range(size):
        item = queue.get(False)
        tert(type(item) is bytes and len(item) == 4,
            'OP_ADD_FLOATS malformed float')
        item, = struct.unpack('!f', item)
        total += item

    vert(not isnan(total), 'OP_ADD_FLOATS nan encountered')

    queue.put(struct.pack('!f', total))

def OP_SUBTRACT_FLOATS(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        pull that many values from the queue, interpreting them as
        floats; subtract them from the first one; put the result back
        onto the queue; advance the pointer appropriately.
    """
    size = int.from_bytes(tape.read(1), 'big')
    item = queue.get(False)
    tert(type(item) is bytes and len(item) == 4,
        'OP_SUBTRACT_FLOATS malformed float')
    total, = struct.unpack('!f', item)

    for _ in range(size-1):
        item = queue.get(False)
        tert(type(item) is bytes and len(item) == 4,
            'OP_SUBTRACT_FLOATS malformed float')
        number, = struct.unpack('!f', item)
        total -= number

    vert(not isnan(total), 'OP_SUBTRACT_FLOATS nan encountered')

    queue.put(struct.pack('!f', total))

def OP_DIV_FLOAT(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next 4 bytes from the tape, interpreting as a float
        divisor; pull a value from the queue, interpreting as a float
        dividend; divide the dividend by the divisor; put the result
        onto the queue; advance the pointer.
    """
    item = queue.get(False)
    tert(type(item) is bytes and len(item) == 4,
        'OP_DIV_FLOAT malformed float')
    dividend, = struct.unpack('!f', item)
    divisor, = struct.unpack('!f', tape.read(4))
    result = divisor / dividend
    vert(not isnan(result), 'OP_DIV_FLOAT nan encountered')
    queue.put(struct.pack('!f', result))

def OP_DIV_FLOATS(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pull two values from the queue, interpreting as floats; divide
        the second by the first; put the result onto the queue.
    """
    item = queue.get(False)
    tert(type(item) is bytes and len(item) == 4, 'OP_DIV_FLOATS malformed float')
    divisor, = struct.unpack('!f', item)

    item = queue.get(False)
    tert(type(item) is bytes and len(item) == 4, 'OP_DIV_FLOATS malformed float')
    dividend, = struct.unpack('!f', item)

    result = divisor / dividend
    vert(not isnan(result), 'OP_DIV_FLOATS nan encountered')
    queue.put(struct.pack('!f', result))

def OP_MOD_FLOAT(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next 4 bytes from the tape, interpreting as a float
        divisor; pull a value from the queue, interpreting as a float
        dividend; perform float modulus: dividend % divisor; put the
        result onto the queue; advance the pointer.
    """
    item = queue.get(False)
    tert(type(item) is bytes and len(item) == 4, 'OP_MOD_FLOAT malformed float')
    dividend, = struct.unpack('!f', item)
    divisor, = struct.unpack('!f', tape.read(4))
    result = dividend % divisor
    vert(not isnan(result), 'OP_MOD_FLOAT nan encountered')
    queue.put(struct.pack('!f', result))

def OP_MOD_FLOATS(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pull two values from the queue, interpreting as floats; perform
        float modulus: second % first; put the result onto the queue.
    """
    item = queue.get(False)
    tert(type(item) is bytes and len(item) == 4, 'OP_MOD_FLOATS malformed float')
    divisor, = struct.unpack('!f', item)

    item = queue.get(False)
    tert(type(item) is bytes and len(item) == 4, 'OP_MOD_FLOATS malformed float')
    dividend, = struct.unpack('!f', item)

    result = dividend % divisor
    vert(not isnan(result), 'OP_MOD_FLOATS nan encountered')
    queue.put(struct.pack('!f', result))

def OP_ADD_POINTS(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        pull that many values from the queue; add them together using
        ed25519 point addition; replace the result onto the queue;
        advance the pointer appropriately.
    """
    count = int.from_bytes(tape.read(1), 'big')
    points = []

    for _ in range(count):
        points.append(queue.get(False))
        tert(type(points[-1]) in (bytes, VerifyKey),
            'OP_ADD_POINTS non-point value encountered')

    # normalize points to bytes
    points = [pt if type(pt) is bytes else bytes(pt) for pt in points]

    # raise an error for invalid points
    for pt in points:
        vert(nacl.bindings.crypto_core_ed25519_is_valid_point(pt),
            'OP_ADD_POINTS invalid point encountered')

    # compute the sum
    sum = points[0]
    for i in range(1, len(points)):
        sum = nacl.bindings.crypto_core_ed25519_add(sum, points[i])

    # put the sum onto the queue
    queue.put(sum)

def OP_COPY(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        pull a value from the queue; place that value and a number of
        copies corresponding to the int from the tape back onto the
        queue; advance the pointer appropriately.
    """
    n_copies = int.from_bytes(tape.read(1), 'big')
    item = queue.get(False)

    for _ in range(n_copies + 1):
        queue.put(item)

def OP_DUP(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """OP_COPY but with only 1 copy and no reading from the tape or
        advancing the pointer. Equivalent to OP_DUP in Bitcoin script.
    """
    item = queue.get(False)
    queue.put(item)
    queue.put(item)

def OP_SHA256(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pull an item from the queue and put its sha256 hash back onto
        the queue.
    """
    item = queue.get(False)
    queue.put(sha256(item).digest())

def OP_SHAKE256(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        pull an item from the queue; put its shake_256 hash of the
        spcified length back onto the queue; advance pointer.
    """
    size = int.from_bytes(tape.read(1), 'big')
    item = queue.get(False)
    queue.put(shake_256(item).digest(size))

def OP_VERIFY(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pull a value from the queue; evaluate it as a bool; and raise a
        ScriptExecutionError if it is False.
    """
    sert(bytes_to_bool(queue.get(False)), 'OP_VERIFY check failed')

def OP_EQUAL(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pull 2 items from the queue; compare them; put the bool result
        onto the queue.
    """
    item1, item2 = queue.get(False), queue.get(False)
    queue.put(b'\x01' if item1 == item2 else b'\x00')

def OP_EQUAL_VERIFY(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Runs OP_EQUAL then OP_VERIFY."""
    OP_EQUAL(tape, queue, cache)
    OP_VERIFY(tape, queue, cache)

def OP_CHECK_SIG(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Take a byte from the tape, interpreting as the encoded allowable
        sigflags; pull a value from the queue, interpreting as a
        VerifyKey; pull a value from the queue, interpreting as a
        signature; check the signature against the VerifyKey and the
        cached sigfields not disabled by a sig flag; put True onto the
        queue if verification succeeds, otherwise put False onto the
        queue.
    """
    allowable_flags = tape.read(1)[0]
    vkey = queue.get(False)
    sig = queue.get(False)

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

    try:
        vkey.verify(message, sig)
        queue.put(b'\x01')
    except BadSignatureError:
        queue.put(b'\x00')

def OP_CHECK_SIG_VERIFY(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Runs OP_CHECK_SIG, then OP_VERIFY."""
    OP_CHECK_SIG(tape, queue, cache)
    OP_VERIFY(tape, queue, cache)

def OP_CHECK_TIMESTAMP(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pulls a value from the queue, interpreting as an unsigned int;
        gets the timestamp to check from the cache; compares the two
        values; if the cache timestamp is less than the queue time, or
        if current Unix epoch is behind cache timestamp by the flagged
        amount, put False onto the queue; otherwise, put True onto the
        queue. If the ts_threshold flag is <= 0, that check will be
        skipped.
    """
    constraint = queue.get(False)
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
        queue.put(b'\x00')
    elif difference >= tape.flags['ts_threshold'] and \
        tape.flags['ts_threshold'] > 0:
        queue.put(b'\x00')
    else:
        queue.put(b'\x01')

def OP_CHECK_TIMESTAMP_VERIFY(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Runs OP_CHECK_TIMESTAMP, then OP_VERIFY."""
    OP_CHECK_TIMESTAMP(tape, queue, cache)
    OP_VERIFY(tape, queue, cache)

def OP_CHECK_EPOCH(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pulls a value from the queue, interpreting as an unsigned int;
        gets the current Unix epoch time; compares the two values; if
        current time is less than the queue time, put False onto the
        queue; otherwise, put True onto the queue.
    """
    constraint = queue.get(False)
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
        queue.put(b'\x00')
    else:
        queue.put(b'\x01')

def OP_CHECK_EPOCH_VERIFY(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Runs OP_CHECK_EPOCH, then OP_VERIFY."""
    OP_CHECK_EPOCH(tape, queue, cache)
    OP_VERIFY(tape, queue, cache)

def OP_DEF(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape as the definition number; read
        the next 2 bytes from the tape, interpreting as an unsigned int;
        read that many bytes from the tape as the subroutine definition;
        advance the pointer appropriately.
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

def OP_CALL(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape as the definition number; call
        run_tape passing that definition tape, the queue, and the cache.
    """
    sert(tape.callstack_count < tape.callstack_limit,
        'callstack limit exceeded')

    def_handle = tape.read(1)
    tape.callstack_count += 1
    subtape = tape.definitions[def_handle]
    init_pointer = subtape.pointer
    subtape.callstack_count = tape.callstack_count

    subtape.pointer = 0
    run_tape(subtape, queue, cache, additional_flags=tape.flags)
    subtape.pointer = init_pointer
    if 'returned' in cache:
        del cache['returned']

def OP_IF(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next 2 bytes from the tape, interpreting as an unsigned
        int; read that many bytes from the tape as a subroutine
        definition; pull a value from the queue and evaluate as a bool;
        if it is true, run the subroutine; advance the pointer
        appropriately.
    """
    def_size = int.from_bytes(tape.read(2), 'big')

    def_data = tape.read(def_size)

    if bytes_to_bool(queue.get(False)):
        subtape = Tape(
            def_data,
            callstack_limit=tape.callstack_limit,
            callstack_count=tape.callstack_count,
            definitions={**tape.definitions},
            contracts=tape.contracts
        )
        run_tape(subtape, queue, cache, additional_flags=tape.flags)
        if 'returned' in cache:
            OP_RETURN(tape, queue, cache)

def OP_IF_ELSE(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next 2 bytes from the tape, interpreting as an unsigned
        int; read that many bytes from the tape as the IF subroutine
        definition; read the next 2 bytes from the tape, interpreting as
        an unsigned int; read that many bytes from the tape as the ELSE
        subroutine definition; pull a value from the queue and evaluate
        as a bool; if it is true, run the IF subroutine; else run the
        ELSE subroutine; advance the pointer appropriately.
    """
    if_def_size = int.from_bytes(tape.read(2), 'big')
    if_def_data = tape.read(if_def_size)

    else_def_size = int.from_bytes(tape.read(2), 'big')
    else_def_data = tape.read(else_def_size)

    subtape = Tape(
        if_def_data if bytes_to_bool(queue.get(False)) else else_def_data,
        callstack_limit=tape.callstack_limit,
        callstack_count=tape.callstack_count,
        definitions={**tape.definitions},
        contracts=tape.contracts,
    )
    run_tape(subtape, queue, cache, additional_flags=tape.flags)
    if 'returned' in cache:
        OP_RETURN(tape, queue, cache)

def OP_EVAL(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pulls a value from the stack then attempts to run it as a script.
        OP_EVAL shares a common queue and cache with other ops. Script
        is disallowed from modifying tape.flags or tape.definitions; it
        is executed with callstack_count=tape.callstack_count+1 and
        copies of tape.flags and tape.definitions; it also has access to
        all loaded contracts.
    """
    sert('disallow_OP_EVAL' not in tape.flags, 'OP_EVAL disallowed')
    script = queue.get(False)
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
    run_tape(subtape, queue, cache, additional_flags=tape.flags)
    if 'returned' in cache:
        if 'eval_return' in tape.flags:
            OP_RETURN(tape, queue, cache)
        else:
            del cache['returned']

def OP_NOT(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pulls a value from the queue, interpreting as a bool; performs
        logical NOT operation; puts that value onto the queue.
    """
    item = queue.get(False)
    queue.put(b'\x01' if item == b'\x00' else b'\x00')

def OP_RANDOM(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        put that many random bytes onto the queue; advance the pointer.
    """
    size = int.from_bytes(tape.read(1), 'big')
    queue.put(token_bytes(size), False)

def OP_RETURN(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Ends the script."""
    tape.pointer = len(tape.data)
    cache['returned'] = True

def OP_SET_FLAG(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        read that many bytes from the tape as a flag; set that flag;
        advance the pointer appropriately.
    """
    size = int.from_bytes(tape.read(1), 'big')
    flag = tape.read(size)
    sert(flag in flags, 'OP_SET_FLAG unrecognized flag')
    tape.flags[flag] = flags[flag]

def OP_UNSET_FLAG(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        read that many bytes from the tape as a flag; unset that flag;
        advance the pointer appropriately.
    """
    size = int.from_bytes(tape.read(1), 'big')
    flag = tape.read(size)
    if flag in tape.flags:
        del tape.flags[flag]

def OP_DEPTH(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Put the size of the queue onto the queue."""
    queue.put(int_to_bytes(queue.qsize()))

def OP_SWAP(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next 2 bytes from the tape, interpreting as unsigned
        ints; swap the queue items at those depths; advance the pointer
        appropriately.
    """
    first_idx = int.from_bytes(tape.read(1), 'big')
    second_idx = int.from_bytes(tape.read(1), 'big')

    if first_idx == second_idx:
        return

    max_idx = first_idx if first_idx > second_idx else second_idx
    sert(len(queue.queue) >= max_idx, 'OP_SWAP queue size exceeded by index')

    length = len(queue.queue)
    first_idx = length - first_idx - 1
    second_idx = length - second_idx - 1

    first = queue.queue[first_idx]
    second = queue.queue[second_idx]
    queue.queue[first_idx] = second
    queue.queue[second_idx] = first

def OP_SWAP2(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Swap the order of the top two items of the queue."""
    first = queue.get(False)
    second = queue.get(False)
    queue.put(first)
    queue.put(second)

def OP_REVERSE(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        reverse that number of items from the top of the queue.
    """
    count = int.from_bytes(tape.read(1), 'big')
    sert(len(queue.queue) >= count, 'OP_REVERSE queue size exceeded')
    items = queue.queue[-count:]
    items.reverse()
    queue.queue[-count:] = items

def OP_CONCAT(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pull two items from the queue; concatenate them; put the result
        onto the queue.
    """
    first = queue.get(False)
    second = queue.get(False)
    queue.put(first + second)

def OP_SPLIT(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int
        index; pull an item from the queue; split the item bytes at the
        index; put the results onto the queue; advance pointer.
    """
    index = int.from_bytes(tape.read(1), 'big')
    item = queue.get(False)
    sert(index < len(item), 'OP_SPLIT item len exceeded by index')
    part0 = item[:index]
    part1 = item[index:]
    queue.put(part1)
    queue.put(part0)

def OP_CONCAT_STR(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pull two items from the queue, interpreting as UTF-8 strings;
        concatenate them; put the result onto the queue.
    """
    first = str(queue.get(False), 'utf-8')
    second = str(queue.get(False), 'utf-8')
    queue.put(bytes(first + second, 'utf-8'))

def OP_SPLIT_STR(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int
        index; pull an item from the queue, interpreting as a UTF-8 str;
        split the item str at the index; put the results onto the queue;
        advance the pointer.
    """
    index = int.from_bytes(tape.read(1), 'big')
    item = str(queue.get(False), 'utf-8')
    sert(index < len(item), 'OP_SPLIT_STR item len exceeded by index')
    part0 = item[:index]
    part1 = item[index:]
    queue.put(bytes(part1, 'utf-8'))
    queue.put(bytes(part0, 'utf-8'))

def OP_CHECK_TRANSFER(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Take an item from the queue as a contract ID; take an item from
        the queue as an amount; take an item from the queue as a
        serialized txn constraint; take an item from the queue as a
        destination (address, locking script hash, etc); take an item
        from the queue, interpreting as an unsigned int count; take
        count number of items from the queue as sources; take the count
        number of items from the queue as transaction proofs; verify
        that the aggregate of the transfers to the destination from the
        sources equal or exceed the amount; verify that the transfers
        were valid using the proofs and the contract code; verify that
        any constraints were followed; and put True onto the queue if
        successful and False otherwise. Sources and proofs must be in
        corresponding order.
    """
    # get parameters
    contract_id = queue.get(False)
    amount = bytes_to_int(queue.get(False))
    constraint = queue.get(False)
    destination = queue.get(False)
    count = int.from_bytes(queue.get(False), 'big')
    sources = []
    txn_proofs = []
    all_proofs_valid = True

    for _ in range(count):
        sources.append(queue.get(False))

    for _ in range(count):
        txn_proofs.append(queue.get(False))

    # check contract is loaded and has required functions
    sert(contract_id in tape.contracts,
        'OP_CHECK_TRANSFER missing contract')
    _check_contract(tape.contracts[contract_id])

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

    queue.put(b'\x01' if all_proofs_valid and amount <= aggregate else b'\x00')

def OP_MERKLEVAL(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read 32 bytes from the tape as the root digest; pull a bool from
        the queue; call OP_DUP then OP_SHA256; call OP_SWAP 1 2; if not
        bool, call OP_SWAP2; call OP_CONCAT; call OP_SHA256; push root
        hash onto the queue; call OP_EQUAL_VERIFY; call OP_EVAL.
    """
    root_hash = tape.read(32)
    is_branch_A = bytes_to_bool(queue.get(False))
    OP_DUP(tape, queue, cache)
    OP_SHA256(tape, queue, cache)
    OP_SWAP(Tape(b'\x01\x02'), queue, cache)
    if not is_branch_A:
        OP_SWAP2(tape, queue, cache)
    OP_CONCAT(tape, queue, cache)
    OP_SHA256(tape, queue, cache)
    queue.put(root_hash)
    OP_EQUAL_VERIFY(tape, queue, cache)
    OP_EVAL(tape, queue, cache)

def OP_TRY_EXCEPT(tape: Tape, queue: LifoQueue, cache: dict) -> None:
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
        run_tape(subtape, queue, cache, additional_flags=tape.flags)
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
        run_tape(subtape, queue, cache, additional_flags=tape.flags)

    if 'returned' in cache:
        OP_RETURN(tape, queue, cache)

def OP_LESS(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pull two ints val1 and val2 from queue; put (v1<v2) onto queue."""
    val1 = bytes_to_int(queue.get(False))
    val2 = bytes_to_int(queue.get(False))
    queue.put(b'\x01' if val1 < val2 else b'\x00')

def OP_LESS_OR_EQUAL(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pull two ints val1 and val2 from queue; put (v1<=v2) onto queue."""
    val1 = bytes_to_int(queue.get(False))
    val2 = bytes_to_int(queue.get(False))
    queue.put(b'\x01' if val1 <= val2 else b'\x00')

def OP_GET_VALUE(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read one byte from the tape as uint size; read size bytes from
        the tape, interpreting as utf-8 string; put the read-only cache
        value(s) at that cache key onto the queue, serialized as bytes.
    """
    size = tape.read(1)[0]
    key = str(tape.read(size), 'utf-8')
    sert(key in cache, f'OP_GET_VALUE key "{key}" not in cache')
    items = cache[key] if type(cache[key]) in (list, tuple) else [cache[key]]
    for val in items:
        if type(val) in (bytes, bytearray):
            queue.put(val)
        elif type(val) is str:
            queue.put(bytes(val, 'utf-8'))
        elif type(val) is int:
            queue.put(int_to_bytes(val))
        elif type(val) is float:
            queue.put(float_to_bytes(val))

def OP_FLOAT_LESS(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pull two floats val1 and val2 from queue; put (v1<v2) onto queue."""
    val1 = bytes_to_float(queue.get(False))
    val2 = bytes_to_float(queue.get(False))
    queue.put(b'\x01' if val1 < val2 else b'\x00')

def OP_FLOAT_LESS_OR_EQUAL(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pull two floats val1 and val2 from queue; put (v1<=v2) onto queue."""
    val1 = bytes_to_float(queue.get(False))
    val2 = bytes_to_float(queue.get(False))
    queue.put(b'\x01' if val1 <= val2 else b'\x00')

def OP_INT_TO_FLOAT(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pull a signed int from the queue and put it back as a float."""
    value = bytes_to_int(queue.get(False))
    queue.put(float_to_bytes(1.0 * value))

def OP_FLOAT_TO_INT(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pull a float from the queue and put it back as a signed int."""
    value = bytes_to_float(queue.get(False))
    queue.put(int_to_bytes(int(value)))

def OP_LOOP(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read 2 bytes from the tape as uint len; read that many bytes from
        the tape as the loop definition; run the loop as long as the top
        value of the queue is not false or until a callstack limit
        exceeded error is raised.
    """
    loop_size = int.from_bytes(tape.read(2), 'big')
    loop_def = tape.read(loop_size)
    condition = queue.get(False)
    queue.put(condition)
    count = 0

    subtape = Tape(
        loop_def, callstack_limit=tape.callstack_limit,
        callstack_count=tape.callstack_count,
        definitions=tape.definitions, flags=tape.flags,
        contracts=tape.contracts
    )

    while bytes_to_bool(condition):
        sert(count < tape.callstack_limit, 'OP_LOOP limit exceeded')
        run_tape(subtape, queue, cache)
        subtape.reset_pointer()
        count += 1
        condition = queue.get(False)
        queue.put(condition)

def OP_CHECK_MULTISIG(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Reads 1 byte from tape as allowable flags; reads 1 byte from tape
        as uint m; reads 1 byte from tape as uint n; pulls n values from
        queue as vkeys; pulls m values from queue as signatures;
        verifies each signature against vkeys; puts false onto the queue
        if any signature fails to validate with one of the vkeys or if
        any vkey is used more than once; puts true onto the queue
        otherwise.
    """
    subtape = Tape(tape.read(1))
    m = tape.read(1)[0]
    n = tape.read(1)[0]
    vkeys = [queue.get(False) for _ in range(n)]
    sigs = [queue.get(False) for _ in range(m)]
    confirmed = set()

    for sig in sigs:
        for vkey in vkeys:
            subtape.reset_pointer()
            queue.put(sig)
            queue.put(vkey)
            OP_CHECK_SIG(subtape, queue, cache)
            result = bytes_to_bool(queue.get(False))
            if result:
                vkeys.remove(vkey)
                confirmed.add(sig)
                break

    if len(confirmed) == len(sigs):
        queue.put(b'\x01')
    else:
        queue.put(b'\x00')

def OP_CHECK_MULTISIG_VERIFY(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Runs OP_CHECK_MULTISIG then OP_VERIFY."""
    OP_CHECK_MULTISIG(tape, queue, cache)
    OP_VERIFY(tape, queue, cache)

def NOP(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int
        and pull that many values from the queue. Does nothing with the
        values. Useful for later soft-forks by redefining byte codes.
    """
    size = int.from_bytes(tape.read(1), 'big')

    for _ in range(size):
        queue.get(False)


opcodes = [
    ('OP_FALSE', OP_FALSE),
    ('OP_TRUE', OP_TRUE),
    ('OP_PUSH0', OP_PUSH0),
    ('OP_PUSH1', OP_PUSH1),
    ('OP_PUSH2', OP_PUSH2),
    ('OP_PUSH4', OP_PUSH4),
    ('OP_POP0', OP_POP0),
    ('OP_POP1', OP_POP1),
    ('OP_SIZE', OP_SIZE),
    ('OP_WRITE_CACHE', OP_WRITE_CACHE),
    ('OP_READ_CACHE', OP_READ_CACHE),
    ('OP_READ_CACHE_SIZE', OP_READ_CACHE_SIZE),
    ('OP_READ_CACHE_Q', OP_READ_CACHE_Q),
    ('OP_READ_CACHE_Q_SIZE', OP_READ_CACHE_Q_SIZE),
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

nopcodes_inverse = {
    nopcodes[key][0]: (key, nopcodes[key][1]) for key in nopcodes
}

# flags are intended to change how specific opcodes function
flags = {
    'ts_threshold': 60*60*12,
    'epoch_threshold': 60*60*12,
}

# contracts are intended for use with OP_CHECK_TRANSFER
_contracts = {}
_contract_interfaces = {
    CanCheckTransfer.__name__: CanCheckTransfer
}


def _check_contract(contract: object) -> None:
    """Check a contract against required interfaces. Raise
        ScriptExecutionError if any checks fail.
    """
    for name, interface in _contract_interfaces.items():
        sert(isinstance(contract, interface),
            f'contract does not fulfill the {name} interface')

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

def set_tape_flags(tape: Tape, additional_flags: dict = {}) -> Tape:
    for key in flags:
        if type(key) is str:
            tape.flags[key] = flags[key]
    for key in additional_flags:
        if type(key) is str:
            tape.flags[key] = additional_flags[key]
    return tape

def run_script(script: bytes, cache_vals: dict = {},
               contracts: dict = {},
               additional_flags: dict = {}) -> tuple[Tape, LifoQueue, dict]:
    """Run the given script byte code. Returns a tape, queue, and dict."""
    tape = Tape(script)
    queue = LifoQueue()
    cache = {**cache_vals}
    tape.contracts = {**_contracts, **contracts}
    run_tape(tape, queue, cache, additional_flags=additional_flags)
    return (tape, queue, cache)

def run_tape(tape: Tape, queue: LifoQueue, cache: dict,
             additional_flags: dict = {}) -> None:
    """Run the given tape using the queue and cache."""
    tape = set_tape_flags(tape, additional_flags)
    while not tape.has_terminated():
        op_code = tape.read(1)[0]
        if op_code in opcodes:
            op = opcodes[op_code][1]
        else:
            op = nopcodes[op_code][1]
        op(tape, queue, cache)

def run_auth_script(script: bytes, cache_vals: dict = {}, contracts: dict = {}) -> bool:
    """Run the given auth script byte code. Returns True iff the queue
        has a single \\x01 value after script execution and no errors were
        raised; otherwise, returns False.
    """
    try:
        tape, queue, cache = run_script(script, cache_vals, contracts)
        assert tape.has_terminated()
        assert not queue.empty()
        item = queue.get(False)
        assert item == b'\x01'
        assert queue.empty()
        return True
    except BaseException as e:
        return False
