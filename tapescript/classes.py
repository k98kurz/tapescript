from __future__ import annotations
from dataclasses import dataclass, field
from hashlib import sha256, shake_256
from math import ceil, floor, isnan, log2
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from queue import LifoQueue
from secrets import token_bytes
from time import time
import nacl.bindings
import struct


@dataclass
class Tape:
    """Class for reading the byte code of the script."""
    data: bytes
    pointer: int = field(default=0)
    callstack_limit: int = field(default=64)
    callstack_count: int = field(default=0)
    definitions: dict = field(default_factory=dict)
    flags: dict = field(default_factory=dict)
    contracts: dict = field(default_factory=dict)

    def read(self, size: int, move_pointer: bool = True) -> bytes:
        """Read symbols from the data."""
        assert self.pointer + size <= len(self.data), \
            'cannot read that many bytes'
        data = self.data[self.pointer:self.pointer+size]

        if move_pointer:
            self.move_pointer(size)

        return data

    def move_pointer(self, n: int) -> int:
        """Move the pointer the given number of places."""
        assert self.pointer + n <= len(self.data), 'cannot move pointer that far'
        self.pointer += n
        return self.pointer

    def reset_pointer(self) -> None:
        """Reset the pointer to 0."""
        self.pointer = 0

    def reset(self) -> None:
        """Reset the pointer to 0 and the definitions to {}."""
        self.pointer = 0
        self.definitions = {}

    def has_terminated(self) -> bool:
        """Return whether or not the tape has terminated."""
        return self.pointer == len(self.data)

    def remaining(self) -> int:
        """Return the remaining number of symbols left in the tape."""
        return len(self.data) - self.pointer


def bytes_to_int(number: bytes) -> int:
    """Convert from bytes to a signed int."""
    assert type(number) is bytes and len(number) > 0
    size = len(number) * 8
    number = int.from_bytes(number, 'big')
    negative = number >> (size - 1)

    return number - 2**size if negative else number

def int_to_bytes(number: int) -> bytes:
    """Convert from arbitrarily large signed int to bytes."""
    assert type(number) is int
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
    size = int.from_bytes(tape.read(1))
    key = tape.read(size)
    n_items = int.from_bytes(tape.read(1))
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
    assert key in cache, 'OP_READ_CACHE key not in cache'
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
    assert key in cache, 'OP_READ_CACHE_Q key not in cache'
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
    total, initialized = 0, False

    for _ in range(size-1):
        item = queue.get(False)
        number = bytes_to_int(item)

        if not initialized:
            total = number
        else:
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
        assert type(item) is bytes and len(item) == 4, \
            'OP_ADD_FLOATS malformed float'
        item, = struct.unpack('!f', item)
        total += item

    assert not isnan(total), 'OP_ADD_FLOATS nan encountered'

    queue.put(struct.pack('!f', total))

def OP_SUBTRACT_FLOATS(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        pull that many values from the queue, interpreting them as
        floats; subtract them from the first one; put the result back
        onto the queue; advance the pointer appropriately.
    """
    size = int.from_bytes(tape.read(1), 'big')
    item = queue.get(False)
    assert type(item) is bytes and len(item) == 4, \
        'OP_SUBTRACT_FLOATS malformed float'
    total, = struct.unpack('!f', item)

    for _ in range(size-1):
        item = queue.get(False)
        assert type(item) is bytes and len(item) == 4, \
            'OP_SUBTRACT_FLOATS malformed float'
        number, = struct.unpack('!f', item)
        total -= number

    assert not isnan(total), 'OP_ADD_FLOATS nan encountered'

    queue.put(struct.pack('!f', total))

def OP_DIV_FLOAT(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next 4 bytes from the tape, interpreting as a float
        divisor; pull a value from the queue, interpreting as a float
        dividend; divide the dividend by the divisor; put the result
        onto the queue; advance the pointer.
    """
    item = queue.get(False)
    assert type(item) is bytes and len(item) == 4, \
        'OP_DIV_FLOAT malformed float'
    dividend, = struct.unpack('!f', item)
    divisor, = struct.unpack('!f', tape.read(4))
    result = divisor / dividend
    assert not isnan(result), 'OP_DIV_FLOAT nan encountered'
    queue.put(struct.pack('!f', result))

def OP_DIV_FLOATS(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pull two values from the queue, interpreting as floats; divide
        the second by the first; put the result onto the queue.
    """
    item = queue.get(False)
    assert type(item) is bytes and len(item) == 4, \
        'OP_DIV_FLOATS malformed float'
    divisor, = struct.unpack('!f', item)

    item = queue.get(False)
    assert type(item) is bytes and len(item) == 4, \
        'OP_DIV_FLOATS malformed float'
    dividend, = struct.unpack('!f', item)

    result = divisor / dividend
    assert not isnan(result), 'OP_DIV_FLOATS nan encountered'
    queue.put(struct.pack('!f', result))

def OP_MOD_FLOAT(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next 4 bytes from the tape, interpreting as a float
        divisor; pull a value from the queue, interpreting as a float
        dividend; perform float modulus: dividend % divisor; put the
        result onto the queue; advance the pointer.
    """
    item = queue.get(False)
    assert type(item) is bytes and len(item) == 4, \
        'OP_MOD_FLOAT malformed float'
    dividend, = struct.unpack('!f', item)
    divisor, = struct.unpack('!f', tape.read(4))
    result = divisor % dividend
    assert not isnan(result), 'OP_MOD_FLOAT nan encountered'
    queue.put(struct.pack('!f', result))

def OP_MOD_FLOATS(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pull two values from the queue, interpreting as floats; perform
        float modulus: second % first; put the result onto the queue.
    """
    item = queue.get(False)
    assert type(item) is bytes and len(item) == 4, \
        'OP_MOD_FLOATS malformed float'
    divisor, = struct.unpack('!f', item)

    item = queue.get(False)
    assert type(item) is bytes and len(item) == 4, \
        'OP_MOD_FLOATS malformed float'
    dividend, = struct.unpack('!f', item)

    result = divisor % dividend
    assert not isnan(result), 'OP_MOD_FLOATS nan encountered'
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
        assert type(points[-1]) in (bytes, VerifyKey), \
            'OP_ADD_POINTS non-point value encountered'

    # normalize points to bytes
    points = [pt if type(pt) is bytes else bytes(pt) for pt in points]

    # raise an error for invalid points
    for pt in points:
        assert nacl.bindings.crypto_core_ed25519_is_valid_point(pt), \
            'OP_ADD_POINTS invalid point encountered'

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
    """Pull a value from the queue; evaluate it as a bool; and raise an
        AssertionError if it is False.
    """
    assert bytes_to_bool(queue.get(False)), 'OP_VERIFY check failed'

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
    """Pull a value from the queue, interpreting as a VerifyKey; pull a
        value from the queue, interpreting as a signature; check the
        signature against the VerifyKey and the cached sigfields not
        disabled by a sig flag; put True onto the queue if verification
        succeeds, otherwise put False onto the queue.
    """
    vkey = queue.get(False)
    sig = queue.get(False)

    assert (type(vkey) is bytes and len(vkey) == nacl.bindings.crypto_sign_PUBLICKEYBYTES) \
        or type(vkey) is VerifyKey, \
        'OP_CHECK_SIG invalid vkey encountered'
    assert type(sig) is bytes and len(sig) in (
        nacl.bindings.crypto_sign_BYTES, nacl.bindings.crypto_sign_BYTES + 1
        ), \
        'OP_CHECK_SIG invalid sig encountered'

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
        queue.
    """
    constraint = queue.get(False)
    assert type(constraint) is bytes and len(constraint) > 0, \
        'OP_CHECK_TIMESTAMP malformed constraint encountered'
    constraint = int.from_bytes(constraint, 'big')

    assert 'timestamp' in cache, 'OP_CHECK_TIMESTAMP cache missing timestamp'
    assert type(cache['timestamp']) is int, \
        'OP_CHECK_TIMESTAMP malformed cache timestamp'

    assert 'ts_threshold' in tape.flags, \
        'OP_CHECK_TIMESTAMP missing ts_threshold flag'
    assert type(tape.flags['ts_threshold']) is int, \
        'OP_CHECK_TIMESTAMP malformed ts_threshold flag'
    assert tape.flags['ts_threshold'] > 0, \
        'OP_CHECK_TIMESTAMP malformed ts_threshold flag'

    if cache['timestamp'] < constraint:
        queue.put(b'\x00')
    elif cache['timestamp'] - int(time()) >= tape.flags['ts_threshold']:
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
    assert type(constraint) is bytes and len(constraint) > 0, \
        'OP_CHECK_EPOCH malformed constraint encountered'
    constraint = int.from_bytes(constraint, 'big')

    assert 'epoch_threshold' in tape.flags, \
        'OP_CHECK_EPOCH missing epoch_threshold flag'
    assert type(tape.flags['epoch_threshold']) is int, \
        'OP_CHECK_EPOCH malformed epoch_threshold flag'
    assert tape.flags['epoch_threshold'] > 0, \
        'OP_CHECK_EPOCH malformed epoch_threshold flag'

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
        the next 3 bytes from the tape, interpreting as an unsigned int;
        read that many bytes from the tape as the subroutine definition;
        advance the pointer appropriately.
    """
    def_handle = tape.read(1)
    def_size = int.from_bytes(tape.read(3), 'big')

    def_data = tape.read(def_size)
    tape.definitions[def_handle] = Tape(def_data, callstack_limit=tape.callstack_limit)

def OP_CALL(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape as the definition number; call
        run_tape passing that definition tape, the queue, and the cache.
    """
    assert tape.callstack_count < tape.callstack_limit, \
        'callstack limit exceeded'

    def_handle = tape.read(1)
    tape.callstack_count += 1
    subtape = tape.definitions[def_handle]
    subtape.callstack_count = tape.callstack_count

    run_tape(subtape, queue, cache)

def OP_IF(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next 3 bytes from the tape, interpreting as an unsigned
        int; read that many bytes from the tape as a subroutine
        definition; pull a value from the queue and evaluate as a bool;
        if it is true, run the subroutine; advance the pointer
        appropriately.
    """
    def_size = int.from_bytes(tape.read(3), 'big')

    def_data = tape.read(def_size)

    if bytes_to_bool(queue.get(False)):
        subtape = Tape(
            def_data,
            callstack_limit=tape.callstack_limit,
            callstack_count=tape.callstack_count
        )
        run_tape(subtape, queue, cache)

def OP_IF_ELSE(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next 3 bytes from the tape, interpreting as an unsigned
        int; read that many bytes from the tape as the IF subroutine
        definition; read the next 3 bytes from the tape, interpreting as
        an unsigned int; read that many bytes from the tape as the ELSE
        subroutine definition; pull a value from the queue and evaluate
        as a bool; if it is true, run the IF subroutine; else run the
        ELSE subroutine; advance the pointer appropriately.
    """
    if_def_size = int.from_bytes(tape.read(3), 'big')
    if_def_data = tape.read(if_def_size)

    else_def_size = int.from_bytes(tape.read(3), 'big')
    else_def_data = tape.read(else_def_size)

    subtape = Tape(
        if_def_data if bytes_to_bool(queue.get(False)) else else_def_data,
        callstack_limit=tape.callstack_limit,
        callstack_count=tape.callstack_count
    )
    run_tape(subtape, queue, cache)

def OP_EVAL(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Pulls a value from the stack then attempts to run it as a script.
        Any values pulled from the eval queue are then put on the main
        queue. Script is disallowed from using OP_EVAL or modifying
        tape.flags, tape.definitions, or cache; it is executed with
        callstack_count=tape.callstack_count+1 and copies of
        tape.callstack_limit, tape.flags, tape.definitions, cache, and
        queue.
    """
    assert 'disallow_OP_EVAL' not in tape.flags, 'OP_EVAL disallowed'
    script = queue.get(False)
    assert len(script) > 0, 'OP_EVAL encountered empty script'

    # setup
    subtape = Tape(
        script,
        callstack_count=tape.callstack_count+1,
        callstack_limit=tape.callstack_limit,
        definitions={**tape.definitions},
        flags={**tape.flags, 'disallow_OP_EVAL': True}
    )
    subcache = {**cache}
    subqueue = LifoQueue()
    subqueue.queue = [*queue.queue]

    # run
    run_tape(subtape, subqueue, cache)

    # copy results
    for item in subqueue.queue:
        queue.put(item)

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

def OP_SET_FLAG(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned int;
        read that many bytes from the tape as a flag; set that flag;
        advance the pointer appropriately.
    """
    size = int.from_bytes(tape.read(1), 'big')
    flag = tape.read(size)
    assert flag in flags, 'OP_SET_FLAG unrecognized flag'
    tape.flags[flag] = flags[flag][0]

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
    assert len(queue.queue) >= max_idx, 'OP_SWAP queue size exceeded by index'

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
    assert len(queue.queue) >= count, 'OP_REVERSE queue size exceeded'
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
    assert index < len(item), 'OP_SPLIT item len exceeded by index'
    part0 = item[:index]
    part1 = item[index:]
    queue.put(part0)
    queue.put(part1)

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
    assert index < len(item), 'OP_SPLIT_STR item len exceeded by index'
    part0 = item[:index]
    part1 = item[index:]
    queue.put(bytes(part0, 'utf-8'))
    queue.put(bytes(part1, 'utf-8'))

def OP_CHECK_TRANSFER(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Read the next byte from the tape, interpreting as an unsigned
        int count; take an item from the queue as a contract ID; take
        an item from the queue as an amount; take an item from the queue
        as a serialized txn constraint; take an item from the queue
        as a destination (address, locking script hash, etc); take the
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
    count = int.from_bytes(tape.read(1), 'big')
    contract_id = queue.get(False)
    amount = queue.get(False)
    constraint = queue.get(False)
    destination = queue.get(False)
    sources = []
    txn_proofs = []
    all_proofs_valid = True

    for _ in range(count):
        sources.append(queue.get(False))

    for _ in range(count):
        txn_proofs.append(queue.get(False))

    # check contract is loaded and has required functions
    assert contract_id in tape.contracts, \
        'OP_CHECK_TRANSFER missing contract'
    assert 'verify_txn_proof' in tape.contracts[contract_id], \
        'OP_CHECK_TRANSFER contract missing verify_txn_proof'
    assert callable(tape.contracts[contract_id]['verify_txn_proof']), \
        'OP_CHECK_TRANSFER malformed contract'
    assert 'verify_transfer' in tape.contracts[contract_id], \
        'OP_CHECK_TRANSFER contract missing verify_transfer'
    assert callable(tape.contracts[contract_id]['verify_transfer']), \
        'OP_CHECK_TRANSFER malformed contract'
    assert 'verify_txn_constraint' in tape.contracts[contract_id], \
        'OP_CHECK_TRANSFER contract missing verify_txn_constraint'
    assert callable(tape.contracts[contract_id]['verify_txn_constraint']), \
        'OP_CHECK_TRANSFER malformed contract'
    assert 'calc_txn_aggregates' in tape.contracts[contract_id], \
        'OP_CHECK_TRANSFER contract missing calc_txn_aggregates'
    assert callable(tape.contracts[contract_id]['calc_txn_aggregates']), \
        'OP_CHECK_TRANSFER malformed contract'

    verify_txn_proof = tape.contracts[contract_id]['verify_txn_proof']
    verify_transfer = tape.contracts[contract_id]['verify_transfer']
    verify_txn_constraint = tape.contracts[contract_id]['verify_txn_constraint']
    calc_txn_aggregates = tape.contracts[contract_id]['calc_txn_aggregates']

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
]
opcodes = {x: opcodes[x] for x in range(len(opcodes))}

nopcodes = {}

for i in range(len(opcodes), 256):
    nopcodes[i] = (f'NOP{i}', NOP)

opcodes_inverse = {
    opcodes[key][0]: (key, opcodes[key][1]) for key in opcodes
}

nopcodes_inverse = {
    nopcodes[key][0]: (key, nopcodes[key][1]) for key in nopcodes
}


# flags are intended to change how specific opcodes function
flags = {
    'ts_threshold': (60*60*12,),
    'epoch_threshold': (60*60*12,),
}

flags_inverse = {
    flags[key]: key for key in flags
}

def compile_script(script: str) -> bytes:
    """Compile the given human-readable script into byte code."""
    assert type(script) is str, 'input script must be str'

    def get_args(opcode: str, symbols: list[str]) -> tuple[int, bytes]:
        """Get the number of symbols to advance and args for an op."""
        symbols_to_advance = 0
        args = []

        match opcode:
            case 'OP_FALSE' | 'OP_TRUE' | 'OP_POP0' | 'OP_SIZE' | \
                'OP_READ_CACHE_Q' | 'OP_READ_CACHE_Q_SIZE' | 'OP_DIV_INTS' | \
                'OP_MOD_INTS' | 'OP_DIV_FLOATS' | 'OP_MOD_FLOATS' | 'OP_DUP' | \
                'OP_SHA256' | 'OP_VERIFY' | 'OP_EQUAL' | 'OP_EQUAL_VERIFY' | \
                'OP_CHECK_SIG' | 'OP_CHECK_SIG_VERIFY' | 'OP_CHECK_TIMESTAMP' | \
                'OP_CHECK_TIMESTAMP_VERIFY' | 'OP_CHECK_EPOCH' | \
                'OP_CHECK_EPOCH_VERIFY' | 'OP_EVAL' | 'OP_NOT' | 'OP_RETURN' | \
                'OP_DEPTH' | 'OP_SWAP2' | 'OP_CONCAT' | 'OP_CONCAT_STR':
                # ops that have no arguments on the tape
                pass
            case 'OP_PUSH':
                # special case: OP_PUSH is a short hand for OP_PUSH[0,1,2,4]
                symbols_to_advance += 1
                val = symbols[0]
                assert val[0].lower() in ('d', 'x'), \
                    'numeric args must be prefaced with d or x'

                match val[0].lower():
                    case 'd':
                        assert val[1:].isnumeric(), \
                            'value prefaced by d must be decimal int'
                        if '.' in val:
                            val = int(val[1:].split('.')[0])
                        else:
                            val = int(val[1:])
                        size = 1 if val < 256 else 2 if val < 65536 else 4
                        val = val.to_bytes(size, 'big')
                    case 'x':
                        assert len(val[1:]) <= 8, \
                            'value must be at most 4 bytes long'
                        val = bytes.fromhex(val[1:])

                if 1 < len(val) < 256:
                    args.append(len(val).to_bytes(1, 'big'))
                elif 255 < len(val) < 65536:
                    args.append(len(val).to_bytes(2, 'big'))
                elif 65_536 < len(val) < 4_294_967_296:
                    args.append(len(val).to_bytes(4, 'big'))
                args.append(val)
            case 'OP_PUSH1' | 'OP_WRITE_CACHE' | 'OP_READ_CACHE' | \
                'OP_READ_CACHE_SIZE' | 'OP_DIV_INT' | \
                'OP_MOD_INT' | 'OP_SET_FLAG' | 'OP_UNSET_FLAG':
                # ops that have tape arguments of form [size 0-255] [val]
                if opcode == 'OP_WRITE_CACHE':
                    symbols_to_advance += 2
                    vals = symbols[:2]
                else:
                    symbols_to_advance += 1
                    vals = (symbols[0])

                for val in vals:
                    assert val[0].lower() in ('d', 'x', 's'), \
                        'values must be prefaced with d, x, or s'
                    match val[0].lower():
                        case 'd':
                            assert val[1:].isnumeric(), \
                                'value prefaced by d must be decimal int or float'
                            if '.' in val:
                                args.append((4).to_bytes(1, 'big'))
                                args.append(struct.pack('!f', float(val[1:])))
                            else:
                                val = int_to_bytes(int(val[1:]))
                                args.append(len(val).to_bytes(1, 'big'))
                                args.append(val)
                        case 'x':
                            val = bytes.fromhex(val[1:])
                            args.append(len(val).to_bytes(1, 'big'))
                            args.append(val)
                        case 's':
                            val = bytes(val[1:], 'utf-8')
                            args.append(len(val).to_bytes(1, 'big'))
                            args.append(val)
            case 'OP_PUSH0' | 'OP_POP1' | 'OP_ADD_INTS' | 'OP_SUBTRACT_INTS' | \
                'OP_MULT_INTS' | 'OP_DIV_INTS' | 'OP_ADD_FLOATS' | \
                'OP_SUBTRACT_FLOATS' | 'OP_ADD_POINTS' | 'OP_CALL' | \
                'OP_COPY' | 'OP_SHAKE256' | 'OP_RANDOM' | 'OP_REVERSE' | \
                'OP_SPLIT' | 'OP_SPLIT_STR':
                # ops that have tape argument of form [0-255]
                symbols_to_advance += 1
                val = symbols[0]
                assert val[0].lower() in ('d', 'x'), \
                    'numeric args must be prefaced with d or x'

                match val[0].lower():
                    case 'd':
                        assert val[1:].isnumeric(), \
                            'value prefaced by d must be decimal int'
                        if '.' in val:
                            args.append(int(val[1:].split('.')[0]).to_bytes(1, 'big'))
                        else:
                            args.append(int(val[1:]).to_bytes(1, 'big'))
                    case 'x':
                        assert len(val[1:]) <= 2, \
                            'value must be at most 1 byte long'
                        val = bytes.fromhex(val[1:])
                        args.append(val if len(val) == 1 else b'\x00')
            case 'OP_PUSH2':
                # ops that have tape argument of form [0-65535] [val]
                symbols_to_advance += 1
                val = symbols[0]
                assert val[0].lower() in ('d', 'x'), \
                    'numeric args must be prefaced with d or x'

                match val[0].lower():
                    case 'd':
                        assert val[1:].isnumeric(), \
                            'value prefaced by d must be decimal int'
                        if '.' in val:
                            args.append(int(val[1:].split('.')[0]).to_bytes(1, 'big'))
                        else:
                            args.append(int(val[1:]).to_bytes(1, 'big'))
                    case 'x':
                        assert len(val[1:]) <= 4, \
                            'value must be at most 2 bytes long'
                        val = bytes.fromhex(val[1:])
                        args.append(val if len(val) == 2 else b'\x00' + val)
            case 'OP_PUSH4':
                # ops that have tape argument of form [0-4_294_967_295] [val]
                symbols_to_advance += 1
                val = symbols[0]
                assert val[0].lower() in ('d', 'x'), \
                    'numeric args must be prefaced with d or x'

                match val[0].lower():
                    case 'd':
                        assert val[1:].isnumeric(), \
                            'value prefaced by d must be decimal int'
                        if '.' in val:
                            args.append(int(val[1:].split('.')[0]).to_bytes(1, 'big'))
                        else:
                            args.append(int(val[1:]).to_bytes(1, 'big'))
                    case 'x':
                        assert len(val[1:]) <= 8, \
                            'value must be at most 4 bytes long'
                        val = bytes.fromhex(val[1:])
                        while len(val) < 4:
                            val = b'\x00' + val
                        args.append(val)
            case 'OP_DIV_FLOAT' | 'OP_MOD_FLOAT':
                # ops that have tape argument of form [4-byte float]
                symbols_to_advance += 1
                val = symbols[0]
                assert val[0].lower() in ('d', 'x'), \
                    'numeric args must be prefaced with d or x'

                match val[0].lower():
                    case 'd':
                        assert val[1:].isnumeric(), \
                            'OP_[DIV|MOD]_FLOAT value prefaced by d must be decimal float'
                        args.append(struct.pack('!f', float(val[1:])))
                    case 'x':
                        assert len(val[1:]) == 8, \
                            'OP_[DIV|MOD]_FLOAT value prefaced by x must be 8 long (4 bytes)'
                        args.append(bytes.fromhex(val[1:]))
            case 'OP_SWAP':
                # ops that have tape arguments of form [0-255] [0-255]
                symbols_to_advance += 2
                vals = symbols[:2]

                for val in vals:
                    assert val[0].lower() in ('d', 'x'), \
                        'numeric args must be prefaced with d or x'

                    match val[0].lower():
                        case 'd':
                            assert val[1:].isnumeric(), \
                                'OP_SWAP value prefaced by d must be decimal int'
                            if '.' in val:
                                args.append(int_to_bytes(int(val[1:].split('.')[0])))
                            else:
                                args.append(int_to_bytes(int(val[1:])))
                        case 'x':
                            assert len(val[1:]) == 2, \
                                'OP_SWAP value prefaced by x must b 2 long (1 byte)'
                            args.append(bytes.fromhex(val[1:]))
            case _:
                pass

        return (symbols_to_advance, tuple(args))

    # setup
    code = []
    in_def, if_depth = False, 0
    defs = {}
    if_codes = []

    # get a list of symbols
    symbols = [s.upper() for s in script.split()]
    index = 0

    while index < len(symbols):
        symbol = symbols[index]

        # ignore comments (symbols between matchin #, ', or ")
        if symbol in ('"', "'", '#'):
            # skip forward past the matching symbol
            index = symbols.index(symbol, index) + 1
            continue

        assert symbols[0] in opcodes_inverse, 'unrecognized opcode'

        # handle definition
        if symbol == 'OP_DEF':
            def_code = b''
            name = symbols[index + 1]
            assert name.isnumeric(), 'def number must be numeric'
            name = int(name)
            assert 0 <= name < 256, 'def number must be in 0-255'

            if symbols[index + 2] == '{':
                # case 1: OP_DEF number { match }
                assert '}' in symbols[index:], 'missing matching }'
                search_idx = symbols.index('}', index)
            else:
                # case 2: find END_DEF
                assert 'END_DEF' in symbols[index:], 'missing END_DEF'
                search_idx = symbols.index('END_DEF')

            # add OP_DEF to code
            code.append(opcodes_inverse['OP_DEF'][0].to_bytes(1, 'big'))

            i = index + 1
            while i < search_idx:
                if symbols[i][3:] == 'OP_':
                    assert symbols[i] != 'OP_DEF', \
                        'cannot use OP_DEF within OP_DEF body'

                    if symbols[i] == 'OP_IF':
                        ...
                    else:
                        advance, args = get_args(symbols[i], symbols[i+1:])
                        i += advance
                        def_code += b''.join(args)

            # add def handle to code
            code.append(name.to_bytes(1, 'big'))

            # add def size to code
            def_size = len(def_code)
            assert 0 < def_size < 2**24, 'def size limit exceeded'
            code.append(def_size.to_bytes(3, 'big'))

            # add def code to code
            code.append(def_code)


def decompile_script(script: bytes) -> str:
    """Decompile the byte code into human-readable script."""
    # @todo write decompiler once compiler finished
    ...


def run_script(script: bytes, cache_vals: dict = {}) -> tuple[Tape, LifoQueue, dict]:
    """Run the given script byte code. Returns a tape, queue, and dict."""
    tape = Tape(script)
    queue = LifoQueue()
    cache = {**cache_vals}

    # set default flags
    for key in flags:
        if type(key) is str:
            tape.flags[key] = flags[key][0]

    run_tape(tape, queue, cache)

    return (tape, queue, cache)

def run_tape(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Run the given tape using the queue and cache."""
    while not tape.has_terminated():
        op_code = tape.read(1)[0]
        assert op_code not in opcodes, 'unrecognized opcode'
        op = opcodes[op_code][1]
        op(tape, queue, cache)
