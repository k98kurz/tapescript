# OPs

All `OP_` functions have the following signature:

```python
def OP_WHATEVER(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    ...
```

## OP_FALSE - 0 - x00

Puts a null byte onto the queue.

## OP_TRUE - 1 - x01

Puts a 0x01 byte onto the queue.

## OP_PUSH0 - 2 - x02

Read the next byte from the tape; put it onto the queue; and advance the pointer
appropriately.

## OP_PUSH1 - 3 - x03

Read the next byte from the tape, interpreting as an unsigned int; take that
many bytes from the tape; put them onto the queue; and advance the pointer
appropriately.

## OP_PUSH2 - 4 - x04

Read the next 2 bytes from the tape, interpreting as an unsigned int; take that
many bytes from the tape; put them onto the queue; and advance the pointer
appropriately.

## OP_PUSH4 - 5 - x05

Read the next 4 bytes from the tape, interpreting as an unsigned int; take that
many bytes from the tape; put them onto the queue; and advance the pointer
appropriately.

## OP_POP0 - 6 - x06

Remove the first item from the queue and put it in the cache.

## OP_POP1 - 7 - x07

Read the next byte from the tape, interpreting as an unsigned int; remove that
many items from the queue and put them in the cache; advance the pointer
appropriately.

## OP_SIZE - 8 - x08

Pull a value from the queue; put the size of the value onto the queue.

## OP_WRITE_CACHE - 9 - x09

Read the next byte from the tape, interpreting as an unsigned int; read that
many bytes from tape as cache key; read another byte from the tape, interpreting
as an int; read that many items from the queue and write them to the cache;
advance the pointer appropriately.

## OP_READ_CACHE - 10 - x0A

Read the next byte from the tape, interpreting as an unsigned int; read that
many bytes from tape as cache key; read those values from the cache and place
them onto the queue; advance the pointer.

## OP_READ_CACHE_SIZE - 11 - x0B

Read the next byte from the tape, interpreting as an unsigned int; read that
many bytes from tape as cache key; count how many values exist at that point in
the cache and place that int onto the queue; advance the pointer.

## OP_READ_CACHE_Q - 12 - x0C

Pull a value from the queue as a cache key; put those values from the cache onto
the queue.

## OP_READ_CACHE_Q_SIZE - 13 - x0D

Pull a value from the queue as a cache key; count the number of values in the
cache at that key; put the result onto the queue.

## OP_ADD_INTS - 14 - x0E

Read the next byte from the tape, interpreting as an unsigned int; pull that
many values from the queue, interpreting them as signed ints; add them together;
put the result back onto the queue; advance the pointer appropriately.

## OP_SUBTRACT_INTS - 15 - x0F

Read the next byte from the tape, interpreting as an unsigned int; pull that
many values from the queue, interpreting them as signed ints; subtract them from
the first one; put the result back onto the queue; advance the pointer
appropriately.

## OP_MULT_INTS - 16 - x10

Read the next byte from the tape, interpreting as an unsigned int; pull that
many values from the queue, interpreting them as signed ints; multiply them
together; put the result back onto the queue; advance the pointer appropriately.

## OP_DIV_INT - 17 - x11

Read the next byte from the tape, interpreting as an unsigned int; read that
many bytes from the tape, interpreting as a signed int divisor (denominator);
pull a value from the queue, interpreting as a signed int dividend (numerator);
divide the dividend by the divisor; put the result onto the queue; advance the
pointer.

## OP_DIV_INTS - 18 - x12

Pull two values from the queue, interpreting as signed ints; divide the first by
the second; put the result onto the queue.

## OP_MOD_INT - 19 - x13

Read the next byte from the tape, interpreting as an unsigned int; read that
many bytes from the tape, interpreting as a signed int divisor; pull a value
from the queue, interpreting as a signed int dividend; perform integer modulus:
dividend % divisor; put the result onto the queue; advance the tape.

## OP_MOD_INTS - 20 - x14

Pull two values from the queue, interpreting as signed ints; perform integer
modulus: first % second; put the result onto the queue.

## OP_ADD_FLOATS - 21 - x15

Read the next byte from the tape, interpreting as an unsigned int; pull that
many values from the queue, interpreting them as floats; add them together; put
the result back onto the queue; advance the pointer appropriately.

## OP_SUBTRACT_FLOATS - 22 - x16

Read the next byte from the tape, interpreting as an unsigned int; pull that
many values from the queue, interpreting them as floats; subtract them from the
first one; put the result back onto the queue; advance the pointer
appropriately.

## OP_DIV_FLOAT - 23 - x17

Read the next 4 bytes from the tape, interpreting as a float divisor; pull a
value from the queue, interpreting as a float dividend; divide the dividend by
the divisor; put the result onto the queue; advance the pointer.

## OP_DIV_FLOATS - 24 - x18

Pull two values from the queue, interpreting as floats; divide the second by the
first; put the result onto the queue.

## OP_MOD_FLOAT - 25 - x19

Read the next 4 bytes from the tape, interpreting as a float divisor; pull a
value from the queue, interpreting as a float dividend; perform float modulus:
dividend % divisor; put the result onto the queue; advance the pointer.

## OP_MOD_FLOATS - 26 - x1A

Pull two values from the queue, interpreting as floats; perform float modulus:
second % first; put the result onto the queue.

## OP_ADD_POINTS - 27 - x1B

Read the next byte from the tape, interpreting as an unsigned int; pull that
many values from the queue; add them together using ed25519 point addition;
replace the result onto the queue; advance the pointer appropriately.

## OP_COPY - 28 - x1C

Read the next byte from the tape, interpreting as an unsigned int; pull a value
from the queue; place that value and a number of copies corresponding to the int
from the tape back onto the queue; advance the pointer appropriately.

## OP_DUP - 29 - x1D

OP_COPY but with only 1 copy and no reading from the tape or advancing the
pointer. Equivalent to OP_DUP in Bitcoin script.

## OP_SHA256 - 30 - x1E

Pull an item from the queue and put its sha256 hash back onto the queue.

## OP_SHAKE256 - 31 - x1F

Read the next byte from the tape, interpreting as an unsigned int; pull an item
from the queue; put its shake_256 hash of the spcified length back onto the
queue; advance pointer.

## OP_VERIFY - 32 - x20

Pull a value from the queue; evaluate it as a bool; and raise a
ScriptExecutionError if it is False.

## OP_EQUAL - 33 - x21

Pull 2 items from the queue; compare them; put the bool result onto the queue.

## OP_EQUAL_VERIFY - 34 - x22

Runs OP_EQUAL then OP_VERIFY.

## OP_CHECK_SIG - 35 - x23

Take a byte from the tape, interpreting as the encoded allowable sigflags; pull
a value from the queue, interpreting as a VerifyKey; pull a value from the
queue, interpreting as a signature; check the signature against the VerifyKey
and the cached sigfields not disabled by a sig flag; put True onto the queue if
verification succeeds, otherwise put False onto the queue.

## OP_CHECK_SIG_VERIFY - 36 - x24

Runs OP_CHECK_SIG, then OP_VERIFY.

## OP_CHECK_TIMESTAMP - 37 - x25

Pulls a value from the queue, interpreting as an unsigned int; gets the
timestamp to check from the cache; compares the two values; if the cache
timestamp is less than the queue time, or if current Unix epoch is behind cache
timestamp by the flagged amount, put False onto the queue; otherwise, put True
onto the queue. If the ts_threshold flag is <= 0, that check will be skipped.

## OP_CHECK_TIMESTAMP_VERIFY - 38 - x26

Runs OP_CHECK_TIMESTAMP, then OP_VERIFY.

## OP_CHECK_EPOCH - 39 - x27

Pulls a value from the queue, interpreting as an unsigned int; gets the current
Unix epoch time; compares the two values; if current time is less than the queue
time, put False onto the queue; otherwise, put True onto the queue.

## OP_CHECK_EPOCH_VERIFY - 40 - x28

Runs OP_CHECK_EPOCH, then OP_VERIFY.

## OP_DEF - 41 - x29

Read the next byte from the tape as the definition number; read the next 2 bytes
from the tape, interpreting as an unsigned int; read that many bytes from the
tape as the subroutine definition; advance the pointer appropriately.

## OP_CALL - 42 - x2A

Read the next byte from the tape as the definition number; call run_tape passing
that definition tape, the queue, and the cache.

## OP_IF - 43 - x2B

Read the next 2 bytes from the tape, interpreting as an unsigned int; read that
many bytes from the tape as a subroutine definition; pull a value from the queue
and evaluate as a bool; if it is true, run the subroutine; advance the pointer
appropriately.

## OP_IF_ELSE - 44 - x2C

Read the next 2 bytes from the tape, interpreting as an unsigned int; read that
many bytes from the tape as the IF subroutine definition; read the next 2 bytes
from the tape, interpreting as an unsigned int; read that many bytes from the
tape as the ELSE subroutine definition; pull a value from the queue and evaluate
as a bool; if it is true, run the IF subroutine; else run the ELSE subroutine;
advance the pointer appropriately.

## OP_EVAL - 45 - x2D

Pulls a value from the stack then attempts to run it as a script. OP_EVAL shares
a common queue and cache with other ops. Script is disallowed from modifying
tape.flags or tape.definitions; it is executed with
callstack_count=tape.callstack_count+1 and copies of tape.flags and
tape.definitions; it also has access to all loaded contracts.

## OP_NOT - 46 - x2E

Pulls a value from the queue, interpreting as a bool; performs logical NOT
operation; puts that value onto the queue.

## OP_RANDOM - 47 - x2F

Read the next byte from the tape, interpreting as an unsigned int; put that many
random bytes onto the queue; advance the pointer.

## OP_RETURN - 48 - x30

Ends the script.

## OP_SET_FLAG - 49 - x31

Read the next byte from the tape, interpreting as an unsigned int; read that
many bytes from the tape as a flag; set that flag; advance the pointer
appropriately.

## OP_UNSET_FLAG - 50 - x32

Read the next byte from the tape, interpreting as an unsigned int; read that
many bytes from the tape as a flag; unset that flag; advance the pointer
appropriately.

## OP_DEPTH - 51 - x33

Put the size of the queue onto the queue.

## OP_SWAP - 52 - x34

Read the next 2 bytes from the tape, interpreting as unsigned ints; swap the
queue items at those depths; advance the pointer appropriately.

## OP_SWAP2 - 53 - x35

Swap the order of the top two items of the queue.

## OP_REVERSE - 54 - x36

Read the next byte from the tape, interpreting as an unsigned int; reverse that
number of items from the top of the queue.

## OP_CONCAT - 55 - x37

Pull two items from the queue; concatenate them; put the result onto the queue.

## OP_SPLIT - 56 - x38

Read the next byte from the tape, interpreting as an unsigned int index; pull an
item from the queue; split the item bytes at the index; put the results onto the
queue; advance pointer.

## OP_CONCAT_STR - 57 - x39

Pull two items from the queue, interpreting as UTF-8 strings; concatenate them;
put the result onto the queue.

## OP_SPLIT_STR - 58 - x3A

Read the next byte from the tape, interpreting as an unsigned int index; pull an
item from the queue, interpreting as a UTF-8 str; split the item str at the
index; put the results onto the queue; advance the pointer.

## OP_CHECK_TRANSFER - 59 - x3B

Read the next byte from the tape, interpreting as an unsigned int count; take an
item from the queue as a contract ID; take an item from the queue as an amount;
take an item from the queue as a serialized txn constraint; take an item from
the queue as a destination (address, locking script hash, etc); take the count
number of items from the queue as sources; take the count number of items from
the queue as transaction proofs; verify that the aggregate of the transfers to
the destination from the sources equal or exceed the amount; verify that the
transfers were valid using the proofs and the contract code; verify that any
constraints were followed; and put True onto the queue if successful and False
otherwise. Sources and proofs must be in corresponding order.

## OP_MERKLEVAL - 60 - x3C

Read 32 bytes from the tape as the root digest; pull a bool from the queue; call
OP_DUP then OP_SHA256; call OP_SWAP 1 2; if not bool, call OP_SWAP2; call
OP_CONCAT; call OP_SHA256; push root hash onto the queue; call OP_EQUAL_VERIFY;
call OP_EVAL.

## OP_TRY_EXCEPT - 61 - x3D

Read the next 2 bytes from the tape, interpreting as an unsigned int; read that
many bytes from the tape as the TRY subroutine definition; read 2 bytes from the
tape, interpreting as an unsigned int; read that many bytes as the EXCEPT
subroutine definition; execute the TRY subroutine in a try block; if an error
occurs, serialize it and put it in the cache then run the EXCEPT subroutine.

## NOP62 - 62 - x3E

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP63 - 63 - x3F

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP64 - 64 - x40

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP65 - 65 - x41

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP66 - 66 - x42

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP67 - 67 - x43

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP68 - 68 - x44

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP69 - 69 - x45

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP70 - 70 - x46

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP71 - 71 - x47

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP72 - 72 - x48

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP73 - 73 - x49

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP74 - 74 - x4A

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP75 - 75 - x4B

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP76 - 76 - x4C

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP77 - 77 - x4D

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP78 - 78 - x4E

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP79 - 79 - x4F

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP80 - 80 - x50

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP81 - 81 - x51

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP82 - 82 - x52

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP83 - 83 - x53

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP84 - 84 - x54

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP85 - 85 - x55

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP86 - 86 - x56

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP87 - 87 - x57

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP88 - 88 - x58

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP89 - 89 - x59

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP90 - 90 - x5A

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP91 - 91 - x5B

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP92 - 92 - x5C

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP93 - 93 - x5D

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP94 - 94 - x5E

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP95 - 95 - x5F

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP96 - 96 - x60

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP97 - 97 - x61

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP98 - 98 - x62

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP99 - 99 - x63

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP100 - 100 - x64

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP101 - 101 - x65

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP102 - 102 - x66

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP103 - 103 - x67

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP104 - 104 - x68

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP105 - 105 - x69

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP106 - 106 - x6A

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP107 - 107 - x6B

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP108 - 108 - x6C

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP109 - 109 - x6D

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP110 - 110 - x6E

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP111 - 111 - x6F

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP112 - 112 - x70

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP113 - 113 - x71

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP114 - 114 - x72

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP115 - 115 - x73

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP116 - 116 - x74

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP117 - 117 - x75

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP118 - 118 - x76

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP119 - 119 - x77

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP120 - 120 - x78

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP121 - 121 - x79

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP122 - 122 - x7A

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP123 - 123 - x7B

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP124 - 124 - x7C

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP125 - 125 - x7D

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP126 - 126 - x7E

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP127 - 127 - x7F

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP128 - 128 - x80

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP129 - 129 - x81

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP130 - 130 - x82

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP131 - 131 - x83

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP132 - 132 - x84

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP133 - 133 - x85

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP134 - 134 - x86

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP135 - 135 - x87

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP136 - 136 - x88

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP137 - 137 - x89

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP138 - 138 - x8A

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP139 - 139 - x8B

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP140 - 140 - x8C

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP141 - 141 - x8D

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP142 - 142 - x8E

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP143 - 143 - x8F

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP144 - 144 - x90

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP145 - 145 - x91

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP146 - 146 - x92

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP147 - 147 - x93

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP148 - 148 - x94

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP149 - 149 - x95

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP150 - 150 - x96

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP151 - 151 - x97

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP152 - 152 - x98

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP153 - 153 - x99

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP154 - 154 - x9A

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP155 - 155 - x9B

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP156 - 156 - x9C

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP157 - 157 - x9D

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP158 - 158 - x9E

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP159 - 159 - x9F

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP160 - 160 - xA0

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP161 - 161 - xA1

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP162 - 162 - xA2

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP163 - 163 - xA3

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP164 - 164 - xA4

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP165 - 165 - xA5

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP166 - 166 - xA6

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP167 - 167 - xA7

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP168 - 168 - xA8

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP169 - 169 - xA9

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP170 - 170 - xAA

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP171 - 171 - xAB

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP172 - 172 - xAC

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP173 - 173 - xAD

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP174 - 174 - xAE

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP175 - 175 - xAF

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP176 - 176 - xB0

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP177 - 177 - xB1

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP178 - 178 - xB2

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP179 - 179 - xB3

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP180 - 180 - xB4

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP181 - 181 - xB5

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP182 - 182 - xB6

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP183 - 183 - xB7

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP184 - 184 - xB8

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP185 - 185 - xB9

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP186 - 186 - xBA

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP187 - 187 - xBB

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP188 - 188 - xBC

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP189 - 189 - xBD

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP190 - 190 - xBE

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP191 - 191 - xBF

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP192 - 192 - xC0

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP193 - 193 - xC1

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP194 - 194 - xC2

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP195 - 195 - xC3

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP196 - 196 - xC4

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP197 - 197 - xC5

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP198 - 198 - xC6

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP199 - 199 - xC7

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP200 - 200 - xC8

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP201 - 201 - xC9

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP202 - 202 - xCA

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP203 - 203 - xCB

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP204 - 204 - xCC

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP205 - 205 - xCD

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP206 - 206 - xCE

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP207 - 207 - xCF

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP208 - 208 - xD0

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP209 - 209 - xD1

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP210 - 210 - xD2

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP211 - 211 - xD3

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP212 - 212 - xD4

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP213 - 213 - xD5

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP214 - 214 - xD6

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP215 - 215 - xD7

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP216 - 216 - xD8

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP217 - 217 - xD9

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP218 - 218 - xDA

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP219 - 219 - xDB

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP220 - 220 - xDC

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP221 - 221 - xDD

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP222 - 222 - xDE

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP223 - 223 - xDF

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP224 - 224 - xE0

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP225 - 225 - xE1

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP226 - 226 - xE2

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP227 - 227 - xE3

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP228 - 228 - xE4

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP229 - 229 - xE5

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP230 - 230 - xE6

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP231 - 231 - xE7

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP232 - 232 - xE8

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP233 - 233 - xE9

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP234 - 234 - xEA

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP235 - 235 - xEB

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP236 - 236 - xEC

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP237 - 237 - xED

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP238 - 238 - xEE

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP239 - 239 - xEF

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP240 - 240 - xF0

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP241 - 241 - xF1

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP242 - 242 - xF2

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP243 - 243 - xF3

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP244 - 244 - xF4

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP245 - 245 - xF5

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP246 - 246 - xF6

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP247 - 247 - xF7

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP248 - 248 - xF8

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP249 - 249 - xF9

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP250 - 250 - xFA

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP251 - 251 - xFB

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP252 - 252 - xFC

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP253 - 253 - xFD

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP254 - 254 - xFE

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.

## NOP255 - 255 - xFF

Read the next byte from the tape, interpreting as an unsigned int and pull that
many values from the queue. Does nothing with the values. Useful for later
soft-forks by redefining byte codes.


# Other interpreter functions

## `run_script(script: bytes, cache_vals: dict = {}, contracts: dict = {}, additional_flags: dict = {}): -> tuple[Tape, LifoQueue, dict]`

Run the given script byte code. Returns a tape, queue, and dict.

## `run_tape(tape: Tape, queue: LifoQueue, cache: dict, additional_flags: dict = {}): -> None`

Run the given tape using the queue and cache.

## `run_auth_script(script: bytes, cache_vals: dict = {}, contracts: dict = {}): -> bool`

Run the given auth script byte code. Returns True iff the queue has a single
\x01 value after script execution and no errors were raised; otherwise, returns
False.

## `add_opcode(code: int, name: str, function: Callable): -> None`

Adds an OP implementation with the code, name, and function.

## `add_contract(contract_id: bytes, contract: object): -> None`

Add a contract to be loaded on each script execution.

## `remove_contract(contract_id: bytes): -> None`

Remove a loaded contract to prevent it from being included on script execution.

## `add_contract_interface(interface: Protocol): -> None`

Adds an interface for type checking contracts. Interface must be a
runtime_checkable Protocol.

## `remove_contract_interface(interface: Protocol): -> None`

Removes an interface for type checking contracts.

# Parsing functions

## `compile_script(script: str): -> bytes`

Compile the given human-readable script into byte code.

## `decompile_script(script: bytes, indent: int = 0): -> list`

Decompile the byte code into human-readable script.

## `add_opcode_parsing_handlers(opname: str, compiler_handler: Callable, decompiler_handler: Callable): -> unseen_return_value`

Adds the handlers for parsing a new OP. The opname should start with OP_. The
compiler_handler should have this annotation: ( opname: str, symbols: list[str],
symbols_to_advance: int, symbol_index: int) -> tuple[int, tuple[bytes]]. The
decompiler_handler should have this annotation: (op_name: str, tape: Tape) ->
listr[str]. The OP implementation must be added to the interpreter via the
add_opcode function, else parsing will fail.

# Tools

## `create_merklized_script(branches: list, levels: list = None): -> tuple`

Produces a Merklized, branching script structure with a branch on the left at
every level. Returns a tuple of root script and list of branch execution
scripts.

## `generate_docs(): -> list`

Generates the docs file using annotations and docstrings.

## `add_soft_fork(code: int, name: str, op: Callable): -> unseen_return_value`

Adds a soft fork, adding the op to the interpreter and handlers for compiling
and decompiling.
