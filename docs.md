# OPs

Each `OP_` function has an alias that excludes the `OP_` prefix.

All `OP_` functions have the following signature:

```python
def OP_WHATEVER(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    ...
```

All OPs advance the Tape pointer by the amount they read.

## OP_FALSE - 0 - x00

Puts a null byte onto the queue.

Aliases:
- FALSE

## OP_TRUE - 1 - x01

Puts a 0x01 byte onto the queue.

Aliases:
- TRUE

## OP_PUSH0 - 2 - x02

Read the next byte from the tape; put it onto the queue.

Aliases:
- PUSH0

## OP_PUSH1 - 3 - x03

Read the next byte from the tape, interpreting as an unsigned int; take that
many bytes from the tape; put them onto the queue.

Aliases:
- PUSH1

## OP_PUSH2 - 4 - x04

Read the next 2 bytes from the tape, interpreting as an unsigned int; take that
many bytes from the tape; put them onto the queue.

Aliases:
- PUSH2

## OP_PUSH4 - 5 - x05

Read the next 4 bytes from the tape, interpreting as an unsigned int; take that
many bytes from the tape; put them onto the queue.

Aliases:
- PUSH4

## OP_POP0 - 6 - x06

Remove the first item from the queue and put it in the cache at key b'P' (can be
put back onto the queue with @P).

Aliases:
- POP0

## OP_POP1 - 7 - x07

Read the next byte from the tape, interpreting as an unsigned int; remove that
many items from the queue and put them in the cache at key b'P' (can be put back
onto the queue with @P).

Aliases:
- POP1

## OP_SIZE - 8 - x08

Pull a value from the queue; put the size of the value onto the queue as signed
int.

Aliases:
- SIZE

## OP_WRITE_CACHE - 9 - x09

Read the next byte from the tape, interpreting as an unsigned int; read that
many bytes from tape as cache key; read another byte from the tape, interpreting
as an int; read that many items from the queue and write them to the cache.

Aliases:
- WRITE_CACHE

## OP_READ_CACHE - 10 - x0A

Read the next byte from the tape, interpreting as an unsigned int; read that
many bytes from tape as cache key; read those values from the cache and place
them onto the queue.

Aliases:
- READ_CACHE

## OP_READ_CACHE_SIZE - 11 - x0B

Read the next byte from the tape, interpreting as an unsigned int; read that
many bytes from tape as cache key; count how many values exist at that point in
the cache and place that int onto the queue.

Aliases:
- READ_CACHE_SIZE
- OP_RCS
- RCS

## OP_READ_CACHE_Q - 12 - x0C

Pull a value from the queue as a cache key; put those values from the cache onto
the queue.

Aliases:
- READ_CACHE_Q
- OP_RCQ
- RCQ

## OP_READ_CACHE_Q_SIZE - 13 - x0D

Pull a value from the queue as a cache key; count the number of values in the
cache at that key; put the result onto the queue as a signed int.

Aliases:
- READ_CACHE_Q_SIZE
- OP_RCQS
- RCQS

## OP_ADD_INTS - 14 - x0E

Read the next byte from the tape, interpreting as an unsigned int; pull that
many values from the queue, interpreting them as signed ints; add them together;
put the result back onto the queue.

Aliases:
- ADD_INTS

## OP_SUBTRACT_INTS - 15 - x0F

Read the next byte from the tape, interpreting as uint count; pull that many
values from the queue, interpreting them as signed ints; subtract count-1 of
them from the first one; put the result onto the queue.

Aliases:
- SUBTRACT_INTS

## OP_MULT_INTS - 16 - x10

Read the next byte from the tape, interpreting as an unsigned int; pull that
many values from the queue, interpreting them as signed ints; multiply them
together; put the result back onto the queue.

Aliases:
- MULT_INTS

## OP_DIV_INT - 17 - x11

Read the next byte from the tape, interpreting as an unsigned int; read that
many bytes from the tape, interpreting as a signed int divisor (denominator);
pull a value from the queue, interpreting as a signed int dividend (numerator);
divide the dividend by the divisor; put the result onto the queue.

Aliases:
- DIV_INT

## OP_DIV_INTS - 18 - x12

Pull two values from the queue, interpreting as signed ints; divide the first by
the second; put the result onto the queue.

Aliases:
- DIV_INTS

## OP_MOD_INT - 19 - x13

Read the next byte from the tape, interpreting as an unsigned int; read that
many bytes from the tape, interpreting as a signed int divisor; pull a value
from the queue, interpreting as a signed int dividend; perform integer modulus:
dividend % divisor; put the result onto the queue.

Aliases:
- MOD_INT

## OP_MOD_INTS - 20 - x14

Pull two values from the queue, interpreting as signed ints; perform integer
modulus: first % second; put the result onto the queue.

Aliases:
- MOD_INTS

## OP_ADD_FLOATS - 21 - x15

Read the next byte from the tape, interpreting as an unsigned int; pull that
many values from the queue, interpreting them as floats; add them together; put
the result back onto the queue.

Aliases:
- ADD_FLOATS

## OP_SUBTRACT_FLOATS - 22 - x16

Read the next byte from the tape, interpreting as an unsigned int; pull that
many values from the queue, interpreting them as floats; subtract them from the
first one; put the result back onto the queue.

Aliases:
- SUBTRACT_FLOATS
- OP_SUBF
- SUBF

## OP_DIV_FLOAT - 23 - x17

Read the next 4 bytes from the tape, interpreting as a float divisor; pull a
value from the queue, interpreting as a float dividend; divide the dividend by
the divisor; put the result onto the queue.

Aliases:
- DIV_FLOAT

## OP_DIV_FLOATS - 24 - x18

Pull two values from the queue, interpreting as floats; divide the second by the
first; put the result onto the queue.

Aliases:
- DIV_FLOATS

## OP_MOD_FLOAT - 25 - x19

Read the next 4 bytes from the tape, interpreting as a float divisor; pull a
value from the queue, interpreting as a float dividend; perform float modulus:
dividend % divisor; put the result onto the queue.

Aliases:
- MOD_FLOAT
- OP_MODF
- MODF

## OP_MOD_FLOATS - 26 - x1A

Pull two values from the queue, interpreting as floats; perform float modulus:
second % first; put the result onto the queue.

Aliases:
- MOD_FLOATS
- OP_MODFS
- MODFS

## OP_ADD_POINTS - 27 - x1B

Read the next byte from the tape, interpreting as an unsigned int; pull that
many values from the queue; add them together using ed25519 point addition;
replace the result onto the queue.

Aliases:
- ADD_POINTS

## OP_COPY - 28 - x1C

Read the next byte from the tape, interpreting as an unsigned int; pull a value
from the queue; place that value and a number of copies corresponding to the int
from the tape back onto the queue.

Aliases:
- COPY

## OP_DUP - 29 - x1D

OP_COPY but with only 1 copy and no reading from the tape or advancing the
pointer. Equivalent to OP_DUP in Bitcoin script.

Aliases:
- DUP

## OP_SHA256 - 30 - x1E

Pull an item from the queue and put its sha256 hash back onto the queue.

Aliases:
- SHA256

## OP_SHAKE256 - 31 - x1F

Read the next byte from the tape, interpreting as an unsigned int; pull an item
from the queue; put its shake_256 hash of the spcified length back onto the
queue.

Aliases:
- SHAKE256

## OP_VERIFY - 32 - x20

Pull a value from the queue; evaluate it as a bool; and raise a
ScriptExecutionError if it is False.

Aliases:
- VERIFY

## OP_EQUAL - 33 - x21

Pull 2 items from the queue; compare them; put the bool result onto the queue.

Aliases:
- EQUAL

## OP_EQUAL_VERIFY - 34 - x22

Runs OP_EQUAL then OP_VERIFY.

Aliases:
- EQUAL_VERIFY

## OP_CHECK_SIG - 35 - x23

Take a byte from the tape, interpreting as the encoded allowable sigflags; pull
a value from the queue, interpreting as a VerifyKey; pull a value from the
queue, interpreting as a signature; check the signature against the VerifyKey
and the cached sigfields not disabled by a sig flag; put True onto the queue if
verification succeeds, otherwise put False onto the queue.

Aliases:
- CHECK_SIG

## OP_CHECK_SIG_VERIFY - 36 - x24

Runs OP_CHECK_SIG, then OP_VERIFY.

Aliases:
- CHECK_SIG_VERIFY
- OP_CSV
- CSV

## OP_CHECK_TIMESTAMP - 37 - x25

Pulls a value from the queue, interpreting as an unsigned int; gets the
timestamp to check from the cache; compares the two values; if the cache
timestamp is less than the queue time, or if current Unix epoch is behind cache
timestamp by the flagged amount, put False onto the queue; otherwise, put True
onto the queue. If the ts_threshold flag is <= 0, that check will be skipped.

Aliases:
- CHECK_TIMESTAMP

## OP_CHECK_TIMESTAMP_VERIFY - 38 - x26

Runs OP_CHECK_TIMESTAMP, then OP_VERIFY.

Aliases:
- CHECK_TIMESTAMP_VERIFY
- OP_CTV
- CTV

## OP_CHECK_EPOCH - 39 - x27

Pulls a value from the queue, interpreting as an unsigned int; gets the current
Unix epoch time; compares the two values; if current time is less than the queue
time, put False onto the queue; otherwise, put True onto the queue.

Aliases:
- CHECK_EPOCH

## OP_CHECK_EPOCH_VERIFY - 40 - x28

Runs OP_CHECK_EPOCH, then OP_VERIFY.

Aliases:
- CHECK_EPOCH_VERIFY
- OP_CEV
- CEV

## OP_DEF - 41 - x29

Read the next byte from the tape as the definition number; read the next 2 bytes
from the tape, interpreting as an unsigned int; read that many bytes from the
tape as the subroutine definition.

Aliases:
- DEF

## OP_CALL - 42 - x2A

Read the next byte from the tape as the definition number; call run_tape passing
that definition tape, the queue, and the cache.

Aliases:
- CALL

## OP_IF - 43 - x2B

Read the next 2 bytes from the tape, interpreting as an unsigned int; read that
many bytes from the tape as a subroutine definition; pull a value from the queue
and evaluate as a bool; if it is true, run the subroutine.

Aliases:
- IF

## OP_IF_ELSE - 44 - x2C

Read the next 2 bytes from the tape, interpreting as an unsigned int; read that
many bytes from the tape as the IF subroutine definition; read the next 2 bytes
from the tape, interpreting as an unsigned int; read that many bytes from the
tape as the ELSE subroutine definition; pull a value from the queue and evaluate
as a bool; if it is true, run the IF subroutine; else run the ELSE subroutine.

Aliases:
- IF_ELSE

## OP_EVAL - 45 - x2D

Pulls a value from the stack then attempts to run it as a script. OP_EVAL shares
a common queue and cache with other ops. Script is disallowed from modifying
tape.flags or tape.definitions; it is executed with
callstack_count=tape.callstack_count+1 and copies of tape.flags and
tape.definitions; it also has access to all loaded contracts.

Aliases:
- EVAL

## OP_NOT - 46 - x2E

Pulls a value from the queue, interpreting as a bool; performs logical NOT
operation; puts that value onto the queue.

Aliases:
- NOT

## OP_RANDOM - 47 - x2F

Read the next byte from the tape, interpreting as an unsigned int; put that many
random bytes onto the queue.

Aliases:
- RANDOM

## OP_RETURN - 48 - x30

Ends the script.

Aliases:
- RETURN

## OP_SET_FLAG - 49 - x31

Read the next byte from the tape, interpreting as an unsigned int; read that
many bytes from the tape as a flag; set that flag.

Aliases:
- SET_FLAG

## OP_UNSET_FLAG - 50 - x32

Read the next byte from the tape, interpreting as an unsigned int; read that
many bytes from the tape as a flag; unset that flag.

Aliases:
- UNSET_FLAG

## OP_DEPTH - 51 - x33

Put the size of the queue onto the queue.

Aliases:
- DEPTH

## OP_SWAP - 52 - x34

Read the next 2 bytes from the tape, interpreting as unsigned ints; swap the
queue items at those depths.

Aliases:
- SWAP

## OP_SWAP2 - 53 - x35

Swap the order of the top two items of the queue.

Aliases:
- SWAP2

## OP_REVERSE - 54 - x36

Read the next byte from the tape, interpreting as an unsigned int; reverse that
number of items from the top of the queue.

Aliases:
- REVERSE

## OP_CONCAT - 55 - x37

Pull two items from the queue; concatenate them first+second; put the result
onto the queue.

Aliases:
- CONCAT

## OP_SPLIT - 56 - x38

Read the next byte from the tape, interpreting as an unsigned int index; pull an
item from the queue; split the item bytes at the index; put the second byte
sequence onto the queue, then put the first byte sequence onto the queue.

Aliases:
- SPLIT

## OP_CONCAT_STR - 57 - x39

Pull two items from the queue, interpreting as UTF-8 strings; concatenate them;
put the result onto the queue.

Aliases:
- CONCAT_STR

## OP_SPLIT_STR - 58 - x3A

Read the next byte from the tape, interpreting as an unsigned int index; pull an
item from the queue, interpreting as a UTF-8 str; split the item str at the
index, then put the first str onto the queue; put the second str onto the queue.

Aliases:
- SPLIT_STR

## OP_CHECK_TRANSFER - 59 - x3B

Take an item from the queue as a contract ID; take an item from the queue as an
amount; take an item from the queue as a serialized txn constraint; take an item
from the queue as a destination (address, locking script hash, etc); take an
item from the queue, interpreting as an unsigned int count; take count number of
items from the queue as sources; take the count number of items from the queue
as transaction proofs; verify that the aggregate of the transfers to the
destination from the sources equal or exceed the amount; verify that the
transfers were valid using the proofs and the contract code; verify that any
constraints were followed; and put True onto the queue if successful and False
otherwise. Sources and proofs must be in corresponding order.

Aliases:
- CHECK_TRANSFER

## OP_MERKLEVAL - 60 - x3C

Read 32 bytes from the tape as the root digest; pull a bool from the queue; call
OP_DUP then OP_SHA256; call OP_SWAP 1 2; if not bool, call OP_SWAP2; call
OP_CONCAT; call OP_SHA256; push root hash onto the queue; call OP_EQUAL_VERIFY;
call OP_EVAL.

Aliases:
- MERKLEVAL

## OP_TRY_EXCEPT - 61 - x3D

Read the next 2 bytes from the tape, interpreting as an unsigned int; read that
many bytes from the tape as the TRY subroutine definition; read 2 bytes from the
tape, interpreting as an unsigned int; read that many bytes as the EXCEPT
subroutine definition; execute the TRY subroutine in a try block; if an error
occurs, serialize it and put it in the cache then run the EXCEPT subroutine.

Aliases:
- TRY_EXCEPT

## OP_LESS - 62 - x3E

Pull two signed ints val1 and val2 from queue; put (v1<v2) onto queue.

Aliases:
- LESS

## OP_LESS_OR_EQUAL - 63 - x3F

Pull two signed ints val1 and val2 from queue; put (v1<=v2) onto queue.

Aliases:
- LESS_OR_EQUAL
- OP_LEQ
- LEQ

## OP_GET_VALUE - 64 - x40

Read one byte from the tape as uint size; read size bytes from the tape,
interpreting as utf-8 string; put the read-only cache value(s) at that cache key
onto the queue, serialized as bytes.

Aliases:
- GET_VALUE
- OP_VAL
- VAL

## OP_FLOAT_LESS - 65 - x41

Pull two floats val1 and val2 from queue; put (v1<v2) onto queue.

Aliases:
- FLOAT_LESS
- OP_FLESS
- FLESS

## OP_FLOAT_LESS_OR_EQUAL - 66 - x42

Pull two floats val1 and val2 from queue; put (v1<=v2) onto queue.

Aliases:
- FLOAT_LESS_OR_EQUAL
- OP_FLEQ
- FLEQ

## OP_INT_TO_FLOAT - 67 - x43

Pull a signed int from the queue and put it back as a float.

Aliases:
- INT_TO_FLOAT
- OP_I2F
- I2F

## OP_FLOAT_TO_INT - 68 - x44

Pull a float from the queue and put it back as a signed int.

Aliases:
- FLOAT_TO_INT
- OP_F2I
- F2I

## OP_LOOP - 69 - x45

Read 2 bytes from the tape as uint len; read that many bytes from the tape as
the loop definition; run the loop as long as the top value of the queue is not
false or until a callstack limit exceeded error is raised.

Aliases:
- LOOP

## OP_CHECK_MULTISIG - 70 - x46

Reads 1 byte from tape as allowable flags; reads 1 byte from tape as uint m;
reads 1 byte from tape as uint n; pulls n values from queue as vkeys; pulls m
values from queue as signatures; verifies each signature against vkeys; puts
false onto the queue if any signature fails to validate with one of the vkeys or
if any vkey is used more than once; puts true onto the queue otherwise.

Aliases:
- CHECK_MULTISIG
- OP_CMS
- CMS

## OP_CHECK_MULTISIG_VERIFY - 71 - x47

Runs OP_CHECK_MULTISIG then OP_VERIFY.

Aliases:
- CHECK_MULTISIG_VERIFY
- OP_CMSV
- CMSV

## OP_SIGN - 72 - x48

Reads 1 byte from the tape as the sig_flag; pulls a value from the queue,
interpreting as a SigningKey; creates a signature using the correct sigfields;
puts the signature onto the queue. Raises ValueError for invalid key seed
length.

Aliases:
- SIGN

## OP_SIGN_QUEUE - 73 - x49

Pulls a value from the queue, interpreting as a SigningKey; pulls a message from
the queue; signs the message with the SigningKey; puts the signature onto the
queue. Raises ValueError for invalid key seed length.

Aliases:
- SIGN_QUEUE

## OP_CHECK_SIG_QUEUE - 74 - x4A

Pulls a value from the queue, interpreting as a VerifyKey; pulls a value from
the queue, interpreting as a signature; pulls a message from the queue; puts
True onto the queue if the signature is valid for the message and the VerifyKey,
otherwise puts False onto the queue. Raises ValueError for invalid vkey or
signature.

Aliases:
- CHECK_SIG_QUEUE
- OP_CSQ
- CSQ

## OP_DERIVE_SCALAR - 75 - x4B

Takes a value seed from queue; derives an ed25519 key scalar from the seed; puts
the key scalar onto the queue. Sets cache key b'x' to x if allowed by
tape.flags.

Aliases:
- DERIVE_SCALAR

## OP_CLAMP_SCALAR - 76 - x4C

Reads a byte from the tape, interpreting as a bool is_key; takes a value from
the queue; clamps it to an ed25519 scalar; puts the clamped ed25519 scalar onto
the queue. Raises ValueError for invalid value.

Aliases:
- CLAMP_SCALAR

## OP_ADD_SCALARS - 77 - x4D

Read the next byte from the tape, interpreting as an unsigned int; pull that
many values from the queue; add them together using ed25519 scalar addition; put
the sum onto the queue.

Aliases:
- ADD_SCALARS

## OP_SUBTRACT_SCALARS - 78 - x4E

Read the next byte from the tape, interpreting as uint count; pull that many
values from the queue, interpreting them as ed25519 scalars; subtract count-1 of
them from the first one; put the difference onto the queue.

Aliases:
- SUBTRACT_SCALARS

## OP_DERIVE_POINT - 79 - x4F

Takes an an ed25519 scalar value x from the queue; derives a curve point X from
scalar value x; puts X onto queue; sets cache key b'X' to X if allowed by
tape.flags (can be used in code with @X).

Aliases:
- DERIVE_POINT

## OP_SUBTRACT_POINTS - 80 - x50

Read the next byte from the tape, interpreting as an unsigned int; pull that
many values from the queue, interpreting them as ed25519 scalars; subtract them
from the first one; put the result onto the queue.

Aliases:
- SUBTRACT_POINTS

## OP_MAKE_ADAPTER_SIG_PUBLIC - 81 - x51

Takes three items from queue: public tweak point T, message m, and prvkey seed;
creates a signature adapter sa; puts nonce point R onto queue; puts signature
adapter sa onto queue; sets cache keys b'R' to R, b'T' to T, and b'sa' to sa if
allowed by tape.flags (can be used in code with @R, @T, and @sa).

Aliases:
- MAKE_ADAPTER_SIG_PUBLIC
- OP_MASU
- MASU

## OP_MAKE_ADAPTER_SIG_PRIVATE - 82 - x52

Takes three values, seed, t, and message m from the queue; derives prvkey x from
seed; derives pubkey X from x; derives private nonce r from seed and m; derives
public nonce point R from r; derives public tweak point T from t; creates
signature adapter sa; puts T, R, and sa onto queue; sets cache keys b't' to t if
tape.flags[5], b'T' to T if tape.flags[6], b'R' to R if tape.flags[4], and b'sa'
to sa if tape.flags[8] (can be used in code with @t, @T, @R, and @sa). Values
seed and t should be 32 bytes each. Values T, R, and sa are all public 32 byte
values and necessary for verification; t is used to decrypt the signature.

Aliases:
- MAKE_ADAPTER_SIG_PRIVATE
- OP_MASV
- MASV

## OP_CHECK_ADAPTER_SIG - 83 - x53

Takes public key X, tweak point T, message m, nonce point R, and signature
adapter sa from the queue; puts True onto queue if the signature adapter is
valid and False otherwise.

Aliases:
- CHECK_ADAPTER_SIG
- OP_CAS
- CAS

## OP_DECRYPT_ADAPTER_SIG - 84 - x54

Takes tweak scalar t, nonce point R, and signature adapter sa from queue;
calculates nonce RT; decrypts signature s from sa; puts s onto queue; puts RT
onto the queue; sets cache keys b's' to s if tape.flags[9] and b'RT' to RT if
tape.flags[7] (can be used in code with @s and @RT).

Aliases:
- DECRYPT_ADAPTER_SIG
- OP_DAS
- DAS

## OP_INVOKE - 85 - x55

Takes an item from the queue as a contract ID; takes a uint from the queue as
argcount; takes argcount items from the queue as arguments; tries to invoke the
contract's abi method, passing it the arguments; puts any return values onto the
queue. Raises ScriptExecutionError if the contract is missing. Raises TypeError
if the return value type is not bytes or NoneType. If allowed by tape.flag[0],
will put any return values into cache at key b'IR'.

Aliases:
- INVOKE

## OP_XOR - 86 - x56

Takes two values from the queue; XORs them together; puts result onto the queue.
Pads the shorter length value with x00.

Aliases:
- XOR

## OP_OR - 87 - x57

Takes two values from the queue; ORs them together; puts result onto the queue.
Pads the shorter length value with x00.

Aliases:
- OR

## OP_AND - 88 - x58

Takes two values from the queue; ANDs them together; puts result onto the queue.
Pads the shorter length value with x00.

Aliases:
- AND

## OP_GET_MESSAGE - 89 - x59

Reads a byte from tape as the sigflags; constructs the message that will be used
by OP_SIGN and OP_CHECK_SIG/_VERIFY from the sigfields; puts the result onto the
queue.

Aliases:
- GET_MESSAGE
- OP_MSG
- MSG

## NOP Codes - 90-255 (x5A-FF)

Codes in 90-255 (x5A-FF) Read the next byte from the tape, interpreting as an
unsigned int and pull that many values from the queue. Does nothing with the
values. Useful for later soft-forks by redefining byte codes.


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

## `add_contract_interface(interface: type): -> None`

Adds an interface for type checking contracts. Interface must be a
runtime_checkable Protocol.

## `remove_contract_interface(interface: type): -> None`

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
list[str]. The OP implementation must be added to the interpreter via the
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

# Notes

## Flags

The virtual machine includes a flag system for configuring some ops. The
following flags are standard:

- ts_threshold: int amount of slack allowable in timestamp comparisons (default 60)
- epoch_threshold: int amount of slack allowable in epoch comparisons (default 60)
- 0: when True (default True), `OP_INVOKE` sets cache key b'IR' to return value
- 1: when True (default True), relevant ops set cache key b'x' (private key)
- 2: when True (default True), relevant ops set cache key b'X' (public key)
- 3: when True (default True), relevant ops set cache key b'r' (nonce scalar)
- 4: when True (default True), relevant ops set cache key b'R' (nonce point)
- 5: when True (default True), relevant ops set cache key b't' (tweak scalar)
- 6: when True (default True), relevant ops set cache key b'T' (tweak point)
- 7: when True (default True), relevant ops set cache key b'RT' (nonce point * tweak point)
- 8: when True (default True), relevant ops set cache key b'sa' (signature adapter)
- 9: when True (default True), relevant ops set cache key b's' (signature)

These values can be changed by updating the `functions.flags` dict. Additional
flags can be defined with similar syntax.

```python
functions.flags['ts_threshold'] = 120
functions.flags[69] = 420
```

Integer flags 0-255 can be set or unset by `OP_SET_FLAG` and `OP_UNSET_FLAG`.
Flag keys must have type int or str, and flag values must have type int or bool.

The script running functions, `run_tape`, `run_script`, and `run_auth_script`
set all flags with keys contained in `functions.flags_to_set` before running the
script; other flags must be enabled with `OP_SET_FLAG`.

At this time, the CLI does not support setting custom flags.
