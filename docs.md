# OPs

Each `OP_` function has an alias that excludes the `OP_` prefix.

All `OP_` functions have the following signature:

```python
def OP_WHATEVER(tape: Tape, stack: Stack, cache: dict) -> None:
    ...
```

All OPs advance the Tape pointer by the amount they read.

## OP_FALSE - 0 - x00

Puts a null byte onto the stack.

Aliases:
- FALSE

## OP_TRUE - 1 - x01

Puts a 0xFF byte onto the stack.

Aliases:
- TRUE

## OP_PUSH0 - 2 - x02

Read the next byte from the tape; put it onto the stack.

Aliases:
- PUSH0

## OP_PUSH1 - 3 - x03

Read the next byte from the tape, interpreting as an unsigned int; take that
many bytes from the tape; put them onto the stack.

Aliases:
- PUSH1

## OP_PUSH2 - 4 - x04

Read the next 2 bytes from the tape, interpreting as an unsigned int; take that
many bytes from the tape; put them onto the stack.

Aliases:
- PUSH2

## OP_GET_MESSAGE - 5 - x05

Reads a byte from tape as the sigflags; constructs the message that will be used
by OP_SIGN and OP_CHECK_SIG/_VERIFY from the sigfields; puts the result onto the
stack. Runs the signature extension plugins beforehand.

Aliases:
- GET_MESSAGE
- OP_MSG
- MSG

## OP_POP0 - 6 - x06

Remove the first item from the stack and put it in the cache at key b'P' (can be
put back onto the stack with @P).

Aliases:
- POP0

## OP_POP1 - 7 - x07

Read the next byte from the tape, interpreting as an unsigned int; remove that
many items from the stack and put them in the cache at key b'P' (can be put back
onto the stack with @P).

Aliases:
- POP1

## OP_SIZE - 8 - x08

Pull a value from the stack; put the size of the value onto the stack as signed
int.

Aliases:
- SIZE

## OP_WRITE_CACHE - 9 - x09

Read the next byte from the tape, interpreting as an unsigned int; read that
many bytes from tape as cache key; read another byte from the tape, interpreting
as an int; read that many items from the stack and write them to the cache.

Aliases:
- WRITE_CACHE

## OP_READ_CACHE - 10 - x0A

Read the next byte from the tape, interpreting as an unsigned int; read that
many bytes from tape as cache key; read those values from the cache and place
them onto the stack.

Aliases:
- READ_CACHE

## OP_READ_CACHE_SIZE - 11 - x0B

Read the next byte from the tape, interpreting as an unsigned int; read that
many bytes from tape as cache key; count how many values exist at that point in
the cache and place that int onto the stack.

Aliases:
- READ_CACHE_SIZE
- OP_RCZ
- RCZ

## OP_READ_CACHE_STACK - 12 - x0C

Pull a value from the stack as a cache key; put those values from the cache onto
the stack.

Aliases:
- READ_CACHE_STACK
- OP_RCS
- RCS

## OP_READ_CACHE_STACK_SIZE - 13 - x0D

Pull a value from the stack as a cache key; count the number of values in the
cache at that key; put the result onto the stack as a signed int.

Aliases:
- READ_CACHE_STACK_SIZE
- OP_RCSZ
- RCSZ

## OP_ADD_INTS - 14 - x0E

Read the next byte from the tape, interpreting as an unsigned int; pull that
many values from the stack, interpreting them as signed ints; add them together;
put the result back onto the stack.

Aliases:
- ADD_INTS
- OP_ADD
- ADD

## OP_SUBTRACT_INTS - 15 - x0F

Read the next byte from the tape, interpreting as uint count; pull that many
values from the stack, interpreting them as signed ints; subtract count-1 of
them from the first one; put the result onto the stack.

Aliases:
- SUBTRACT_INTS
- OP_SUB
- SUB

## OP_MULT_INTS - 16 - x10

Read the next byte from the tape, interpreting as an unsigned int; pull that
many values from the stack, interpreting them as signed ints; multiply them
together; put the result back onto the stack.

Aliases:
- MULT_INTS
- OP_MULT
- MULT

## OP_DIV_INT - 17 - x11

Read the next byte from the tape, interpreting as an unsigned int; read that
many bytes from the tape, interpreting as a signed int divisor (denominator);
pull a value from the stack, interpreting as a signed int dividend (numerator);
divide the dividend by the divisor; put the result onto the stack.

Aliases:
- DIV_INT

## OP_DIV_INTS - 18 - x12

Pull two values from the stack, interpreting as signed ints; divide the first by
the second; put the result onto the stack.

Aliases:
- DIV_INTS
- OP_DIV
- DIV

## OP_MOD_INT - 19 - x13

Read the next byte from the tape, interpreting as an unsigned int; read that
many bytes from the tape, interpreting as a signed int divisor; pull a value
from the stack, interpreting as a signed int dividend; perform integer modulus:
dividend % divisor; put the result onto the stack.

Aliases:
- MOD_INT

## OP_MOD_INTS - 20 - x14

Pull two values from the stack, interpreting as signed ints; perform integer
modulus: first % second; put the result onto the stack.

Aliases:
- MOD_INTS
- OP_MOD
- MOD

## OP_ADD_FLOATS - 21 - x15

Read the next byte from the tape, interpreting as an unsigned int; pull that
many values from the stack, interpreting them as floats; add them together; put
the result back onto the stack.

Aliases:
- ADD_FLOATS

## OP_SUBTRACT_FLOATS - 22 - x16

Read the next byte from the tape, interpreting as an unsigned int; pull that
many values from the stack, interpreting them as floats; subtract them from the
first one; put the result back onto the stack.

Aliases:
- SUBTRACT_FLOATS
- OP_SUBF
- SUBF

## OP_DIV_FLOAT - 23 - x17

Read the next 4 bytes from the tape, interpreting as a float divisor; pull a
value from the stack, interpreting as a float dividend; divide the dividend by
the divisor; put the result onto the stack.

Aliases:
- DIV_FLOAT

## OP_DIV_FLOATS - 24 - x18

Pull two values from the stack, interpreting as floats; divide the second by the
first; put the result onto the stack.

Aliases:
- DIV_FLOATS

## OP_MOD_FLOAT - 25 - x19

Read the next 4 bytes from the tape, interpreting as a float divisor; pull a
value from the stack, interpreting as a float dividend; perform float modulus:
dividend % divisor; put the result onto the stack.

Aliases:
- MOD_FLOAT
- OP_MODF
- MODF

## OP_MOD_FLOATS - 26 - x1A

Pull two values from the stack, interpreting as floats; perform float modulus:
second % first; put the result onto the stack.

Aliases:
- MOD_FLOATS
- OP_MODFS
- MODFS

## OP_ADD_POINTS - 27 - x1B

Read the next byte from the tape, interpreting as an unsigned int; pull that
many values from the stack; add them together using ed25519 point addition;
replace the result onto the stack.

Aliases:
- ADD_POINTS

## OP_COPY - 28 - x1C

Read the next byte from the tape, interpreting as an unsigned int; pull a value
from the stack; place that value and a number of copies corresponding to the int
from the tape back onto the stack.

Aliases:
- COPY

## OP_DUP - 29 - x1D

OP_COPY but with only 1 copy and no reading from the tape or advancing the
pointer. Equivalent to OP_DUP in Bitcoin script.

Aliases:
- DUP

## OP_SHA256 - 30 - x1E

Pull an item from the stack and put its sha256 hash back onto the stack.

Aliases:
- SHA256

## OP_SHAKE256 - 31 - x1F

Read the next byte from the tape, interpreting as an unsigned int; pull an item
from the stack; put its shake_256 hash of the spcified length back onto the
stack.

Aliases:
- SHAKE256

## OP_VERIFY - 32 - x20

Pull a value from the stack; evaluate it as a bool; and raise a
ScriptExecutionError if it is False.

Aliases:
- VERIFY

## OP_EQUAL - 33 - x21

Pull 2 items from the stack; compare them; put the bool result onto the stack.

Aliases:
- EQUAL
- OP_EQ
- EQ

## OP_EQUAL_VERIFY - 34 - x22

Runs OP_EQUAL then OP_VERIFY.

Aliases:
- EQUAL_VERIFY
- OP_EQV
- EQV

## OP_CHECK_SIG - 35 - x23

Take a byte from the tape, interpreting as the encoded allowable sigflags; pull
a value from the stack, interpreting as a VerifyKey; pull a value from the
stack, interpreting as a signature; check the signature against the VerifyKey
and the cached sigfields not disabled by a sig flag; put True onto the stack if
verification succeeds, otherwise put False onto the stack. Runs the signature
extension plugins beforehand.

Aliases:
- CHECK_SIG
- OP_CS
- CS

## OP_CHECK_SIG_VERIFY - 36 - x24

Runs OP_CHECK_SIG, then OP_VERIFY.

Aliases:
- CHECK_SIG_VERIFY
- OP_CSV
- CSV

## OP_CHECK_TIMESTAMP - 37 - x25

Pulls a value from the stack, interpreting as an unsigned int; gets the
timestamp to check from the cache; compares the two values; if the cache
timestamp is less than the stack time, or if current Unix epoch is behind cache
timestamp by the flagged amount, put False onto the stack; otherwise, put True
onto the stack. If the ts_threshold flag is <= 0, that check will be skipped.

Aliases:
- CHECK_TIMESTAMP
- OP_CTS
- CTS

## OP_CHECK_TIMESTAMP_VERIFY - 38 - x26

Runs OP_CHECK_TIMESTAMP, then OP_VERIFY.

Aliases:
- CHECK_TIMESTAMP_VERIFY
- OP_CTSV
- CTSV

## OP_CHECK_EPOCH - 39 - x27

Pulls a value from the stack, interpreting as an unsigned int; gets the current
Unix epoch time; compares the two values; if current time is less than the stack
time, put False onto the stack; otherwise, put True onto the stack.

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
that definition tape, the stack, and the cache.

Aliases:
- CALL

## OP_IF - 43 - x2B

Read the next 2 bytes from the tape, interpreting as an unsigned int; read that
many bytes from the tape as a subroutine definition; pull a value from the stack
and evaluate as a bool; if it is true, run the subroutine.

Aliases:
- IF

## OP_IF_ELSE - 44 - x2C

Read the next 2 bytes from the tape, interpreting as an unsigned int; read that
many bytes from the tape as the IF subroutine definition; read the next 2 bytes
from the tape, interpreting as an unsigned int; read that many bytes from the
tape as the ELSE subroutine definition; pull a value from the stack and evaluate
as a bool; if it is true, run the IF subroutine; else run the ELSE subroutine.

Aliases:
- IF_ELSE

## OP_EVAL - 45 - x2D

Pulls a value from the stack then attempts to run it as a script. OP_EVAL shares
a common stack and cache with other ops. Script is disallowed from modifying
tape.flags or tape.definitions; it is executed with
callstack_count=tape.callstack_count+1 and copies of tape.flags and
tape.definitions; it also has access to all loaded contracts.

Aliases:
- EVAL

## OP_NOT - 46 - x2E

Pulls a value from the stack; performs bitwise NOT operation; puts result onto
the stack.

Aliases:
- NOT

## OP_RANDOM - 47 - x2F

Pull an item from the tape, interpreting as a signed int; put that many random
bytes onto the stack.

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

Put the stack item count onto the stack.

Aliases:
- DEPTH

## OP_SWAP - 52 - x34

Read the next 2 bytes from the tape, interpreting as unsigned ints; swap the
stack items at those depths.

Aliases:
- SWAP

## OP_SWAP2 - 53 - x35

Swap the order of the top two items of the stack.

Aliases:
- SWAP2

## OP_REVERSE - 54 - x36

Read the next byte from the tape, interpreting as an unsigned int; reverse that
number of items from the top of the stack.

Aliases:
- REVERSE

## OP_CONCAT - 55 - x37

Pull two items from the stack; concatenate them bottom+top; put the result onto
the stack.

Aliases:
- CONCAT
- OP_CAT
- CAT

## OP_SPLIT - 56 - x38

Pull a signed int index from the stack; pull an item from the stack; split the
item bytes at the index; put the first byte sequence onto the stack, then put
the second byte sequence onto the stack. Raises ScriptExecutionError for invalid
index.

Aliases:
- SPLIT

## OP_CONCAT_STR - 57 - x39

Pull two items from the stack, interpreting as UTF-8 strings; concatenate them;
put the result onto the stack.

Aliases:
- CONCAT_STR
- OP_CATS
- CATS

## OP_SPLIT_STR - 58 - x3A

Pull a signed int index from the stack; pull an item from the stack,
interpreting as a UTF-8 str; split the item str at the index; put the first str
onto the stack, then put the second str onto the stack.

Aliases:
- SPLIT_STR

## OP_CHECK_TRANSFER - 59 - x3B

Take an item from the stack as a contract ID; take an item from the stack as an
amount; take an item from the stack as a serialized txn constraint; take an item
from the stack as a destination (address, locking script hash, etc); take an
item from the stack, interpreting as an unsigned int count; take count number of
items from the stack as sources; take the count number of items from the stack
as transaction proofs; verify that the aggregate of the transfers to the
destination from the sources equals or exceeds the amount; verify that the
transfers were valid using the proofs and the contract code; verify that any
constraints were followed; and put True onto the stack if successful and False
otherwise. Sources and proofs must be in corresponding order.

Aliases:
- CHECK_TRANSFER

## OP_MERKLEVAL - 60 - x3C

Read 32 bytes from the tape as the root digest; call OP_DUP then OP_SHA256
twice; move stack item at index 2 to the top and call OP_SHA256 once; call
OP_XOR; call OP_SHA256; push root hash onto the stack; call OP_EQUAL_VERIFY;
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

Pull two signed ints val1 and val2 from stack; put (v1<v2) onto stack.

Aliases:
- LESS

## OP_LESS_OR_EQUAL - 63 - x3F

Pull two signed ints val1 and val2 from stack; put (v1<=v2) onto stack.

Aliases:
- LESS_OR_EQUAL
- OP_LEQ
- LEQ

## OP_GET_VALUE - 64 - x40

Read one byte from the tape as uint size; read size bytes from the tape,
interpreting as utf-8 string; put the read-only cache value(s) at that cache key
onto the stack, serialized as bytes.

Aliases:
- GET_VALUE
- OP_VAL
- VAL

## OP_FLOAT_LESS - 65 - x41

Pull two floats val1 and val2 from stack; put (v1<v2) onto stack.

Aliases:
- FLOAT_LESS
- OP_FLESS
- FLESS

## OP_FLOAT_LESS_OR_EQUAL - 66 - x42

Pull two floats val1 and val2 from stack; put (v1<=v2) onto stack.

Aliases:
- FLOAT_LESS_OR_EQUAL
- OP_FLEQ
- FLEQ

## OP_INT_TO_FLOAT - 67 - x43

Pull a signed int from the stack and put it back as a float.

Aliases:
- INT_TO_FLOAT
- OP_I2F
- I2F

## OP_FLOAT_TO_INT - 68 - x44

Pull a float from the stack and put it back as a signed int.

Aliases:
- FLOAT_TO_INT
- OP_F2I
- F2I

## OP_LOOP - 69 - x45

Read 2 bytes from the tape as uint len; read that many bytes from the tape as
the loop definition; run the loop as long as the top value of the stack is not
false or until a callstack limit exceeded error is raised.

Aliases:
- LOOP

## OP_CHECK_MULTISIG - 70 - x46

Reads 1 byte from tape as allowable flags; reads 1 byte from tape as uint m;
reads 1 byte from tape as uint n; pulls n values from stack as vkeys; pulls m
values from stack as signatures; verifies each signature against vkeys; puts
false onto the stack if any signature fails to validate with one of the vkeys or
if any vkey is used more than once; puts true onto the stack otherwise.

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

Reads 1 byte from the tape as the sig_flag; pulls a value from the stack,
interpreting as a SigningKey; creates a signature using the correct sigfields;
puts the signature onto the stack. Raises ValueError for invalid key seed
length. Runs the signature extension plugins beforehand. Resulting signature
will have the sig_flag appended to it if a non-null sig_flag is specified.

Aliases:
- SIGN

## OP_SIGN_STACK - 73 - x49

Pulls a value from the stack, interpreting as a SigningKey; pulls a message from
the stack; signs the message with the SigningKey; puts the signature onto the
stack. Raises ValueError for invalid key seed length.

Aliases:
- SIGN_STACK

## OP_CHECK_SIG_STACK - 74 - x4A

Pulls a value from the stack, interpreting as a VerifyKey; pulls a message from
the stack; pulls a value from the stack, interpreting as a signature; puts True
onto the stack if the signature is valid for the message and the VerifyKey,
otherwise puts False onto the stack. Raises ValueError for invalid vkey or
signature.

Aliases:
- CHECK_SIG_STACK
- OP_CSS
- CSS

## OP_DERIVE_SCALAR - 75 - x4B

Takes a value seed from stack; derives an ed25519 key scalar from the seed; puts
the key scalar onto the stack. Sets cache key b'x' to x if allowed by
tape.flags.

Aliases:
- DERIVE_SCALAR

## OP_CLAMP_SCALAR - 76 - x4C

Reads a byte from the tape, interpreting as a bool is_key; takes a value from
the stack; clamps it to an ed25519 scalar; puts the clamped ed25519 scalar onto
the stack. Raises ValueError for invalid value.

Aliases:
- CLAMP_SCALAR

## OP_ADD_SCALARS - 77 - x4D

Read the next byte from the tape, interpreting as an unsigned int; pull that
many values from the stack; add them together using ed25519 scalar addition; put
the sum onto the stack.

Aliases:
- ADD_SCALARS

## OP_SUBTRACT_SCALARS - 78 - x4E

Read the next byte from the tape, interpreting as uint count; pull that many
values from the stack, interpreting them as ed25519 scalars; subtract count-1 of
them from the first one; put the difference onto the stack.

Aliases:
- SUBTRACT_SCALARS

## OP_DERIVE_POINT - 79 - x4F

Takes an an ed25519 scalar value x from the stack; derives a curve point X from
scalar value x; puts X onto stack; sets cache key b'X' to X if allowed by
tape.flags (can be used in code with @X).

Aliases:
- DERIVE_POINT

## OP_SUBTRACT_POINTS - 80 - x50

Read the next byte from the tape, interpreting as an unsigned int; pull that
many values from the stack, interpreting them as ed25519 scalars; subtract the
rest from the first one; put the result onto the stack.

Aliases:
- SUBTRACT_POINTS

## OP_MAKE_ADAPTER_SIG_PUBLIC - 81 - x51

Takes three items from stack: public tweak point T, message m, and prvkey seed;
creates a signature adapter sa; puts nonce point R onto stack; puts signature
adapter sa onto stack; sets cache keys b'R' to R, b'T' to T, and b'sa' to sa if
allowed by tape.flags (can be used in code with @R, @T, and @sa).

Aliases:
- MAKE_ADAPTER_SIG_PUBLIC
- OP_MASU
- MASU

## OP_MAKE_ADAPTER_SIG_PRIVATE - 82 - x52

Takes three values from the stack: seed, t, and message m; derives prvkey x from
seed; derives pubkey X from x; derives private nonce r from seed and m; derives
public nonce point R from r; derives public tweak point T from t; creates
signature adapter sa; puts T, R, and sa onto stack; sets cache keys b't' to t if
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
adapter sa from the stack; puts True onto stack if the signature adapter is
valid and False otherwise.

Aliases:
- CHECK_ADAPTER_SIG
- OP_CAS
- CAS

## OP_DECRYPT_ADAPTER_SIG - 84 - x54

Takes tweak scalar t, nonce point R, and signature adapter sa from stack;
calculates nonce RT; decrypts signature s from sa; puts RT onto the stack; puts
s onto stack; sets cache keys b's' to s if tape.flags[9] and b'RT' to RT if
tape.flags[7] (can be used in code with @s and @RT).

Aliases:
- DECRYPT_ADAPTER_SIG
- OP_DAS
- DAS

## OP_INVOKE - 85 - x55

Takes an item from the stack as `contract_id`; takes an int from the stack as
`argcount`; takes `argcount` items from the stack as arguments; tries to invoke
the contract's abi method, passing it the arguments; puts any return values onto
the stack. Raises ScriptExecutionError if the argcount is negative, contract is
missing, or the contract does not implement the `CanBeInvoked` interface. Raises
TypeError if the return value type is not bytes or NoneType. If allowed by
tape.flag[0], will put any return values into cache at key b'IR'.

Aliases:
- INVOKE

## OP_XOR - 86 - x56

Takes two values from the stack; XORs them together; puts result onto the stack.
Pads the shorter length value with x00.

Aliases:
- XOR

## OP_OR - 87 - x57

Takes two values from the stack; ORs them together; puts result onto the stack.
Pads the shorter length value with x00.

Aliases:
- OR

## OP_AND - 88 - x58

Takes two values from the stack; ANDs them together; puts result onto the stack.
Pads the shorter length value with x00.

Aliases:
- AND

## OP_CHECK_TEMPLATE - 89 - x59

Reads 1 byte from the tape, interpreting as sigflags; pull an item from the
stack for each indicated sigfield as a template; check that all indicated
sigfields validate against the template using the plugin system; put True onto
the stack if every sigfield validated against its template by at least one ctv
plugin function, and False otherwise. Runs the signature extension plugins first
if tape.flags[10] is set to True, which is the default behavior. (The stack
passed to the plugin will contain the template on the top and the sigfield
beneath.)

Aliases:
- CHECK_TEMPLATE
- OP_CT
- CT

## OP_CHECK_TEMPLATE_VERIFY - 90 - x5A

Runs OP_CHECK_TEMPLATE and then OP_VERIFY.

Aliases:
- CHECK_TEMPLATE_VERIFY
- OP_CTV
- CTV

## OP_TAPROOT - 91 - x5B

Reads 1 byte from the tape as allowable sigflags; pops the top item of the stack
as the root; gets a copy of the next stack item (using stack.peek); if the item
has length 32, it is an ed25519 public key, otherwise it is a signature; if it
was a public key, then it is executing the committed script; if it is a
signature, then it is executing the key-spend path. For committed script
execution, get the public key and script from the stack, concatenate the
pubkey||sha256(script), sha256, clamp to the ed25519 scalar field, derive a
point, and add the point to the public key; if the result was the root, then put
the script back on the stack and `OP_EVAL`, otherwise remove the script and put
0x00 (False) onto the stack. For key-spend, run `OP_CHECK_SIG` using the
allowable sigflags.
https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-January/015614.html

Aliases:
- TAPROOT
- OP_TR
- TR

## NOP Codes - 92-255 (x5C-FF)

Codes in 92-255 (x5C-FF) Read the next byte from the tape, interpreting as a
signed int and pull that many values from the stack. Does nothing with the
values. Useful for later soft-forks by redefining byte codes. Raises
ScriptExecutionError if count is negative.


# Other interpreter functions

## `run_script(script: bytes | ScriptProtocol, cache_vals: dict = {}, contracts: dict = {}, additional_flags: dict = {}, plugins: dict = {}, stack_max_items: int = 1024, stack_max_item_size: int = 1024, callstack_limit: int = 128): -> tuple[Tape, Stack, dict]`

Run the given script byte code. Returns a tape, stack, and dict.

## `run_tape(tape: Tape, stack: Stack, cache: dict, additional_flags: dict = {}): -> None`

Run the given tape using the stack and cache.

## `run_auth_script(script: bytes | ScriptProtocol, cache_vals: dict = {}, contracts: dict = {}, plugins: dict = {}, stack_max_items: int = 1024, stack_max_item_size: int = 1024, callstack_limit: int = 128): -> bool`

Run the given auth script byte code. Returns True iff the stack has a single
\xff value after script execution and no errors were raised; otherwise, returns
False.

## `add_opcode(code: int, name: str, function: Callable): -> None`

Adds an OP implementation with the code, name, and function. Raises TypeError
for invalid arg types and ValueError for invalid code or name.

## `add_contract(contract_id: bytes, contract: object): -> None`

Add a contract to be loaded on each script execution. Raises TypeError if
contract_id is not bytes. Calls _check_contract, which raises
ScriptExecutionError if the contract does not match at least one contract
interface.

## `remove_contract(contract_id: bytes): -> None`

Remove a loaded contract to prevent it from being included on script execution.
Raises TypeError if contract_id is not bytes.

## `add_contract_interface(interface: type): -> None`

Adds an interface for type checking contracts. Interface must be a
runtime_checkable Protocol. Raises TypeError if the interface is not a Protocol.

## `remove_contract_interface(interface: type): -> None`

Removes an interface for type checking contracts. Raises TypeError if the
interface is not a Protocol.

# Parsing functions

## `get_symbols(script: str): -> list`

Split the script source into symbols. Raises SyntaxError for unterminated string
values.

## `parse_comptime(symbols: list, macros: dict = {}): -> list`

Preparses a list of symbols, replacing any comptime blocks with the compiled
byte code of the block as a hex value symbol or the top stack item as a hex
value symbol by compiling and executing the contents of the block. Returns a
modified list of symbols in which all comptime blocks have been replaced. Any
macros defined within the comptime block will be accessible outside of it, and
macros defined outside a comptime block can be invoked within it.

## `assemble(symbols: list, macros: dict = {}): -> bytes`

Assemble the symbols into bytecode. Raises SyntaxError and ValueError for
invalid syntax or values.

## `compile_script(script: str): -> bytes`

Compile the given human-readable script into byte code. Bubbles any SyntaxError
or ValueError raised by assemble.

## `decompile_script(script: bytes, indent: int = 0): -> list`

Decompile the byte code into human-readable script.

## `add_opcode_parsing_handlers(opname: str, compiler_handler: Callable, decompiler_handler: Callable): -> None`

Adds the handlers for parsing a new OP. The opname should start with OP_. The
compiler_handler should have this annotation: ( opname: str, symbols: list[str],
symbols_to_advance: int, symbol_index: int) -> tuple[int, tuple[bytes]]. The
decompiler_handler should have this annotation: (op_name: str, tape: Tape) ->
list[str]. The OP implementation must be added to the interpreter via the
add_opcode function, else parsing will fail.

# Tools

## `Script`

Represent a script as a pairing of source and byte code.

### Annotations

- src: str
- bytes: bytes

### Methods

#### `__init__(src: str, bytes: bytes):`

#### `@classmethod from_src(src: str) -> Script:`

Create an instance from tapescript source code.

#### `@classmethod from_bytes(code: bytes) -> Script:`

Create an instance from tapescript byte code.

#### `commitment() -> bytes:`

Return a cryptographic commitment for the Script.

## `ScriptLeaf`

A leaf in a Merklized script tree.

### Annotations

- hash: bytes
- script: Script | None
- parent: ScriptNode | None

### Methods

#### `__init__(hash: bytes, script: Script | None = None, parent: ScriptNode | None = None):`

#### `@classmethod from_script(script: Script) -> ScriptLeaf:`

Create an instance from a Script object.

#### `@classmethod from_src(src: str) -> ScriptLeaf:`

Create an instance from the source code.

#### `@classmethod from_code(code: bytes) -> ScriptLeaf:`

Create an instance from the byte code.

#### `commitment() -> bytes:`

Return the cryptographic commitment for the leaf.

#### `unlocking_script() -> Script:`

Calculate an unlocking script recursively, traveling up the parents. Returns a
Script with the source and byte codes. When executed, this will validate the
LeafScript against the root ScriptNode commitment (within an `OP_MERKLEVAL`
locking script), and then `OP_MERKLEVAL` will execute the underlying script.

#### `pack() -> bytes:`

Serialize the instance to bytes.

#### `@classmethod unpack(serialized: bytes) -> ScriptLeaf:`

Deserialize an instance from bytes.

## `ScriptNode`

A node in a Merklized script tree.

### Annotations

- left: ScriptLeaf | ScriptNode
- right: ScriptLeaf | ScriptNode
- parent: ScriptNode | None

### Methods

#### `__init__(left: ScriptLeaf | ScriptNode, right: ScriptLeaf | ScriptNode) -> None:`

Initialize the instance.

#### `root() -> bytes:`

Calculate and return the local root between the two branches.

#### `locking_script() -> Script:`

Calculates the locking script for the node. Returns a Script with the source and
byte codes in the form `OP_MERKLEVAL <root>`.

#### `commitment() -> bytes:`

Calculates the commitment to execute this ScriptNode and returns as bytes.

#### `unlocking_script() -> Script:`

Calculates a recursive unlocking script for the node. Returns a Script with the
source and byte codes.

#### `pack() -> bytes:`

Serialize the script tree to bytes.

#### `@classmethod unpack(data: bytes) -> ScriptNode:`

Deserialize a script tree from bytes.



## `repl(cache: dict = {}, contracts: dict = {}, add_flags: dict = {}, plugins: dict = {}): -> None`

Provides a REPL (Read Execute Print Loop). Lines of source code are read,
compiled, and executed, and the runtime state is shared between executions. If a
code block is opened, the Read functionality will continue accepting input until
all opened code blocks have closed, and it will automatically indent the input
line. To exit the loop, type "return", "exit", or "quit".

## `make_script_tree_prioritized(leaves: list[str | ScriptProtocol], tree: ScriptNode | None = None): -> ScriptNode`

Construct a script tree from the leaves using a ScriptLeaf for each leaf script,
combining the last two into a ScriptNode and then recursively combining a
ScriptLeaf for the last of the remaining script leaves with the previously
generated ScriptNode until all leaves have been included, priorizing the lower
index leaf scripts with smaller unlocking script sizes.

## `make_merklized_script_prioritized(leaves: list[str | ScriptProtocol]): -> tuple[Script, list[Script]]`

Produces a Merklized, branching script structure with one leaf and one node at
every level except for the last node, which is balanced. Returns a tuple of root
locking script and list of unlocking scripts. The tree is unbalanced; execution
is optimized for earlier branches (lower index leaf scripts), and execution is
linearly worse for each subsequent branch. In practice, the input scripts should
be locking scripts, and then they should be used by concatenating the
corresponding unlocking script and the unlocking script from this function.

## `make_script_tree_balanced(leaves: list[str | ScriptProtocol]): -> ScriptNode`

Create a balanced script tree from the leaves, filling with filler
leaves/branches to make sure the tree is balanced. The filler leaves take the
form of `push x{16 random bytes} return`, so they can never validate, and they
will have unique hashes to avoid revealing the presence of empty leaves/branches
during execution of actual leaf scripts. Used internally by the
`make_merklized_script_balanced` function.

## `make_merklized_script_balanced(leaves: list[str | ScriptProtocol]): -> tuple[Script, list[Script]]`

Produces a Merklized, branching script with a balanced tree structure, filling
with filler branches to make sure the tree is balanced (calls
`make_script_tree_balanced` under the hood). Returns a tuple of root locking
script and list of unlocking scripts corresponding to the input scripts. In
practice, the input scripts should be locking scripts, and then they should be
used by concatenating the corresponding unlocking script and the unlocking
script from this function.

## `make_adapter_lock_pub(pubkey: bytes, tweak_point: bytes, sigflags: str = 00): -> Script`

Make an adapter locking script that verifies a sig adapter, decrypts it, and
then verifies the decrypted signature. DEPRECATED: use `make_adapter_locks_pub`
instead.

## `make_adapter_lock_prv(pubkey: bytes, tweak: bytes, sigflags: str = 00): -> Script`

Make an adapter locking script that verifies a sig adapter, decrypts it, and
then verifies the decrypted signature. DEPRECATED: use `make_adapter_locks_prv`
instead.

## `make_single_sig_lock(pubkey: bytes, sigflags: str = 00): -> Script`

Make a locking Script that requires a valid signature from a single key to
unlock.

## `make_single_sig_lock2(pubkey: bytes, sigflags: str = 00): -> Script`

Make a locking Script that commits to and requires a public key and then valid
signature from the pubkey to unlock. Saves 8 bytes in locking script at expense
of an additional 33 bytes in the witness.

## `make_single_sig_witness(prvkey: bytes, sigfields: dict[str, bytes], sigflags: str = 00): -> Script`

Make an unlocking script that validates for a single sig locking script by
signing the sigfields. Returns Script that pushes the signature onto the stack.

## `make_single_sig_witness2(prvkey: bytes, sigfields: dict[str, bytes], sigflags: str = 00): -> Script`

Make an unlocking script that validates for a single sig locking script by
signing the sigfields. Returns a Script that pushes the signature and pubkey
onto the stack. 33 bytes larger witness than `make_single_sig_witness` to save 8
bytes in the locking script.

## `make_multisig_lock(pubkeys: list[bytes], quorum_size: int, sigflags: str = 00): -> Script`

Make a locking Script that requires quorum_size valid signatures from unique
keys within the pubkeys list. Can be unlocked by joining the results of
quorum_size calls to `make_single_sig_witness` by different key holders.

## `make_adapter_locks_pub(pubkey: bytes, tweak_point: bytes, sigflags: str = 00): -> tuple[Script, Script]`

Make adapter locking scripts using a public key and a tweak point. Returns 2
Scripts: one that checks if a sig adapter is valid, and one that verifies the
decrypted signature.

## `make_adapter_decrypt(tweak: bytes): -> Script`

Make adapter decryption script from a tweak scalar.

## `decrypt_adapter(adapter_witness: bytes | ScriptProtocol, tweak: bytes): -> bytes`

Decrypt an adapter signature with the given tweak scalar, returning the
decrypted signature.

## `make_adapter_locks_prv(pubkey: bytes, tweak: bytes, sigflags: str = 00): -> tuple[Script, Script, Script]`

Make adapter locking scripts using a public key and a tweak scalar. Returns a
tuple of 3 Scripts: one that checks if a sig adapter is valid, one that decrypts
the signature, and one that verifies the decrypted signature.

## `make_adapter_witness(prvkey: bytes, tweak_point: bytes, sigfields: dict, sigflags: str = 00): -> Script`

Make an adapter signature witness using a private key and a tweak point. Returns
tapescript src code.

## `make_delegate_key_lock(root_pubkey: bytes, sigflags: str = 00): -> Script`

Takes a root_pubkey and returns a locking Script that is unlocked with a
signature from the delegate key and a signed certificate from the root key
authorizing the delegate key.

## `make_delegate_key_cert(root_skey: bytes, delegate_pubkey: bytes, begin_ts: int, end_ts: int, can_further_delegate: bool = True): -> bytes`

Returns a signed key delegation cert. By default, this cert will authorize the
delegate_pubkey holder to create further delegate certs, allowing authorization
by a chain of certs. To disable this behavior and create a terminal cert, pass
`False` as the can_further_delegate argument.

## `make_delegate_key_witness(prvkey: bytes, cert: bytes, sigfields: dict, sigflags: str = 00): -> Script`

Returns an unlocking (witness) script including a signature from the delegate
key as well as the delegation certificate.

## `make_delegate_key_chain_witness(prvkey: bytes, certs: list[bytes], sigfields: dict, sigflags: str = 00): -> Script`

Returns an unlocking (witness) script including a signature from the delegate
key as well as the chain of delegation certificates ordered from the one
authorizing this key down to the first cert authorized by the root.

## `make_htlc_sha256_lock(receiver_pubkey: bytes, preimage: bytes, refund_pubkey: bytes, timeout: int = 86400, sigflags: str = 00): -> Script`

Returns an HTLC that can be unlocked either with the preimage and a signature
matching receiver_pubkey or with a signature matching the refund_pubkey after
the timeout has expired. Suitable only for systems with guaranteed causal
ordering and non-repudiation of transactions. Preimage should be at least 16
random bytes but not more than 32.

## `make_htlc_shake256_lock(receiver_pubkey: bytes, preimage: bytes, refund_pubkey: bytes, hash_size: int = 20, timeout: int = 86400, sigflags: str = 00): -> Script`

Returns an HTLC that can be unlocked either with the preimage and a signature
matching receiver_pubkey or with a signature matching the refund_pubkey after
the timeout has expired. Suitable only for systems with guaranteed causal
ordering and non-repudiation of transactions. Using a hash_size of 20 saves 11
bytes compared to the sha256 version with a 96 bit reduction in security
(remaining 160 bits) for the hash lock. Preimage should be at least 16 random
bytes but not more than 32.

## `make_htlc_witness(prvkey: bytes, preimage: bytes, sigfields: dict, sigflags: str = 00): -> Script`

Returns a witness to unlock either the hash lock or the time lock path of an
HTLC, depending upon whether or not the preimage matches. To use the time lock
path, pass a preimage of 1 byte to save space in the witness.

## `make_htlc2_sha256_lock(receiver_pubkey: bytes, preimage: bytes, refund_pubkey: bytes, timeout: int = 86400, sigflags: str = 00): -> Script`

Returns an HTLC that can be unlocked either with the preimage and a signature
matching receiver_pubkey or with a signature matching the refund_pubkey after
the timeout has expired. Suitable only for systems with guaranteed causal
ordering and non-repudiation of transactions. This version is optimized for
smaller locking script size (-18 bytes) at the expense of larger witnesses (+33
bytes) for larger overall txn size (+15 bytes). Which to use will depend upon
the intended use case: for public blockchains where all nodes must hold a UTXO
set in memory and can trim witness data after consensus, the lock script size
reduction is significant and useful; for other use cases, in particular systems
where witness data cannot be trimmed, the other version is more appropriate.

## `make_htlc2_shake256_lock(receiver_pubkey: bytes, preimage: bytes, refund_pubkey: bytes, hash_size: int = 20, timeout: int = 86400, sigflags: str = 00): -> Script`

Returns an HTLC that can be unlocked either with the preimage and a signature
matching receiver_pubkey or with a signature matching the refund_pubkey after
the timeout has expired. Suitable only for systems with guaranteed causal
ordering and non-repudiation of transactions. Using a hash_size of 20 saves 11
bytes compared to the sha256 version with a 96 bit reduction in security
(remaining 160 bits) for the hash lock. This version is optimized for smaller
locking script size (-18 bytes) at the expense of larger witnesses (+33 bytes)
for larger overall txn size (+15 bytes). Which to use will depend upon the
intended use case: for public blockchains where all nodes must hold a UTXO set
in memory and can trim witness data after consensus, the lock script size
reduction is significant and useful; for other use cases, in particular systems
where witness data cannot be trimmed, the other version is more appropriate.

## `make_htlc2_witness(prvkey: bytes, preimage: bytes, sigfields: dict, sigflags: str = 00): -> Script`

Returns a witness Script to unlock either the hash lock or the time lock path of
an HTLC, depending upon whether or not the preimage matches. This version is
optimized for smaller locking script size (-18 bytes) at the expense of larger
witnesses (+33 bytes) for larger overall txn size (+15 bytes). Which to use will
depend upon the intended use case: for public blockchains where all nodes must
hold a UTXO set in memory and can trim witness data after consensus, the lock
script size reduction is significant and useful; for other use cases, in
particular systems where witness data cannot be trimmed or in which witness size
should be minimized, the other version is more appropriate.

## `make_ptlc_lock(receiver_pubkey: bytes, refund_pubkey: bytes, tweak_point: bytes = None, timeout: int = 86400, sigflags: str = 00): -> Script`

Returns a Point Time Locked Contract (PTLC) Script that can be unlocked with
either a signature matching the receiver_pubkey or with a signature matching the
refund_pubkey after the timeout has expired. Suitable only for systems with
guaranteed causal ordering and non-repudiation of transactions. If a tweak_point
is passed, use tweak_point+receiver_pubkey as the point lock.

## `make_ptlc_witness(prvkey: bytes, sigfields: dict, tweak_scalar: bytes = None, sigflags: str = 00): -> Script`

Returns a PTLC witness unlocking the main branch. If a tweak_scalar is passed,
add tweak_scalar to x within signature generation to unlock the point
corresponding to `derive_point(tweak_scalar) + derive_point(x)`.

## `make_ptlc_refund_witness(prvkey: bytes, sigfields: dict, sigflags: str = 00): -> Script`

Returns a PTLC witness unlocking the time locked refund branch.

## `make_taproot_lock(pubkey: bytes, script: Script = None, script_commitment: bytes = None, sigflags: str = 00): -> Script`

Returns a Script for a taproot locking script that can either be unlocked with a
signature that validates using the taproot root commitment as a public key or by
supplying both the committed script and the committed public key to execute the
committed script.

## `make_taproot_witness_keyspend(prvkey: bytes, sigfields: dict, committed_script: Script = None, script_commitment: bytes = None, sigflags: str = 00): -> Script`

Returns a Script witness for a taproot keyspend.

## `make_taproot_witness_scriptspend(pubkey: bytes, committed_script: Script): -> Script`

Returns a Script witness for a taproot scriptspend, i.e. a witness that causes
the committed script to be executed.

## `make_nonnative_taproot_lock(pubkey: bytes, script: Script = None, script_commitment: bytes = None, sigflags: str = 00): -> Script`

Returns a locking Script for non-native taproot. This Script exists primarily to
compare against the native taproot lock and the nonnative graftroot lock.

## `make_graftap_lock(pubkey: bytes): -> Script`

Make a taproot lock committing to the (internal) pubkey and a graftroot lock.

## `make_graftap_witness_keyspend(prvkey: bytes, sigfields: dict, sigflags: str = 00): -> Script`

Make a Script witness for a taproot keyspend, providing the committed graftroot
lock hash and a signature.

## `make_graftap_witness_scriptspend(prvkey: bytes, surrogate_script: Script): -> Script`

Make a Script witness for a taproot scriptspend, providing the committed
graftroot lock, the internal pubkey, and the graftroot surrogate witness script.

## `setup_amhl(seed: bytes, pubkeys: tuple[bytes] | list[bytes], sigflags: str = 00, refund_pubkeys: dict[bytes] = None, timeout: int = 86400): -> dict[bytes | str, bytes | tuple[Script | bytes, ...]]`

Sets up an annoymous multi-hop lock for a sorted list of pubkeys. Returns a dict
mapping each public key to a tuple containing the tuple of scripts returned by
make_adapter_locks_pub and the tweak point for the hop, and mapping the key
'key' to the first tweak scalar needed to unlock the last hop in the AMHL and
begin the cascade back to the funding source. The order of pubkeys must start
with the originator and end with the correspondent of the receiver. If
refund_pubkeys dict is passed, then for any pk in pubkeys that is also a key in
the refund_pubkeys dict, the single sig lock (2nd value) will be replaced with a
PTLC.

## `release_left_amhl_lock(adapter_witness: bytes | ScriptProtocol, signature: bytes, y: bytes): -> bytes`

Release the next lock using an adapter witness and a decrypted signature from
right lock. Returns the tweak scalar used to decrypt the left adapter signature.

## `add_soft_fork(code: int, name: str, op: Callable): -> None`

Adds a soft fork, adding the op to the interpreter and handlers for compiling
and decompiling.

## `generate_docs(): -> list[str]`

Generates the docs file using annotations and docstrings. Requires the autodox
library, which is included in the optional "docs" dependencies.

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
- 10: when True (default True), `OP_CHECK_TEMPLATE` will run the signature extension plugins

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
