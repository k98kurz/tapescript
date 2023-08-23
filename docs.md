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

## NOP Codes - 62-255 (x3E-FF)

Codes in 62-255 (x3E-FF) Read the next byte from the tape, interpreting as an
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
