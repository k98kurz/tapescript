# Tapescript

## Overview

This scripting language was inspired by Bitcoin script. The main use envisioned
is as a method for embedding ACL into decentralized data structures, e.g. hash
DAGs. The core mechanisms under the hood are the following:

1. Tape: the `Tape` takes the script bytes and advances a pointer as the bytes are
read. It also keeps a dict of flags which control how certain ops execute and
a dict of contracts mapping contract_id to dict contracts used for checking
transfers between compatible protocols.
2. Queue: the `LifoQueue` provides a memory structure similar to the stack used in
Forth and Bitcoin script. Most ops interact with the queue, and most values are
stored in the queue.
3. Cache: the `dict` cache is where special values are held, e.g. a timestamp or
the parts of a message to be used for checking signatures. Additionally, it is
possible to move items from queue to cache or vice versa with the limitation
that only `bytes` cache keys can be used for these operations while interpreter
values are stored with `str` cache keys and thus inaccessible to scripts.

## Syntax

The syntax of tapescript is simple and unforgiving, and it takes two forms: the
bytes fed into the interpreter and the human-readable source code fed into the
compiler (which is really a transpiler). The syntax for byte code is just the
op code followed by its arguments. The syntax for human-readable code is
outlined below.

All symbols must be separated by whitespace, but which whitespace is used does
not matter. (Making source code easy on the eyes is still recommended, as it is
in any language; see [Style](## Style) section for detailed recommentations.)
Any op name, value, or bracket/parenthesis is a symbol.

### Values

All values in human-readable tapescript are prefixed by an encoding char:
- `d`: any value starting with `d` is an int or decimal float (e.g. `d123`)
- `s`: any value starting with `s` is is a string (e.g. `s"hello world"`)
- `x`: any value starting with `x` is hexadecimal bytes (e.g. `x00ff`)

### Comments

Everything between two hashtags or double quotes is disregarded as a comment.

### Calling ops

To call an op, write the op name followed by any argument(s). For example,
`OP_PUSH s"hello world"` will convert the utf-8 string "hello world" into bytes
and push it onto the queue, utilizing `OP_PUSH1`.

### Conditional programming

Tapescript includes three conditional operators: `OP_IF`, `OP_IF_ELSE`, and
`OP_MERKLEVAL`. `OP_IF_ELSE` is used under the hood for the human-readable
syntax of `OP_IF ( if_body ) ELSE ( else_body )`.

#### `OP_IF`/`OP_IF_ELSE`

Unlike in c- type languages, the condition is pulled from the queue by `OP_IF`/
`OP_IF_ELSE`, so the condition is not provided as an argument to the operators.

```s
OP_IF (
    OP_PUSH s"true value found on the queue"
) ELSE (
    OP_PUSH s"false value found on the queue"
)
```

If `OP_TRUE` was called, or non-null bytes were put on the queue in some other
way, before this script ran, the first branch will execute. If `OP_FALSE` was
called, or if null bytes were put on the queue, before this script ran, the
second branch will execute.

The bodies for both clauses must be between parentheses, or the final clause
must be terminated by `END_IF`, e.g. `OP_IF OP_DUP ELSE OP_POP0 END_IF`.

#### `OP_MERKLEVAL`

Tapescript includes a streamlined mechanism for branching scripts that hide the
unexecuted branches behind cryptographic commitments. The syntax for a locking
script using this mechanism is simply `OP_MERKLEVAL <root sha256 hash>`. This
op reads 32 bytes from the tape as the root digest; pulls a bool from the queue;
calls `OP_DUP` then `OP_SHA256`; calls `OP_SWAP d1 d2`; if not bool, calls
`OP_SWAP2`; calls `OP_CONCAT`; calls `OP_SHA256`; pushes root hash onto the
queue; calls `OP_EQUAL_VERIFY`; then calls `OP_EVAL`.

The unlocking script must provide the code of the branch to execute, the hash of
the unexecuted branch, and anything needed to execute the branch (in reverse
order). This generalizes to any number of levels of branches, but there can be
only two branches per level. These form a Merkle-tree like script structure.

See "Example 5: merklized script" in the [script_examples.md](https://github.com/k98kurz/tapescript/blob/master/script_examples.md#example-5-merklized-script)
file for a thorough example of how this works and how it compares to using
`OP_IF_ELSE` for conditional execution and cryptographic script commitments.

### Defining and calling functions

A function can be defined using `OP_DEF`. Up to 256 functions can be
defined, and all statements between the opening and closing curly braces (`{`
and `}`) or before a terminal `END_DEF` will be executed when the function is
called using `OP_CALL`. Each definition is referenced by an integer 0-255.
Note that the definition number passed as an argument for `OP_CALL` must be a
value like any other, while the integer used with `OP_DEF` is just a plain int.

Also note that the compiler currently does not support defining functions within
other functions. The interpreter can probably handle it, but that would be
undocumented behavior. If I get feedback that indicates this would be a useful
feature to support, I will revisit the topic.

```s
OP_DEF 0 {
    OP_DUP
    OP_SHA256
}

OP_DEF 1
    OP_DUP
    OP_SHAKE256 d20
END_DEF

OP_PUSH x0123
OP_CALL d0
OP_CALL d1
```

This will define two functions, put the 2 bytes x0123 onto the queue, then call
the two functions in sequence. The result will be a queue with x0123 and
`shake_256(sha256(b'\x01\x23').digest()).digest(20)`.

## Style

While style of human-readable source scripts is not enforced, the following are
encouraged:

- Each statement invoking an op should be on its own line.
- The bodies of functions and conditional clauses should be indented. I
recommend 4 spaces per indentation level.
- The opening bracket of a function should be at the end of the line starting
`OP_DEF`, and the closing bracket of the function should be on its own line
following the final statement of the function body. If `END_DEF` is used instead
of brackets, then it should be on its own line.
- The opening parenthesis should be at the end of the line starting `OP_IF` or
`ELSE`, and the closing parenthesis should be on a new line following the final
statement of the conditional clause body.
- `ELSE` should be on the same line as the closing parenthesis of the previous
conditional clause, i.e. `) ELSE (` should be its own line.
- If `END_IF` is used instead of a closing parenthesis, it should be on its own
line following the final statement of the conditional clause.
- The type prefix of a value should be lowercase. If not, at least be consistent.
- Brackets and parenthesis are recommended instead `END_DEF`/`END_IF`. Choose a
single convention and be consistent.

## Ops

Below is a list of ops, the arguments for each, and a brief explanation of what
each does. See [docs.md](docs.md) for more in-depth details about each op.

### List of ops

- `OP_FALSE` - puts x00 onto queue
- `OP_TRUE` - puts x01 onto queue
- `OP_PUSH val` - puts `val` onto queue; uses one of `OP_PUSH0`, `OP_PUSH1`,
`OP_PUSH2`, and `OP_PUSH4`, depending on the size of the `val`
- `OP_PUSH0 val` - puts `val` onto queue; `val` must be exactly 1 byte
- `OP_PUSH1 size val` - puts `val` onto queue; `val` byte length must be <256;
`size` must be the length of the `val`
- `OP_PUSH2 size val` - puts `val` onto queue; `val` byte length must be <65536;
`size` must be the length of the `val`
- `OP_PUSH4 size val` - puts `val` onto queue; `val` byte length must be <2^32;
`size` must be the length of the `val`
- `OP_POP0` - takes the top item from the queue and puts in the cache at b'P'
- `OP_POP1 count` - takes the top `count` items from the queue and puts them in the
cache at b'P'
- `OP_SIZE` - counts the number of items on the queue and puts it onto the queue
- `OP_WRITE_CACHE size cache_key count` - takes `count` number of items from the
queue and stores them at `cache_key`; `size` must be the length of `cache_key`
- `OP_READ_CACHE size cache_key` - takes values from the cache at `cache_key`
and puts them onto the queue; `size` must be the length of `cache_key`
- `OP_READ_CACHE_SIZE size cache_key` - counts the number of items in the cache
at `cache_key`; `size` must be the length of `cache_key`
- `OP_READ_CACHE_Q` - takes an item from the queue as a cache_key, reads the
items in the cache at that location, and puts them onto the queue
- `OP_READ_CACHE_Q_SIZE` - takes an item from the queue as a cache_key, counts the
number of items in the cache at that location, and puts the count onto the queue
- `OP_ADD_INTS count` - takes `count` number of ints from the queue, adds them
together, and puts the sum onto the queue
- `OP_SUBTRACT_INTS count` - takes `count` number of ints from the queue,
subtracts them from the first one, and puts the difference onto the queue
- `OP_MULT_INTS count` - takes `count` number of ints from the queue,
multiplies them together, and puts the product onto the queue
- `OP_DIV_INT size divisor` - takes an int from the queue, divides it by the
`divisor`, and puts the quotient onto the queue; `size` must be the byte length
of the divisor
- `OP_DIV_INTS` - takes two ints from the queue, divides the first by the second,
and puts the quotient onto the queue
- `OP_MOD_INT size divisor` - takes an int from the queue, divides it by the
`divisor`, and puts the remainder onto the queue; `size` must be the byte length
of the `divisor`
- `OP_MOD_INTS` - takes two ints from the queue, divides the first by the second,
and puts the remainder onto the queue
- `OP_ADD_FLOATS count` - takes `count` number of floats from the queue, adds
them together, and puts the sum onto the queue
- `OP_SUBTRACT_FLOATS count` - takes `count` number of floats from the queue,
subtracts them from the first one, and puts the difference onto the queue
- `OP_DIV_FLOAT divisor` - takes a float from the queue, divides it by `divisor`,
and puts the quotient onto the queue; `divisor` must be a 4-byte float
- `OP_DIV_FLOATS` - takes 2 floats from the queue, divides the second by the
first, and puts the quotient onto the queue
- `OP_MOD_FLOAT divisor` - takes a float from the queue, divides it by `divisor`,
and puts the remainder onto the queue
- `OP_MOD_FLOATS` - takes 2 floats from the queue, divides the second by the
first, and puts the remainder onto the queue
- `OP_ADD_POINTS count` - takes `count` ed25519 points from the queue, adds them
together, and puts the resulting ed25519 point onto the queue
- `OP_COPY count` - copies the top value on the queue `count` times
- `OP_DUP` - duplicates the top queue value
- `OP_SHA256` - replaces the top value of the queue with its sha256 digest
- `OP_SHAKE256 size` - replaces the top value of the queue with its `size`
length shake_256 digest
- `OP_VERIFY` - takes a value from the queue and raises an error if it does not
evaluate to `True`
- `OP_EQUAL` - takes 2 values from the queue and puts `True` onto the queue if
they are the same or `False` if they are not
- `OP_EQUAL_VERIFY` - calls `OP_EQUAL` and then `OP_VERIFY`
- `OP_CHECK_SIG allowed_flags` - takes a VerifyKey and signature from the queue,
builds a message from the cache values `sigfield[0-7]` depending upon the sig
flags allowed by `allowed_flags` and appended to the signature, checks if the
signature is valid for the VerifyKey and message, and puts `True` onto the queue
if the signature validated or `False` if it did not
- `OP_CHECK_SIG_VERIFY allowed_flags` - calls `OP_CHECK_SIG allowed_flags` then
`OP_VERIFY`
- `OP_CHECK_TIMESTAMP` - takes an unsigned int from the queue as a constraint,
takes a timestamp from the cache at "timestamp", compares the timestamp to the
constraint, and puts `False` onto the queue if the timestamp is less than the
constraint or if the "ts_threshold" flag was set and exceeded by the difference
between the timestamp and the current time and puts `True` onto the queue
otherwise
- `OP_CHECK_TIMESTAMP_VERIFY` - calls `OP_CHECK_TIMESTAMP` then `OP_VERIFY`
- `OP_CHECK_EPOCH` - takes an unsigned int from the queue as a constraint,
subtracts the current time from the constraint, and puts `False` onto the queue
if the "epoch_threshold" flag is met or exceeded by the difference and puts
`True` onto the queue otherwise
- `OP_CHECK_EPOCH_VERIFY` - calls `OP_CHECK_EPOCH` then `OP_VERIFY`
- `OP_DEF handle size def_body` - defines a function; see section above
- `OP_CALL handle` - calls a function; see section above
- `OP_IF length clause` - runs conditional code; see section above
- `OP_IF_ELSE length1 clause1 length2 clause2` - runs conditional code; see
section above
- `OP_EVAL` - takes a value from the queue and runs it as a script
- `OP_NOT` - takes a value from the queue and puts the inverse boolean value
onto the queue
- `OP_RANDOM size` - puts a random byte string `size` long onto the queue
- `OP_RETURN` - ends the script; since functions and conditional clauses are
run as subtapes, `OP_RETURN` ends only the local execution and returns to the
outer context
- `OP_SET_FLAG number` - sets the tape flag `number` to the default value
- `OP_UNSET_FLAG number` - unsets the tape flag `number`
- `OP_DEPTH` - puts the size of the queue onto the queue
- `OP_SWAP idx1 idx2` - swaps the items at the given indices on the queue
- `OP_SWAP2` - swaps the order of the top two items on the queue
- `OP_REVERSE count` - reverses the order of the top `count` items on the queue
- `OP_CONCAT` - takes two values from the queue, concatenates the second onto
the first, and puts the result onto the queue
- `OP_SPLIT idx` - takes a value from the queue, splits it at the given `idx`,
and puts the two resulting byte strings onto the queue
- `OP_CONCAT_STR` - takes 2 utf-8 strings from the queue, concatenates the 2nd
onto the 1st, and puts the result onto the queue
- `OP_SPLIT_STR idx` - takes a utf-8 string from the queue, splits at `idx`, and
puts the 2 resulting strings onto the queue
- `OP_CHECK_TRANSFER count` - checks proofs of a transfer; see section below
- `OP_MERKLEVAL hash` - enforces cryptographic commitment to branching script;
see section above
- `NOP count` - removes `count` values from the queue; dummy ops useful for soft
fork updates

### `OP_CHECK_TRANSFER count`

Reads the next byte from the tape, interpreting as an unsigned int `count`;
takes an item from the queue as a `contract_id`; takes an item from the queue as
an `amount`; takes an item from the queue as a serialized `constraint`; takes an
item from the queue as a `destination` (address, locking script hash, etc);
takes the `count` number of items from the queue as `sources`; takes the `count`
number of items from the queue as `txn_proofs`; verifies that the aggregate of
the transfers to the `destination` from the `sources` equals or exceeds the
`amount`; verifies that the transfers were valid using the proofs and the
contract code; verifies the `constraint` was followed for each txn proof; and
puts `True` onto the queue if successful and `False` otherwise. Sources and
proofs must be in corresponding order on the queue.

For this to work, the contract must be loaded into the tape's `contracts` dict
at the bytes `contract_id` dict key. This can be done by passing a contracts dict
into `run_script` or `run_auth_script`. The contract must be a dict with the
following functions defined at the corresponding dict keys:
- `verify_txn_proof(txn_proof: bytes) -> bool`
- `verify_transfer(txn_proof: bytes, source: bytes, destination: bytes) -> bool`
- `verify_txn_constraint(txn_proof: bytes, constraint: bytes) -> bool`
- `calc_txn_aggregates(txn_proofs: list[bytes], scope: bytes = None) -> dict[bytes, int]`

The contract should be the source of the values put onto the queue and passed to
the contract functions by `OP_CHECK_TRANSFER count` or at least sharing an
interface with the source of those values.

The first three functions will be called on each transaction proof, and a `False`
returned for any of them will result in `False` placed onto the queue. Then,
`calc_txn_aggregates` will be called and supplied the list of txn proofs, and
the result for the destination will be taken out of the result of that function
call; if it is equal to or greater than the `amount` and all proofs were valid,
it puts `True` onto the queue, else it puts `False` onto the queue.
