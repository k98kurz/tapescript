# Tapescript

## Overview

This scripting language was inspired by Bitcoin script. The main use envisioned
is as a method for embedding ACL into decentralized data structures, e.g. hash
DAGs. The core mechanisms under the hood are the following:

1. Tape: the `Tape` takes the script bytes and advances a pointer as the bytes
are read. It also keeps a dict of flags which control how certain ops execute
and a dict of contracts mapping contract_id to dict contracts used for checking
transfers between compatible protocols.
2. Queue: the `LifoQueue` provides a memory structure similar to the stack used
in Forth and Bitcoin script. Most ops interact with the queue, and most values
are stored in the queue.
3. Cache: the `dict` cache is where special values are held, e.g. a timestamp or
the parts of a message to be used for checking signatures. Additionally, it is
possible to move items from queue to cache or vice versa with the limitation
that only `bytes` cache keys can be used for these operations while interpreter
values are stored with `str` cache keys and thus inaccessible to scripts.

## Syntax

The syntax of tapescript is simple and unforgiving, and it takes two forms: the
bytes fed into the interpreter and the human-readable source code fed into the
compiler which produces bytecode for the VM. The syntax for bytecode is just the
op code followed by its arguments. The syntax for human-readable code is
outlined below.

All symbols must be separated by whitespace, but which whitespace is used does
not matter. (Making source code easy on the eyes is still recommended, as it is
in any language; see [Style](## Style) section for detailed recommendations.)
Any op name, value, or bracket/parenthesis is a symbol.

### Values

All values in human-readable tapescript are prefixed by an encoding char:
- `d`: any value starting with `d` is an int or decimal float (e.g. `d123`)
- `s`: any value starting with `s` is is a string (e.g. `s"hello world"`)
- `x`: any value starting with `x` is hexadecimal bytes (e.g. `x00ff`)

Note that string escapes are not currently supported. It is especially important
to note that an escaped quotation mark will not be interpreted by the compiler
as escaped and will instead terminate the string and cause a syntax error.

### Comments

Everything between two hashtags or double quotes is disregarded as a comment.

### Calling ops

To call an op, write the op name followed by any argument(s). For example,
`OP_PUSH s"hello world"` will convert the utf-8 string "hello world" into bytes
and push it onto the queue, utilizing `OP_PUSH1`. Note that each op has an alias
equal to the name of the op without the `OP_` prefix.

### Subtapes

Some features are implemented using subtapes by reading a 2 byte uint size
argument from the tape, then reading that many bytes from the tape as the
subtape definition, then executing the subtape. Subtape definitions have a
maximum size of 64KiB (2^16-1 bytes). The following features use subtapes:

- `OP_IF`
- `OP_IF_ELSE`
- `OP_DEF`
- `OP_TRY_EXCEPT`
- `OP_EVAL`
- `OP_LOOP`

Note that `OP_EVAL` does not require any arguments because it reads the top item
from the queue as the subtape definition rather than parsing one out from the
tape.

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

A tool is provided that generates the locking and unlocking scripts for use with
`OP_MERKLEVAL`. See the "#### Merklized Scripts" section of the readme for more
details.

### Exception handling

Some ops, such as `OP_VERIFY` and `OP_CHECK_EPOCH_VERIFY`, will raise exceptions
under certain conditions. If these ops are called within an `OP_TRY` block, the
exception will be caught, serialized, and put into the cache under the key x45,
then the `EXCEPT` block will be executed. Example:

```s
OP_TRY {
    OP_VERIFY
    OP_PUSH x20
} EXCEPT {
    OP_READ_CACHE x45
    OP_PUSH s"ScriptExecutionError|OP_VERIFY check failed"
    OP_EQUAL
}
```

The above results in a `20` hexadecimal value if it executed without error,
`true` if it raised a `ScriptExecutionError` with the given error message, and
`false` is some other error was raised.

This feature can be combined with soft forks for conditional logic.

```s
OP_TRY {
    OP_PUSH s"this is a new feature"
    OP_SOME_SOFT_FORK_RAISES_ERROR d1
    OP_PUSH s"old nodes will always execute this"
} EXCEPT {
    OP_PUSH s"old nodes will not execute this"
}
```

### Defining and calling functions

A function can be defined using `OP_DEF`. Up to 256 functions can be defined,
and all statements between the opening and closing curly braces (`{` and `}`)
or before a terminal `END_DEF` will be executed when the function is called
using `OP_CALL`. Each definition is referenced by an integer 0-255. Note that
the definition number passed as an argument for `OP_CALL` must be a value like
any other, while the integer used with `OP_DEF` can be a plain int or a value.

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
    OP_SHAKE256 d20
END_DEF

OP_PUSH x0123
OP_CALL d0
OP_CALL d1
```

This will define two functions, put the 2 bytes x0123 onto the queue, then call
the two functions in sequence. The result will be a queue with x0123 and
`shake_256(sha256(b'\x01\x23').digest()).digest(20)`.

### Loops

As of 0.4.0, tapescript supports loops. Loop logic is similar to conditional
logic: using `OP_LOOP { clause }`, it is possible to run the `clause` in a loop
as long as the top value of the queue evaluates to `True`. For example, to count
down from 10 to 0:

```s
push d10
loop {
    push d1
    swap2
    subtract_ints d2
}
```

If the top value evaluates to `False`, the loop code will not run. Additionally,
if the loop runs for more than the `callstack_limit`, a `ScriptExecutionError`
will be raised to prevent locking up the runtime with an infinite loop.

### Macros and Variables

As of v0.3.0, the compiler supports macros and variables of a sort.

#### Macros

Macros are code templates that take in arguments and return the source code with
the template values replaced by the macro arguments.

To define a macro, use the following syntax:

```s
!= name [ arg1 arg2 etc ] {
    OP_SOMETHING arg1
    OP_PUSH arg2
    OP_SOMETHING_ELSE
    # etc #
}
```

To invoke a macro, use the following:

```s
!name [ arg1 arg2 etc ]
```

Only positional arguments are supported, and the values supplied to macro calls
must be valid. Each macro invocation will be followed by a separate compilation
of just the resulting code, and that bytecode will be inserted if successful.

#### Variables

Variables are simply syntactic sugar for using the cache as a set of registers.
The syntax is simple: `@= name [ values ]` or `@= name int` to set and `@name`
to copy the values onto the stack. The first setting syntax pushes values onto
the stack and then puts them from the stack into the cache. The second setting
syntax simply pulls values from the stack. Variables cannot be used for
arguments to ops.

## Style

While style of human-readable source scripts is not enforced, the following are
encouraged:

- Each statement invoking an op should be on its own line except when a few such
statements are logically connected and result in one or zero values, e.g. two
`PUSH` ops followed by `ADD_INTS d2` or an op followed by `VERIFY`.
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
- The opening bracket of a try...except block should be at the end of the line
starting `OP_TRY`, and the closing bracket be on its own line following the
statements in the block. If an `EXCEPT` block is specified, it should be on the
same line as the closing bracket of the previous block. If `END_TRY` is used
instead of a closing bracket, then it should be on its own line.
- Brackets and parenthesis are recommended instead `END_DEF`/`END_IF`/`END_TRY`.
Choose a single convention and be consistent.

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
builds a message from the cache values `sigfield[1-8]` depending upon the sig
flags allowed by `allowed_flags` and appended to the signature, checks if the
signature is valid for the VerifyKey and message, and puts `True` onto the queue
if the signature validated or `False` if it did not
- `OP_CHECK_SIG_VERIFY allowed_flags` - calls `OP_CHECK_SIG allowed_flags` then
`OP_VERIFY`
- `OP_CHECK_TIMESTAMP` - takes an unsigned int from the queue as a constraint,
takes a timestamp from the cache at "timestamp", compares the timestamp to the
constraint, and puts `False` onto the queue if the timestamp is less than the
constraint or if the "ts_threshold" flag was set and exceeded by the difference
between the timestamp and the current time (i.e. if the timestamp is more than
ts_threshold into the future) and puts `True` onto the queue otherwise
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
- `OP_CHECK_TRANSFER` - checks proofs of a transfer; see section below
- `OP_MERKLEVAL hash` - enforces cryptographic commitment to branching script;
see section above
- `OP_TRY_EXCEPT size1 try_body size2 except_body` - executes the first block; if
an exception is raised, it is serialized into a string and put on the queue,
then the second block is executed
- `OP_LESS` - pulls 2 values `v1` and `v2` from queue; puts `(v1<v2)` onto queue
- `OP_LESS_OR_EQUAL` - pulls 2 values `v1` and `v2` from queue; puts `(v1<=v2)`
onto queue
- `OP_GET_VALUE key` - puts the read-only cache value(s) at the str `key` onto
the queue
- `OP_FLOAT_LESS` - takes floats `f1` and `f2` from the queue and puts `(f1<f2)`
onto the queue
- `OP_FLOAT_LESS_OR_EQUAL` - takes floats `f1` and `f2` from the queue and puts
`(f1<=f2)` onto the queue
- `OP_INT_TO_FLOAT` - takes int from queue and puts it back as a float
- `OP_FLOAT_TO_INT` - takes float from queue and puts it back as an int
- `OP_LOOP length clause` - runs the clause in a loop as long as the top value
on the queue is true; errors if the callstack limit is exceeded
- `OP_CHECK_MULTISIG allowed_flags m n` - takes `n` vkeys and `m` signatures
from queue; puts true onto the queue if each of the signatures is valid for one
of the vkeys and if each vkey is used only once; otherwise, puts false onto the
queue
- `OP_CHECK_MULTISIG_VERIFY allowed_flags m n` - calls `OP_CHECK_MULTISIG` then
`OP_VERIFY`
- `OP_SIGN allowed_flags` - pulls a signing key seed from the queue; generates a
signature from the sigfields; puts the signature onto the queue
- `OP_SIGN flags` - takes a signing key seed from the queue, signs a message
constructed from sigfields not blanked by the flags, and puts that signature
onto the queue.
- `OP_SIGN_QUEUE` - takes a signing key seed and message from the queue, signs
the message, and puts the signature onto the queue.
- `OP_CHECK_SIG_QUEUE` - takes a verify key, signature, and message from the
queue; puts `True` onto the queue if the signature was valid for the vkey and
message, otherwise puts `False` onto the queue.
- `OP_DERIVE_SCALAR` - takes a seed from queue; derives an ed25519 private key
scalar from it; puts the scalar onto the queue and into cache[b'x'] if
`tape.flags[1]`.
- `OP_CLAMP_SCALAR is_key` - reads byte from tape as bool `is_key`; pulls a
value from the queue; clamps the value as an ed25519 private key if `is_key`
else as normal scalar; puts clamped scalar onto the queue.
- `OP_ADD_SCALARS count` - takes `count` values from queue; uses ed25519 scalar
addition to sum them; put the sum onto the queue.
- `OP_SUBTRACT_SCALARS count` - takes `count` values from queue; uses ed25519
scalar subtraction to subtract `count-1` values from the first value; put the
difference onto the queue.
- `OP_DERIVE_POINT` - takes a value from the queue as a scalar; generates an
ed25519 curve point from it; puts the point onto the queue and into cache[b'X']
if `tape.flags[2]`.
- `OP_SUBTRACT_POINTS count` - takes `count` values from the queue as ed25519
points; subtracts `count-1` of them from the first using ed25519 inverse group
operator; puts difference onto the queue.
- `OP_MAKE_ADAPTER_SIG_PUBLIC` - takes tweak point `T`, message `m`, and prvkey
`seed` from queue; derives key scalar `x` from `seed` and nonce `r` from `seed`
and `m`; derives nonce point `R` from `r`; generates signature adapter `sa`;
puts `R` and `sa` onto queue; sets cache[b'r'] to `r` if `tape.flags[3]`; sets
cache[b'R'] to `R` if `tape.flages[4]`; sets cache[b'T'] to `T` if
`tape.flags[6]`; sets cache[b'sa'] if `tape.flags[9]`.
- `OP_MAKE_ADAPTER_SIG_PRIVATE` - takes prvkey `seed`, tweak scalar `t`, and
message `m` from the queue; derives prvkey scalar `x` from `seed`; derives
pubkey `X` from `x`; derives private nonce `r` from `seed` and `m`; derives
public nonce point `R` from `r`; derives public tweak point `T` from `t`;
creates signature adapter `sa`; puts `T`, `R`, and `sa` onto queue; sets cache
keys b't' to `t` if `tape.flags[5]`, b'T' to `T` if `tapeflags[6]`, b'R' to `R`
if `tape.flags[4]`, and b'sa' to `sa` if `tape.flags[8]` (can be used in code
with @t, @T, @R, and @sa). Values `seed` and `t` should be 32 bytes each. Values
`T`, `R`, and `sa` are all public 32 byte values and necessary for verification;
`t` is used to decrypt the signature.
- `OP_CHECK_ADAPTER_SIG` - takes public key `X`, tweak point `T`, message `m`,
nonce point `R`, and signature adapter `sa` from the queue; puts `True` onto the
queue if the signature adapter is valid and `False` otherwise.
- `OP_DECRYPT_ADAPTER_SIG` - takes tweak scalar `t`, nonce point `R`, and
signature adapter `sa` from queue; calculates nonce `RT`; decrypts signature
`s` from `sa`; puts `s` onto queue; puts `RT` onto the queue; sets cache keys
b's' to `s` if `tape.flags[9]` and b'RT' to `RT` if `tape.flags[7]` (can be used
in code with @s and @RT).
- `OP_INVOKE` - takes an item from the queue as a contract ID; takes a uint from
the queue as `count`; takes `count` items from the queue as arguments; tries to
invoke the contract's `abi` method, passing it the arguments; puts any return
values onto the queue. Raises `ScriptExecutionError` if the contract is missing.
Raises `TypeError` if the return value type is not bytes or NoneType. If allowed
by `tape.flags[0]`, will put any return values into cache at key b'IR'.
- `OP_XOR` - takes two items from the queue; bitwise XORs them together; puts
result onto the queue. Can be used in boolean logic as boolean values are just
bytes.
- `OP_OR` - takes two items from the queue; bitwise ORs them together; puts
result onto the queue. Can be used in boolean logic as boolean values are just
bytes.
- `OP_AND` - takes two items from the queue; bitwise ANDs them together; puts
result onto the queue. Can be used in boolean logic as boolean values are just
bytes.
- `NOP count` - removes `count` values from the queue; dummy ops useful for soft
fork updates

### `OP_CHECK_TRANSFER`

Pulls an item from the queue, interpreting as an unsigned int `count`;
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
into `run_script` or `run_auth_script`. If the contract should be loaded for all
script executions, instead it can be added with `add_contract(contract_id, contract)`.
The contract must be an instance of a class implementing the `CanCheckTransfer`
interface with following functions:
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

### `OP_INVOKE`

Takes an item from the queue as `contract_id`; takes a uint from the queue as
`argcount`; takes `argcount` items from the queue as arguments; tries to invoke
the contract's `abi` method, passing it the arguments; puts any return values
onto the queue. Raises `ScriptExecutionError` if the contract is missing or does
not implement the `CanBeInvoked` interface. Raises `TypeError` if the return
value type is not bytes or NoneType. If allowed by tape.flag[0], will put any
return values into cache at key b'IR'.

Example:

```python
# file somecontract.py
from tapescript import int_to_bytes

class SomeContract:
    def abi(self, args: list[bytes]) -> list[bytes]:
        if not len(args):
            return [b'\x00']
        avg_size = sum([len(a) for a in args]) / len(args)
        return [int_to_bytes(int(avg_size))]

# file bootstrap.py
from hashlib import shake_256
from inspect import getsource
import somecontract

def boot():
    contract_id = shake_256(bytes(getsource(somecontract), 'utf-8')).digest(20)
    add_contract(contract_id, somecontract.SomeContract)

# file test.py
from bootstrap import boot
from tapescript import compile_script, run_script, bytes_to_int

boot()

script = '''
push xfeedbeef
push s"yellow submarine"
push d2
push x66b58394825b07bc65e504697654d7dd43640f26
invoke
'''

_, queue, cache = run_script(compile_script(script))
assert queue.qsize() == 1
assert bytes_to_int(queue.get(False)) == 10
```
