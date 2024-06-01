# Tapescript

## Overview

This scripting language was inspired by Bitcoin script. The main use envisioned
is as a method for embedding ACL into decentralized data structures, e.g. hash
DAGs. The core mechanisms under the hood are the following:

1. Tape: the `Tape` takes the script bytes and advances a pointer as the bytes
are read. It also keeps a dict of flags which control how certain ops execute
and a dict of contracts mapping contract_id to dict contracts used for checking
transfers between compatible protocols.
2. Stack: the `Stack` provides a memory structure similar to the stack used
in Forth and Bitcoin script. Most ops interact with the stack, and most values
are stored in the stack. The stack can contain only `bytes` items; each item is
limited in size; and the number of items is also limited.
3. Cache: the `dict` cache is where special values are held, e.g. a timestamp or
the parts of a message to be used for checking signatures. Additionally, it is
possible to move items from stack to cache or vice versa with the limitation
that only `bytes` cache keys can be used for these operations while interpreter
values are stored with `str` cache keys and thus cannot be written by scripts.

## Syntax

The syntax of tapescript is simple and unforgiving, and it takes two forms: the
bytes fed into the interpreter and the human-readable source code fed into the
compiler which produces bytecode for the VM. The syntax for bytecode is just the
op code followed by its arguments. The syntax for human-readable code is
outlined below.

All symbols must be separated by whitespace, but which whitespace is used does
not matter. (Making source code easy on the eyes is still recommended, as it is
in any language; see the Style section below for detailed recommendations.)
Any op name, value, or bracket/parenthesis is a symbol.

### Values

All values in human-readable tapescript are prefixed by an encoding char:
- `d`: any value starting with `d` is a decimal int (e.g. `d123`)
- `f`: any value starting with `f` is a decimal float (e.g. `f-3.21`)
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
and push it onto the stack, utilizing `OP_PUSH1`. Note that each op has an alias
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
- `OP_MERKLEVAL`
- `OP_TAPROOT`
- `OP_LOOP`

Note that `OP_EVAL` does not require any arguments because it reads the top item
from the stack as the subtape definition rather than parsing one out from the
tape. `OP_MERKLEVAL` and `OP_TAPROOT` call `OP_EVAL` if the supplied script
validates as part of the cryptographic commitment.

### Conditional programming

Tapescript includes three conditional operators: `OP_IF`, `OP_IF_ELSE`, and
`OP_MERKLEVAL`. `OP_IF_ELSE` is used under the hood for the human-readable
syntax of `OP_IF ( hoisted_statements ) { if_body } ELSE { else_body }`.

#### `OP_IF`/`OP_IF_ELSE`

Unlike in c- type languages, the condition is pulled from the stack by `OP_IF`/
`OP_IF_ELSE`, so the condition is not provided as an argument to the operators.

```s
OP_IF {
    OP_PUSH s"true value found on the stack"
} ELSE {
    OP_PUSH s"false value found on the stack"
}
```

However, conditional statement hoisting is available, so any statements in
parentheses after `OP_IF` will be hoisted, e.g. `IF ( <statements> ) { <body> }`
will be compiled as `<statements> IF { <body> }`.

If `OP_TRUE` was called, or non-null bytes were put on the stack in some other
way, before this script ran, the first branch will execute. If `OP_FALSE` was
called, or if null bytes were put on the stack, before this script ran, the
second branch will execute.

The bodies for both clauses must be between parentheses, or the final clause
must be terminated by `END_IF`, e.g. `OP_IF OP_DUP ELSE OP_POP0 END_IF`.

#### `OP_MERKLEVAL`

Tapescript includes a streamlined mechanism for branching scripts that hide the
unexecuted branches behind cryptographic commitments. The syntax for a locking
script using this mechanism is simply `OP_MERKLEVAL <root sha256 hash>`. This
op reads 32 bytes from the tape as the root digest; calls `OP_DUP` then
`OP_SHA256` twice; moves stack item at index 2 to the top and calls `OP_SHA256`
once; calls `OP_XOR`; calls `OP_SHA256`; pushes root hash onto the stack;
calls `OP_EQUAL_VERIFY`; then finally calls `OP_EVAL`.

The unlocking script must provide the code of the branch to execute, the hash of
the unexecuted branch, and anything needed to execute the branch (in reverse
order). This generalizes to any number of levels of branches, but there can be
only two branches per level. These form a Merkle-tree like script structure.

See "Example 5: merklized script" in the [script_examples.md](https://github.com/k98kurz/tapescript/blob/v0.5.0/script_examples.md#example-5-merklized-script)
file for a thorough example of how this works and how it compares to using
`OP_IF_ELSE` for conditional execution and cryptographic script commitments.

Tools are provided that generate the locking and unlocking scripts for use with
`OP_MERKLEVAL`. See the "#### Merklized Scripts" section of the readme for more
details.

#### `OP_TAPROOT`

Tapescript includes an implementation of the taproot mechanism whereby a script
commitment and a public key are combined into a single root commitment which
allows for two execution branches: checking a signature against the root
commitment (which is a valid public key) and executing the committed script
after proving that the committed script and public key combine to form the root.
The locking script is `OP_TAPROOT <root commitment>`.

The key-spend unlocking script takes the following form: `PUSH <sig>`, where the
`sig` is a signature created with the private key corresponding to the committed
public key tweaked by adding an ed25519 scalar derived from
`sha256(pubkey + sha256(script))`. This signature then validates against the
root commitment, itself a tweaked public key.

The script-spend unlocking script takes the following form:
`PUSH <script> PUSH <pubkey>`. When the locking script runs, `OP_TAPROOT` will
verify that the supplied script and pubkey combine to form the root commitment,
then it will execute the script. Any additional conditions encoded in the script
must be fulfilled prior; in practice the committed script will be another
locking script, and the unlocking script will be a combination of the unlocking
script for the script and then the unlocking proof for `OP_TAPROOT`.

By using an `OP_MERKLEVAL` locking script as the committed script, `OP_TAPROOT`
provides an equivalent script experience as the Taproot+MAST upgrade to Bitcoin.

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

This will define two functions, put the 2 bytes x0123 onto the stack, then call
the two functions in sequence. The result will be a stack with x0123 and
`shake_256(sha256(b'\x01\x23').digest()).digest(20)`.

### Loops

As of 0.4.0, tapescript supports loops. Loop logic is similar to conditional
logic: using `OP_LOOP { clause }`, it is possible to run the `clause` in a loop
as long as the top value of the stack evaluates to `True`. For example, to count
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
syntax simply pulls values from the stack. Variables cannot be used for on-tape
arguments to ops, e.g. `OP_MERKLEVAL @root` will not work.

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
of brackets, then it should be on its own deindented line.
- The opening parenthesis should be at the end of the line starting `OP_IF` or
`ELSE`, and the closing parenthesis should be on a new line following the final
statement of the conditional clause body.
- `ELSE` should be on the same line as the closing parenthesis of the previous
conditional clause, i.e. `} ELSE {` should be its own line.
- If `END_IF` is used instead of a closing parenthesis, it should be on its own
deindented line following the final statement of the conditional clause.
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

In the op call syntax below, prefixed values within brackets are items on the
stack, in the order in which they must be pushed onto the stack.

- `OP_FALSE` - puts x00 onto stack
- `OP_TRUE` - puts xFF onto stack
- `OP_PUSH val` - puts `val` onto stack; uses one of `OP_PUSH0`, `OP_PUSH1`, or
`OP_PUSH2`, depending on the size of the `val`
- `OP_PUSH0 val` - puts `val` onto stack; `val` must be exactly 1 byte
- `OP_PUSH1 size val` - puts `val` onto stack; `val` byte length must be <256;
`size` must be the length of the `val`
- `OP_PUSH2 size val` - puts `val` onto stack; `val` byte length must be <65536;
`size` must be the length of the `val`
- `OP_GET_MESSAGE sigflags` - constructs the message from the sigfields and puts
it onto the stack; runs signature extension plugins beforehand
- `OP_POP0` - takes the top item from the stack and puts in the cache at b'P'
- `OP_POP1 count` - takes the top `count` items from the stack and puts them in the
cache at b'P'
- `OP_SIZE` - counts the number of items on the stack and puts it onto the stack
- `OP_WRITE_CACHE size cache_key count` - takes `count` number of items from the
stack and stores them at `cache_key`; `size` must be the length of `cache_key`
- `OP_READ_CACHE size cache_key` - takes values from the cache at `cache_key`
and puts them onto the stack; `size` must be the length of `cache_key`
- `OP_READ_CACHE_SIZE size cache_key` - counts the number of items in the cache
at `cache_key`; `size` must be the length of `cache_key`
- `[cache_key] OP_READ_CACHE_STACK` - takes an item from the stack as a
cache_key, reads the items in the cache at that location, and puts them onto the
stack
- `[cache_key] OP_READ_CACHE_STACK_SIZE` - takes an item from the stack as a
cache_key, counts the number of items in the cache at that location, and puts
the count onto the stack
- `[... int1] OP_ADD_INTS count` - takes `count` number of ints from the stack,
adds them together, and puts the sum onto the stack
- `[... int1] OP_SUBTRACT_INTS count` - takes `count` number of ints from the
stack, subtracts `count-1` of them from the first one, and puts the difference
onto the stack
- `[int1 ...] OP_MULT_INTS count` - takes `count` number of ints from the stack,
multiplies them together, and puts the product onto the stack
- `[int1] OP_DIV_INT size divisor` - takes an int from the stack, divides it by
the `divisor`, and puts the quotient onto the stack; `size` must be the byte
length of the divisor
- `[int1 int2] OP_DIV_INTS` - takes two ints from the stack, divides the first
by the second, and puts the quotient onto the stack
- `[int1] OP_MOD_INT size divisor` - takes an int from the stack, divides it by
the `divisor`, and puts the remainder onto the stack; `size` must be the byte
length of the `divisor`
- `[int2 int1] OP_MOD_INTS` - takes two ints from the stack, divides `int1` by
`int2`, and puts the remainder onto the stack
- `[... float1] OP_ADD_FLOATS count` - takes `count` number of floats from the
stack, adds them together, and puts the sum onto the stack
- `[... float1] OP_SUBTRACT_FLOATS count` - takes `count` number of floats from
- the stack, subtracts `count-1` of them from the first one, and puts the
difference onto the stack
- `[float1] OP_DIV_FLOAT divisor` - takes a float from the stack, divides it by
`divisor`, and puts the quotient onto the stack; `divisor` must be a 4-byte float
- `[float1 float2] OP_DIV_FLOATS` - takes 2 floats from the stack, divides
`float1` by `float2`, and puts the quotient onto the stack
- `OP_MOD_FLOAT divisor` - takes a float from the stack, divides it by `divisor`,
and puts the remainder onto the stack
- `OP_MOD_FLOATS` - takes 2 floats from the stack, divides the second by the
first, and puts the remainder onto the stack
- `[... point1] OP_ADD_POINTS count` - takes `count` ed25519 points from the
stack, adds them together, and puts the resulting ed25519 point onto the stack
- `[item] OP_COPY count` - copies the top value on the stack `count` times
- `[item] OP_DUP` - duplicates the top stack value
- `[item] OP_SHA256` - replaces the top value of the stack with its sha256 digest
- `[item] OP_SHAKE256 size` - replaces the top value of the stack with its `size`
length shake_256 digest
- `[bool] OP_VERIFY` - takes a value from the stack and raises an error if it
does not evaluate to `True`
- `[item1 item2] OP_EQUAL` - takes 2 values from the stack and puts `True` onto
the stack if they are the same or `False` if they are not
- `[item1 item2] OP_EQUAL_VERIFY` - calls `OP_EQUAL` and then `OP_VERIFY`
- `[sig vkey] OP_CHECK_SIG allowed_flags` - takes a VerifyKey and signature
from the stack, builds a message from the cache values `sigfield[1-8]` depending
upon the sigflags allowed by `allowed_flags` and appended to the signature,
checks if the signature is valid for the VerifyKey and message, and puts `True`
onto the stack if the signature validated or `False` if it did not
- `[sig vkey] OP_CHECK_SIG_VERIFY allowed_flags` - calls
`OP_CHECK_SIG allowed_flags` then `OP_VERIFY`
- `[constraint] OP_CHECK_TIMESTAMP` - takes an unsigned int from the stack as a
constraint, takes a timestamp from the cache at "timestamp", compares the
timestamp to the constraint, and puts `False` onto the stack if the timestamp is
less than the constraint or if the "ts_threshold" flag was set and exceeded by
the difference between the timestamp and the current time (i.e. if the timestamp
is more than ts_threshold into the future) and puts `True` onto the stack
otherwise
- `[constraint] OP_CHECK_TIMESTAMP_VERIFY` - calls `OP_CHECK_TIMESTAMP` then
`OP_VERIFY`
- `[constraint] OP_CHECK_EPOCH` - takes an unsigned int from the stack as a
constraint, subtracts the current time from the constraint, and puts `False`
onto the stack if the "epoch_threshold" flag is met or exceeded by the
difference and puts `True` onto the stack otherwise
- `[constraint] OP_CHECK_EPOCH_VERIFY` - calls `OP_CHECK_EPOCH` then `OP_VERIFY`
- `OP_DEF handle size def_body` - defines a function; see section above
- `OP_CALL handle` - calls a function; see section above
- `[bool] OP_IF length clause` - runs conditional code; see section above
- `[bool] OP_IF_ELSE length1 clause1 length2 clause2` - runs conditional code;
see section above
- `[script] OP_EVAL` - takes a value from the stack and runs it as a script
- `[item] OP_NOT` - takes a value from the stack and puts the inverse boolean
value onto the stack
- `[int] OP_RANDOM` - pulls an int from the stack and puts a random byte string
that long onto the stack
- `OP_RETURN` - ends the script; since functions and conditional clauses are
run as subtapes, `OP_RETURN` ends only the local execution and returns to the
outer context
- `OP_SET_FLAG number` - sets the tape flag `number` to the default value
- `OP_UNSET_FLAG number` - unsets the tape flag `number`
- `OP_DEPTH` - puts the size of the stack onto the stack as signed int
- `[...] OP_SWAP idx1 idx2` - swaps the items at the given indices on the stack
- `[item1 item2] OP_SWAP2` - swaps the order of the top two items on the stack
- `[...] OP_REVERSE count` - reverses the order of the top `count` items on the
stack
- `[item2 item1] OP_CONCAT` - takes two values from the stack, concatenates
`item2 + item1`, and puts the result onto the stack
- `[item] OP_SPLIT idx` - takes a value from the stack, splits it at the given
`idx`, and puts the two resulting byte strings onto the stack
- `[str1 str2] OP_CONCAT_STR` - takes 2 utf-8 strings from the stack,
concatenates `str2 + str1`, and puts the result onto the stack
- `[str] OP_SPLIT_STR idx` - takes a utf-8 string from the stack, splits at
`idx`, and puts the 2 resulting strings onto the stack
- `[...] OP_CHECK_TRANSFER` - checks proofs of a transfer; see section below
- `[commitment script] OP_MERKLEVAL hash` - enforces cryptographic commitment to
branching script; see section above
- `OP_TRY_EXCEPT size1 try_body size2 except_body` - executes the first block; if
an exception is raised, it is serialized into a string and put on the stack,
then the second block is executed
- `[v2 v1] OP_LESS` - pulls 2 values `v1` and `v2` from stack; puts `(v1<v2)`
onto stack
- `[v2 v1] OP_LESS_OR_EQUAL` - pulls 2 values `v1` and `v2` from stack; puts
`(v1<=v2)` onto stack
- `OP_GET_VALUE key` - puts the read-only cache value(s) at the str `key` onto
the stack
- `[f2 f1] OP_FLOAT_LESS` - takes floats `f1` and `f2` from the stack and puts
`(f1<f2)` onto the stack
- `[f2 f1] OP_FLOAT_LESS_OR_EQUAL` - takes floats `f1` and `f2` from the stack
and puts `(f1<=f2)` onto the stack
- `[int] OP_INT_TO_FLOAT` - takes int from stack and puts it back as a float
- `[f32] OP_FLOAT_TO_INT` - takes float from stack and puts it back as an int
- `[bool] OP_LOOP length clause` - runs the clause in a loop as long as the top
value on the stack is not null; errors if the callstack limit is exceeded
- `[...] OP_CHECK_MULTISIG allowed_flags m n` - takes `n` vkeys and `m` signatures
from stack; puts true onto the stack if each of the signatures is valid for one
of the vkeys and if each vkey is used only once; otherwise, puts false onto the
stack
- `[...] OP_CHECK_MULTISIG_VERIFY allowed_flags m n` - calls `OP_CHECK_MULTISIG`
then `OP_VERIFY`
- `[seed] OP_SIGN flags` - takes a signing key seed from the stack, signs a message
constructed from sigfields not blanked by the flags, and puts that signature
onto the stack.
- `[message seed] OP_SIGN_STACK` - takes a signing key seed and message from the
stack, signs the message, and puts the signature onto the stack.
- `[sig msg vkey] OP_CHECK_SIG_STACK` - takes a verify key, message, and
signature from the stack; puts `True` onto the stack if the signature was valid
for the vkey and message, otherwise puts `False` onto the stack.
- `[seed] OP_DERIVE_SCALAR` - takes a seed from stack; derives an ed25519
private key scalar from it; puts the scalar onto the stack and into cache[b'x']
if `tape.flags[1]`.
- `[scalar] OP_CLAMP_SCALAR is_key` - reads byte from tape as bool `is_key`;
pulls a value from the stack; clamps the value as an ed25519 private key if
`is_key` else as normal scalar; puts clamped scalar onto the stack.
- `[...] OP_ADD_SCALARS count` - takes `count` values from stack; uses ed25519
scalar addition to sum them; put the sum onto the stack.
- `[... minuend] OP_SUBTRACT_SCALARS count` - takes `count` values from stack;
uses ed25519 scalar subtraction to subtract `count-1` values from the first
value; put the difference onto the stack.
- `[scalar] OP_DERIVE_POINT` - takes a value from the stack as a scalar;
generates an ed25519 curve point from it; puts the point onto the stack and into
cache[b'X'] if `tape.flags[2]`.
- `[... minuend] OP_SUBTRACT_POINTS count` - takes `count` values from the stack
as ed25519 points; subtracts `count-1` of them from the first using ed25519
inverse group operator; puts difference onto the stack.
- `[seed m T] OP_MAKE_ADAPTER_SIG_PUBLIC` - takes tweak point `T`, message `m`,
and prvkey `seed` from stack; derives key scalar `x` from `seed` and nonce `r`
from `seed` and `m`; derives nonce point `R` from `r`; generates signature
adapter `sa`; puts `R` and `sa` onto stack; sets cache[b'r'] to `r` if
`tape.flags[3]`; sets cache[b'R'] to `R` if `tape.flages[4]`; sets cache[b'T']
to `T` if `tape.flags[6]`; sets cache[b'sa'] if `tape.flags[9]`.
- `[m t seed] OP_MAKE_ADAPTER_SIG_PRIVATE` - takes prvkey `seed`, tweak scalar
`t`, and message `m` from the stack; derives prvkey scalar `x` from `seed`;
derives pubkey `X` from `x`; derives private nonce `r` from `seed` and `m`;
derives public nonce point `R` from `r`; derives public tweak point `T` from `t`;
creates signature adapter `sa`; puts `T`, `R`, and `sa` onto stack; sets cache
keys b't' to `t` if `tape.flags[5]`, b'T' to `T` if `tapeflags[6]`, b'R' to `R`
if `tape.flags[4]`, and b'sa' to `sa` if `tape.flags[8]` (can be used in code
with @t, @T, @R, and @sa). Values `seed` and `t` should be 32 bytes each. Values
`T`, `R`, and `sa` are all public 32 byte values and necessary for verification;
`t` is used to decrypt the signature.
- `[sa R m T X] OP_CHECK_ADAPTER_SIG` - takes public key `X`, tweak point `T`,
message `m`, nonce point `R`, and signature adapter `sa` from the stack; puts
`True` onto the stack if the signature adapter is valid and `False` otherwise.
- `[sa R t] OP_DECRYPT_ADAPTER_SIG` - takes tweak scalar `t`, nonce point `R`,
and signature adapter `sa` from stack; calculates nonce `RT`; decrypts signature
`s` from `sa`; puts `s` onto stack; puts `RT` onto the stack; sets cache keys
b's' to `s` if `tape.flags[9]` and b'RT' to `RT` if `tape.flags[7]` (can be used
in code with @s and @RT).
- `[... argcount contract_id] OP_INVOKE` - takes an item from the stack as a
contract ID; takes a uint from the stack as `count`; takes `count` items from
the stack as arguments; tries to invoke the contract's `abi` method, passing it
the arguments; puts any return values onto the stack. Raises
`ScriptExecutionError` if the contract is missing. Raises `TypeError` if the
return value type is not bytes or NoneType. If allowed by `tape.flags[0]`, will
put any return values into cache at key b'IR'.
- `[item2 item1] OP_XOR` - takes two items from the stack; bitwise XORs them
together; puts result onto the stack. Can be used in boolean logic as boolean
values are just bytes.
- `[item2 item1] OP_OR` - takes two items from the stack; bitwise ORs them
together; puts result onto the stack. Can be used in boolean logic as boolean
values are just bytes.
- `[item2 item1] OP_AND` - takes two items from the stack; bitwise ANDs them
together; puts result onto the stack. Can be used in boolean logic as boolean
values are just bytes.
- `[...] OP_CHECK_TEMPLATE sigflags` - pulls a template from the stack for every
sigfield indicated in the sigflags and validates the associated sigfield against
the template by running the "check_template" plugins or, if there are none, by
doing an equality comparison; if all template checks pass, puts 0xff onto the
stack, otherwise puts 0x00 onto the stack; runs the signature extension plugins
beforehand if `tape.flags[10]` is set, which is default behavior.
- `[...] OP_CHECK_TEMPLATE_VERIFY sigflags` - runs `OP_CHECK_TEMPLATE sigflags`
then `OP_VERIFY`
- `[...] OP_TAPROOT root` - if the top item in the stack is a public key, verify
the supplied script (2nd item from stack top) and the public key combine into
the root using sha256 and ed25519, then execute the supplied script if they do
or remove the script from the stack and put 0x00 onto the stack if they do not;
else verify the top item is a signature that validates against the root as the
public key, and put 0xFF onto stack if it is or 0x00 onto the stack otherwise
- `NOP count` - removes `count` values from the stack; dummy ops useful for soft
fork updates

### `OP_CHECK_TRANSFER`

Pulls an item from the stack, interpreting as an unsigned int `count`;
takes an item from the stack as a `contract_id`; takes an item from the stack as
an `amount`; takes an item from the stack as a serialized `constraint`; takes an
item from the stack as a `destination` (address, locking script hash, etc);
takes the `count` number of items from the stack as `sources`; takes the `count`
number of items from the stack as `txn_proofs`; verifies that the aggregate of
the transfers to the `destination` from the `sources` equals or exceeds the
`amount`; verifies that the transfers were valid using the proofs and the
contract code; verifies the `constraint` was followed for each txn proof; and
puts `True` onto the stack if successful and `False` otherwise. Sources and
proofs must be in corresponding order on the stack.

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

The contract should be the source of the values put onto the stack and passed to
the contract functions by `OP_CHECK_TRANSFER count` or at least sharing an
interface with the source of those values.

The first three functions will be called on each transaction proof, and a `False`
returned for any of them will result in `False` placed onto the stack. Then,
`calc_txn_aggregates` will be called and supplied the list of txn proofs, and
the result for the destination will be taken out of the result of that function
call; if it is equal to or greater than the `amount` and all proofs were valid,
it puts `True` onto the stack, else it puts `False` onto the stack.

### `OP_INVOKE`

Takes an item from the stack as `contract_id`; takes a uint from the stack as
`argcount`; takes `argcount` items from the stack as arguments; tries to invoke
the contract's `abi` method, passing it the arguments; puts any return values
onto the stack. Raises `ScriptExecutionError` if the contract is missing or does
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

_, stack, cache = run_script(compile_script(script))
assert stack.qsize() == 1
assert bytes_to_int(stack.get()) == 10
```
