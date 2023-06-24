# Tapescript

Simple script system loosely inspired by Bitcoin script but also hopefully more
useful for other applications. The idea is to programmatically ensure access
controls in a distributed system.

## Status

- [x] OPs
- [x] Interpreter functions and classes
- [x] Byte-code compiler
- [x] Decompiler
- [x] Unit tests
- [x] E2e tests
- [x] Merkleval test vectors
- [x] Omega e2e test with all ops and nops
- [x] Plugin architecture: new ops with compiler, decompiler, interpreter
- [x] Half-decent docs
- [x] Decent docs
- [x] Package published
- [x] Added try...except

## Usage

### Installation

```bash
pip install tapescript
```

### Write, compile, decompile

See the
[langauge_spec.md](https://github.com/k98kurz/tapescript/blob/master/language_spec.md)
and [docs.md](https://github.com/k98kurz/tapescript/blob/master/docs.md) files
for syntax and operation specifics.

Once you have a script written, use the `compile_script(code: str) -> bytes`
function to turn it into the byte code that the interpreter runs.

#### Merklized scripts

There is an included tool for making merklized branching scripts. To use it,
write the desired branches, then pass them to the `create_merklized_script`
function. For example:

```py
from tapescript import create_merklized_script

branches = [
    'OP_PUSH xb26d10053b4b25497081561f529e42da9ccfac860a7b3d1ec932901c2a70afce\nOP_CHECK_SIG x00',
    'OP_PUSH x9e477d55a62fc1ecc6b7c89d69c4f9cba94d5173f0d59f971951ff46acb9017b\nOP_CHECK_SIG x00',
    'OP_PUSH xdd86edfbcfd5ac3e8c1acb527cc4178a14af0755aea1e447dc2b278f52fcedbf\nOP_CHECK_SIG x00',
]
locking_script, unlocking_scripts = create_merklized_script(branches)
```

This function returns a tuple containing the locking script that uses
`OP_MERKLEVAL` to enforce the cryptographic commitment to the branches and a
list of unlocking scripts that fulfill the cryptographic commitment and execute
the individual script branches. The unlocking scripts are ordered identically to
the input branches. In the above example, each branch expects a signature from
the given public key. To use as an auth script, the locking script would be
compiled and used as the locking condition. A signature would be prepended to
the unlocking script with an `OP_PUSH x<hex signature> `, and this would then be
compiled to become the unlocking bytes. Then concatenate the locking script to
the unlocking script (i.e. script = unlock + lock) and run through the
`run_auth_script` function, which will return a `True` if it executed
successfully and `False` otherwise.

### Run a script

Run a script by compiling it to byte code (if it wasn't already) and run with
either `run_script(script: bytes, cache_vals: dict = {}, contracts: dict = {})`
or `run_auth_script(script: bytes, cache_vals: dict = {}, contracts: dict = {})`.
The `run_script` function returns `tuple` of length 3 containing a `Tape`, a
`LifoQueue`, and the final state of the `cache` dict. The `run_auth_script`
instead returns a bool that is `True` if the script ran without error and
resulted in a single `True` value on the queue; otherwise it returns `False`.

In the case where a signature is expected to be validated, the message parts for
the signature must be passed in via the `cache_vals` dict at keys `sigfield[1-8]`.
In the case where `OP_CHECK_TRANSFER` might be called, the contracts must be
passed in via the `contracts` dict. See the
[section in the language_spec.md](https://github.com/k98kurz/tapescript/blob/master/language_spec.md#op_check_transfer-count)
file for more informaiton about `OP_CHECK_TRANSFER`.

#### Changing flags

The interpreter flags can be changed by changing the `functions.flags` dict.

#### Adding ops

The ops can be updated via monkeypatching.

```py
from queue import LifoQueue
from tapescript import Tape, add_opcode, add_opcode_parsing_handlers


def OP_SOME_NONSENSE(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    count = tape.read(1)[0]
    for _ in range(count):
        queue.put(b'some nonsense')

def OP_SOME_NONSENSE_compiler(opname: str, symbols: list[str], symbols_to_advance: int):
    symbols_to_advance += 1
    val = int(symbols[0][1:]).to_bytes(1, 'big)
    return (symbols_to_advance, (val,))

def OP_SOME_NONSENSE_decompiler(opname: str, tape: Tape):
    val = tape.read(1)[0]
    return [f'{opname} d{val}']

# add opcode to bytecode interpreter
add_opcode(255, 'OP_SOME_NONSENSE', OP_SOME_NONSENSE)

# add opcode to compiler and decompiler
add_opcode_parsing_handlers(
    'OP_SOME_NONSENSE',
    OP_SOME_NONSENSE_compiler,
    OP_SOME_NONSENSE_decompiler
)
```

### Contracts

The interpreter includes a system for including contracts for greater
extensibility. For example, the bundled `CanCheckTransfer` interface is used
to check that contracts can be used with the `OP_CHECK_TRANSFER` operation. To
add an interface for checking loaded contracts, call `add_contract_interface`
and pass a `runtime_checkable` subclass of `typing.Protocol` as the argument. To
remove an interface, call `remove_contract_interface` and pass the interface as
the argument.

To add a contract, use `add_contract(contract_id: bytes, contract: object)`. To
remove a contract, use `remove_contract(contract_id: bytes)`.

Each contract will be checked against each interface when added and again at
runtime when an op that uses a contract is executed. All contracts added via the
`add_contract` function will be included in the runtime environment of scripts
run thereafter. Additionally, contracts can be passed into the `run_script` and
`run_auth_script` functions, and these will override any contracts in the global
runtime environment in case of a contract_id conflict.

To use a contract in a custom op, find it in the `tape.contracts` dict by its
contract_id.

### Signature checking

Notes for the `OP_CHECK_SIG` and `OP_CHECK_SIG_VERIFY` functions:

1. The body of the message to be used in checking the signature is comprised of
the `sigfield[1-8]` cache items.
2. Each signature can have an additional (33rd) byte attached which encodes up
to 8 bit flags. Each bit flag encoded will exclude the associated `sigfield{n}`
cache item from the message body during signature checks.
3. These ops take a 1 byte param from the tape that encodes the allowable flags.
If a signature is passed to a signature checker that uses a disallowed sigflag,
a `ScriptExecutionError` will be raised.

### Soft Forks

A soft fork is a protocol upgrade such that all scripts written under the new
protocol also validate under the old version -- older versions do not break when
encountering use of the new feature. Tapescript was designed with soft-fork
support in mind, and the helper function `add_soft_fork` is included to
streamline the process and reduce the use of boilerplate.

To enable a soft fork, a NOP code must be replaced with an op that reads the
next byte as an unsigned int, pulls that many values from the queue, runs any
checks on the data, and raises an error in case any check fails. This maintains
the behavior of the original NOP such that any nodes that did not activate the
soft fork will not have any errors parsing scripts using the new OP.

Example soft fork:

```python
from tapescript import (
    Tape,
    ScriptExecutionError,
    add_soft_fork
)
from queue import LifoQueue


def OP_CHECK_ALL_EQUAL_VERIFY(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    """Replacement for NOP255: read the next byte as uint count, take
        that many items from queue, run checks, and raise an error if
        any check fails.
    """
    count = tape.read(1)[0]
    items = []
    for i in range(count):
        items.append(queue.get(False))

    compare = items.pop()
    while len(items):
        if items.pop() != compare:
            raise ScriptExecutionError('not all the same')


add_soft_fork(255, 'OP_CHECK_ALL_EQUAL_VERIFY', OP_CHECK_ALL_EQUAL_VERIFY)
```

Scripts written with the new op will always execute successfully on nodes
running the old version of the interpreter. Example script:

```s
# locking script #
OP_CHECK_ALL_EQUAL_VERIFY d3
OP_TRUE

# locking script as decompiled by old nodes #
NOP255 d3
OP_TRUE

# unlocking script that validates on both versions #
OP_PUSH x0123
OP_PUSH x0123
OP_PUSH x0123

# unlocking script that fails validation on the new version #
OP_PUSH x0123
OP_PUSH x0123
OP_PUSH x3210
```

Additionally, conditional programming can be accomplished with soft fork ops by
using `OP_TRY_EXCEPT`. The `EXCEPT` clause will never be executed by nodes that
have not activated the soft fork, but it will be executed by nodes that have
activated the soft fork and encountered an exception during execution of the new
op.

Note that any new language features added to the interpreter will be hard forks
replacing lower value NOPs. (For example, `OP_TRY_EXCEPT` was a hard fork that
replaced `NOP61`.) To opt-in to hard fork compatibility in this package while
implementing soft-forks for an application using tapescript as a dependency,
start by soft forking `NOP255` and count down with each additional soft fork.

### Testing

First, clone the repo, set up the virtualenv, and install requirements.

```bash
git clone ...
python -m venv venv/
source venv/bin/activate
pip install -r requirements.txt
```

For windows, replace `source venv/bin/activate` with `source venv/Scripts/activate`.

Then run the test suite with the following:

```bash
python test/test_classes.py
python test/test_functions.py
python test/test_parsing.py
python test/test_tools.py
```

There are currently 159 tests and 32 test vectors used for validating the
compiler, decompiler, and script running functions.

## ISC License

Copyleft (c) 2023 k98kurz

Permission to use, copy, modify, and/or distribute this software
for any purpose with or without fee is hereby granted, provided
that the above copyleft notice and this permission notice appear in
all copies.

Exceptions: this permission is not granted to Alphabet/Google, Amazon,
Apple, Microsoft, Netflix, Meta/Facebook, Twitter, or Disney; nor is
permission granted to any company that contracts to supply weapons or
logistics to any national military; nor is permission granted to any
national government or governmental agency; nor is permission granted to
any employees, associates, or affiliates of these designated entities.
Notwithstanding the above exceptions, the code may be used without
constraint for demonstration, educational, or entertainment purposes.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
