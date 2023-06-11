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
- [ ] Package published

## Usage

### Installation

```bash
pip install tapescript
```

### Write, compile, decompile

See the [langauge_spec.md](language_spec.md) and [docs.md](docs.md) files for
syntax and operation specifics.

One you have a script written, use the `compile_script(code: str) -> bytes`
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
the input branches. In the above example, the each branch expects a signature
from the given public key. To use as an auth script, the locking script would be
used as the locking condition, a signature would be prepended to the unlocking
script with an `OP_PUSH x<hex signature> `, and this would then be compiled; the
locking script will be compiled and appended to this, and then the whole thing
would be run through the `run_auth_script` function.

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
    val = int(symbols[0][1:]).to_bytes(1)
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
3. These function calls take a 1 byte param from the tap that encodes the
allowable flags. If a signature is passed to a signature checker that uses a
disallowed sigflag, a `ScriptExecutionError` will be raised.

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

There are currently 156 tests and 31 test vectors used for validating the
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

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
