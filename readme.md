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
- [ ] Omega e2e test with all ops and nops
- [ ] Way to register new ops with compiler and decompiler
- [x] Half-decent docs
- [ ] Decent docs
- [ ] Package published

## Usage

### Installation

```bash
pip install tapescript
```

### Write, compile, decompile

See the langauge_spec.md file for syntax and language specifics.

One you have a script written, use the `compile_script(code: str) -> bytes`
function to turn it into the byte code that the interpreter runs.

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
passed in via the `contracts` dict. See the section in the language_spec.md file
for more informaiton about `OP_CHECK_TRANSFER`.

#### Changing flags

The interpreter flags can be changed by changing the `functions.flags` dict.

#### Adding ops

The ops can be updated via monkeypatching.

```py
from queue import LifoQueue
from tapescript import Tape
from tapescript import functions as tsf


def OP_SOME_NONSENSE(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    # do something presumably
    ...

tsf.OP_SOME_NONSENSE = OP_SOME_NONSENSE
tsf.opcodes[200] = ('OP_SOME_NONSENSE', OP_SOME_NONSENSE)
# now the op can be used in byte code scripts
```

Currently, there is not an elegant way to add semantics of new ops to the
compiler or decompiler.

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
```

There are currently 138 tests and 28 test vectors used for validating the
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
