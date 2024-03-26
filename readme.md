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
- [x] Aliases without `OP_` prefix
- [x] Macros and variables
- [x] Loops
- [x] HTLCs, AMHLs, adapter signatures, delegated key scripts
- [x] Simple CLI: compile, decompile, run, and auth functionality
- [ ] Rewrite `OP_MERKLEVAL` and tools to use root=xor(hash(hash(branch)), hash(hash(branch)))

## Usage

### Installation

```bash
pip install tapescript
```

or

```bash
pip install tapescript={version}
```

### CLI

As of version 0.4.0, a simple CLI has been included with the following features:
- `compile src_file bin_file` -- compiles the human-readable source into bytecode
- `decompile bin_file` -- decompiles bytecode to human-readable source
- `run bin_file [cache_file]` -- runs Tapescript bytecode and prints the cache
and queue
- `auth bin_file [cache_file]` -- runs the Tapescript bytecode as an auth script
and prints "true" or "false

Passing the optional `cache_file` parameter will set specific cache values after
parsing the `cache_file`, which must adhere to a specific format. The intent of
this CLI is to make it easy to experiment and/or debug Tapescript scripts.

### Write, compile, decompile

See the
[langauge_spec.md](https://github.com/k98kurz/tapescript/blob/master/language_spec.md)
and [docs.md](https://github.com/k98kurz/tapescript/blob/master/docs.md) files
for syntax and operation specifics.

Once you have a script written, use the `compile_script(code: str) -> bytes`
function to turn it into the byte code that the interpreter runs. Note that each
`OP_` function has an alias that excludes the `OP_` prefix; e.g. `OP_PUSH d1`
can also be written `PUSH d1`. Op names are not case-sensitive, and several ops
have additional aliases. Variable and macro names are case-sensitive.

#### Variables and Macros

Version 0.3.0 and 0.3.1 added a sort of variable and macro system to the
compiler.

Variable assignment uses two possible syntaxes: `@= varname [vals]` or
`@= varname count`; the first pushes the values onto the queue then calls
`OP_WRITE_CACHE` to store those values in the cache at the `varname` key, while
the second instead just calls `OP_WRITE_CACHE` and takes `count` items from the
queue. Using `@varname` calls `OP_READ_CACHE` and places the values held at the
`varname` cache key onto the queue.

Macros allow use of string interpolation in the compiler: use the syntax
`!= macroname [ arg1 arg2 ... ] { statements }` to define a macro and
`!macroname [ arg1 arg2 ... ]` to call the macro. The compiler will replace the
macro call with the `statements` after substituting the args before compilation.

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

#### Hash Time Locked Contracts and Point Time Locked Contracts

Tapescript includes tools for generating locking scripts and unlocking scripts/
witnesses for HTLCs and PTLCs:
- `make_htlc_sha256_lock`
- `make_htlc_sha256_witness`
- `make_htlc_shake256_lock`
- `make_htlc_shake256_witness`
- `make_htlc2_sha256_lock`
- `make_htlc2_sha256_witness`
- `make_htlc2_shake256_lock`
- `make_htlc2_shake256_witness`
- `make_ptlc_lock`
- `make_ptlc_witness`
- `make_ptlc_refund_witness`

The general idea behind an HTLC is that the main branch can be unlocked with the
combination of a preimage matching a specific hash and a signature matching the
receiver_pubkey, while the refund branch can be unlocked with a signature
matching the refund_pubkey only after a timeout has expired. The PTLC by
comparison drops the hash lock and instead locks to a point on the ed25519
curve, i.e. it simply uses a `check_sig` lock.

#### Adapter Signatures and Anonymous Multi-Hop Locks

Ed25519 fulfills the homomorphic one-way criteria: given 2 scalars, `x1` and
`x2`, and 2 points, `X1=x1*G` and `X2=x2*G`, a third point, `X3`, can be
constructed either by adding `X1` and `X2` or by first adding `x1` and `x2`
before multiplying by the base/generator point; i.e. `X1+X2 = (x1+x2)*G`.
Additionally, it is computationally infeasible to find the scalar that matches a
given point; i.e. the function `oneway(x) -> x*G` cannot be reversed. This
enables novel and inventive cryptographic systems to be built using Ed25519
cryptographic primitives. Tapescript provides the following ops for use with
novel cryptographic systems using the Ed25519 primitives:

- `OP_ADD_POINTS`
- `OP_DERIVE_SCALAR`
- `OP_CLAMP_SCALAR`
- `OP_ADD_SCALARS`
- `OP_SUBTRACT_SCALARS`
- `OP_DERIVE_POINT`
- `OP_SUBTRACT_POINTS`

One such system is the adapter signature. See
[here](https://medium.com/crypto-garage/adaptor-signature-schnorr-signature-and-ecdsa-da0663c2adc4)
for an introduction to how the adapter signature works. The basic summary is
that an additional "tweak" point, `T=t*G`, and associated scalar "tweak" value,
`t`, can be used to create verifiable encrypted signatures and decrypt them,
respectively. Tapescript provides the following ops and tools for using adapter
signatures:

- `functions.OP_MAKE_ADAPTER_SIG_PUBLIC`
- `functions.OP_MAKE_ADAPTER_SIG_PRIVATE`
- `functions.OP_CHECK_ADAPTER_SIG`
- `functions.OP_DECRYPT_ADAPTER_SIG`
- `tools.make_adapter_lock_pub`
- `tools.make_adapter_lock_prv`
- `tools.make_adapter_locks_pub`
- `tools.make_adapter_decrypt`
- `tools.decrypt_adapter`
- `tools.make_adapter_locks_prv`
- `tools.make_adapter_witness`

Another system is the anonymous multi-hop lock (AMHL), which allows for a chain
of related transactions to be constructed in such a way that unlocking one of
them unlocks all of them through a mathematical cascade. When combined with
adapter signatures, it allows all links in the chain to be verified before they
are unlocked. See [the original paper](https://secpriv.wien/fulltext/publik_278436.pdf)
for a full explanation of the mathematics of the AMHL. Tapescript provides the
following tools for using AMHLs:

- `tools.setup_amhl`
- `tools.release_left_amhl_lock`

The `setup_amhl` tools constructs adapter signature locking scripts and will
provide PTLCs for any pubkey for which a corresponding entry is found in the
optional `refund_pubkeys` argument.

These may be changed or more ops/tools added in the future as the technology is
tested in specific applications.

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
[section in the language_spec.md](https://github.com/k98kurz/tapescript/blob/master/language_spec.md#op_check_transfer)
file for more informaiton about `OP_CHECK_TRANSFER`.

#### Changing flags

The interpreter flags can be changed by changing the `functions.flags` dict.

#### Adding ops

The ops can be updated via a plugin system.

```py
from queue import LifoQueue
from tapescript import Tape, add_opcode, add_opcode_parsing_handlers


def OP_SOME_NONSENSE(tape: Tape, queue: LifoQueue, cache: dict) -> None:
    count = tape.read(1)[0]
    for _ in range(count):
        queue.put(b'some nonsense')

def OP_SOME_NONSENSE_compiler(opname: str, symbols: list[str],
        symbols_to_advance: int, symbol_index: int):
    symbols_to_advance += 1
    if symbols[0][0] != 'd':
        raise SyntaxError(f'{opname} - int argument must begin with d - {symbol_index}')
    val = int(symbols[0][1:]).to_bytes(1, 'big')
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
to check that contracts can be used with the `OP_CHECK_TRANSFER` operation, and
the `CanBeInvoked` interface is used to check that contracts can be used with
the `OP_INVOKE` operation. To add an interface for checking loaded contracts,
call `add_contract_interface` and pass a `runtime_checkable` subclass of
`typing.Protocol` as the argument. To remove an interface, call
`remove_contract_interface` and pass the interface as the argument.

To add a contract, use `add_contract(contract_id: bytes, contract: object)`. To
remove a contract, use `remove_contract(contract_id: bytes)`.

Each contract will be checked against each interface when added (it must meet at
least one) and again at runtime when an op that uses a contract is executed. All
contracts added via the `add_contract` function will be included in the runtime
environment of scripts run thereafter. Additionally, contracts can be passed
into the `run_script` and `run_auth_script` functions, and these will override
any contracts in the global runtime environment in case of a contract_id
conflict.

To use a contract in a custom op, find it in the `tape.contracts` dict by its
contract_id.

### Signature checking

Notes for the `OP_CHECK_SIG` and `OP_CHECK_SIG_VERIFY` operations:

1. The body of the message to be used in checking the signature is comprised of
the `sigfield[1-8]` cache items.
2. Each signature can have an additional (65th) byte attached which encodes 8
bit flags. Each bit flag encoded will exclude the associated `sigfield{n}` cache
item from the message body during signature checks.
3. These ops take a 1 byte param from the tape that encodes the allowable flags.
If a signature is passed to a signature checker that uses a disallowed sigflag,
a `ScriptExecutionError` will be raised.

These also apply to the `OP_CHECK_MULTI_SIG` and `OP_CHECK_MULTI_SIG_VERIFY`
operations. See the language spec and docs files for more detailed information
about how `CMS` and `CMSV` work.

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
implementing soft-forks for an application using Tapescript as a dependency,
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
find tests -name test_*.py -exec {} \;
```

or

```bash
python test/test_classes.py
python test/test_functions.py
python test/test_parsing.py
python test/test_tools.py
python test/test_e2e_eltoo.py
```

There are currently 223 tests and 37 test vectors used for validating the
compiler, decompiler, and script running functions. This includes 3 tests for a
proof-of-concept implementation of the eltoo payment channel protocol, a test
proving the one-way homomorphic quality of ed25519, and e2e tests combining the
anonymous multi-hop lock (AMHL) system with adapter signatures.

## ISC License

Copyright (c) 2024 Jonathan Voss

Permission to use, copy, modify, and/or distribute this software
for any purpose with or without fee is hereby granted, provided
that the above copyleft notice and this permission notice appear in
all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
