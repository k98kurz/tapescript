# Tapescript

Simple DSL and VM loosely inspired by Bitcoin script but also hopefully more
useful for other applications. The idea is to programmatically ensure access
controls in a distributed system using cryptography. Unlike Java or WASM VMs,
many op codes do complex things rather than simple/primitive ones, e.g.
`OP_MERKLEVAL` and `OP_CHECK_MULTISIG`.

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
- [x] Simple CLI: compile, decompile, run, and auth
- [x] Document plugin system
- [x] Rewrite `OP_MERKLEVAL` and tools to use root=xor(hash(hash(branchA)), hash(hash(branchB)))
- [x] REPL and comptime

## Usage

### Installation

```bash
pip install tapescript
```

or

```bash
pip install tapescript=={version}
```

### CLI

As of version 0.4.0, a simple CLI has been included with the following features:
- `repl` -- activates a REPL (Read Execute Print Loop; default if CLI is executed
without arguments added in 0.6.0)
- `compile src_file bin_file` -- compiles the human-readable source into bytecode
- `decompile bin_file` -- decompiles bytecode to human-readable source
- `run bin_file [cache_file]` -- runs Tapescript bytecode and prints the cache
and stack
- `auth bin_file [cache_file]` -- runs the Tapescript bytecode as an auth script
and prints "true" if it succeeded and "false" otherwise

Passing the optional `cache_file` parameter will set specific cache values after
parsing the `cache_file`, which must adhere to a specific format. The intent of
this CLI is to make it easy to experiment and/or debug Tapescript scripts. Run
the command `tapescript help` to get the help text.

Note that the CLI does not currently include support for soft-forks, contracts,
or plugins.

### Write, compile, decompile

See the
[langauge_spec.md](https://github.com/k98kurz/tapescript/blob/v0.6.1/language_spec.md)
and [docs.md](https://github.com/k98kurz/tapescript/blob/v0.6.1/docs.md) files
for syntax and operation specifics.

Once you have a script written, use the `compile_script(code: str) -> bytes`
function to turn it into the byte code that the interpreter runs. Alternatvely,
there is a `Script` class that can be initialized with either the source code or
the byte code with `Script.from_src` and `Script.from_bytes`, respectively, and
it will automatically compile source code to byte code or decompile byte code to
source code; `Script` instances can also be added together with a simple +, e.g.
`script = unlocking_script + locking_script`. The script running functions can
accept either a `Script` object or the byte code.

Note that each `OP_` function has an alias that excludes the `OP_` prefix; e.g.
`OP_PUSH d1` can also be written `PUSH d1`. Op names are not case-sensitive, and
several ops have additional aliases. Variable names, macro names, and string
values are case-sensitive.

The following functions are also available for VM-compatible serialization:
- `bytes_to_int`
- `int_to_bytes`
- `uint_to_bytes`
- `bytes_to_bool`
- `bytes_to_float`
- `float_to_bytes`

And these functions are available for convenience and cryptography:
- `clamp_scalar`
- `H_big`
- `H_small`
- `derive_key_from_seed`
- `derive_point_from_scalar`
- `aggregate_points`
- `aggregate_scalars`
- `sign_with_scalar`
- `not_bytes`
- `xor`
- `and_bytes`
- `or_bytes`
- `bytes_are_same`

#### Variables and Macros

Versions 0.3.0 and 0.3.1 added a sort of variable and macro system to the
compiler. Full documentation can be found in the language spec file.

Variable assignment uses two possible syntaxes: `@= varname [ vals ]` or
`@= varname count`; the first pushes the values onto the stack then calls
`OP_WRITE_CACHE` to store those values in the cache at the `varname` key, while
the second instead just calls `OP_WRITE_CACHE` and takes `count` items from the
queue. Using `@varname` calls `OP_READ_CACHE` and places the values held at the
`varname` cache key onto the stack.

Macros allow use of string interpolation in the compiler: use the syntax
`!= macroname [ arg1 arg2 ... ] { statements }` to define a macro and
`!macroname [ arg1 arg2 ... ]` to call the macro. The compiler will replace the
macro call with the `statements` after substituting the args before compilation.

#### Comptime

Version 0.6.0 added two comptime features: `~ { ops }` is replaced with a
hexadecimal value symbol equal to the compiled byte code of `ops`; `~! { ops }`
is replaced with the top stack value as a hexadecimal symbol after compiling and
executing `ops`. This allows the cryptographic commitment for scripts to be
generated from the source code directly where the commitment is used. Below is
an example taken from the compilation test vectors:

```s
# locking script #
OP_DUP
OP_SHAKE256 d20
OP_PUSH ~! {
    push ~ {
        # committed script #
        OP_IF {
            OP_PUSH x09f5067410b240ac3aa3143016f2285f32fd6eb86ee0efe34248a25bb57bb937
            OP_CHECK_SIG x00
        } ELSE {
            OP_PUSH x1481cd547c77799b4551f1e2947a9ad350bafe972ba55c827ef78279a096343f
            OP_PUSH xcdf907630128847e63dc0b6156b331b29f56cf899e5689b61da3747382d1a80a
            OP_SWAP d1 d2
            OP_CHECK_SIG_VERIFY x00
            OP_CHECK_SIG x00
        }
    }
    shake256 d20
}
OP_EQUAL_VERIFY
OP_EVAL
```

Note that variables defined outside of a comptime block cannot be used within
an executed comptime block, and variables defined within an executed comptime
block cannot be used outside of it. However, macros defined outside of comptime
blocks can be invoked within them, and macros defined within comptime blocks can
be invoked outside of them.

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

Tools are included for making merklized scripts:
- `ScriptLeaf` and `ScriptNode` classes
- `create_script_tree_prioritized(...) -> ScriptNode`
- `create_merklized_script_prioritized(...) -> tuple[Script, list[Script]]`,
which uses `create_script_tree_prioritized` under the hood

The two functions accept a list of leaf scripts and produce an unbalanced tree
that priotizes efficient execution of lowest index scripts at the expense of
linearly increasing unlocking script size for higher index scripts. There are
not currently any functions for producing a balanced tree, but the included
`ScriptLeaf` and `ScriptNode` classes can be used to make any arbitrary tree:

```python
from tapescript import ScriptLeaf, ScriptNode

# get some scripts from somewhere
sources = get_five_script_sources()

tree = ScriptNode(
    ScriptNode(
        ScriptLeaf.from_src(sources[0]),
        ScriptNode(
            ScriptLeaf.from_src(sources[1]),
            ScriptLeaf.from_src(sources[2]),
        )
    ),
    ScriptNode(
        ScriptLeaf.from_src(sources[3]),
        ScriptLeaf.from_src(sources[4]),
    )
)
```

#### Taproot scripts

The basic Taproot concept is to take a sha256 hash of a script as a commitment,
clamp it to the ed25519 scalar field, derive a point from it, and add that point
to a public key to create the root commitment, which itself functions both as a
commitment to the script and as a public key. Signatures can be made that
validate against the root, or the committed script can be executed by supplying
both the script and the original public key. The script execution path (aka
script-spend) verifies that the script and public key combine to form the root,
then it executes the committed script if verification succeeded and otherwise
removes the script and places `x00` (`False`) onto the stack. The signature path
(aka key-spend) instead validates the supplied signature against the root as a
public key.

Signatures are created using the original private key and the script commitment
by adding the script commitment (clamped to the scalar field) to the scalar
derived from the private key, then using that in place of the private key scalar.

Tools are included for using taproot:
- `make_taproot_lock`
- `make_taproot_witness_keyspend`
- `make_taproot_witness_scriptspend`

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
enables powerful cryptographic systems to be built using Ed25519 cryptographic
primitives. Tapescript provides the following ops for use with novel
cryptographic systems using the Ed25519 primitives:

- `OP_DERIVE_SCALAR`
- `OP_CLAMP_SCALAR`
- `OP_ADD_SCALARS`
- `OP_SUBTRACT_SCALARS`
- `OP_DERIVE_POINT`
- `OP_ADD_POINTS`
- `OP_SUBTRACT_POINTS`

One such system is the adapter signature. See
[here](https://medium.com/crypto-garage/adaptor-signature-schnorr-signature-and-ecdsa-da0663c2adc4)
for an introduction to how adapter signatures work. The basic summary is that an
additional "tweak" point, `T=t*G`, and associated scalar "tweak" value, `t`, can
be used to create verifiable encrypted signatures and decrypt them,
respectively. Tapescript provides the following ops and tools for using adapter
signatures:

- `OP_MAKE_ADAPTER_SIG_PUBLIC`
- `OP_MAKE_ADAPTER_SIG_PRIVATE`
- `OP_CHECK_ADAPTER_SIG`
- `OP_DECRYPT_ADAPTER_SIG`
- `make_adapter_lock_pub`
- `make_adapter_lock_prv`
- `make_adapter_locks_pub`
- `make_adapter_locks_prv`
- `make_adapter_decrypt`
- `decrypt_adapter`
- `make_adapter_witness`
- `clamp_scalar`
- `derive_key_from_seed`
- `derive_point_from_scalar`
- `aggregate_points`
- `aggregate_scalars`

Another system is the anonymous multi-hop lock (AMHL), which allows for a chain
of related transactions to be constructed in such a way that unlocking one of
them unlocks all of them through a mathematical cascade. When combined with
adapter signatures, it allows all links in the chain to be verified before they
are unlocked. See [the original paper](https://secpriv.wien/fulltext/publik_278436.pdf)
for a full explanation of the mathematics of the AMHL. Tapescript provides the
following tools for using AMHLs:

- `setup_amhl`
- `release_left_amhl_lock`

The `setup_amhl` tool constructs adapter signature locking scripts, `check_sig`
locks, and intermediate values, and it will provide PTLCs in lieu of `check_sig`
locks for any pubkey for which a corresponding entry is found in the optional
`refund_pubkeys` argument. The paper authors envision its use with MuSig/MuSig2
aggregated keys in a "scriptless script" setting, but MuSig and MuSig2 are
beyond the scope of this project.

These may be changed or more ops/tools added in the future as the technology is
tested in specific applications.

### Run a script

Run a script by compiling the source to byte code or creating a `Script` object
and run with either
`run_script(script: bytes|Script, cache_vals: dict = {}, contracts: dict = {})`
or `run_auth_script(script: bytes|Script, cache_vals: dict = {}, contracts: dict = {})`.
The `run_script` function returns `tuple` of length 3 containing a `Tape`, a
`LifoQueue`, and the final state of the `cache` dict. The `run_auth_script`
instead returns a bool that is `True` if the script ran without error and
resulted in a single `0x01` value on the stack; otherwise it returns `False`.

In the case where a signature is expected to be validated, the message parts for
the signature must be passed in via the `cache_vals` dict at keys `sigfield[1-8]`.
In the case where `OP_CHECK_TRANSFER` or `OP_INVOKE` might be called, the
contracts must be passed in via the `contracts` dict. See the
[check_transfer](https://github.com/k98kurz/tapescript/blob/v0.5.0/language_spec.md#op_check_transfer)
and
[invoke](https://github.com/k98kurz/tapescript/blob/v0.5.0/language_spec.md#op_invoke)
sections in the language_spec.md file for more informaiton about these two ops.

#### Changing flags

The interpreter flags can be changed by changing the `functions.flags` dict.

#### Adding ops

The ops can be updated via a plugin system.

```py
from tapescript import Stack, Tape, add_opcode, add_opcode_parsing_handlers


def OP_SOME_NONSENSE(tape: Tape, stack: Stack, cache: dict) -> None:
    count = tape.read(1)[0]
    for _ in range(count):
        stack.put(b'some nonsense')

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

#### Adding an alias

If you want to use a new alias for an op code, you can create this alias using
the `add_alias` function. Valid aliases are alpha-numeric and may contain
underscores. This function will raise a `TypeError` for non-str args and a
`ValueError` if the alias contains invalid chars or is already in use.

### Plugins

There is a simple plugin system available for modifying execution behavior when
calling certain ops. Existing uses are documented below, but this system may be
used for future extensions when such use cases arise.

The basic functions for interacting with the plugin system are the following:
- `add_plugin(scope: str, plugin: Callable[[Tape, Stack, dict], Any]) -> None`
- `remove_plugin(scope: str, plugin: Callable[[Tape, Stack, dict], Any]) -> None`
- `reset_plugins(scope: str) -> None`

Additionally, plugins can be supplied in a dict format to `run_script` or
`run_auth_script`, but this will overwrite any plugins previously added for any
scope included in the injected `plugins` argument.

#### Signature Extensions

The signature extension system executes all plugins under the
"signature_extensions" scope at the beginning of these ops:
- `OP_GET_MESSAGE`
- `OP_CHECK_SIG`
- `OP_CHECK_SIG_VERIFY`
- `OP_CHECK_MULTISIG`
- `OP_CHECK_MULTISIG_VERIFY`
- `OP_SIGN`
- `OP_CHECK_TEMPLATE` if tape.flags[10] is set to True, which is the default
- `OP_CHECK_TEMPLATE_VERIFY` if tape.flags[10] is set to True, which is the default

The functions registered as signature extension plugins should modify the
sigfields in the cache, but they are free to do anything with the runtime data.
Signature extension plugins can be managed using the following functions:
- `add_signature_extension(plugin: Callable[[Tape, Stack, dict], None]) -> None`
- `remove_signature_extension(plugin: Callable[[Tape, Stack, dict], None]) -> None`
- `reset_signature_extensions() -> None`
- `run_sig_extensions(tape: Tape, stack: Stack, cache: dict) -> None`

#### Check Template

`OP_CHECK_TEMPLATE` and `OP_CHECK_TEMPLATE_VERIFY` will run the plugins in the
"check_template" scope when checking each sigfield against the appropriate
template. This execution is different from the signature extension system: the
args passed into this plugin execution call are not the runtime data but rather
limited to just the two items in question and the cache; also, the return values
are collected, and if any return value is True, then the check passes. If there
are no plugins, `OP_CHECK_TEMPLATE/VERIFY` will instead do a strict equality
check.

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

Each contract will be checked against each interface when added (it must
implement at least one) and again at runtime when an op that uses a contract is
executed. All contracts added via the `add_contract` function will be included
in the runtime environment of scripts run thereafter. Additionally, contracts
can be passed into the `run_script` and `run_auth_script` functions, and these
will override any contracts in the global runtime environment in case of a
contract_id conflict. The contract_id should be a cryptographic hash of the
contract's source code; it is called a contract rather than a module because the
users of a system must commit to running the same code, and this forms a
contractual relationship between users.

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

#### Signature Extension Plugins

As of 0.4.2, the following OPs can be slightly modified with a plugin system:
`CHECK_SIG`, `CHECK_MULTISIG`, `SIGN`, and `GET_MESSAGE`. Signature extension
plugins can be managed with the following functions:
- `add_signature_extension(plugin: Callable[[Tape, Stack, dict], None])`
- `remove_signature_extension(plugin: Callable[[Tape, Stack, dict], None])`
- `reset_signature_extensions()`

Additionally, plugins can be injected when calling `run_script` or
`run_auth_script` the same way as contracts. The underlying plugin system uses
string scopes, and the signature extension plugins have the scope of
"signature_extensions". For example:

```python
t, q, c = run_script(script, plugins={
    'signature_extensions': [some_plugin_function]
})
```

Plugin functions must take a Tape, Stack, and dict (i.e. the runtime data)
as arguments, and they must do all of their work on them. (Technically, they
are procedures with side-effects.) For signature extension, the sigfields in the
dict cache are the most likely target for alteration.

### Soft Forks

A soft fork is a protocol upgrade such that all scripts written under the new
protocol also validate under the old version -- older versions do not break when
encountering use of the new feature. Tapescript was designed with soft-fork
support in mind, and the helper function `add_soft_fork` is included to
streamline the process and reduce the use of boilerplate.

To enable a soft fork, a NOP code must be replaced with an op that reads the
next byte as a signed int, pulls that many values from the stack, runs any
checks on the data, and raises an error in case any check fails. This maintains
the behavior of the original NOP such that any nodes that did not activate the
soft fork will not have any errors parsing scripts using the new OP.

Example soft fork:

```python
from tapescript import (
    Tape,
    Stack,
    ScriptExecutionError,
    add_soft_fork,
    bytes_to_int,
)


def OP_CHECK_ALL_EQUAL_VERIFY(tape: Tape, stack: Stack, cache: dict) -> None:
    """Replacement for NOP255: read the next byte an int count, take
        that many items from stack, run checks, and raise an error if
        any check fails.
    """
    count = bytes_to_int(tape.read(1))
    assert count >= 0
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
find tests -name test_*.py -print -exec {} \;
```

or

```bash
python tests/test_classes.py
python tests/test_functions.py
python tests/test_parsing.py
python tests/test_security.py
python tests/test_tools.py
python tests/test_e2e_eltoo.py
python tests/test_e2e_sigext.py
```

There are currently 250 tests and 107 test vectors used for validating the ops,
compiler, decompiler, and script running functions. This includes 3 tests for a
proof-of-concept implementation of the eltoo payment channel protocol, and e2e
tests combining the anonymous multi-hop lock (AMHL) system with adapter
signatures, as well as tests for the contract system, signature extension
plugins, hard-forks, and the soft-fork system. There are an additional 7
security tests, including a test proving the one-way homomorphic quality of
ed25519 and a test proving that all symmetric script trees share the same root.

## Contributing

Check out the [Pycelium discord server](https://discord.gg/b2QFEJDX69). If you
experience a problem, please discuss it on the Discord server. All suggestions
for improvement are also welcome, and the best place for that is also Discord.
If you experience a bug and do not use Discord, open an issue on Github.

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
