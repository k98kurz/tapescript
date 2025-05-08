# Tapescript

Simple DSL and VM loosely inspired by Bitcoin script but also hopefully more
useful for other applications. The idea is to programmatically ensure access
controls in a distributed system using cryptography. Unlike Java or WASM VMs,
many op codes do complex things rather than simple/primitive ones, e.g.
`OP_MERKLEVAL` and `OP_CHECK_MULTISIG`.

## Status

Primary development has been completed. Incorporating feedback from use in real
applications and integration into libraries.

Open issues can be tracked [here](https://github.com/k98kurz/tapescript/issues).
Historical changes can be found in the
[changelog](https://github.com/k98kurz/tapescript/blob/main/CHANGELOG.md).

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
- `repl [cache_file]` -- activates a REPL (Read Execute Print Loop; default if
CLI is executed without arguments added in 0.6.0; cache_file processing added in
0.7.1)
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
[langauge_spec.md](https://github.com/k98kurz/tapescript/blob/v0.7.1/language_spec.md)
and [docs.md](https://github.com/k98kurz/tapescript/blob/v0.7.1/docs.md) files
for syntax, operation specifics, and thorough tool documentation.

Once you have a script written, use the `compile_script(code: str) -> bytes`
function to turn it into the byte code that the interpreter runs. Alternatvely,
there is a `Script` class that can be initialized with either the source code or
the byte code with `Script.from_src` and `Script.from_bytes`, respectively, and
it will automatically compile source code to byte code or decompile byte code to
source code; `Script` instances can also be added together with a simple +, e.g.
`script = part1 + part2`. The script running functions can accept either
`Script` object(s) or the byte code.

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
stack. Using `@varname` calls `OP_READ_CACHE` and places the values held at the
`varname` cache key onto the stack. The number of items in a variable can be
read with `@#varname` (equivalent to `rcz s"varname"`).

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
an example taken from the compilation test vectors.

<details>
<summary>Example</summary>

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

</details>

Note that variables defined outside of a comptime block cannot be used within
an executed comptime block, and variables defined within an executed comptime
block cannot be used outside of it. However, macros defined outside of comptime
blocks can be invoked within them, and macros defined within comptime blocks can
be invoked outside of them.

#### Merklized scripts

There are included tools for making merklized branching scripts. To use them,
write the desired branches, then pass them to `make_merklized_script_prioritized`
or to `make_merklized_script_balanced`.

<details>
<summary>Example</summary>

```py
from tapescript import (
    make_merklized_script_prioritized,
    make_merklized_script_balanced,
    make_single_sig_lock,
    make_single_sig_witness,
    run_auth_scripts,
)
from os import urandom
from nacl.signing import SigningKey

seeds = [urandom(32) for _ in range(3)]
branches = [
    make_single_sig_lock(bytes(SigningKey(seeds[0]).verify_key)),
    make_single_sig_lock(bytes(SigningKey(seeds[1]).verify_key)),
    make_single_sig_lock(bytes(SigningKey(seeds[2]).verify_key)),
]
# prioritized script tree has one leaf and one node per level, so the scripts at
# lower indices have shorter tree inclusion proof unlocking scripts
locking_script, unlocking_scripts = make_merklized_script_prioritized(branches)

# balanced script tree has all leaves at the same level, so all scripts have the
# same size inclusion proof unlocking scripts
locking_script, unlocking_scripts = make_merklized_script_balanced(branches)

# run a script
sigfields = {'sigfield1': urandom(64)}
witness = make_single_sig_witness(seeds[0], sigfields)
assert run_auth_scripts(
    [witness, unlocking_scripts[0], locking_script],
    cache_vals={'sigfield1': sigfields['sigfield1']}
)
```

</details>

These functions return a tuple containing the locking script that uses
`OP_MERKLEVAL` to enforce the cryptographic commitment to the branches and a
list of unlocking scripts that fulfill the cryptographic commitment and execute
the individual script branches. The unlocking scripts are ordered identically to
the input leaf scripts. In the above example, each branch expects a signature
from the given public key. To use as an auth script, the locking script would be
compiled and used as the locking condition. A signature would be prepended to
the unlocking script with an `OP_PUSH x<hex signature> `, and this would then be
compiled to become the unlocking bytes. Then run the `run_auth_scripts` function
on the unlocking script, the locking script, and the sigfields (i.e.
`run_auth_scripts([unlock, lock], {**sigfields})`), which will return a `True`
if they executed successfully and `False` otherwise.

Tools are included for making merklized scripts:
- `ScriptLeaf` and `ScriptNode` classes
- `make_script_tree_prioritized(...) -> ScriptNode`
- `make_merklized_script_prioritized(...) -> tuple[Script, list[Script]]`,
  which uses `make_script_tree_prioritized` under the hood
- `make_script_tree_balanced(...) -> ScriptNode`
- `make_merklized_script_balanced(...) -> tuple[Script, list[Script]]`,
  which uses `make_script_tree_balanced` under the hood

The `_prioritized` functions accept a list of leaf scripts and produce an
unbalanced tree that priotizes efficient execution of lowest index scripts at
the expense of linearly increasing unlocking script size for higher index
scripts. The `_balanced` functions accept the same arguments but produce a
balanced tree that gives all leaf executions identical Merkle proof overhead.

Additionally, the `ScriptLeaf` and `ScriptNode` classes can be used to make
arbitrary script tree structures.

<details>
<summary>Example</summary>

```python
from tapescript import ScriptLeaf, ScriptNode, Script, run_auth_scripts

# get some scripts from somewhere
sources = [
    'equal',
    'and',
    'or',
    'xor',
    'not',
]

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

lock = tree.locking_script()
unlocks = [
    tree.left.left.unlocking_script(),
    tree.left.right.left.unlocking_script(),
    tree.left.right.right.unlocking_script(),
    tree.right.left.unlocking_script(),
    tree.right.right.unlocking_script(),
]

# run each script
assert run_auth_scripts([Script.from_src('push d1 dup'), unlocks[0], lock])
assert run_auth_scripts([Script.from_src('true dup'), unlocks[1], lock])
assert run_auth_scripts([Script.from_src('true false'), unlocks[2], lock])
assert run_auth_scripts([Script.from_src('true false'), unlocks[3], lock])
assert run_auth_scripts([Script.from_src('false'), unlocks[4], lock])
```

</details>

#### Taproot scripts

The basic Taproot concept is to take a sha256 hash of a script as a commitment,
concatenate it to a public key, sha256 hash that concatenated result, clamp it
to the ed25519 scalar field, derive a point from it, and add that point to a
public key to create the root commitment, which itself functions both as a
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
- `make_taproot_lock` - 36 bytes
- `make_taproot_witness_keyspend` - 66-67 bytes
- `make_taproot_witness_scriptspend` - 35-36 bytes + committed script length
- `make_nonnative_taproot_lock` - 72 bytes

<details>
<summary>Example</summary>

```python
from tapescript import (
    make_taproot_lock,
    make_taproot_witness_keyspend,
    make_taproot_witness_scriptspend,
    make_nonnative_taproot_lock,
    Script,
    run_auth_scripts,
)
from nacl.signing import SigningKey
from os import urandom

sk = SigningKey(urandom(32))
committed_script = Script.from_src('equal')
lock = make_taproot_lock(sk.verify_key, committed_script)
sigfields = {'sigfield1': urandom(64)}
witness_keyspend = make_taproot_witness_keyspend(
    sk, sigfields, committed_script=committed_script
)
witness_scriptspend = Script.from_src('push d1 dup') + make_taproot_witness_scriptspend(
    sk.verify_key, committed_script
)

# get a nonnative taproot lock
nonnative_lock = make_nonnative_taproot_lock(sk.verify_key, committed_script)

# run the script
assert run_auth_scripts([witness_keyspend, lock], sigfields)
assert run_auth_scripts([witness_scriptspend, lock], sigfields)
assert run_auth_scripts([witness_keyspend, nonnative_lock], sigfields)
assert run_auth_scripts([witness_scriptspend, nonnative_lock], sigfields)
```

</details>

#### Delegated access and Graftroot

The general concept behind the Graftroot proposal by Gregory Maxwell is that the
holder(s) of a private key should be able to authorize another locking script to
replace the existing one without first broadcasting this change; the holder(s)
instead sign the new locking script and retain the signature. In the case of a
multi-party signature, this allows infinite variations to be generated ahead of
time by collaborating parties which can be used as fallbacks in the case that
multi-sig collaboration fails or otherwise is not possible in the future. In
Graftroot terminology, these scripts are called "surrogates" or "delegates". But
in the case that the parties can collaborate in the future, they can safely make
a valid signature and discard the pre-signed delegate scripts.

I considered whether to implement Graftroot as an op code when I implemented
Taproot, and I decided against it partly because of the forward security risk of
reusing an aggregate public key. (I.e. if several parties make a multi-sig
public key, e.g. with [musig](https://pypi.org/project/musig), and they sign a
surrogate script that is not used before they sign a transaction collaboratively,
then reusing that public key means the earlier surrogate script becomes valid
again in a new context.) The unconstrained validity of the surrogate scripts
seemed a bit too much.

However, delegating access after the lock is set still makes sense, and for this
purpose I have included some tooling around delegating access:

- `make_delegate_key_lock` - 98 bytes
- `make_delegate_key_chain_lock` - 128 bytes
- `make_delegate_key_cert` - 105 bytes
- `make_delegate_key_witness` - 173 bytes
- `make_delegate_key_chain_witness` - 66 bytes + 108 bytes per cert

<details>
<summary>Example</summary>

```python
from tapescript import (
    make_delegate_key_lock,
    make_delegate_key_cert,
    make_delegate_key_witness,
    make_delegate_key_chain_lock,
    make_delegate_key_chain_witness,
    run_auth_scripts,
)
from nacl.signing import SigningKey
from os import urandom
from time import time

now = lambda: int(time())
hour = 60*60

root_prvkey = SigningKey(urandom(32))
delegate_prvkey = SigningKey(urandom(32))
sigfields = {'sigfield1': urandom(64)}
lock = make_delegate_key_lock(root_prvkey.verify_key)
cert = make_delegate_key_cert(root_prvkey, delegate_prvkey.verify_key, now()-hour, now() + hour)
witness = make_delegate_key_witness(delegate_prvkey, cert, sigfields)
chain_lock = make_delegate_key_chain_lock(root_prvkey.verify_key)
chain_witness = make_delegate_key_chain_witness(delegate_prvkey, [cert], sigfields)

assert run_auth_scripts([witness, lock], sigfields)
assert run_auth_scripts([chain_witness, chain_lock], sigfields)
```
</details>

The idea is that the holder of a root private key will be able to generate a
certificate authorizing an arbitrary public key for a set amount of time, and
optionally allow that delegate to authorize further public keys. The chain lock
allows delegates of delegates to unlock it, but the non-chain lock allows only a
single layer of delegation, regardless of the content of that field in the cert.

The time constraints in the certs provide an amount of forward security as long
as you do not provide an `end_ts` too far into the future, eliminating the main
drawback of Graftroot. However, there are two drawbacks of this scheme compared
to Graftroot:

1. The locks provided do not directly allow signatures from the root.
2. The surrogate script is always a form of `push x{pubkey} check_sig x{sigflags}`;
   i.e. there is not infinite variation in surrogate scripts.

The former can be alleviated by using `OP_TAPROOT` and committing the delegate
key/chain lock, adding <40 bytes of additional overhead to the delegate access
execution path.

In the case that a pure graftroot is desirable, the following tools implement
the original graftroot concept using pure tapescript:

- `make_graftroot_lock` - 58 bytes
- `make_graftroot_witness_keyspend` - 67 bytes
- `make_graftroot_witness_surrogate` - 68-69 byte overhead + surrogate length

<details>
<summary>Example</summary>

```python
from tapescript import (
    make_graftroot_lock,
    make_graftroot_witness_keyspend,
    make_graftroot_witness_surrogate,
    run_auth_scripts,
    Script,
)
from nacl.signing import SigningKey
from os import urandom

prvkey = SigningKey(urandom(32))
sigfields = {'sigfield1': urandom(64)}
surrogate = Script.from_src('equal')
lock = make_graftroot_lock(prvkey.verify_key)
witness = make_graftroot_witness_keyspend(prvkey, sigfields)
surrogate_witness = Script.from_src('push d1 dup') + make_graftroot_witness_surrogate(
    prvkey, surrogate
)

assert run_auth_scripts([witness, lock], sigfields)
assert run_auth_scripts([surrogate_witness, lock], sigfields)
```
</details>

I have also added tools for a graftroot within taproot construction, which
commits to a script that checks a signature of a surrogate and then executes the
surrogate script; keyspend path is then taproot, and executing a surrogate first
takes the taproot scriptspend path before engaging the graftroot mechanism.

- `make_graftap_lock` - 36 bytes
- `make_graftap_witness_keyspend` - 66 bytes
- `make_graftap_witness_scriptspend` - 145 byte overhead + surrogate length

<details>
<summary>Example</summary>

```python
from tapescript import (
    make_graftap_lock,
    make_graftap_witness_keyspend,
    make_graftap_witness_scriptspend,
    run_auth_scripts,
    Script,
)
from nacl.signing import SigningKey
from os import urandom

prvkey = SigningKey(urandom(32))
sigfields = {'sigfield1': urandom(64)}
surrogate = Script.from_src('equal')
lock = make_graftap_lock(prvkey.verify_key)
witness_keyspend = make_graftap_witness_keyspend(prvkey, sigfields)
witness_scriptspend = Script.from_src('push d1 dup') + make_graftap_witness_scriptspend(
    prvkey, surrogate
)

assert run_auth_scripts([witness_keyspend, lock], sigfields)
assert run_auth_scripts([witness_scriptspend, lock], sigfields)
```
</details>

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

<details>
<summary>Example</summary>

```python
from tapescript import (
    make_htlc_sha256_lock,
    make_htlc_shake256_lock,
    make_htlc2_sha256_lock,
    make_htlc2_shake256_lock,
    make_htlc_witness,
    make_htlc2_witness,
    make_ptlc_lock,
    make_ptlc_witness,
    make_ptlc_refund_witness,
    run_auth_scripts,
    clamp_scalar,
    derive_point_from_scalar,
    Script,
)
from nacl.signing import SigningKey
from os import urandom
from time import time

receiver_prvkey = SigningKey(urandom(32))
receiver_pubkey = receiver_prvkey.verify_key
sender_prvkey = SigningKey(urandom(32))
refund_pubkey = sender_prvkey.verify_key
sigfields = {'sigfield1': urandom(16)}
timeout = 10
get_refund_cache = lambda: {
    'timestamp': int(time()) + timeout,
    **sigfields
}
preimage = b'super secret: ' + urandom(16)

# HTLC-SHA256
lock = make_htlc_sha256_lock(receiver_pubkey, preimage, refund_pubkey, timeout=timeout)
# receiver gets the preimage
receiver_witness = make_htlc_witness(receiver_prvkey, preimage, sigfields)
assert run_auth_scripts([receiver_witness, lock], sigfields)
# sender is refunded in the future
refund_witness = make_htlc_witness(sender_prvkey, b'1', sigfields)
assert run_auth_scripts([refund_witness, lock], get_refund_cache())

# HTLC-SHAKE256
lock = make_htlc_shake256_lock(receiver_pubkey, preimage, refund_pubkey, timeout=timeout)
# receiver gets the preimage
receiver_witness = make_htlc_witness(receiver_prvkey, preimage, sigfields)
assert run_auth_scripts([receiver_witness, lock], sigfields)
# sender is refunded in the future
assert run_auth_scripts([refund_witness, lock], get_refund_cache())

# HTLC2-SHA256
lock = make_htlc2_sha256_lock(receiver_pubkey, preimage, refund_pubkey, timeout=timeout)
# receiver gets the preimage
receiver_witness = make_htlc2_witness(receiver_prvkey, preimage, sigfields)
assert run_auth_scripts([receiver_witness, lock], sigfields)
# sender is refunded in the future
refund_witness = make_htlc2_witness(sender_prvkey, b'1', sigfields)
assert run_auth_scripts([refund_witness, lock], get_refund_cache())

# HTLC2-SHAKE256
lock = make_htlc2_shake256_lock(receiver_pubkey, preimage, refund_pubkey, timeout=timeout)
# receiver gets the preimage
receiver_witness = make_htlc2_witness(receiver_prvkey, preimage, sigfields)
assert run_auth_scripts([receiver_witness, lock], sigfields)
# sender is refunded in the future
assert run_auth_scripts([refund_witness, lock], get_refund_cache())

# PTLC without tweak
lock = make_ptlc_lock(receiver_pubkey, refund_pubkey, timeout=timeout)
# receiver gets the preimage
witness = make_ptlc_witness(receiver_prvkey, sigfields)
assert run_auth_scripts([witness, lock], sigfields)
# sender is refunded in the future
refund_witness = make_ptlc_refund_witness(sender_prvkey, sigfields)
assert run_auth_scripts([refund_witness, lock], get_refund_cache())

# PTLC with tweak
scalar = clamp_scalar(urandom(32))
point = derive_point_from_scalar(scalar)
lock = make_ptlc_lock(receiver_pubkey, refund_pubkey, tweak_point=point, timeout=timeout)
# receiver gets the preimage
witness = make_ptlc_witness(receiver_prvkey, sigfields, tweak_scalar=scalar)
assert run_auth_scripts([witness, lock], sigfields)
# sender is refunded in the future
refund_witness = make_ptlc_refund_witness(sender_prvkey, sigfields)
assert run_auth_scripts([refund_witness, lock], get_refund_cache())
```
</details>

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
or `run_auth_scripts(scripts: list[bytes|Script], cache_vals: dict = {}, contracts: dict = {})`.
The `run_script` function returns `tuple` of length 3 containing a `Tape`, a
`LifoQueue`, and the final state of the `cache` dict. The `run_auth_scripts`
instead returns a bool that is `True` if the scripts ran without error and
resulted in a single `0x01` value on the stack; otherwise it returns `False`.

The recommended way to use this system is to pass a list containing the
unlocking/witness script and the locking script as separate scripts to the
`run_auth_scripts` function, e.g. `run_auth_scripts([witness, lock])`. This
ensures that the locking scripts runs last and enforces its constraints, and any
failure to satisfy the constraints or attempts to bypass them will result in the
function returning `False`.

In the case where a signature is expected to be validated, the message parts for
the signature must be passed in via the `cache_vals` dict at keys `sigfield[1-8]`.
In the case where `OP_CHECK_TRANSFER` or `OP_INVOKE` might be called, the
contracts must be passed in via the `contracts` dict. See the
[check_transfer](https://github.com/k98kurz/tapescript/blob/v0.7.1/language_spec.md#op_check_transfer)
and
[invoke](https://github.com/k98kurz/tapescript/blob/v0.7.1/language_spec.md#op_invoke)
sections in the language_spec.md file for more informaiton about these two ops.

#### Changing flags

The interpreter flags can be changed by changing the `functions.flags` dict.

#### Adding ops

The ops can be updated via a plugin system.

<details>
<summary>Example</summary>

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
</details>

#### Adding an alias

If you want to use a new alias for an op code, you can create this alias using
the `add_alias` function. Valid aliases are alpha-numeric and may contain
underscores. This function will raise a `TypeError` for non-str args and a
`ValueError` if the alias contains invalid chars or is already in use.

<details>
<summary>Example</summary>

```py
from tapescript import add_alias

add_alias('arbitrary_alias', 'OP_CHECK_SIG_VERIFY')
```
</details>

### Plugins

There is a simple plugin system available for modifying execution behavior when
calling certain ops. Existing uses are documented below, but this system may be
used for future extensions when such use cases arise.

The basic functions for interacting with the plugin system are the following:
- `add_plugin(scope: str, plugin: Callable[[Tape, Stack, dict], Any]) -> None`
- `remove_plugin(scope: str, plugin: Callable[[Tape, Stack, dict], Any]) -> None`
- `reset_plugins(scope: str) -> None`

Additionally, plugins can be supplied in a dict format to `run_script` or
`run_auth_scripts`, but this will overwrite any plugins previously added for any
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
can be passed into the `run_script` and `run_auth_scripts` functions, and these
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

These also apply to the `OP_CHECK_MULTI_SIG`, `OP_CHECK_MULTI_SIG_VERIFY`,
`OP_TAPROOT`, `OP_SIGN`, and `OP_GET_MESSAGE` operations. See the language spec
and docs files for more detailed information about how these ops work.

#### Signature Extension Plugins

As of 0.4.2, the following OPs can be slightly modified with a plugin system:
`CHECK_SIG`, `CHECK_MULTISIG`, `SIGN`, and `GET_MESSAGE`. Signature extension
plugins can be managed with the following functions:
- `add_signature_extension(plugin: Callable[[Tape, Stack, dict], None])`
- `remove_signature_extension(plugin: Callable[[Tape, Stack, dict], None])`
- `reset_signature_extensions()`

Additionally, plugins can be injected when calling `run_script` or
`run_auth_scripts` the same way as contracts. The underlying plugin system uses
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

<details>
<summary>Example</summary>

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
        items.append(stack.get())
    compare = items.pop()
    while len(items):
        if items.pop() != compare:
            raise ScriptExecutionError('not all the same')

aliases = ['CHECK_ALL_EQUAL_VERIFY', 'CAEV']
add_soft_fork(255, 'OP_CHECK_ALL_EQUAL_VERIFY', OP_CHECK_ALL_EQUAL_VERIFY, aliases)
```
</details>

Scripts written with the new op will always execute successfully on nodes
running the old version of the interpreter.

<details>
<summary>Example</summary>

```python
from tapescript import Script, run_auth_scripts

# locking script
lock = Script.from_src('OP_CHECK_ALL_EQUAL_VERIFY d3 OP_TRUE')
# or to use aliases
lock = Script.from_src('caev d3 true')
assert lock.bytes.hex() == 'ff0301'

# locking script as decompiled by old nodes
lock = Script.from_bytes(bytes.fromhex('ff0301'))
print(lock.src)
'''NOP255 d3
OP_TRUE'''

# unlocking script that validates on both versions #
unlock = Script.from_src('push x0123 push x0123 push x0123')
assert run_auth_scripts([unlock, lock])

# unlocking script that fails validation on the new version #
unlock_fail = Script.from_src('push x0123 push x0123 push x3210')
assert not run_auth_scripts([unlock_fail, lock]), 'soft fork not activated'
```
</details>

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

<details>
<summary>Example tapescript source code</summary>

```s
TRY {
    OP_CHECK_ALL_EQUAL_VERIFY d3 OP_TRUE
} EXCEPT {
    OP_FALSE
}
```
</details>

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
python tests/test_e2e_extensions.py
```

There are currently 260 tests and 107 test vectors used for validating the ops,
compiler, decompiler, and script running functions. This includes 3 e2e tests
for a proof-of-concept implementation of the eltoo payment channel protocol, and
e2e tests combining the anonymous multi-hop lock (AMHL) system with adapter
signatures, as well as tests for the contract system, signature extension
plugins, hard-forks, and the soft-fork system. There are an additional 8
security tests, including a test proving the one-way homomorphic quality of
ed25519 and a test proving that all symmetric script trees share the same root.

## Contributing

Check out the [Pycelium discord server](https://discord.gg/b2QFEJDX69). If you
experience a problem, please discuss it on the Discord server. All suggestions
for improvement are also welcome, and the best place for that is also Discord.
If you experience a bug and do not use Discord, open an issue or discussion on
Github.

## ISC License

Copyleft (c) 2025 Jonathan Voss (k98kurz)

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
