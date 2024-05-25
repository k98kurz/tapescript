## 0.5.0

- Signature extension system: call a plugin at the beginning of each of the
following ops, passing it the runtime: `CHECK_SIG`, `CHECK_MULTISIG`, `SIGN`,
and `GET_MESSAGE`. Each plugin function must have this signature:
`Callable[[Tape, LifoQueue, dict], None]`
- Example sig extension implementation using values in cache key b'sigext'
- Signature extension system uses an underlying scoped plugin system. In the
future, additional OPs may get plugin hooks using this system.
- Slightly simplified `CHECK_SIG` and `SIGN` to now use `GET_MESSAGE` instead of
repeating that message construction logic. To avoid calling plugins twice, a new
Tape containing only the sigflag is passed to `GET_MESSAGE` by these calls.
- New class `Stack` with item size limits to avoid denial of service attack from
the 6 byte script `true loop { dup concat }`. Refactor system to use new `Stack`.
(Internally use `collections.deque`.)
- Removed `OP_PUSH4`
- Redefined x05 to be `OP_GET_MESSAGE` and x59 to be `NOP89`
- Reversed the order in which the message and signature are pulled from the
queue by `CHECK_SIG_QUEUE` to make it equivalent to the `OP_CSFS` BIP.
- Reversed the order of `CONCAT` to make it equivalent to the `OP_CAT` BIP.
- Reversed the order of outputs of `DECRYPT_ADAPTER_SIG` to for compatability
with changed `CONCAT`.
- Renamed ops:
  - `OP_SIGN_QUEUE` -> `OP_SIGN_STACK`
  - `OP_CHECK_SIG_QUEUE` -> `OP_CHECK_SIG_STACK`
  - `OP_READ_CACHE_Q` -> `OP_READ_CACHE_STACK`
  - `OP_READ_CACHE_Q_SIZE` -> `OP_READ_CACHE_STACK_SIZE`
- Changed aliases:
  - `OP_RCS` (`RCS`) -> `OP_RCZ` (`RCZ`)
  - `OP_RCQ` (`RCQ`) -> `OP_RCS` (`RCS`)
  - `OP_RCQS` (`RCQS`) -> `OP_RCSZ` (`RCSZ`)
  - `OP_CSQ` (`CSQ`) -> `OP_CSS` (`CSS`)
- Added `OP_CAT` alias for `OP_CONCAT`
- Added `OP_CATS` alias for `OP_CONCAT_STR`

## 0.4.1

- Fixed `OP_NOT` to do a proper bitwise `NOT` operation.
- Switched the `true` value from `0x01` to `0xff` for compatibility with `FALSE NOT`
- Fixed compiler to handle negative ints.
- Added 32-bit float type to arg parsing forsome args: preface the value with `f`.

## 0.4.0

- Changed `OP_CHECK_TRANSFER` to pull the `count` parameter from the queue.
- Added `OP_LESS`: pulls ints value1 and value2 from the queue and puts
`value1<value2` onto the queue.
- Added `OP_LESS_OR_EQUAL` (alias `OP_LEQ`): pulls ints value1 and value2 from
the queue and puts `value1<=value2` onto the queue.
- Added `OP_GET_VALUE s"key"` (alias `OP_VAL`): puts the read-only cache values
at the string key onto the queue.
- Added example txn protocol using a sequence number (held in a sigfield) and
sequence number constraint. Included an e2e test implementing eltoo protocol.
- Added `OP_FLOAT_LESS` (alias `OP_FLESS`): pulls floats value1 and value2 from
the queue and puts `value1<value2` onto the queue.
- Added `OP_FLOAT_LESS_OR_EQUAL` (alias `OP_FLEQ`): pulls floats value1 and
value2 from the queue and puts `value1<=value2` onto the queue.
- Added `OP_INT_TO_FLOAT` (alias `OP_I2F`): pulls an int from the queue,
converts it to a float, then puts it back onto the queue.
- Added `OP_FLOAT_TO_INT` (alias `OP_F2I`): pulls a float from the queue,
converts it to an int, then puts its back onto the queue.
- Added `OP_LOOP`: simple "while" loop that runs its code block until the top
value of the queue is false; raises an error if loop runs more than
`Tape.callstack_limit` times.
- Added `OP_CHECK_MULTISIG flags m n` (alias `OP_CMS`) to do a Bitcoin-style
m-of-n multisig: pulls `n` public keys from queue, then pulls `m` signatures
from queue, then checks each signature against each public key; puts False onto
queue if public key is used more than once or if any signature that does not
validate to a public key, else puts True onto queue.
- Added `OP_CHECK_MULTISIG_VERIFY flags m n` (alias `OP_CMSV`) to run
`OP_CHECK_MULTISIG` followed by `OP_VERIFY`.
- Changed `IF` syntax to use '{' and '}' instead of '(' and ')' to designate
blocks.
- Refactored compiler innards.
- Added compiler ability to hoist statements between parentheses following `IF`
to run before the `OP_IF`, e.g. `IF ( @var1 @var2 LEQ ) { ...` will now hoist
to `@var1 @var2 LEQ IF {...`. Inclusion of parenthetic substatements is
optional.
- Added `OP_SIGN flags`: takes a signing key seed from the queue, signs a
message constructed from sigfields not blanked by the flags, and puts that
signature onto the queue.
- Added `OP_SIGN_QUEUE`: takes a signing key seed and message from the queue,
signs the message, and puts the signature onto the queue.
- Added `OP_CHECK_SIG_QUEUE`: takes a verify key, signature, and message from
the queue; puts True onto the queue if the signature was valid for the vkey and
message, otherwise puts False onto the queue.
- Reversed order of items placed onto queue after `OP_SPLIT` and `OP_SPLIT_STR`.
- Updated `OP_EQUAL` to use a timing attack safe comparison.
- Added `OP_XOR`, `OP_OR`, and `OP_AND` bitwise operators.
- Added `OP_DERIVE_SCALAR`, `OP_CLAMP_SCALAR`, `OP_ADD_SCALARS`,
`OP_SUBTRACT_SCALARS`, `OP_DERIVE_POINT`, and `OP_SUBTRACT_POINTS` to expose
more ed25519 maths.
- Added `OP_MAKE_ADAPTER_SIG_PUBLIC`, `OP_MAKE_ADAPTER_SIG_PRIVATE`,
`OP_CHECK_ADAPTER_SIG`, and `OP_DECRYPT_ADAPTER_SIG` to allow easier use of
adapter signatures.
- Added `OP_INVOKE` and associated `CanBeInvoked` interface for more flexible
contracts that can be invoked with `OP_INVOKE`.
- Added a simple CLI and a bunch of new tools for using adapter signatures,
HTLCs, PTLCs, and AMHLs.

## 0.3.1

- Expanded the variable syntax to include directly pulling items from the queue.

## 0.3.0

- Added a macro and variable system to the compiler.

## 0.2.8

- Added OP code aliases.
- Improved compiler and fixed some edge cases.
  - Extended comment support to within control flow blocks.
  - Fixed string value parsing.
  - Refactored compiler logic.

## 0.2.7

- Improved compiler error reporting.

## 0.2.6

- Improved `OP_EVAL` and other subtape execution OPs.
- Bug fixes.

## 0.2.5

- Bug fixes.

## 0.2.4

- Compiler improvement: handle `OP_TRY_EXCEPT` within `OP_IF` and `OP_IF_ELSE`.

## 0.2.3

- Bug fixes.

## 0.2.0

- Replaced `NOP61` with `OP_TRY_EXCEPT`. Constitutes a hard fork, but nobody is
using this yet, so no harm done.
- Reduced maximum subtape size from 16MB to 64KB, saving a byte in encoded size
arguments for `OP_IF`, `OP_IF_ELSE`, `OP_DEF`, and `OP_TRY_EXCEPT`.
