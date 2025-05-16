## 0.7.2

### VM

- Bugfix: `run_auth_scripts` now copies definitions between `Tape`s used to
  execute scripts in a sequence.
- Documentation: clarified order that more ops pull values from the stack.

### Tools

- Added new `Certificate` utility class for parsing certs used in some tools.
- Improved HTLC lock creation tools with ability to be created with either a
  preimage or a hash digest. Useful for copying hash locks.

### Misc

- Moved `version()` into its own file.

## 0.7.1

### VM

- Added new `run_auth_scripts` function to run scripts sequentially in the same
  runtime environment.
- Added deprecation warning to `run_auth_script`.
- Updated package to replace calls to `run_auth_script` with calls to `run_auth_scripts`
- Similarly updated documentation to replace calls to the deprecated function

## 0.7.0

### Compiler

- Added `@#name` syntactic sugar for `OP_READ_CACHE_SIZE s"name"`
- Added more aliases:
  - `EQ` for `OP_EQUAL`
  - `EQV` for `OP_EQUAL_VERIFY`
  - `CS` for `OP_CHECK_SIG`

### VM

- Changed `OP_TAPROOT` to take the root from the stack instead of from the tape;
  it also now takes an `allowable_sigflag` param from the tape instead of from
  cache key`b'trsf'`. Locking script syntax now consistent with `OP_CHECK_SIG`:
  `push x<root> taproot x<allowable_sigflags>`.
- Fixed `OP_EVAL`: it will now cause a `ScriptExecutionError` with message
  "callstack limit exceeded" instead of a Python "max recursion limit exceeded"
  error. This change makes it subject to the same callstack limit of everything
  else, and calls to it increase the callstack count.
- Added option to include aliases in `add_opcode`

### Tools

- REPL:
  - Added decompilation feature to repl (type `~~` followed by the hexadecimal
    byte codes of a script to see the disassembled script)
  - Can now pass a `cache_file` path to the repl invocation, and it will load it
  - Repl now automatically sets the "timestamp" cache value to the Unix epoch
    timestamp at the time the repl is invoked
  - Added macro:
    - `~ts` to set the timestamp in the cache to current Unix epoch ts.
    - `~~` followed by the hexadecimal byte codes of a script to disassemble it
    - `~d` to decode the top stack item into a signed int and print it
    - `~f` to decode the top stack item into a float and print it
    - `~s[1-8] value` to set a sigfield to the value; if the value has "x" in
      the first 2 chars, it will be interpreter as hexadecimal; otherwise, it
      will be interpreted as a string
- Added `sign_script_prefix` parameter to many `make_*_witness` functions
- Added ability to pass `SigningKey` objects to `make_*_witness` functions
- Added ability to pass `VerifyKey` objects as pubkeys to functions that make
  locks
- Updated tooling for delegate keys:
  - Updated `make_delegate_key_cert`:
    - Optimized the system by concatenating timestamps into the cert, saving 6
      bytes in the unlocking script and enabline cert chains
    - Appended a bool to indicate if the delegate can further delegate access,
      adding 1 byte of overhead per cert
    - Overall, the changes result in 5 bytes saved for one cert
  - Updated `make_delegate_key_lock` parsing to account for new cert format
  - Optimized `make_delegate_key_lock`, saving 27 bytes compared to 0.6.2 (from
    125 bytes to 98), including the updated parsing
  - Updated `make_delegate_key_unlock`:
    - Renamed to `make_delegate_key_witness`
    - New cert format saved 5 bytes overall (down to 173 bytes)
  - Added `make_delegate_key_chain_lock` - 128 bytes
  - Added `make_delegate_key_chain_witness` - 66 bytes + 108 bytes per cert
- Added new tools for using balanced Merklized script trees:
  - `create_script_tree_balanced`
  - `create_merklized_script_balanced`
- Added new tools for graftroot:
  - `make_graftroot_lock` - 58 bytes
  - `make_graftroot_witness_keyspend` - 67 bytes
  - `make_graftroot_witness_surrogate` - 68-69 byte overhead
- Added new tools for graftroot within taproot ("graftap")
  - `make_graftap_lock` - 36 bytes
  - `make_graftap_witness_keyspend` - 66 bytes
  - `make_graftap_witness_scriptspend` - 145 byte overhead
- Updated `make_taproot_lock` tool to reflect new `OP_TAPROOT` syntax; locking
  scripts are now 36 bytes long.
- Updated `make_taproot_witness_keyspend` to remove pushing sigflags to cache
  `b'trsf'`, saving 9 bytes in such witnesses (now just 67 bytes; 66 bytes for
  witness that signed without blanking any sigfields).
- Added `make_nonnative_taproot_lock` that implements `OP_TAPROOT` as a demo of
  cryptographic ops and a hacky optimization trick. Script size is 72 bytes.
- Added option to include aliases in `add_soft_fork`

## 0.6.2

- Made some compatibility patches for systems missing some functions
- Some corrections and improvements to the language spec document

## 0.6.1

- Made `tools.make_scripthash_lock`, `tools.make_scripthash_witness`,
`parsing.get_symbols`, `parsing.parse_comptime`, and `parsing.assemble`
visible at the module root level.

## 0.6.0

- Fix: `OP_EVAL` now includes plugin support
- Changed `OP_SPLIT` and `OP_SPLIT_STR` to take index parameter from stack
- Added another signature extension e2e test
- Added `make_scripthash_lock` and `make_scripthash_witness` tools
- Added REPL in `tools.repl` and made it accessible via CLI: `tapescript repl`
- Added comptime (preprocessor) features to parsing: `~ { ops }` is replaced
with the byte code for `ops` as a hexadecimal symbol before assembly (i.e. it
compiles `ops` and replaces the symbol section with the result); `~! { ops }`
causes `ops` to be compiled and executed, then the whole section is replaced
with the top item in the Stack as a hexadecimal symbol.

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
  - `OP_CTV` (`CTV`) -> `OP_CTSV` (`CTSV`)
- Added `OP_CTS` alias for `OP_CHECK_TIMESTAMP`
- Added `OP_CAT` alias for `OP_CONCAT`
- Added `OP_CATS` alias for `OP_CONCAT_STR`
- Added new classes `Script`, `ScriptLeaf`, and `ScriptNode` and replaced the
`create_merklized_script` function with `create_merklized_script_prioritized` to
make using the new `OP_MERKLEVAL` easier.
- Updated all tool functions to use the `Script` class
- Added `Script.__bytes__`, `Script.__str__`, and `Script.__add__`
- Added `ScriptProtocol` representing `Script` functionality
- Added `ScriptProtocol` compatibility to script running functions
- Fix: `OP_LOOP` now exits if `OP_RETURN` is called within the loop body
- Added `OP_CHECK_TEMPLATE` (`OP_CT`) and `OP_CHECK_TEMPLATE_VERIFY` (`OP_CTV`)
- Added `OP_TAPROOT` (`OP_TR`)
- Fixed `OP_DIV_FLOAT` arithmetic bug
- Changed `OP_RANDOM` to take its argument from the stack instead of the tape
- Added `OP_ADD` alias for `OP_ADD_INTS`
- Added `OP_SUB` alias for `OP_SUBTRACT_INTS`
- Added `OP_MULT` alias for `OP_MULT_INTS`
- Added `OP_DIV` alias for `OP_DIV_INTS`
- Added `OP_MOD` alias for `OP_MOD_INTS`
- Improved documentation generation

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
