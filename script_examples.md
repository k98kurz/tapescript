These examples are in a human-readable form and would need to be transpiled
through the `compile_script` function to produce the byte code tape that can
then be executed with `run_script`.

Note that these are currently untested; this was a series of thought experiments
to help inform the design/implementation process. Once the system is complete,
these will be thoroughly tested/vetted, updated/replaced as necessary, and
expanded upon.

# Example 1: P2PK

The below example includes a branching locking script that references
preconditions (i.e. is run before the main locking script) and the two unlocking
scripts. To make the scripts execute successfully, one of the two unlocking
scripts will have to be used, as well as the signature from the relevant
private key.

```s
"example 1"
# precondition script #
OP_DEF 0 {
    OP_PUSH d1694791613
    OP_CHECK_TIMESTAMP_VERIFY
    OP_PUSH x<hex pubkey0>
    OP_CHECK_SIG x00
    OP_VERIFY
}

OP_DEF 1 {
    OP_PUSH x<hex pubkey1>
    OP_CHECK_SIG x00
    OP_VERIFY
}

# unlocking script 0 #
OP_PUSH x<hex signature from pubkey0>
OP_TRUE

# unlocking script 1 #
OP_PUSH x<hex signature from pubkey1>
OP_FALSE

# locking script #
OP_IF (
    OP_CALL d0
) ELSE (
    OP_CALL d1
)
```

# Example 2: P2SH

This example shows a pay-to-script-hash locking script and the associated
unlocking script.

```s
"example 2: P2SH"
# committed conditional P2PK script: 86 bytes #
OP_IF (
    # branch A: 43 bytes #
    OP_PUSH d1694791613
    OP_CHECK_TIMESTAMP_VERIFY
    OP_PUSH x<hex pubkey0>
    OP_CHECK_SIG x00
) ELSE (
    # branch B: 36 bytes #
    OP_PUSH x<hex pubkey1>
    OP_CHECK_SIG x00
)

# unlocking script: 155 bytes #
OP_PUSH x<hex signature from pubkey0>
OP_TRUE
OP_PUSH x<hex committed P2PK script src>

# locking script: 27 bytes #
OP_DUP
OP_SHAKE256 d20
OP_PUSH x<hex script shake256 hash>
OP_EQUAL_VERIFY
OP_EVAL
```

# Example 3: credit default swap

This example shows how a complex derivative might be implemented using a
committed contract script, keeping the contract terms private until execution.
This branching logic is for three spending paths, and the contract code can be
further obfuscated with more commitments, e.g. by replacing the first branch
with a committment similar to the locking script to save several hundred bytes
for executions of the other two spending paths.

```s
"example 3: underwriting/CDS on obligation"
# committed script: multisig contract #
OP_IF (
    OP_PUSH d<unix epoch of maturation + grace period>
    OP_DUP
    OP_CHECK_TIMESTAMP_VERIFY
    OP_CHECK_EPOCH_VERIFY
    OP_PUSH x<funding source>
    OP_PUSH x<funding destination>
    OP_PUSH x<encoded txn constraints>
    OP_PUSH d<amount>
    OP_PUSH x<hex contract hash>
    OP_PUSH d1
    OP_CHECK_TRANSFER
    OP_VERIFY
    OP_PUSH x<hex pubkey_CDS_purchaser>
    OP_CHECK_SIG x00
) ELSE (
    OP_IF (
        OP_PUSH d<unix epoch of maturation + grace period + 30 days>
        OP_CHECK_EPOCH_VERIFY
        OP_PUSH x<hex pubkey_CDS_issuer>
        OP_CHECK_SIG x00
    ) ELSE (
        OP_PUSH x<hex pubkey_2of2>
        OP_CHECK_SIG x00
    )
)

# unlocking script: CDS redemption #
OP_PUSH x<hex signature from pubkey_CDS_purchaser>
OP_PUSH x<hex transfer proof from contract>
OP_TRUE
OP_PUSH x<hex committed P2PK script src>

# unlocking script: CDS expiration #
OP_PUSH x<hex signature from pubkey_CDS_issuer>
OP_TRUE
OP_FALSE
OP_PUSH x<hex committed P2PK script src>

# unlocking script: CDS transfer #
OP_PUSH x<hex signature from pubkey_2of2>
OP_FALSE
OP_FALSE
OP_PUSH x<hex committed P2PK script src>

# locking script #
OP_DUP
OP_SHAKE256 d20
OP_PUSH x<hex committed script shake256 hash>
OP_EQUAL_VERIFY
OP_EVAL
```

# Example 4: correspondent banking style account encumbrances

```s
"example 4: nostro/vostro account encumbrance"
# committed script #
OP_IF (
    OP_PUSH x<hex musig pubkey>
    OP_CHECK_SIG x00
) ELSE (
    OP_PUSH x<hex pubkey1>
    OP_PUSH x<hex pubkey2>
    OP_SWAP d1 d2
    OP_CHECK_SIG_VERIFY x00
    OP_CHECK_SIG x00
)

# locking script #
OP_DUP
OP_SHAKE256 d20
OP_PUSH x<hex committed script shake256 hash>
OP_EQUAL_VERIFY
OP_EVAL

# unlocking script: musig #
OP_PUSH x<hex signature from musig pubkey>
OP_TRUE
OP_PUSH x<hex committed script src>

# unlocking script: 2 signatures #
OP_PUSH x<hex signature from pubkey1>
OP_PUSH x<hex signature from pubkey2>
OP_FALSE
OP_PUSH x<hex committed script src>
```

# Example 5: merklized script

This is an example of a streamlined branching script where unexecuted branches
remain hidden behind cryptographic commitments. Only those script branches
included in the root commitment can be executed.

```s
# locking script: 33 bytes #
OP_MERKLEVAL x<hex 32 byte root sha256 hash>

# committed script branch A: 36 bytes #
OP_PUSH x<hex pubkey0>
OP_CHECK_SIG x00

# unlocking script A: 139 bytes #
OP_PUSH x<hex signature from pubkey0>
OP_PUSH x<hex 32 byte branch B sha256 hash>
OP_PUSH x<hex branch A script>
OP_TRUE

# committed script branch B: 33 bytes #
OP_MERKLEVAL x<hex 32 byte branch B root sha256 hash>

# committed script branch BA: 36 bytes #
OP_PUSH x<hex pubkey1>
OP_CHECK_SIG x00

# unlocking script BA: 147 bytes #
OP_PUSH x<hex signature from pubkey1>
OP_PUSH x<hex 32 byte branch BB sha256 hash>
OP_PUSH x<hex branch BA script>
OP_TRUE
OP_PUSH x<hex 32 byte branch A sha256 hash>
OP_PUSH x<hex branch B script>
OP_FALSE

# committed script branch BB: 36 bytes #
OP_PUSH x<hex pubkey2>
OP_CHECK_SIG x00

# unlocking script BB: 147 bytes #
OP_PUSH x<hex signature from pubkey2>
OP_PUSH x<hex 32 byte branch BA sha256 hash>
OP_PUSH x<hex branch BB script>
OP_FALSE
OP_PUSH x<hex 32 byte branch A sha256 hash>
OP_PUSH x<hex branch B script>
OP_FALSE
```

This functionality can be replicated with the other ops, but it will have more
overhead since OP_MERKLEVAL is like a macro that runs a number of other ops.
Note that 5 bytes can be shaved from the commitment scripts by using OP_SHAKE256
with digest length 26, reducing the commitment security from 256 to 208 bits;
this reduces the size of unlocking scripts A by 10 bytes and unlocking scripts
BA and BB by 20 bytes. If we decreased the commitment security down to 180 bits
using `OP_SHAKE256 d20`, this shaves an additional 6 bytes from the locking
script, 12 bytes from unlocking script A, and 24 bytes from unlocking scripts BA
and BB (final byte counts of 27, 174, and 232 respectively). The OP_MERKLEVAL
option is both more secure and a more efficient branching script solution. The
below example of this was not added as a test vector because it is strictly
inferior to the OP_MERKLEVAL method above, and it would have been a lot of time
and effort that I would rather put elsewhere.

```s
# locking script: 38 bytes #
OP_DUP
OP_SHA256
OP_PUSH x<hex 32 byte root sha256 hash>
OP_EQUAL_VERIFY
OP_EVAL

# committed script root: 83 bytes #
OP_IF (
    # committment to branch A: 38 bytes #
    OP_DUP
    OP_SHA256
    OP_PUSH x<hex 32 byte branch A sha256 hash>
    OP_EQUAL_VERIFY
    OP_EVAL
) ELSE (
    # committed script branch B: 38 bytes #
    OP_DUP
    OP_SHA256
    OP_PUSH x<hex 32 byte branch B root sha256 hash>
    OP_EQUAL_VERIFY
    OP_EVAL
)

# committed script branch A: 36 bytes #
OP_PUSH x<hex pubkeyA>
OP_CHECK_SIG x00

# unlocking script A: 190 bytes #
OP_PUSH x<hex signature from pubkeyA>
OP_PUSH x<hex committed script branch A>
OP_TRUE
OP_PUSH x<hex committed script root>

# committed script branch B: 83 bytes #
OP_IF (
    # commitment to script branch BA: 38 bytes #
    OP_DUP
    OP_SHA256
    OP_PUSH x<hex 32 byte branch A sha256 hash>
    OP_EQUAL_VERIFY
    OP_EVAL
) ELSE (
    # commitment to script branch BB: 38 bytes #
    OP_DUP
    OP_SHA256
    OP_PUSH x<hex 32 byte branch A sha256 hash>
    OP_EQUAL_VERIFY
    OP_EVAL
)

# committed script branch BA: 36 bytes #
OP_PUSH x<hex pubkeyBA>
OP_CHECK_SIG x00

# unlocking script BA: 276 bytes #
OP_PUSH x<hex signature from pubkeyBA>
OP_PUSH x<hex committed script branch BA>
OP_TRUE
OP_PUSH x<hex committed script branch B>
OP_FALSE
OP_PUSH x<hex committed script root>

# committed script branch BB: 36 bytes #
OP_PUSH x<hex pubkeyBB>
OP_CHECK_SIG x00

# unlocking script BB: 276 bytes #
OP_PUSH x<hex signature from pubkeyBB>
OP_PUSH x<hex committed script branch BB>
OP_FALSE
OP_PUSH x<hex committed script branch B>
OP_FALSE
OP_PUSH x<hex committed script root>
```

# Example 6: eltoo-like protocol

This example shows how the features of tapescript can be used to implement the
[eltoo off-chain protocol](https://blockstream.com/eltoo.pdf) using on-chain
primitives. This example was implemented as an e2e test
[here](https://github.com/k98kurz/tapescript/blob/master/tests/test_e2e_eltoo.py).
This assumes instant confirmation of transactions once broadcast for the sake of
convenience -- the Unix timestamp based constraints can be adapted for a system
that enforces causal ordering, e.g. a blockchain or other logical clock.

## Original proposal

In the original paper, designed for Bitcoin and introducing a new sighash flag
and a change to how sequence numbers are interpreted, the locking scripts were
as follows:
- setup: `2 <pubkey A> <pubkey B> 2 OP_CHECKMULTISIGVERIFY`
- trigger and update:
```s
OP_IF
    <N> OP_CSV
    2 <pubkey A_(s,i)> <pubkey B_(s,i)> 2 OP_CHECKMULTISIGVERIFY
ELSE
    <S_i + 1> OP_CLTV
    2 <pubkey A_u> <pubkey B_u> 2 OP_CHECKMULTISIGVERIFY
ENDIF
```

(`OP_CSV` = `OP_CHECKSEQUENCEVERIFY`; `OP_CLTV` = `OP_CHECKLOCKTIMEVERIFY`)

`<pubkey A>` and `<pubkey B>` are public keys used by the channel participants
to set up the channel. `<pubkey A_u>` and ``<pubkey B_u>` are public keys used
for signing update transactions. `<pubkey A_(s,i)>` and ``<pubkey B_(s,i)>` are
settlement keys calculated using a seed and a state counter used to sign
settlement transactions.

Before broadcasting the setup transaction to open the channel, a trigger txn is
signed that spends the setup UTXO, and a settlement txn is signed that spends
the trigger UTXO to return funds to the channel participants. Both participants
retain the trigger txn and the initial settlement txn. The update txns are
signed using the proposed `SIGHASH_NOINPUT` sighash-flag, which blanks the
previous input field during signature creation and verification, allowing the
signature to be used for any matching locking script without committing to spend
a specific UTXO.

To update the channel, an update txn is created with an incremented sequence
number, and a new settlement txn is also created and signed using the new
settlement keys for this state. The state counter is held in the txn sequence
field. Invalidation of earlier update txns is enforced using `OP_CLTV` (i.e. an
earlier update txn cannot spend the UTXO of a later update txn), and settlement
txns must wait `N` blocks after the update txn is confirmed on the blockchain
before becoming valid (enforced by the `OP_CSV`), allowing either participant to
broadcast a later update txn before the prior settlement txn becomes valid.
Importantly, the sequence number must be included in signature generation and
verification.

To open a channel, only the setup txn is broadcast and confirmed. The trigger,
update, and settlement txns are all held by the participants until they decide
to close the payment channel and settle, at which point the trigger txn is
broadcast and confirmed on the blockchain, then the latest update txn, then
finally the settlement txn. If one participant attempts to cheat the other by
broadcasting an old settlement transaction, it will first have to broadcast and
confirm the trigger and corresponding update transaction; the timeout on the
settlement transaction will allow the other participant to detect the attempted
fraud and broadcast the most recent update txn, invalidating the old settlement
txn before it can be confirmed. This also allows for synchronization between
participants in the case that one node experiences a fault, whereas the current
Lightning Network protocol causes a total loss of funds for a faulty node.

## Tapescript implementation

Transactions will consist of a list of entries. Each entry will consist of the
following:
- `inputs`: ordered list of IDs of funding UTXOs in the form `[(txn_id, index), ...]`
- `outputs`: ordered list of tuples of locking scripts of the new UTXOs to be
generated and the values assigned to each, i.e. `[(lock, val), ...]`
- `witnesses`: the unlocking scripts that satisfy the locking scripts of the
inputs

Each transaction will contain the following fields:
- `state`: unsigned 32-bit integer
- `timestamp`: Unix epoch timestamp at time of transaction creation
- `entries`: `[entry1, ...]`

The following values must be held as read-only in the cache at execution time:
- `time`: the Unix epoch timestamp at time of execution
- `sigfield[1-8]`: the relevant signature fields
- `input_ts`: greatest txn timestamp from entry inputs

For validating signatures, the following values will be held in the sigfields:
- `sigfield1`: entry inputs
- `sigfield2`: entry outputs
- `sigfield3`: transaction sequence
- `sigfield4`: transaction timestamp

An important note is that because the tapescript `CHECK_SIG` and
`CHECK_SIG_VERIFY` ops take a parameter encoding allowable sighash flags,
invalidating any signatures that use a disallowed flag to exclude a required
sigfield, the same public keys can be used for all locking scripts. The original
eltoo proposal was made for the Bitcoin script system, which does not include
the ability to selectively enable sighash flags in locking scripts, so the
authors had to use another scheme to ensure that signatures could not be bound
to settlement transactions without any constraints, hence the use of unique keys
for each settlement txn spending path in the update txn locking scripts. If
instead the same keys were used for all locking scripts, an update txn signature
could be bound to any settlement txn.

By disallowing all sighash flags in the settlement path locking scripts, each
settlement transaction in the tapescript implementation is bound solely to the
corresponding update txn, while allowing the exclusion of `sigfield1` containing
the inputs in the update spending path allows the signatures for update txns to
couple only to the state counter and outputs.

### Setup txn

Locking script:
```s
PUSH x<pubkey A>
CHECK_SIG_VERIFY x00
PUSH x<pubkey B>
CHECK_SIG x00
```

Txn entry:
- `inputs`: `[funding inputs]`
- `outputs`: `[(lock, total value from inputs less fee)]`
- `witnesses`: `[unlocking scripts]`

Transaction:
- `state`: `0`
- `timestamp`: uint32
- `entries`: `[txn entry]`

### Trigger txn

Locking script:
```s
IF (
    # txn timestamp must be 24 hours greater than youngest input #
    VAL s"sigfield4"
    VAL s"input_ts" PUSH d43200 ADD_INTS d2
    LESS VERIFY
    # current time must be greater than or equal to txn timestamp #
    VAL s"time"
    VAL s"sigfield4"
    LEQ VERIFY
    PUSH x<pubkey A>
    CHECK_SIG_VERIFY x00
    PUSH x<pubkey B>
    CHECK_SIG x00
) ELSE (
    VAL s"sigfield3"
    PUSH d0
    LESS VERIFY
    PUSH x<pubkey A>
    CHECK_SIG_VERIFY x01
    PUSH x<pubkey B>
    CHECK_SIG x01
)
```

Witness matching setup locking script:
```s
PUSH x<signature from pubkey B>
PUSH x<signature from pubkey A>
```

Txn entry:
- `inputs`: `[setup UTXO]`
- `outputs`: `[(locking script, value)]`
- `witnesses`: `[witness]`

Transaction:
- `sequence`: `0`
- `timestamp`: uint32
- `entries`: `[txn entry]`

### Update txn

Locking script:
```s
IF (
    # txn timestamp must be 24 hours greater than youngest input #
    VAL s"sigfield4"
    VAL s"input_ts" PUSH d43200 ADD_INTS d2
    LESS VERIFY
    # current time must be greater than or equal to txn timestamp #
    VAL s"time"
    VAL s"sigfield4"
    LEQ VERIFY
    PUSH x<pubkey A>
    CHECK_SIG_VERIFY x00
    PUSH x<pubkey B>
    CHECK_SIG x00
) ELSE (
    VAL s"sigfield3"
    PUSH d<i>
    LESS VERIFY
    PUSH x<pubkey A>
    CHECK_SIG_VERIFY x01
    PUSH x<pubkey B>
    CHECK_SIG x01
)
```

Witness matching trigger locking script:
```s
PUSH x<signature from pubkey B + x01>
PUSH x<signature from pubkey A + x01>
```

Txn entry:
- `inputs`: `[trigger UTXO]`
- `outputs`: `[(locking script, value)]`
- `witnesses`: `[witness]`

Transaction:
- `sequence`: `previous state + 1`
- `timestamp`: uint32
- `entries`: `[txn entry]`

### Settlement txn

Lock_A locking script: `PUSH x<pubkey A> CHECK_SIG x00`

Lock_B locking script: `PUSH x<pubkey B> CHECK_SIG x00`

Witness matching update locking script:
```s
PUSH x<signature from pubkey B + x01>
PUSH x<signature from pubkey A + x01>
```

Txn entry:
- `inputs`: `[update UTXO]`
- `outputs`: `[(lock_A, val_A), (lock_B, val_B)]`
- `witnesses`: `[witness]`

Transaction:
- `sequence`: `previous state + 1`
- `timestamp`: uint32
- `entries`: `[settlement txn entry]`
