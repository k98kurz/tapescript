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
