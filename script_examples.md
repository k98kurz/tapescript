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
# committed conditional P2PK script #
OP_IF (
    OP_PUSH d1694791613
    OP_CHECK_TIMESTAMP_VERIFY
    OP_PUSH x<hex pubkey0>
    OP_CHECK_SIG x00
) ELSE (
    OP_PUSH x<hex pubkey1>
    OP_CHECK_SIG x00
)

# unlocking script #
OP_PUSH x<hex signature from pubkey0>
OP_TRUE
OP_PUSH x<hex committed P2PK script src>

# locking script #
OP_DUP
OP_SHAKE256 20
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
# committed script: eltoo-like multisig contract #
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
    OP_CHECK_TRANSFER 1
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
OP_SHAKE256 20
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
    OP_SWAP 1 2
    OP_CHECK_SIG_VERIFY
    OP_CHECK_SIG x00
)

# locking script #
OP_DUP
OP_SHAKE256 20
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
