from .classes import Tape, Stack
from .errors import ScriptExecutionError, SyntaxError
from .functions import (
    run_script,
    run_tape,
    run_auth_script,
    add_opcode,
    add_alias,
    add_contract,
    remove_contract,
    add_contract_interface,
    remove_contract_interface,
    bytes_to_int,
    int_to_bytes,
    uint_to_bytes,
    bytes_to_bool,
    bytes_to_float,
    float_to_bytes,
    clamp_scalar,
    derive_key_from_seed,
    derive_point_from_scalar,
    aggregate_points,
    aggregate_scalars,
    sign_with_scalar,
    xor,
    bytes_are_same,
    add_signature_extension,
    remove_signature_extension,
    reset_signature_extensions,
    run_sig_extensions,
)
from .interfaces import CanCheckTransfer, CanBeInvoked, ScriptProtocol
from .parsing import (
    get_symbols,
    parse_comptime,
    assemble,
    compile_script,
    decompile_script,
    add_opcode_parsing_handlers,
)
from .tools import (
    Script,
    ScriptLeaf,
    ScriptNode,
    create_script_tree_prioritized,
    create_merklized_script_prioritized,
    create_script_tree_balanced,
    create_merklized_script_balanced,
    generate_docs,
    add_soft_fork,
    make_adapter_lock_pub,
    make_adapter_lock_prv,
    make_single_sig_lock,
    make_single_sig_lock2,
    make_single_sig_witness,
    make_single_sig_witness2,
    make_multisig_lock,
    make_adapter_locks_pub,
    make_adapter_decrypt,
    decrypt_adapter,
    make_adapter_locks_prv,
    make_adapter_witness,
    make_delegate_key_lock,
    make_delegate_key_chain_lock,
    make_delegate_key_cert,
    make_delegate_key_unlock,
    make_graftroot_lock,
    make_graftroot_witness_keyspend,
    make_graftroot_witness_surrogate,
    make_htlc_sha256_lock,
    make_htlc_shake256_lock,
    make_htlc_witness,
    make_htlc2_sha256_lock,
    make_htlc2_shake256_lock,
    make_htlc2_witness,
    make_ptlc_lock,
    make_ptlc_witness,
    make_ptlc_refund_witness,
    make_taproot_lock,
    make_taproot_witness_keyspend,
    make_taproot_witness_scriptspend,
    make_graftap_lock,
    make_graftap_witness_keyspend,
    make_graftap_witness_scriptspend,
    make_scripthash_lock,
    make_scripthash_witness,
    setup_amhl,
    release_left_amhl_lock,
)

__version__ = '0.7.0'

def version() -> str:
    """Get the version of the tapescript library."""
    return __version__
