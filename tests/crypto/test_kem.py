"""Crypto layer: KEM roundtrips per algorithm, and the two KEM roles."""
from __future__ import annotations

import pytest

from crypto import kem

ALL_KEMS = kem.available_kems()


def test_all_four_study_kems_are_available():
    """The study needs exactly these four; a missing one invalidates the benchmark."""
    assert set(ALL_KEMS) == set(kem.SUPPORTED_KEMS), (
        f"liboqs build is missing {set(kem.SUPPORTED_KEMS) - set(ALL_KEMS)}"
    )


@pytest.mark.parametrize("algorithm", ALL_KEMS)
def test_encapsulate_decapsulate_roundtrip(algorithm):
    mechanism = kem.KEM(algorithm)
    keypair = mechanism.generate_keypair()

    encapsulation = mechanism.encapsulate(keypair.public_key)
    recovered = mechanism.decapsulate(keypair.secret_key, encapsulation.ciphertext)

    assert recovered == encapsulation.shared_secret
    assert len(recovered) == mechanism.shared_secret_bytes


@pytest.mark.parametrize("algorithm", ALL_KEMS)
def test_reported_sizes_match_actual_material(algorithm):
    mechanism = kem.KEM(algorithm)
    keypair = mechanism.generate_keypair()
    encapsulation = mechanism.encapsulate(keypair.public_key)

    assert len(keypair.public_key) == mechanism.public_key_bytes
    assert len(keypair.secret_key) == mechanism.secret_key_bytes
    assert len(encapsulation.ciphertext) == mechanism.ciphertext_bytes


@pytest.mark.parametrize("algorithm", ALL_KEMS)
def test_fresh_keypairs_and_encapsulations_differ(algorithm):
    mechanism = kem.KEM(algorithm)
    first, second = mechanism.generate_keypair(), mechanism.generate_keypair()
    assert first.public_key != second.public_key

    a = mechanism.encapsulate(first.public_key)
    b = mechanism.encapsulate(first.public_key)
    assert a.ciphertext != b.ciphertext
    assert a.shared_secret != b.shared_secret


@pytest.mark.parametrize("algorithm", ALL_KEMS)
def test_decapsulating_with_the_wrong_secret_key_does_not_recover_the_secret(algorithm):
    """ML-KEM/FrodoKEM are implicitly rejecting: wrong key yields a junk secret."""
    mechanism = kem.KEM(algorithm)
    target, other = mechanism.generate_keypair(), mechanism.generate_keypair()
    encapsulation = mechanism.encapsulate(target.public_key)

    wrong = mechanism.decapsulate(other.secret_key, encapsulation.ciphertext)
    assert wrong != encapsulation.shared_secret


def test_unsupported_algorithm_is_rejected():
    with pytest.raises(kem.UnsupportedKEM):
        kem.KEM("Kyber512")  # enabled in liboqs, but outside this study
    with pytest.raises(kem.UnsupportedKEM):
        kem.KEM("not-a-kem")


def test_wrong_size_inputs_are_rejected():
    mechanism = kem.KEM("ML-KEM-768")
    with pytest.raises(kem.KEMError):
        mechanism.encapsulate(b"\x00" * 10)
    with pytest.raises(kem.KEMError):
        mechanism.decapsulate(mechanism.generate_keypair().secret_key, b"\x00" * 10)


# -- roles --------------------------------------------------------------------


def test_long_term_keypair_persists_and_authenticates_implicitly():
    """Alice authenticates Bob by encapsulating to his persistent public key."""
    bob = kem.LongTermKEM("ML-KEM-768")
    public_key_before = bob.public_key

    encapsulation = kem.KEM("ML-KEM-768").encapsulate(bob.public_key)
    assert bob.decapsulate(encapsulation.ciphertext) == encapsulation.shared_secret
    # Nothing about a session changes the identity key.
    assert bob.public_key == public_key_before


def test_long_term_keypair_can_be_reloaded_from_stored_material():
    original = kem.LongTermKEM("ML-KEM-512")
    reloaded = kem.LongTermKEM("ML-KEM-512", keypair=original.keypair)

    encapsulation = original.encapsulate_to(reloaded.public_key)
    assert reloaded.decapsulate(encapsulation.ciphertext) == encapsulation.shared_secret


def test_long_term_keypair_algorithm_mismatch_is_rejected():
    keypair = kem.LongTermKEM("ML-KEM-512").keypair
    with pytest.raises(kem.UnsupportedKEM):
        kem.LongTermKEM("ML-KEM-768", keypair=keypair)


def test_ephemeral_keypair_is_fresh_per_handshake():
    ephemeral = kem.EphemeralKEM("ML-KEM-768")
    first = ephemeral.generate()
    second = ephemeral.generate()
    assert first != second


def test_ephemeral_roundtrip_and_forget():
    ephemeral = kem.EphemeralKEM("ML-KEM-768")
    public_key = ephemeral.generate()

    encapsulation = kem.KEM("ML-KEM-768").encapsulate(public_key)
    assert ephemeral.decapsulate(encapsulation.ciphertext) == encapsulation.shared_secret

    ephemeral.forget()
    with pytest.raises(kem.KEMError):
        ephemeral.decapsulate(encapsulation.ciphertext)


def test_ephemeral_use_before_generate_is_an_error():
    ephemeral = kem.EphemeralKEM("ML-KEM-512")
    with pytest.raises(kem.KEMError):
        _ = ephemeral.public_key


def test_same_algorithm_can_serve_both_roles():
    """The role distinction is lifecycle, not primitive."""
    long_term = kem.LongTermKEM("ML-KEM-768")
    ephemeral = kem.EphemeralKEM("ML-KEM-768")
    assert long_term.algorithm == ephemeral.algorithm

    to_identity = ephemeral.encapsulate_to(long_term.public_key)
    assert long_term.decapsulate(to_identity.ciphertext) == to_identity.shared_secret


def test_kem_sizes_covers_every_study_kem():
    sizes = kem.kem_sizes()
    assert set(sizes) == set(ALL_KEMS)
    # FrodoKEM's conservative parameters cost far more on the wire than ML-KEM.
    assert sizes["FrodoKEM-976-AES"]["public_key"] > sizes["ML-KEM-1024"]["public_key"]
    assert all(entry["shared_secret"] >= 16 for entry in sizes.values())


def test_crypto_layer_never_imports_the_qkd_client():
    """Design rule: the crypto layer does not know the QKD server exists."""
    import pathlib

    crypto_dir = pathlib.Path(kem.__file__).parent
    for path in crypto_dir.glob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "qkd_client" not in source, f"{path.name} references the QKD client"
        assert "httpx" not in source, f"{path.name} does network I/O"
