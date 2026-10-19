"""liboqs-python wrapper exposing the two KEM *roles* the HAKE needs.

We do not implement a KEM. Everything here delegates to liboqs via
`oqs`; this module only manages key lifecycle and gives the protocol a
stable surface.

The two roles differ in **lifecycle, not primitive** -- the same algorithm
can serve both:

* `LongTermKEM` -- keypair persists across sessions, published out-of-band
  (SSH `known_hosts` style). Encapsulating to a peer's long-term public key
  is what gives the handshake implicit authentication: only the holder of
  the matching secret key can decapsulate and continue.
* `EphemeralKEM` -- fresh keypair per handshake, discarded afterwards.
  This is what gives forward secrecy.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import oqs

#: The four KEMs the study benchmarks. ML-KEM is FIPS 203; FrodoKEM is the
#: conservative non-structured-lattice alternative.
SUPPORTED_KEMS: tuple[str, ...] = (
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
    "FrodoKEM-976-AES",
)

DEFAULT_KEM = "ML-KEM-768"


class UnsupportedKEM(ValueError):
    """The requested algorithm is outside this study, or absent from liboqs."""


class KEMError(RuntimeError):
    """liboqs rejected an encapsulation or decapsulation."""


@dataclass(frozen=True)
class KeyPair:
    algorithm: str
    public_key: bytes
    secret_key: bytes


@dataclass(frozen=True)
class Encapsulation:
    ciphertext: bytes
    shared_secret: bytes


def available_kems() -> tuple[str, ...]:
    """The subset of SUPPORTED_KEMS this liboqs build actually enables."""
    enabled = set(oqs.get_enabled_kem_mechanisms())
    return tuple(name for name in SUPPORTED_KEMS if name in enabled)


def assert_supported(algorithm: str) -> None:
    if algorithm not in SUPPORTED_KEMS:
        raise UnsupportedKEM(
            f"{algorithm!r} is not part of this study; expected one of {SUPPORTED_KEMS}"
        )
    if not oqs.is_kem_enabled(algorithm):
        raise UnsupportedKEM(f"{algorithm!r} is not enabled in this liboqs build")


class KEM:
    """Stateless facade over one liboqs KEM mechanism.

    Each operation creates and frees its own liboqs object, so instances are
    safe to share between threads (the load generator does exactly that).
    """

    def __init__(self, algorithm: str = DEFAULT_KEM) -> None:
        assert_supported(algorithm)
        self.algorithm = algorithm
        with oqs.KeyEncapsulation(algorithm) as kem:
            details = kem.details
        self.public_key_bytes: int = details["length_public_key"]
        self.secret_key_bytes: int = details["length_secret_key"]
        self.ciphertext_bytes: int = details["length_ciphertext"]
        self.shared_secret_bytes: int = details["length_shared_secret"]
        self.claimed_nist_level: int = details["claimed_nist_level"]

    def generate_keypair(self) -> KeyPair:
        with oqs.KeyEncapsulation(self.algorithm) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
        return KeyPair(self.algorithm, bytes(public_key), bytes(secret_key))

    def encapsulate(self, peer_public_key: bytes) -> Encapsulation:
        if len(peer_public_key) != self.public_key_bytes:
            raise KEMError(
                f"{self.algorithm} public key must be {self.public_key_bytes} bytes, "
                f"got {len(peer_public_key)}"
            )
        with oqs.KeyEncapsulation(self.algorithm) as kem:
            ciphertext, shared_secret = kem.encap_secret(peer_public_key)
        return Encapsulation(bytes(ciphertext), bytes(shared_secret))

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        if len(ciphertext) != self.ciphertext_bytes:
            raise KEMError(
                f"{self.algorithm} ciphertext must be {self.ciphertext_bytes} bytes, "
                f"got {len(ciphertext)}"
            )
        with oqs.KeyEncapsulation(self.algorithm, secret_key=secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
        return bytes(shared_secret)

    def __repr__(self) -> str:
        return f"KEM({self.algorithm!r})"


class LongTermKEM:
    """A persistent identity keypair, plus the peer public keys we trust.

    Authentication is *implicit*: we never verify a signature. We encapsulate
    to the peer's long-term public key and mix the resulting shared secret
    into the KDF, so only the genuine peer can derive the same session key.
    """

    def __init__(self, algorithm: str = DEFAULT_KEM, keypair: KeyPair | None = None) -> None:
        self.kem = KEM(algorithm)
        if keypair is not None and keypair.algorithm != algorithm:
            raise UnsupportedKEM(
                f"keypair is for {keypair.algorithm!r}, not {algorithm!r}"
            )
        self.keypair = keypair or self.kem.generate_keypair()

    @property
    def algorithm(self) -> str:
        return self.kem.algorithm

    @property
    def public_key(self) -> bytes:
        return self.keypair.public_key

    def encapsulate_to(self, peer_public_key: bytes) -> Encapsulation:
        """Authenticate the *peer* by encapsulating to their identity key."""
        return self.kem.encapsulate(peer_public_key)

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Prove we are who we claim, by recovering the peer's encapsulation."""
        return self.kem.decapsulate(self.keypair.secret_key, ciphertext)


class EphemeralKEM:
    """A per-handshake keypair. Generate, use once, drop.

    `forget()` clears the local reference to the secret key. Python gives no
    guarantee the bytes leave memory, so this documents intent rather than
    enforcing erasure -- noted as a limitation in the README.
    """

    def __init__(self, algorithm: str = DEFAULT_KEM) -> None:
        self.kem = KEM(algorithm)
        self._keypair: KeyPair | None = None

    @property
    def algorithm(self) -> str:
        return self.kem.algorithm

    def generate(self) -> bytes:
        """Create the fresh keypair and return the public key to put on the wire."""
        self._keypair = self.kem.generate_keypair()
        return self._keypair.public_key

    @property
    def public_key(self) -> bytes:
        if self._keypair is None:
            raise KEMError("ephemeral keypair has not been generated yet")
        return self._keypair.public_key

    def encapsulate_to(self, peer_public_key: bytes) -> Encapsulation:
        return self.kem.encapsulate(peer_public_key)

    def decapsulate(self, ciphertext: bytes) -> bytes:
        if self._keypair is None:
            raise KEMError("ephemeral keypair has not been generated yet")
        return self.kem.decapsulate(self._keypair.secret_key, ciphertext)

    def forget(self) -> None:
        self._keypair = None


def kem_sizes(algorithms: Iterable[str] | None = None) -> dict[str, dict[str, int]]:
    """Wire sizes per algorithm, for the benchmark's bytes-on-wire reporting."""
    names = tuple(algorithms) if algorithms is not None else available_kems()
    sizes = {}
    for name in names:
        kem = KEM(name)
        sizes[name] = {
            "public_key": kem.public_key_bytes,
            "ciphertext": kem.ciphertext_bytes,
            "shared_secret": kem.shared_secret_bytes,
            "nist_level": kem.claimed_nist_level,
        }
    return sizes
