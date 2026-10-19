"""Wire formats for M1..M4.

Compact big-endian binary (DECISIONS.md D2), so the benchmark's
bytes-on-wire numbers reflect real KEM cost rather than base64 inflation.

    every message:  magic b"QH1" | msg_type u8 | session_id 16B | <fields>
    variable field: u32 length prefix || bytes

The MAC, where present, is **always the final 32 bytes**, so "the message
minus its MAC field" is exactly ``encoded[:-MAC_LENGTH]``. That is what makes
the transcript definition unambiguous.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import ClassVar

from crypto.mac import MAC_LENGTH

MAGIC = b"QH1"
SESSION_ID_BYTES = 16
NONCE_BYTES = 32

#: M2 flag bits
FLAG_QKD_ACK = 0x01
#: M4 flag bits
FLAG_DOWNGRADED = 0x01
FLAG_HYBRID = 0x02


class MessageFormatError(ValueError):
    """A message could not be decoded, or is not the expected type."""


def _pack_bytes(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _pack_str(value: str) -> bytes:
    return _pack_bytes(value.encode("utf-8"))


class _Reader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0

    def take(self, count: int) -> bytes:
        if self._offset + count > len(self._data):
            raise MessageFormatError(
                f"truncated message: wanted {count} bytes at offset {self._offset}, "
                f"have {len(self._data) - self._offset}"
            )
        chunk = self._data[self._offset : self._offset + count]
        self._offset += count
        return chunk

    def take_u8(self) -> int:
        return self.take(1)[0]

    def take_bytes(self) -> bytes:
        (length,) = struct.unpack(">I", self.take(4))
        return self.take(length)

    def take_str(self) -> str:
        return self.take_bytes().decode("utf-8")

    def finish(self) -> None:
        if self._offset != len(self._data):
            raise MessageFormatError(
                f"trailing garbage: {len(self._data) - self._offset} unparsed bytes"
            )


def _header(msg_type: int, session_id: bytes) -> bytes:
    if len(session_id) != SESSION_ID_BYTES:
        raise MessageFormatError(f"session_id must be {SESSION_ID_BYTES} bytes")
    return MAGIC + bytes([msg_type]) + session_id


def _read_header(reader: _Reader, expected_type: int) -> bytes:
    if reader.take(len(MAGIC)) != MAGIC:
        raise MessageFormatError("bad magic; not a qkd-hake message")
    msg_type = reader.take_u8()
    if msg_type != expected_type:
        raise MessageFormatError(f"expected message type {expected_type}, got {msg_type}")
    return reader.take(SESSION_ID_BYTES)


@dataclass(frozen=True)
class Message1:
    """I -> R: session parameters, initiator nonce, ephemeral key, QKD key id.

    ``qkd_key_id`` is the empty string when the initiator has no QKD key --
    either because it is running the pure-PQC baseline, or because the pool
    was empty. Only the *id* travels; the responder fetches the key material
    itself over ETSI ``dec_keys``.
    """

    MSG_TYPE: ClassVar[int] = 1

    session_id: bytes
    nonce_i: bytes
    suite: str
    epk_i: bytes
    qkd_key_id: str = ""

    def encode(self) -> bytes:
        if len(self.nonce_i) != NONCE_BYTES:
            raise MessageFormatError(f"nonce_i must be {NONCE_BYTES} bytes")
        return (
            _header(self.MSG_TYPE, self.session_id)
            + self.nonce_i
            + _pack_str(self.suite)
            + _pack_bytes(self.epk_i)
            + _pack_str(self.qkd_key_id)
        )

    @classmethod
    def decode(cls, data: bytes) -> "Message1":
        reader = _Reader(data)
        session_id = _read_header(reader, cls.MSG_TYPE)
        message = cls(
            session_id=session_id,
            nonce_i=reader.take(NONCE_BYTES),
            suite=reader.take_str(),
            epk_i=reader.take_bytes(),
            qkd_key_id=reader.take_str(),
        )
        reader.finish()
        return message


@dataclass(frozen=True)
class Message2:
    """R -> I: responder nonce, ephemeral encapsulation, encapsulation to pk_I.

    ``flags`` carries `FLAG_QKD_ACK`: set when the responder successfully
    fetched the QKD key the initiator named. Cleared means "I could not use
    QKD", and the initiator must drop its own QKD key to stay in agreement
    (DECISIONS.md D4).
    """

    MSG_TYPE: ClassVar[int] = 2

    session_id: bytes
    nonce_r: bytes
    ct_eph: bytes
    ct_lt_i: bytes
    flags: int = 0

    @property
    def qkd_ack(self) -> bool:
        return bool(self.flags & FLAG_QKD_ACK)

    def encode(self) -> bytes:
        if len(self.nonce_r) != NONCE_BYTES:
            raise MessageFormatError(f"nonce_r must be {NONCE_BYTES} bytes")
        return (
            _header(self.MSG_TYPE, self.session_id)
            + self.nonce_r
            + _pack_bytes(self.ct_eph)
            + _pack_bytes(self.ct_lt_i)
            + bytes([self.flags & 0xFF])
        )

    @classmethod
    def decode(cls, data: bytes) -> "Message2":
        reader = _Reader(data)
        session_id = _read_header(reader, cls.MSG_TYPE)
        message = cls(
            session_id=session_id,
            nonce_r=reader.take(NONCE_BYTES),
            ct_eph=reader.take_bytes(),
            ct_lt_i=reader.take_bytes(),
            flags=reader.take_u8(),
        )
        reader.finish()
        return message


@dataclass(frozen=True)
class Message3:
    """I -> R: encapsulation to pk_R, plus the initiator's transcript MAC."""

    MSG_TYPE: ClassVar[int] = 3

    session_id: bytes
    ct_lt_r: bytes
    mac: bytes = b""

    def body(self) -> bytes:
        """The message without its MAC field -- the transcript contribution."""
        return _header(self.MSG_TYPE, self.session_id) + _pack_bytes(self.ct_lt_r)

    def encode(self) -> bytes:
        if len(self.mac) != MAC_LENGTH:
            raise MessageFormatError(f"mac must be {MAC_LENGTH} bytes")
        return self.body() + self.mac

    @classmethod
    def decode(cls, data: bytes) -> "Message3":
        if len(data) < MAC_LENGTH:
            raise MessageFormatError("message 3 is shorter than its MAC field")
        reader = _Reader(data[:-MAC_LENGTH])
        session_id = _read_header(reader, cls.MSG_TYPE)
        message = cls(
            session_id=session_id,
            ct_lt_r=reader.take_bytes(),
            mac=data[-MAC_LENGTH:],
        )
        reader.finish()
        return message


@dataclass(frozen=True)
class Message4:
    """R -> I: negotiated security mode flags, plus the responder's MAC.

    The flags are the on-wire downgrade signal. They are always present; what
    differs between modes is whether the *application* is shown them
    (DECISIONS.md D5).
    """

    MSG_TYPE: ClassVar[int] = 4

    session_id: bytes
    flags: int = 0
    mac: bytes = b""

    @property
    def downgraded(self) -> bool:
        return bool(self.flags & FLAG_DOWNGRADED)

    @property
    def hybrid(self) -> bool:
        return bool(self.flags & FLAG_HYBRID)

    def body(self) -> bytes:
        return _header(self.MSG_TYPE, self.session_id) + bytes([self.flags & 0xFF])

    def encode(self) -> bytes:
        if len(self.mac) != MAC_LENGTH:
            raise MessageFormatError(f"mac must be {MAC_LENGTH} bytes")
        return self.body() + self.mac

    @classmethod
    def decode(cls, data: bytes) -> "Message4":
        if len(data) < MAC_LENGTH:
            raise MessageFormatError("message 4 is shorter than its MAC field")
        reader = _Reader(data[:-MAC_LENGTH])
        session_id = _read_header(reader, cls.MSG_TYPE)
        message = cls(
            session_id=session_id,
            flags=reader.take_u8(),
            mac=data[-MAC_LENGTH:],
        )
        reader.finish()
        return message


def build_transcript(m1: bytes, m2: bytes, m3_body: bytes, m4_body: bytes = b"") -> bytes:
    """Concatenate transcript contributions (each message minus its MAC)."""
    return m1 + m2 + m3_body + m4_body
