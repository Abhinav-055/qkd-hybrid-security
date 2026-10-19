"""Protocol: wire format roundtrips and decode strictness."""
from __future__ import annotations

import pytest

from crypto.mac import MAC_LENGTH
from protocol import messages as m


SESSION_ID = bytes(range(16))
NONCE = bytes(range(32))


def test_message1_roundtrip():
    original = m.Message1(
        session_id=SESSION_ID,
        nonce_i=NONCE,
        suite="qkd-hake-v1/ML-KEM-768/ML-KEM-768",
        epk_i=b"\xab" * 1184,
        qkd_key_id="2289bc38-29af-4e94-bff7-7f323c64c3ca",
    )
    assert m.Message1.decode(original.encode()) == original


def test_message1_roundtrip_without_a_qkd_key_id():
    original = m.Message1(
        session_id=SESSION_ID, nonce_i=NONCE, suite="s", epk_i=b"pk", qkd_key_id=""
    )
    decoded = m.Message1.decode(original.encode())
    assert decoded.qkd_key_id == ""


def test_message2_roundtrip_and_flag_accessor():
    original = m.Message2(
        session_id=SESSION_ID,
        nonce_r=NONCE,
        ct_eph=b"\x01" * 1088,
        ct_lt_i=b"\x02" * 1088,
        flags=m.FLAG_QKD_ACK,
    )
    decoded = m.Message2.decode(original.encode())
    assert decoded == original
    assert decoded.qkd_ack is True
    assert m.Message2.decode(
        m.Message2(session_id=SESSION_ID, nonce_r=NONCE, ct_eph=b"", ct_lt_i=b"", flags=0).encode()
    ).qkd_ack is False


def test_message3_roundtrip_and_body_excludes_the_mac():
    original = m.Message3(session_id=SESSION_ID, ct_lt_r=b"\x03" * 1088, mac=b"\x04" * MAC_LENGTH)
    encoded = original.encode()
    assert m.Message3.decode(encoded) == original
    assert original.body() == encoded[:-MAC_LENGTH]


def test_message4_roundtrip_and_flag_accessors():
    original = m.Message4(
        session_id=SESSION_ID,
        flags=m.FLAG_DOWNGRADED | m.FLAG_HYBRID,
        mac=b"\x05" * MAC_LENGTH,
    )
    decoded = m.Message4.decode(original.encode())
    assert decoded == original
    assert (decoded.downgraded, decoded.hybrid) == (True, True)
    assert original.body() == original.encode()[:-MAC_LENGTH]


def test_mac_is_the_final_32_bytes():
    """DECISIONS.md D2: this is what makes the transcript unambiguous."""
    mac = b"\x06" * MAC_LENGTH
    for message in (
        m.Message3(session_id=SESSION_ID, ct_lt_r=b"ct", mac=mac),
        m.Message4(session_id=SESSION_ID, flags=1, mac=mac),
    ):
        assert message.encode()[-MAC_LENGTH:] == mac


def test_wrong_message_type_is_rejected():
    encoded = m.Message1(session_id=SESSION_ID, nonce_i=NONCE, suite="s", epk_i=b"p").encode()
    with pytest.raises(m.MessageFormatError, match="expected message type 2"):
        m.Message2.decode(encoded)


def test_bad_magic_is_rejected():
    encoded = bytearray(
        m.Message1(session_id=SESSION_ID, nonce_i=NONCE, suite="s", epk_i=b"p").encode()
    )
    encoded[0:3] = b"XXX"
    with pytest.raises(m.MessageFormatError, match="bad magic"):
        m.Message1.decode(bytes(encoded))


def test_truncated_message_is_rejected():
    encoded = m.Message1(session_id=SESSION_ID, nonce_i=NONCE, suite="s", epk_i=b"p" * 100).encode()
    with pytest.raises(m.MessageFormatError, match="truncated"):
        m.Message1.decode(encoded[:-10])


def test_trailing_garbage_is_rejected():
    encoded = m.Message1(session_id=SESSION_ID, nonce_i=NONCE, suite="s", epk_i=b"p").encode()
    with pytest.raises(m.MessageFormatError, match="trailing garbage"):
        m.Message1.decode(encoded + b"\x00")


def test_short_mac_carrying_messages_are_rejected():
    with pytest.raises(m.MessageFormatError, match="shorter than its MAC"):
        m.Message3.decode(b"\x00" * 10)
    with pytest.raises(m.MessageFormatError, match="shorter than its MAC"):
        m.Message4.decode(b"\x00" * 10)


@pytest.mark.parametrize("length", [0, 15, 17])
def test_wrong_session_id_length_is_rejected(length):
    with pytest.raises(m.MessageFormatError, match="session_id"):
        m.Message1(session_id=b"\x00" * length, nonce_i=NONCE, suite="s", epk_i=b"p").encode()


def test_wrong_nonce_length_is_rejected():
    with pytest.raises(m.MessageFormatError, match="nonce_i"):
        m.Message1(session_id=SESSION_ID, nonce_i=b"\x00" * 31, suite="s", epk_i=b"p").encode()
    with pytest.raises(m.MessageFormatError, match="nonce_r"):
        m.Message2(session_id=SESSION_ID, nonce_r=b"", ct_eph=b"", ct_lt_i=b"").encode()


def test_missing_mac_is_rejected_at_encode_time():
    with pytest.raises(m.MessageFormatError, match="mac must be"):
        m.Message3(session_id=SESSION_ID, ct_lt_r=b"ct").encode()
    with pytest.raises(m.MessageFormatError, match="mac must be"):
        m.Message4(session_id=SESSION_ID, flags=0).encode()


def test_build_transcript_concatenates_in_order():
    assert m.build_transcript(b"1", b"2", b"3", b"4") == b"1234"
    assert m.build_transcript(b"1", b"2", b"3") == b"123"
