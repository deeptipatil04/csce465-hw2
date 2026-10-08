import os
import pytest

from secure_record import seal, open_record


# Test values used for all tests
K_ENC = os.urandom(32)
K_MAC = os.urandom(32)
SESSION_ID = os.urandom(8)

DIRECTION = 1
SEQUENCE = 0
MESSAGE_TYPE = 1
PLAINTEXT = b'{"action":"READ","path":"notes.txt"}'


def make_record():
    return seal(
        K_ENC,
        K_MAC,
        SESSION_ID,
        DIRECTION,
        SEQUENCE,
        MESSAGE_TYPE,
        PLAINTEXT,
    )


def test_valid_record():
    record = make_record()

    result = open_record(
        K_ENC,
        K_MAC,
        SESSION_ID,
        DIRECTION,
        SEQUENCE,
        record,
    )

    # open_record may return the plaintext alone or
    # return metadata together with the plaintext.
    assert PLAINTEXT in result if isinstance(result, tuple) else result == PLAINTEXT


def test_replay_rejected():
    record = make_record()

    # Receiver expects sequence 1, but this record contains sequence 0.
    with pytest.raises(ValueError):
        open_record(
            K_ENC,
            K_MAC,
            SESSION_ID,
            DIRECTION,
            1,
            record,
        )


def test_wrong_direction_rejected():
    record = make_record()

    with pytest.raises(ValueError):
        open_record(
            K_ENC,
            K_MAC,
            SESSION_ID,
            2,
            SEQUENCE,
            record,
        )


def test_tampered_ciphertext_rejected():
    record = bytearray(make_record())

    # Header = 15 bytes and IV = 16 bytes,
    # so this modifies the encrypted payload.
    record[31] ^= 0x01

    with pytest.raises(Exception):
        open_record(
            K_ENC,
            K_MAC,
            SESSION_ID,
            DIRECTION,
            SEQUENCE,
            bytes(record),
        )


def test_tampered_tag_rejected():
    record = bytearray(make_record())

    # Modify one bit of the authentication tag.
    record[-1] ^= 0x01

    with pytest.raises(Exception):
        open_record(
            K_ENC,
            K_MAC,
            SESSION_ID,
            DIRECTION,
            SEQUENCE,
            bytes(record),
        )
