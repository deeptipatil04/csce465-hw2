import hashlib
import os

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa

from handshake import build_transcript, sign_transcript, verify_signature
from secure_record import seal, open_record


def make_transcript():
    gateway_public = os.urandom(384)
    node_public = os.urandom(384)
    gateway_nonce = os.urandom(16)
    node_nonce = os.urandom(16)

    transcript = build_transcript(
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    )

    return transcript


def test_modified_transcript_rejected():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    transcript = make_transcript()
    transcript_hash = hashlib.sha256(transcript).digest()

    signature = sign_transcript(
        private_key,
        b"gateway",
        transcript_hash,
    )

    modified = bytearray(transcript)
    modified[-1] ^= 1
    modified_hash = hashlib.sha256(bytes(modified)).digest()

    with pytest.raises(InvalidSignature):
        verify_signature(
            public_key,
            signature,
            b"gateway",
            modified_hash,
        )


def test_wrong_signing_key_rejected():
    correct_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    wrong_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    transcript = make_transcript()
    transcript_hash = hashlib.sha256(transcript).digest()

    signature = sign_transcript(
        correct_private,
        b"gateway",
        transcript_hash,
    )

    with pytest.raises(InvalidSignature):
        verify_signature(
            wrong_private.public_key(),
            signature,
            b"gateway",
            transcript_hash,
        )


def test_reflected_role_rejected():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    transcript = make_transcript()
    transcript_hash = hashlib.sha256(transcript).digest()

    signature = sign_transcript(
        private_key,
        b"gateway",
        transcript_hash,
    )

    with pytest.raises(InvalidSignature):
        verify_signature(
            public_key,
            signature,
            b"node",
            transcript_hash,
        )


def test_ciphertext_tampering_rejected():
    k_enc = os.urandom(32)
    k_mac = os.urandom(32)
    session_id = os.urandom(8)

    record = seal(
        k_enc,
        k_mac,
        session_id,
        1,
        0,
        1,
        b"READ notes.txt",
    )

    tampered = bytearray(record)

    # Header is 15 bytes and IV is 16 bytes,
    # so byte 31 is the beginning of the ciphertext.
    tampered[31] ^= 1

    with pytest.raises(Exception):
        open_record(
            k_enc,
            k_mac,
            session_id,
            1,
            0,
            bytes(tampered),
        )


def test_replayed_sequence_rejected():
    k_enc = os.urandom(32)
    k_mac = os.urandom(32)
    session_id = os.urandom(8)

    record = seal(
        k_enc,
        k_mac,
        session_id,
        1,
        0,
        1,
        b"READ notes.txt",
    )

    # Receiver now expects sequence number 1.
    # Reusing the record with sequence number 0 must fail.
    with pytest.raises(ValueError):
        open_record(
            k_enc,
            k_mac,
            session_id,
            1,
            1,
            record,
        )
