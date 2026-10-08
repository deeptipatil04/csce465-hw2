import hashlib
import os

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from handshake import (
    build_transcript,
    sign_transcript,
    verify_signature,
)


def make_rsa_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )


def sample_transcript():
    gateway_public = os.urandom(384)
    node_public = os.urandom(384)
    gateway_nonce = os.urandom(16)
    node_nonce = os.urandom(16)

    return build_transcript(
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    )


def test_valid_signature():
    private_key = make_rsa_key()
    public_key = private_key.public_key()

    transcript = sample_transcript()
    th = hashlib.sha256(transcript).digest()

    signature = sign_transcript(
        private_key,
        b"gateway",
        th,
    )

    # A valid signature should verify without an exception.
    verify_signature(
        public_key,
        signature,
        b"gateway",
        th,
    )


def test_changed_transcript_rejected():
    private_key = make_rsa_key()
    public_key = private_key.public_key()

    transcript = sample_transcript()
    original_hash = hashlib.sha256(transcript).digest()

    signature = sign_transcript(
        private_key,
        b"gateway",
        original_hash,
    )

    # Simulate an attacker changing a nonce/transcript byte.
    changed = bytearray(transcript)
    changed[-1] ^= 0x01
    changed_hash = hashlib.sha256(bytes(changed)).digest()

    with pytest.raises(InvalidSignature):
        verify_signature(
            public_key,
            signature,
            b"gateway",
            changed_hash,
        )


def test_wrong_rsa_key_rejected():
    legitimate_key = make_rsa_key()
    attacker_key = make_rsa_key()

    transcript = sample_transcript()
    th = hashlib.sha256(transcript).digest()

    signature = sign_transcript(
        legitimate_key,
        b"gateway",
        th,
    )

    # The attacker's unrelated public key must not verify.
    with pytest.raises(InvalidSignature):
        verify_signature(
            attacker_key.public_key(),
            signature,
            b"gateway",
            th,
        )


def test_reflected_role_rejected():
    private_key = make_rsa_key()
    public_key = private_key.public_key()

    transcript = sample_transcript()
    th = hashlib.sha256(transcript).digest()

    gateway_signature = sign_transcript(
        private_key,
        b"gateway",
        th,
    )

    # A gateway signature cannot be reflected as a node signature
    # because the role is included in the signed value.
    with pytest.raises(InvalidSignature):
        verify_signature(
            public_key,
            gateway_signature,
            b"node",
            th,
        )
