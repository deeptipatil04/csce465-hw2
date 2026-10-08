import pytest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from secure_channel import (
    load_parameters,
    establish_keys,
    Sender,
    Receiver,
)


@pytest.fixture(scope="module")
def session_keys():
    """Create one pair of matching session keys for the tests."""
    parameters = load_parameters()
    return establish_keys(parameters)


def test_successful_encrypt_decrypt(session_keys):
    """A legitimate encrypted message should decrypt correctly."""
    sender_key, receiver_key = session_keys

    sender = Sender(sender_key)
    receiver = Receiver(receiver_key)

    message = b'{"action":"READ","path":"notes.txt"}'
    packet = sender.send(message)

    plaintext = receiver.receive(packet)

    assert plaintext == message


def test_tampered_ciphertext_rejected(session_keys):
    """A one-bit modification to the ciphertext must fail authentication."""
    sender_key, receiver_key = session_keys

    sender = Sender(sender_key)
    aesgcm = AESGCM(receiver_key)

    seq, nonce, ciphertext = sender.send(b"test message")

    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01

    aad = seq.to_bytes(8, byteorder="big")

    with pytest.raises(InvalidTag):
        aesgcm.decrypt(nonce, bytes(tampered), aad)


def test_tampered_nonce_rejected(session_keys):
    """A one-bit modification to the nonce must fail authentication."""
    sender_key, receiver_key = session_keys

    sender = Sender(sender_key)
    aesgcm = AESGCM(receiver_key)

    seq, nonce, ciphertext = sender.send(b"test message")

    tampered_nonce = bytearray(nonce)
    tampered_nonce[0] ^= 0x01

    aad = seq.to_bytes(8, byteorder="big")

    with pytest.raises(InvalidTag):
        aesgcm.decrypt(bytes(tampered_nonce), ciphertext, aad)


def test_tampered_aad_rejected(session_keys):
    """A changed authenticated sequence number must fail authentication."""
    sender_key, receiver_key = session_keys

    sender = Sender(sender_key)
    aesgcm = AESGCM(receiver_key)

    seq, nonce, ciphertext = sender.send(b"test message")

    tampered_seq = seq ^ 0x01
    tampered_aad = tampered_seq.to_bytes(8, byteorder="big")

    with pytest.raises(InvalidTag):
        aesgcm.decrypt(nonce, ciphertext, tampered_aad)


def test_replay_rejected(session_keys):
    """The receiver must reject a packet that was already processed."""
    sender_key, receiver_key = session_keys

    sender = Sender(sender_key)
    receiver = Receiver(receiver_key)

    packet = sender.send(b"test message")

    # First delivery succeeds.
    assert receiver.receive(packet) == b"test message"

    # Delivering the exact same packet again must fail.
    with pytest.raises(ValueError, match="Replay rejected"):
        receiver.receive(packet)
