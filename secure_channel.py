import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def load_parameters(filename="ffdhe3072.pem"):
    """Load the standard FFDHE3072 parameters created in Task 0."""
    with open(filename, "rb") as f:
        return serialization.load_pem_parameters(f.read())


def derive_key(shared_secret):
    """
    Derive a 256-bit AES key from the Diffie-Hellman shared secret
    using HKDF-SHA256.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,                     # 32 bytes = 256 bits
        salt=None,
        info=b"csce465-hw2-channel",
    ).derive(shared_secret)


def establish_keys(parameters):
    """
    Simulate two parties performing ephemeral FFDHE3072
    and independently deriving the same session key.
    """
    alice_private = parameters.generate_private_key()
    bob_private = parameters.generate_private_key()

    alice_public = alice_private.public_key()
    bob_public = bob_private.public_key()

    alice_shared = alice_private.exchange(bob_public)
    bob_shared = bob_private.exchange(alice_public)

    alice_key = derive_key(alice_shared)
    bob_key = derive_key(bob_shared)

    return alice_key, bob_key


class Sender:
    def __init__(self, key):
        self.aesgcm = AESGCM(key)
        self.sequence = 0

    def send(self, plaintext):
        """
        Encrypt a message with AES-256-GCM.

        A fresh 96-bit nonce is generated for every message.
        The sequence number is authenticated as AAD.
        """
        self.sequence += 1

        seq = self.sequence
        aad = seq.to_bytes(8, byteorder="big")

        # 12 bytes = 96 bits, the standard GCM nonce size.
        nonce = os.urandom(12)

        ciphertext = self.aesgcm.encrypt(
            nonce,
            plaintext,
            aad
        )

        return seq, nonce, ciphertext


class Receiver:
    def __init__(self, key):
        self.aesgcm = AESGCM(key)
        self.highest_sequence = 0

    def receive(self, packet):
        """
        Reject old/replayed sequence numbers, then authenticate
        and decrypt the message.
        """
        seq, nonce, ciphertext = packet

        if seq <= self.highest_sequence:
            raise ValueError(
                f"Replay rejected: sequence {seq} has already been processed"
            )

        aad = seq.to_bytes(8, byteorder="big")

        # AESGCM.decrypt verifies the authentication tag.
        plaintext = self.aesgcm.decrypt(
            nonce,
            ciphertext,
            aad
        )

        # Only update after successful authentication.
        self.highest_sequence = seq

        return plaintext


def main():
    print("Loading FFDHE3072 parameters...")
    parameters = load_parameters()

    print("Performing ephemeral FFDHE3072 key exchange...")
    sender_key, receiver_key = establish_keys(parameters)

    print("Sender and receiver derived same key:",
          sender_key == receiver_key)

    sender = Sender(sender_key)
    receiver = Receiver(receiver_key)

    message = b'{"action":"READ","path":"notes.txt"}'

    print("\nSending legitimate message...")
    packet = sender.send(message)

    print("Sequence number:", packet[0])
    print("Nonce:", packet[1].hex())

    plaintext = receiver.receive(packet)
    print("Receiver accepted:", plaintext.decode())

    print("\nAttempting to replay the SAME packet...")

    try:
        receiver.receive(packet)
        print("ERROR: replay was accepted")
    except ValueError as error:
        print(error)
        print("Replay successfully rejected.")


if __name__ == "__main__":
    main()
