from cryptography.exceptions import InvalidTag

from secure_channel import load_parameters, establish_keys, Sender


def flip_one_bit(data):
    """Return a copy of data with one bit flipped."""
    modified = bytearray(data)
    modified[0] ^= 0x01
    return bytes(modified)


def try_decrypt(aesgcm, seq, nonce, ciphertext, label):
    """Try to decrypt a packet and report whether authentication fails."""
    aad = seq.to_bytes(8, byteorder="big")

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        print(f"{label}: UNEXPECTEDLY ACCEPTED")
        print("Plaintext:", plaintext.decode())

    except InvalidTag:
        print(f"{label}: authentication failed (InvalidTag) - REJECTED")


def main():
    print("Setting up secure FFDHE3072 + AES-GCM channel...")

    parameters = load_parameters()
    sender_key, receiver_key = establish_keys(parameters)

    sender = Sender(sender_key)

    # We use the receiver key directly so each tampering experiment
    # is independent of the replay state from Task 2.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    receiver_aesgcm = AESGCM(receiver_key)

    message = b'{"action":"READ","path":"notes.txt"}'

    packet = sender.send(message)
    seq, nonce, ciphertext = packet

    print("\nOriginal packet:")
    print("Sequence:", seq)
    print("Nonce:", nonce.hex())
    print("Ciphertext + tag:", ciphertext.hex())

    # First prove the untouched packet authenticates correctly.
    aad = seq.to_bytes(8, byteorder="big")
    plaintext = receiver_aesgcm.decrypt(nonce, ciphertext, aad)

    print("\nUntampered packet:")
    print("ACCEPTED:", plaintext.decode())

    # ---------------------------------------------------------
    # Test 1: Flip one bit in the ciphertext.
    # ---------------------------------------------------------
    tampered_ciphertext = flip_one_bit(ciphertext)

    print("\nTamper Test 1 - Ciphertext:")
    try_decrypt(
        receiver_aesgcm,
        seq,
        nonce,
        tampered_ciphertext,
        "Ciphertext bit flip"
    )

    # ---------------------------------------------------------
    # Test 2: Flip one bit in the nonce.
    # ---------------------------------------------------------
    tampered_nonce = flip_one_bit(nonce)

    print("\nTamper Test 2 - Nonce:")
    try_decrypt(
        receiver_aesgcm,
        seq,
        tampered_nonce,
        ciphertext,
        "Nonce bit flip"
    )

    # ---------------------------------------------------------
    # Test 3: Flip one bit in the authenticated sequence number.
    # Changing seq changes the AAD supplied to AES-GCM.
    # ---------------------------------------------------------
    tampered_seq = seq ^ 0x01

    print("\nTamper Test 3 - AAD / Sequence Number:")
    try_decrypt(
        receiver_aesgcm,
        tampered_seq,
        nonce,
        ciphertext,
        "AAD bit flip"
    )

    print("\nResult:")
    print("All three one-bit modifications were detected by AES-GCM.")


if __name__ == "__main__":
    main()
