import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# The fixed command required by the assignment.
ORIGINAL_MESSAGE = b'{"action":"READ","path":"notes.txt"}'


def aes_ctr_encrypt(key, iv, plaintext):
    """Encrypt plaintext using AES in CTR mode."""
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def aes_ctr_decrypt(key, iv, ciphertext):
    """Decrypt ciphertext using AES in CTR mode."""
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def relay_change_read(ciphertext):
    """
    Modify READ to WRITE without knowing the AES key.

    CTR mode is malleable because changing ciphertext bytes with XOR
    causes predictable changes to the corresponding plaintext bytes.
    """
    original = b"READ"
    replacement = b"EDIT"

    # Find where READ occurs in the known message.
    offset = ORIGINAL_MESSAGE.index(original)

    modified = bytearray(ciphertext)

    print("\nXOR relation used by relay:")
    print("Original bytes:   ", original)
    print("Replacement bytes:", replacement)

    # C' = C XOR P XOR P'
    for i in range(len(original)):
        delta = original[i] ^ replacement[i]
        modified[offset + i] ^= delta

        print(
            f"byte {i}: "
            f"0x{original[i]:02x} XOR "
            f"0x{replacement[i]:02x} = "
            f"0x{delta:02x}"
        )

    return bytes(modified)


def receiver(key, iv, ciphertext):
    """Decrypt and process a received command."""
    plaintext = aes_ctr_decrypt(key, iv, ciphertext)
    print("Receiver processed:", plaintext.decode())
    return plaintext


def main():
    # AES-256 uses a 32-byte key.
    key = os.urandom(32)

    # AES has a 16-byte block size, so CTR uses a 16-byte IV here.
    iv = os.urandom(16)

    print("Original plaintext:")
    print(ORIGINAL_MESSAGE.decode())

    ciphertext = aes_ctr_encrypt(key, iv, ORIGINAL_MESSAGE)

    print("\nOriginal ciphertext (hex):")
    print(ciphertext.hex())

    # ---------------------------------------------------------
    # Attack 1: Modify ciphertext without knowing the AES key.
    # ---------------------------------------------------------
    modified_ciphertext = relay_change_read(ciphertext)

    print("\nModified ciphertext (hex):")
    print(modified_ciphertext.hex())

    print("\nReceiver decrypts modified ciphertext:")
    receiver(key, iv, modified_ciphertext)

    # ---------------------------------------------------------
    # Attack 2: Replay exactly the same ciphertext.
    # ---------------------------------------------------------
    print("\nReplay demonstration:")
    print("First delivery:")
    receiver(key, iv, ciphertext)

    print("Second delivery of SAME ciphertext:")
    receiver(key, iv, ciphertext)

    print("\nResult:")
    print("The receiver processed the same encrypted command twice.")
    print("AES-CTR encryption alone provides no integrity or replay protection.")


if __name__ == "__main__":
    main()
