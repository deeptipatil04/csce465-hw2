import struct

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature


VERSION = 1

# Direction values used in the authenticated header.
GATEWAY_TO_NODE = 1
NODE_TO_GATEWAY = 2


def _aes_ctr(key, iv, data):
    """Encrypt/decrypt data with AES-256-CTR."""
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _make_header(direction, sequence, message_type, ciphertext_length):
    """Create the authenticated record header."""
    if direction not in (GATEWAY_TO_NODE, NODE_TO_GATEWAY):
        raise ValueError("invalid direction")

    if not 0 <= sequence < (1 << 64):
        raise ValueError("invalid sequence number")

    if not 0 <= message_type <= 255:
        raise ValueError("invalid message type")

    return struct.pack(
        ">BBQBI",
        VERSION,
        direction,
        sequence,
        message_type,
        ciphertext_length,
    )


def seal(k_enc, k_mac, session_id, direction, sequence, message_type, plaintext):
    """
    Protect one record using AES-256-CTR followed by HMAC-SHA-256.
    """

    if len(session_id) != 8:
        raise ValueError("session_id must be exactly 8 bytes")

    if len(k_enc) != 32 or len(k_mac) != 32:
        raise ValueError("encryption and MAC keys must be 32 bytes")

    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")

    # Assignment-required IV:
    # session_id (8 bytes) || sequence number (8 bytes)
    iv = session_id + sequence.to_bytes(8, "big")

    ciphertext = _aes_ctr(k_enc, iv, plaintext)

    header = _make_header(
        direction,
        sequence,
        message_type,
        len(ciphertext),
    )

    # Encrypt-then-MAC:
    # authenticate header, IV, and ciphertext.
    mac = hmac.HMAC(k_mac, hashes.SHA256())
    mac.update(header + iv + ciphertext)
    tag = mac.finalize()

    return header + iv + ciphertext + tag


def open_record(
    k_enc,
    k_mac,
    session_id,
    expected_direction,
    expected_sequence,
    record,
):
    """
    Authenticate and decrypt one record.

    HMAC is verified before plaintext is released.
    The exact expected sequence number and direction are required.
    """

    if len(session_id) != 8:
        raise ValueError("session_id must be exactly 8 bytes")

    if len(k_enc) != 32 or len(k_mac) != 32:
        raise ValueError("encryption and MAC keys must be 32 bytes")

    # Header is 15 bytes:
    # version(1) + direction(1) + sequence(8)
    # + message_type(1) + ciphertext_length(4)
    HEADER_LEN = 15
    IV_LEN = 16
    TAG_LEN = 32

    if len(record) < HEADER_LEN + IV_LEN + TAG_LEN:
        raise ValueError("record is too short")

    header = record[:HEADER_LEN]

    version, direction, sequence, message_type, ciphertext_length = (
        struct.unpack(">BBQBI", header)
    )

    if version != VERSION:
        raise ValueError("unsupported version")

    if direction != expected_direction:
        raise ValueError("wrong direction")

    if sequence != expected_sequence:
        raise ValueError("unexpected or replayed sequence number")

    expected_total = HEADER_LEN + IV_LEN + ciphertext_length + TAG_LEN

    if len(record) != expected_total:
        raise ValueError("invalid ciphertext length")

    iv_start = HEADER_LEN
    ciphertext_start = iv_start + IV_LEN
    tag_start = ciphertext_start + ciphertext_length

    iv = record[iv_start:ciphertext_start]
    ciphertext = record[ciphertext_start:tag_start]
    tag = record[tag_start:]

    expected_iv = session_id + sequence.to_bytes(8, "big")

    if iv != expected_iv:
        raise ValueError("invalid IV")

    # IMPORTANT: verify authentication before decrypting.
    mac = hmac.HMAC(k_mac, hashes.SHA256())
    mac.update(header + iv + ciphertext)

    try:
        mac.verify(tag)
    except InvalidSignature:
        raise ValueError("authentication failed")

    plaintext = _aes_ctr(k_enc, iv, ciphertext)

    return message_type, plaintext


if __name__ == "__main__":
    # Small local demonstration.
    k_enc = bytes.fromhex("11" * 32)
    k_mac = bytes.fromhex("22" * 32)
    session_id = bytes.fromhex("0102030405060708")

    plaintext = b'{"action":"READ","path":"notes.txt"}'

    print("Creating gateway-to-node protected record...")

    record = seal(
        k_enc,
        k_mac,
        session_id,
        GATEWAY_TO_NODE,
        0,
        1,
        plaintext,
    )

    print("Sequence number: 0")
    print("Record length:", len(record))
    print("Protected record (hex):")
    print(record.hex())

    message_type, recovered = open_record(
        k_enc,
        k_mac,
        session_id,
        GATEWAY_TO_NODE,
        0,
        record,
    )

    print()
    print("Record authenticated successfully.")
    print("Message type:", message_type)
    print("Recovered plaintext:", recovered.decode())

    print()
    print("Attempting replay with expected sequence number 1...")

    try:
        open_record(
            k_enc,
            k_mac,
            session_id,
            GATEWAY_TO_NODE,
            1,
            record,
        )
    except ValueError as error:
        print("Replay rejected:", error)
