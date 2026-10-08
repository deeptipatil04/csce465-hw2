import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa


PROTOCOL_LABEL = b"CSCE465-HS-v2"
GROUP_ID = b"ffdhe3072"
GATEWAY_ID = b"gateway"
NODE_ID = b"node"

DH_WIDTH = 384


def encode_field(data: bytes) -> bytes:
    """Encode a field as 4-byte big-endian length || data."""
    return len(data).to_bytes(4, "big") + data


def dh_public_to_bytes(public_key) -> bytes:
    """Encode an FFDHE3072 public value as exactly 384 bytes."""
    y = public_key.public_numbers().y
    return y.to_bytes(DH_WIDTH, "big")


def build_transcript(
    gateway_public: bytes,
    node_public: bytes,
    gateway_nonce: bytes,
    node_nonce: bytes,
) -> bytes:
    """
    Build the canonical length-prefixed transcript required by HW2.
    """

    fields = [
        PROTOCOL_LABEL,
        GROUP_ID,
        GATEWAY_ID,
        NODE_ID,
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    ]

    return b"".join(encode_field(field) for field in fields)


def sign_transcript(private_key, role: bytes, transcript_hash: bytes) -> bytes:
    """Sign role || SHA-256(transcript) using RSA-PSS/SHA-256."""

    return private_key.sign(
        role + transcript_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(
    public_key,
    signature: bytes,
    role: bytes,
    transcript_hash: bytes,
):
    """Verify an RSA-PSS transcript signature."""

    public_key.verify(
        signature,
        role + transcript_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def derive_key(master: bytes, label: bytes, transcript_hash: bytes) -> bytes:
    """Assignment-specific HMAC-SHA-256 key derivation."""
    return hmac.new(
        master,
        label + transcript_hash,
        hashlib.sha256,
    ).digest()


def main():
    print("Loading FFDHE3072 parameters...")

    with open("ffdhe3072.pem", "rb") as f:
        parameters = serialization.load_pem_parameters(f.read())

    print("Generating long-term 3072-bit RSA signing keys...")

    gateway_rsa_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )

    node_rsa_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )

    gateway_rsa_public = gateway_rsa_private.public_key()
    node_rsa_public = node_rsa_private.public_key()

    print("Generating fresh ephemeral FFDHE3072 keys...")

    gateway_dh_private = parameters.generate_private_key()
    node_dh_private = parameters.generate_private_key()

    gateway_dh_public = gateway_dh_private.public_key()
    node_dh_public = node_dh_private.public_key()

    gateway_public_bytes = dh_public_to_bytes(gateway_dh_public)
    node_public_bytes = dh_public_to_bytes(node_dh_public)

    gateway_nonce = os.urandom(16)
    node_nonce = os.urandom(16)

    transcript = build_transcript(
        gateway_public_bytes,
        node_public_bytes,
        gateway_nonce,
        node_nonce,
    )

    transcript_hash = hashlib.sha256(transcript).digest()

    print("Signing canonical transcript...")

    gateway_signature = sign_transcript(
        gateway_rsa_private,
        b"gateway",
        transcript_hash,
    )

    node_signature = sign_transcript(
        node_rsa_private,
        b"node",
        transcript_hash,
    )

    # Each side verifies the other side's identity/signature.
    verify_signature(
        node_rsa_public,
        node_signature,
        b"node",
        transcript_hash,
    )

    verify_signature(
        gateway_rsa_public,
        gateway_signature,
        b"gateway",
        transcript_hash,
    )

    print("RSA-PSS signatures verified.")

    # Both sides independently compute the DH shared secret.
    gateway_shared = gateway_dh_private.exchange(node_dh_public)
    node_shared = node_dh_private.exchange(gateway_dh_public)

    print(
        "Gateway and node derived same DH secret:",
        gateway_shared == node_shared,
    )

    # FFDHE3072 shared secret must be represented as 384 bytes.
    z_int = int.from_bytes(gateway_shared, "big")
    Z = z_int.to_bytes(DH_WIDTH, "big")

    # Exact assignment-specific master key derivation.
    K_master = hashlib.sha256(
        b"CSCE465-KDF-v1" + Z + transcript_hash
    ).digest()

    K_g2n_enc = derive_key(
        K_master,
        b"gateway-to-node encryption",
        transcript_hash,
    )

    K_g2n_mac = derive_key(
        K_master,
        b"gateway-to-node MAC",
        transcript_hash,
    )

    K_n2g_enc = derive_key(
        K_master,
        b"node-to-gateway encryption",
        transcript_hash,
    )

    K_n2g_mac = derive_key(
        K_master,
        b"node-to-gateway MAC",
        transcript_hash,
    )

    session_id = hmac.new(
        K_master,
        b"session identifier" + transcript_hash,
        hashlib.sha256,
    ).digest()[:8]

    print()
    print("Handshake successful.")
    print("Protocol:", PROTOCOL_LABEL.decode())
    print("Group:", GROUP_ID.decode())
    print("Gateway nonce:", gateway_nonce.hex())
    print("Node nonce:", node_nonce.hex())
    print("Transcript hash:", transcript_hash.hex())
    print("Session ID:", session_id.hex())

    print()
    print("Derived directional keys:")
    print("K_g2n_enc:", K_g2n_enc.hex())
    print("K_g2n_mac:", K_g2n_mac.hex())
    print("K_n2g_enc:", K_n2g_enc.hex())
    print("K_n2g_mac:", K_n2g_mac.hex())

    print()
    print("Key separation checks:")
    print("G2N encryption != G2N MAC:", K_g2n_enc != K_g2n_mac)
    print("G2N encryption != N2G encryption:", K_g2n_enc != K_n2g_enc)


if __name__ == "__main__":
    main()
