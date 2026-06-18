
import os
import logging

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

logger = logging.getLogger("nexus.crypto.encryption")

NONCE_LENGTH = 12   # bytes — GCM standard
TAG_LENGTH   = 16   # bytes — GCM authentication tag (appended automatically by AESGCM)
HKDF_INFO    = b"nexus-dht-v1-message-key"


class MessageEncryption:
    """
    Stateless encryption helper.  All methods are class-level so it can be
    used without instantiation, or as a regular instance — both patterns work.
    """

    # ──────────────────────────────────────────────
    #  Key exchange
    # ──────────────────────────────────────────────

    @staticmethod
    def derive_shared_secret(my_x25519_private_key, peer_x25519_public_bytes: bytes) -> bytes:
        """
        Run X25519 ECDH between our private key and the peer's raw public key bytes.
        Returns a 32-byte AES key derived via HKDF-SHA256.

        Parameters
        ----------
        my_x25519_private_key : X25519PrivateKey
            Our own X25519 private key object from crypto/keys.py.
        peer_x25519_public_bytes : bytes
            Raw 32-byte X25519 public key received from the peer.

        Returns
        -------
        bytes
            32-byte symmetric key suitable for AES-256-GCM.
        """
        peer_pub = X25519PublicKey.from_public_bytes(peer_x25519_public_bytes)
        raw_shared = my_x25519_private_key.exchange(peer_pub)

        # Stretch/normalise with HKDF so the raw DH output is not used directly
        hkdf = HKDF(algorithm=SHA256(), length=32, salt=None, info=HKDF_INFO)
        aes_key = hkdf.derive(raw_shared)
        return aes_key

    # ──────────────────────────────────────────────
    #  Encrypt / Decrypt
    # ──────────────────────────────────────────────

    @staticmethod
    def encrypt(plaintext: bytes, aes_key: bytes) -> bytes:
        """
        Encrypt plaintext with AES-256-GCM.

        Returns
        -------
        bytes
            nonce (12 bytes) || ciphertext+tag
        """
        nonce = os.urandom(NONCE_LENGTH)
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # no AAD
        return nonce + ciphertext

    @staticmethod
    def decrypt(payload: bytes, aes_key: bytes) -> bytes:
        """
        Decrypt a payload produced by encrypt().

        Parameters
        ----------
        payload : bytes
            nonce (12 bytes) || ciphertext+tag
        aes_key : bytes
            32-byte symmetric key from derive_shared_secret().

        Returns
        -------
        bytes
            Plaintext, or raises on authentication failure.
        """
        if len(payload) < NONCE_LENGTH + TAG_LENGTH:
            raise ValueError("Payload too short to be valid ciphertext.")
        nonce      = payload[:NONCE_LENGTH]
        ciphertext = payload[NONCE_LENGTH:]
        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    # ──────────────────────────────────────────────
    #  Convenience: encrypt/decrypt JSON messages
    # ──────────────────────────────────────────────

    @staticmethod
    def encrypt_message(message_text: str, aes_key: bytes) -> bytes:
        """Encrypt a UTF-8 message string. Returns raw bytes payload."""
        return MessageEncryption.encrypt(message_text.encode("utf-8"), aes_key)

    @staticmethod
    def decrypt_message(payload: bytes, aes_key: bytes) -> str:
        """Decrypt a payload produced by encrypt_message(). Returns str."""
        return MessageEncryption.decrypt(payload, aes_key).decode("utf-8")

    # ──────────────────────────────────────────────
    #  Shared-secret cache helpers (for bridge use)
    # ──────────────────────────────────────────────

    @staticmethod
    def save_shared_secret(db_conn, chat_uuid: str, shared_secret: bytes):
        """Persist a derived shared secret in the chats table for a given chat_uuid."""
        db_conn.cursor().execute(
            "UPDATE chats SET shared_secret = ? WHERE chat_uuid = ?",
            (shared_secret, chat_uuid)
        )
        db_conn.commit()

    @staticmethod
    def load_shared_secret(db_conn, chat_uuid: str) -> bytes | None:
        """Retrieve a cached shared secret from the chats table."""
        cursor = db_conn.cursor()
        cursor.execute("SELECT shared_secret FROM chats WHERE chat_uuid = ?", (chat_uuid,))
        row = cursor.fetchone()
        if row and row[0]:
            return row[0]
        return None