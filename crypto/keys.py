
import hashlib
import logging

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)

logger = logging.getLogger("nexus.crypto.keys")


# ─────────────────────────────────────────────────────────────
#  Key type constants stored in crypto_keys table
# ─────────────────────────────────────────────────────────────
KEY_ED25519_PRIVATE = "ed25519_private"
KEY_ED25519_PUBLIC  = "ed25519_public"
KEY_X25519_PRIVATE  = "x25519_private"
KEY_X25519_PUBLIC   = "x25519_public"


class CryptoKeyManager:
    """
    Manages the node's permanent cryptographic identity.

    Usage
    -----
    km = CryptoKeyManager(db_conn)
    km.load_or_generate()   # call once at startup
    user_id = km.user_id    # 64-char hex string, permanent forever
    """

    def __init__(self, db_conn):
        self._db = db_conn
        self._ensure_table()

        # Populated by load_or_generate()
        self.ed25519_private_key = None
        self.ed25519_public_key  = None
        self.x25519_private_key  = None
        self.x25519_public_key   = None
        self.user_id             = None   # SHA-256(ed25519_pub) hex
        self.ed25519_public_bytes = None  # raw 32 bytes
        self.x25519_public_bytes  = None  # raw 32 bytes

    # ──────────────────────────────────────────────
    #  Public API
    # ──────────────────────────────────────────────

    def load_or_generate(self):
        """Load keys from DB, or generate + persist brand-new ones."""
        row = self._load_from_db(KEY_ED25519_PRIVATE)
        if row:
            logger.info("Loaded existing cryptographic identity from database.")
            self._deserialize_all(row)
        else:
            logger.info("No existing identity found — generating new keypair.")
            self._generate_and_save()

        self.user_id = self._derive_user_id(self.ed25519_public_bytes)
        logger.info(f"Node User ID: {self.user_id}")
        return self.user_id

    def sign(self, data: bytes) -> bytes:
        """Sign arbitrary bytes with our Ed25519 private key."""
        return self.ed25519_private_key.sign(data)

    def verify(self, public_key_bytes: bytes, signature: bytes, data: bytes) -> bool:
        """Verify an Ed25519 signature from a peer's raw public key bytes."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        try:
            pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pub.verify(signature, data)
            return True
        except Exception:
            return False

    def get_x25519_public_bytes(self) -> bytes:
        return self.x25519_public_bytes

    def get_ed25519_public_bytes(self) -> bytes:
        return self.ed25519_public_bytes

    @staticmethod
    def derive_user_id_from_public_bytes(public_key_bytes: bytes) -> str:
        """Derive a User ID from any raw Ed25519 public key bytes."""
        return hashlib.sha256(public_key_bytes).hexdigest()

    # ──────────────────────────────────────────────
    #  Internal helpers
    # ──────────────────────────────────────────────

    def _ensure_table(self):
        cursor = self._db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS crypto_keys (
                id        INTEGER PRIMARY KEY,
                key_type  TEXT NOT NULL UNIQUE,
                key_data  BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self._db.commit()

    def _generate_and_save(self):
        # Ed25519
        ed_priv = Ed25519PrivateKey.generate()
        ed_pub  = ed_priv.public_key()
        ed_priv_bytes = ed_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        ed_pub_bytes  = ed_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

        # X25519
        x_priv = X25519PrivateKey.generate()
        x_pub  = x_priv.public_key()
        x_priv_bytes = x_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        x_pub_bytes  = x_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

        for key_type, key_data in [
            (KEY_ED25519_PRIVATE, ed_priv_bytes),
            (KEY_ED25519_PUBLIC,  ed_pub_bytes),
            (KEY_X25519_PRIVATE,  x_priv_bytes),
            (KEY_X25519_PUBLIC,   x_pub_bytes),
        ]:
            self._db.cursor().execute(
                "INSERT OR REPLACE INTO crypto_keys (key_type, key_data) VALUES (?, ?)",
                (key_type, key_data)
            )
        self._db.commit()

        self.ed25519_private_key  = ed_priv
        self.ed25519_public_key   = ed_pub
        self.ed25519_public_bytes = ed_pub_bytes
        self.x25519_private_key   = x_priv
        self.x25519_public_key    = x_pub
        self.x25519_public_bytes  = x_pub_bytes
        logger.info("New Ed25519 + X25519 keypair generated and saved.")

    def _load_from_db(self, key_type):
        cursor = self._db.cursor()
        cursor.execute("SELECT key_data FROM crypto_keys WHERE key_type = ?", (key_type,))
        return cursor.fetchone()

    def _deserialize_all(self, _):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _EP
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey as _XP

        ed_priv_bytes = self._load_from_db(KEY_ED25519_PRIVATE)[0]
        ed_pub_bytes  = self._load_from_db(KEY_ED25519_PUBLIC)[0]
        x_priv_bytes  = self._load_from_db(KEY_X25519_PRIVATE)[0]
        x_pub_bytes   = self._load_from_db(KEY_X25519_PUBLIC)[0]

        self.ed25519_private_key  = _EP.from_private_bytes(ed_priv_bytes)
        self.ed25519_public_key   = self.ed25519_private_key.public_key()
        self.ed25519_public_bytes = ed_pub_bytes
        self.x25519_private_key   = _XP.from_private_bytes(x_priv_bytes)
        self.x25519_public_key    = self.x25519_private_key.public_key()
        self.x25519_public_bytes  = x_pub_bytes

    @staticmethod
    def _derive_user_id(public_key_bytes: bytes) -> str:
        return hashlib.sha256(public_key_bytes).hexdigest()