
import os
import sys
import sqlite3
import logging

logger = logging.getLogger("sampark.database")

def get_app_data_dir() -> str:
    """
    Returns the absolute path to the system-specific local app data folder.
    e.g., C:\\Users\\<Username>\\AppData\\Local\\SamparkKranti on Windows.
    Creates the directory if it does not exist.
    """
    if sys.platform == "win32":
        base_dir = os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
    elif sys.platform == "darwin":
        base_dir = os.path.expanduser("~/Library/Application Support")
    else:
        base_dir = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
        
    app_dir = os.path.join(base_dir, "SamparkKranti")
    os.makedirs(app_dir, exist_ok=True)
    return app_dir

# Resolve the database path relative to the isolated local AppData directory
raw_db_path = os.environ.get("NEXUS_DB", "messenger.db")
if os.path.isabs(raw_db_path):
    DB_PATH = raw_db_path
else:
    DB_PATH = os.path.join(get_app_data_dir(), raw_db_path)


class DatabaseManager:
    """
    Creates / migrates the SQLite database and hands out connections.
    All data is kept under the system local AppData/SamparkKranti directory.
    """

    def __init__(self, db_path: str = DB_PATH):
        if db_path and not os.path.isabs(db_path):
            self._db_path = os.path.join(get_app_data_dir(), db_path)
        else:
            self._db_path = db_path if db_path else DB_PATH
        self._init_db()

    # ──────────────────────────────────────────────
    #  Connection helper
    # ──────────────────────────────────────────────

    def get_connection(self) -> sqlite3.Connection:
        """
        Return a new SQLite connection with row_factory = Row set.
        Use as a context manager — commits / rolls back automatically.
        """
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Enable Write-Ahead Logging (WAL) to prevent lock contention between instances
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            pass
        return conn

    # ──────────────────────────────────────────────
    #  Init & migration
    # ──────────────────────────────────────────────

    def _init_db(self):
        with self.get_connection() as conn:
            self._create_tables(conn)
            self._migrate(conn)
            conn.commit()
        logger.info(f"Database ready: {os.path.abspath(self._db_path)}")

    def _create_tables(self, conn: sqlite3.Connection):
        cursor = conn.cursor()

        # ── Users / contacts ──────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid          TEXT    UNIQUE,
                public_id     TEXT,
                display_name  TEXT    DEFAULT 'Unknown',
                username      TEXT,
                status        TEXT    DEFAULT 'offline',
                avatar_letter TEXT    DEFAULT 'U',
                avatar_color  TEXT    DEFAULT '#6366f1',
                bio           TEXT    DEFAULT '',
                ip            TEXT,
                port          INTEGER DEFAULT 7777,
                user_id       TEXT    UNIQUE,
                public_key    BLOB,
                x25519_public BLOB,
                created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ── Chats ─────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chats (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_uuid     TEXT    UNIQUE NOT NULL,
                chat_name     TEXT    DEFAULT 'Chat',
                chat_type     TEXT    DEFAULT 'direct',
                peer_user_id  TEXT,
                shared_secret BLOB,
                is_pinned     INTEGER DEFAULT 0,
                is_archived   INTEGER DEFAULT 0,
                draft_text    TEXT    DEFAULT '',
                unread_count  INTEGER DEFAULT 0,
                last_message  TEXT    DEFAULT '',
                created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ── Messages ──────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                message_uuid  TEXT    UNIQUE,
                chat_uuid     TEXT    NOT NULL,
                sender_id     TEXT    NOT NULL,
                message       TEXT    DEFAULT '',
                state         TEXT    DEFAULT 'sending',
                is_encrypted  INTEGER DEFAULT 0,
                file_path     TEXT,
                file_name     TEXT,
                file_size     INTEGER,
                file_type     TEXT,
                created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY   (chat_uuid) REFERENCES chats(chat_uuid) ON DELETE CASCADE
            )
        """)

        # ── Message queue (offline retry) ─────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS message_queue (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                message_uuid   TEXT    UNIQUE NOT NULL,
                destination_id TEXT    NOT NULL,
                payload        TEXT    NOT NULL,
                status         TEXT    DEFAULT 'queued',
                retry_count    INTEGER DEFAULT 0,
                next_retry_at  REAL    DEFAULT 0,
                created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ── Processed messages (dedup) ────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS processed_messages (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                message_uuid TEXT    UNIQUE NOT NULL,
                processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ── ACK records ───────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ack_records (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                message_uuid TEXT    UNIQUE NOT NULL,
                acked_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ── Friend requests ───────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS friend_requests (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id   TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                status      TEXT DEFAULT 'pending',
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (sender_id, receiver_id)
            )
        """)

        # ── Friends (confirmed) ───────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS friends (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                user1   TEXT NOT NULL,
                user2   TEXT NOT NULL,
                UNIQUE (user1, user2)
            )
        """)

        # ── Crypto keys ───────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS crypto_keys (
                id         INTEGER PRIMARY KEY,
                key_type   TEXT NOT NULL UNIQUE,
                key_data   BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ── DHT peers (Kademlia routing table) ────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dht_peers (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id      TEXT UNIQUE NOT NULL,
                ip           TEXT NOT NULL,
                port         INTEGER NOT NULL,
                last_seen    REAL    DEFAULT 0,
                is_bootstrap INTEGER DEFAULT 0
            )
        """)

        # ── Files ─────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                file_uuid  TEXT UNIQUE NOT NULL,
                chat_uuid  TEXT,
                sender_id  TEXT,
                file_name  TEXT,
                file_path  TEXT,
                file_type  TEXT,
                file_size  INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

    # ──────────────────────────────────────────────
    #  Schema migration (add new columns safely)
    # ──────────────────────────────────────────────

    def _migrate(self, conn: sqlite3.Connection):
        """
        Idempotent column additions so existing databases are safely upgraded.
        """
        self._add_column_if_missing(conn, "users",  "user_id",       "TEXT UNIQUE")
        self._add_column_if_missing(conn, "users",  "public_key",    "BLOB")
        self._add_column_if_missing(conn, "users",  "x25519_public", "BLOB")
        self._add_column_if_missing(conn, "users",  "ip",            "TEXT")
        self._add_column_if_missing(conn, "users",  "port",          "INTEGER DEFAULT 7777")

        self._add_column_if_missing(conn, "chats",  "peer_user_id",  "TEXT")
        self._add_column_if_missing(conn, "chats",  "shared_secret", "BLOB")
        self._add_column_if_missing(conn, "chats",  "draft_text",    "TEXT DEFAULT ''")
        self._add_column_if_missing(conn, "chats",  "is_archived",   "INTEGER DEFAULT 0")
        self._add_column_if_missing(conn, "chats",  "unread_count",  "INTEGER DEFAULT 0")
        self._add_column_if_missing(conn, "chats",  "last_message",  "TEXT DEFAULT ''")

        self._add_column_if_missing(conn, "messages", "is_encrypted", "INTEGER DEFAULT 0")
        self._add_column_if_missing(conn, "messages", "file_path",    "TEXT")
        self._add_column_if_missing(conn, "messages", "file_name",    "TEXT")
        self._add_column_if_missing(conn, "messages", "file_size",    "INTEGER")
        self._add_column_if_missing(conn, "messages", "file_type",    "TEXT")

        self._add_column_if_missing(conn, "message_queue", "retry_count",   "INTEGER DEFAULT 0")
        self._add_column_if_missing(conn, "message_queue", "next_retry_at", "REAL DEFAULT 0")

        # Performance Indexes
        cursor = conn.cursor()
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_messages_chat_uuid ON messages(chat_uuid)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_user_id ON users(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_dht_peers_node_id ON dht_peers(node_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_queue_status ON message_queue(status, next_retry_at)")

    @staticmethod
    def _add_column_if_missing(conn: sqlite3.Connection, table: str,
                                column: str, col_def: str):
        cursor = conn.cursor()
        cursor.execute(f"PRAGMA table_info({table})")
        existing = {row[1] for row in cursor.fetchall()}
        if column not in existing:
            try:
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")
                logger.debug(f"Migration: added {table}.{column}")
            except sqlite3.OperationalError as e:
                logger.warning(f"Migration skipped {table}.{column}: {e}")