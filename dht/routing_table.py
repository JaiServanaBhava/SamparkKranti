
import time
import logging
import threading

logger = logging.getLogger("nexus.dht.routing_table")

K_BUCKET_SIZE = 20          # Kademlia's standard k
ID_BITS       = 256         # SHA-256 output size in bits
STALE_SECONDS = 7200        # 2 hours — peers not seen in this window are considered stale


def _xor_distance(id_a: str, id_b: str) -> int:
    """Return the integer XOR distance between two hex node IDs."""
    return int(id_a, 16) ^ int(id_b, 16)


def _bucket_index(my_id: str, peer_id: str) -> int:
    """
    Return which k-bucket (0‥255) the peer belongs to.
    Bucket index = position of the highest set bit in the XOR distance.
    Returns 0 if the IDs are identical (degenerate case).
    """
    dist = _xor_distance(my_id, peer_id)
    if dist == 0:
        return 0
    return dist.bit_length() - 1


class RoutingTable:
    """
    Thread-safe Kademlia routing table.

    Parameters
    ----------
    my_node_id : str
        Our own 64-char hex User ID.
    db_conn : sqlite3.Connection
        An open SQLite connection (row_factory = sqlite3.Row recommended).
    """

    def __init__(self, my_node_id: str, db_conn):
        self._my_id = my_node_id
        self._db    = db_conn
        self._lock  = threading.Lock()

        # List-of-lists: buckets[i] is a list of peer dicts
        self._buckets: list[list[dict]] = [[] for _ in range(ID_BITS)]

        self._ensure_table()
        self._load_from_db()

    # ──────────────────────────────────────────────
    #  Public API
    # ──────────────────────────────────────────────

    def add_peer(self, node_id: str, ip: str, port: int):
        """
        Insert or refresh a peer in the routing table.
        Evicts the oldest entry if the bucket is full.
        Also persists the peer to SQLite.
        """
        if node_id == self._my_id:
            return  # Never add ourselves

        idx = _bucket_index(self._my_id, node_id)
        now = time.time()

        with self._lock:
            bucket = self._buckets[idx]

            # Refresh if already present
            for peer in bucket:
                if peer["node_id"] == node_id:
                    peer["ip"]        = ip
                    peer["port"]      = port
                    peer["last_seen"] = now
                    self._upsert_db(node_id, ip, port, now)
                    return

            # Bucket has room → append
            if len(bucket) < K_BUCKET_SIZE:
                entry = {"node_id": node_id, "ip": ip, "port": port, "last_seen": now}
                bucket.append(entry)
                self._upsert_db(node_id, ip, port, now)
                return

            # Bucket full → evict oldest (LRU)
            oldest_idx = min(range(len(bucket)), key=lambda i: bucket[i]["last_seen"])
            evicted = bucket[oldest_idx]
            logger.debug(f"Routing table bucket {idx} full. Evicting {evicted['node_id'][:12]}…")
            bucket[oldest_idx] = {"node_id": node_id, "ip": ip, "port": port, "last_seen": now}
            self._upsert_db(node_id, ip, port, now)

    def remove_peer(self, node_id: str):
        """Remove a peer from both the in-memory table and SQLite."""
        idx = _bucket_index(self._my_id, node_id)
        with self._lock:
            self._buckets[idx] = [p for p in self._buckets[idx] if p["node_id"] != node_id]
        self._db.cursor().execute("DELETE FROM dht_peers WHERE node_id = ?", (node_id,))
        self._db.commit()

    def find_closest(self, target_id: str, n: int = K_BUCKET_SIZE) -> list[dict]:
        """
        Return the n closest peers (by XOR distance) to target_id.
        Used for FIND_NODE and FIND_VALUE RPCs.
        """
        all_peers = []
        with self._lock:
            for bucket in self._buckets:
                all_peers.extend(bucket)

        # Sort by XOR distance to target
        all_peers.sort(key=lambda p: _xor_distance(p["node_id"], target_id))
        return all_peers[:n]

    def get_all_peers(self) -> list[dict]:
        """Return a flat list of every known peer (snapshot)."""
        result = []
        with self._lock:
            for bucket in self._buckets:
                result.extend(list(bucket))
        return result

    def peer_count(self) -> int:
        with self._lock:
            return sum(len(b) for b in self._buckets)

    def prune_stale(self):
        """Remove peers that haven't been seen in STALE_SECONDS."""
        cutoff = time.time() - STALE_SECONDS
        with self._lock:
            for i, bucket in enumerate(self._buckets):
                fresh = [p for p in bucket if p["last_seen"] >= cutoff]
                if len(fresh) != len(bucket):
                    stale_ids = [p["node_id"] for p in bucket if p["last_seen"] < cutoff]
                    for sid in stale_ids:
                        self._db.cursor().execute(
                            "DELETE FROM dht_peers WHERE node_id = ?", (sid,)
                        )
                    self._buckets[i] = fresh
            self._db.commit()
        logger.debug(f"Routing table prune complete. Active peers: {self.peer_count()}")

    # ──────────────────────────────────────────────
    #  SQLite persistence
    # ──────────────────────────────────────────────

    def _ensure_table(self):
        self._db.cursor().execute("""
            CREATE TABLE IF NOT EXISTS dht_peers (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id      TEXT UNIQUE NOT NULL,
                ip           TEXT NOT NULL,
                port         INTEGER NOT NULL,
                last_seen    REAL DEFAULT 0,
                is_bootstrap INTEGER DEFAULT 0
            )
        """)
        self._db.commit()

    def _load_from_db(self):
        cursor = self._db.cursor()
        cursor.execute("SELECT node_id, ip, port, last_seen FROM dht_peers")
        rows = cursor.fetchall()
        loaded = 0
        for row in rows:
            node_id   = row["node_id"] if hasattr(row, "keys") else row[0]
            ip        = row["ip"]       if hasattr(row, "keys") else row[1]
            port      = row["port"]     if hasattr(row, "keys") else row[2]
            last_seen = row["last_seen"] if hasattr(row, "keys") else row[3]

            idx = _bucket_index(self._my_id, node_id)
            bucket = self._buckets[idx]
            if len(bucket) < K_BUCKET_SIZE:
                bucket.append({"node_id": node_id, "ip": ip, "port": port,
                                "last_seen": last_seen or 0.0})
                loaded += 1
        logger.info(f"Routing table restored {loaded} peers from SQLite.")

    def _upsert_db(self, node_id: str, ip: str, port: int, last_seen: float):
        self._db.cursor().execute("""
            INSERT INTO dht_peers (node_id, ip, port, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(node_id) DO UPDATE SET
                ip        = excluded.ip,
                port      = excluded.port,
                last_seen = excluded.last_seen
        """, (node_id, ip, port, last_seen))
        self._db.commit()

    def mark_bootstrap(self, node_id: str):
        """Flag a peer as a bootstrap node so it survives pruning."""
        self._db.cursor().execute(
            "UPDATE dht_peers SET is_bootstrap = 1 WHERE node_id = ?", (node_id,)
        )
        self._db.commit()