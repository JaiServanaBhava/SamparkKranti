import json
import uuid
import secrets
import threading
import time
import sys
import os
import logging
import base64
import socket

# Ensure search path is clean
ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from database import DatabaseManager
from storage  import StorageEngine

try:
    from crypto.keys       import CryptoKeyManager
    from crypto.encryption import MessageEncryption
except ImportError as e:
    logging.getLogger("sampark.bridge").error(f"Failed to import crypto: {e}")

try:
    from dht.routing_table import RoutingTable
    from dht.node          import DHTNode
    from dht.bootstrap     import BootstrapManager
except ImportError as e:
    logging.getLogger("sampark.bridge").error(f"Failed to import DHT: {e}")

try:
    from networking.transport import AsyncTransport
    from messaging.handler import MessageHandler
except ImportError as e:
    logging.getLogger("sampark.bridge").error(f"Failed to import networking: {e}")

# Safe webview resolution for file dialogue systems
try:
    import webview
    WEBVIEW_DIALOG_TYPE = webview.OPEN_DIALOG
except ImportError:
    WEBVIEW_DIALOG_TYPE = 1


class APIBridge:
    def __init__(self, config_manager, logger_instance):
        self._config  = config_manager
        self._logger  = logger_instance
        self._window  = None

        # ── Storage ──
        self._db      = DatabaseManager()
        self._storage = StorageEngine()

        # ── Cryptographic identity ──
        with self._db.get_connection() as conn:
            self._km = CryptoKeyManager(conn)
            self._km.load_or_generate()

        # ── Identity record ──
        self.my_identity = self._build_identity()

        # ── Non-blocking Public IP Resolution Cache ──
        self._cached_public_ip = "Resolving..."
        threading.Thread(target=self._resolve_public_ip_bg, daemon=True).start()

        # ── Determine ports ──
        tcp_port = 7777
        for i, arg in enumerate(sys.argv):
            if arg == "--port" and i + 1 < len(sys.argv):
                tcp_port = int(sys.argv[i + 1])

        # ── DHT routing table ──
        with self._db.get_connection() as conn:
            self._routing_table = RoutingTable(self._km.user_id, conn)

        # ── DHT node ──
        self._dht_node = DHTNode(self._km.user_id, self._routing_table, self._km)

        # ── Async transport ──
        self._transport = AsyncTransport(self, tcp_port=tcp_port)
        self._transport.start()

        # Give the event loop a moment to initialise
        time.sleep(0.3)

        # Inject loop reference into DHT node
        if self._transport._loop:
            self._dht_node.set_transport(self._transport, self._transport._loop)

        # ── Bootstrap into DHT network ──
        self._bootstrap = BootstrapManager(self._dht_node, self._routing_table, self._config)
        threading.Thread(
            target=self._bootstrap.join_network_sync,
            args=(self._get_non_blocking_ip, tcp_port, self._transport._loop),
            daemon=True
        ).start()

        # ── Messaging handler ──
        self._msg_handler = MessageHandler(self, self._km)

        # ── Republish our address periodically ──
        threading.Thread(target=self._republish_loop, args=(tcp_port,), daemon=True).start()

        # ── Stale peer pruning ──
        threading.Thread(target=self._prune_loop, daemon=True).start()

        self._logger.info(
            f"Sampark Kranti node ready. User ID: {self._km.user_id[:16]}…  Port: {tcp_port}"
        )

    def set_window(self, window):
        self._window = window

    # ──────────────────────────────────────────────
    #  Safe Hex-to-Bytes Converter Helper
    # ──────────────────────────────────────────────

    def _safe_fromhex(self, hex_str: str) -> bytes | None:
        if not hex_str or not isinstance(hex_str, str):
            return None
        try:
            return bytes.fromhex(hex_str.strip())
        except Exception as e:
            self._logger.warning(f"Failed to parse hex string '{hex_str}': {e}")
            return None

    # ──────────────────────────────────────────────
    #  JSON Serialization Guard (Bytes-to-Hex)
    # ──────────────────────────────────────────────

    def _to_json_safe(self, obj):
        """Recursively scan object and safely convert python 'bytes' to Hex strings."""
        if isinstance(obj, dict):
            return {k: self._to_json_safe(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._to_json_safe(x) for x in obj]
        elif isinstance(obj, tuple):
            return tuple(self._to_json_safe(x) for x in obj)
        elif isinstance(obj, bytes):
            return obj.hex()
        return obj

    # ──────────────────────────────────────────────
    #  Non-blocking Public IP Resolver Thread
    # ──────────────────────────────────────────────

    def _resolve_public_ip_bg(self):
        try:
            time.sleep(2.0)
            if hasattr(self, '_transport') and self._transport:
                resolved = self._transport.get_public_ip()
                if resolved and resolved != "Resolving...":
                    self._cached_public_ip = resolved
                    return
        except Exception:
            pass
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self._cached_public_ip = s.getsockname()[0]
            s.close()
        except Exception:
            self._cached_public_ip = "127.0.0.1"

    def _get_non_blocking_ip(self) -> str:
        if self._cached_public_ip in ["Resolving...", "127.0.0.1"] and hasattr(self, '_transport'):
            try:
                val = self._transport.get_public_ip()
                if val:
                    return val
            except Exception:
                pass
        return self._cached_public_ip

    # ──────────────────────────────────────────────
    #  Identity Builder
    # ──────────────────────────────────────────────

    def _build_identity(self) -> dict:
        profile  = self._config.load_profile()
        user_id  = self._km.user_id

        with self._db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users
                    (uuid, public_id, display_name, username, status, user_id, public_key, x25519_public)
                VALUES (?, ?, ?, ?, 'online', ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    display_name  = excluded.display_name,
                    username      = excluded.username,
                    status        = 'online',
                    public_key    = excluded.public_key,
                    x25519_public = excluded.x25519_public
            """, (
                str(uuid.uuid4()),
                user_id,
                profile.get("name", ""),
                profile.get("username", ""),
                user_id,
                self._km.get_ed25519_public_bytes(),
                self._km.get_x25519_public_bytes(),
            ))
            conn.commit()

            cursor.execute("SELECT * FROM users WHERE user_id = ? LIMIT 1", (user_id,))
            row = cursor.fetchone()
            identity = dict(row) if row else {}

        identity["user_id"]     = user_id
        identity["public_id"]   = user_id
        identity["display_name"] = profile.get("name", "")
        identity["username"]     = profile.get("username", "")
        return self._to_json_safe(identity)

    # ──────────────────────────────────────────────
    #  Background loops
    # ──────────────────────────────────────────────

    def _republish_loop(self, my_port: int):
        time.sleep(10)
        while True:
            try:
                my_ip = self._get_non_blocking_ip()
                self._dht_node.store_sync(self._km.user_id, my_ip, my_port)
            except Exception as e:
                self._logger.warning(f"DHT republish error: {e}")
            time.sleep(1800)

    def _prune_loop(self):
        while True:
            time.sleep(3600)
            try:
                self._routing_table.prune_stale()
            except Exception as e:
                self._logger.warning(f"Prune loop error: {e}")

    # ──────────────────────────────────────────────
    #  UUIDv7 generator
    # ──────────────────────────────────────────────

    def generate_uuidv7(self) -> str:
        millis    = int(time.time() * 1000)
        v7_bin    = millis.to_bytes(6, byteorder='big')
        rand_bytes = secrets.token_bytes(10)
        v7_hi     = (rand_bytes[0] & 0x0f) | 0x70
        v7_lo     = (rand_bytes[1] & 0x3f) | 0x80
        return (f"msg_{v7_bin.hex()[:8]}-{v7_bin.hex()[8:]}"
                f"-{v7_hi:02x}{rand_bytes[2]:02x}"
                f"-{v7_lo:02x}{rand_bytes[3]:02x}"
                f"-{rand_bytes[4:].hex()}")

    # ──────────────────────────────────────────────
    #  DHT Token system
    # ──────────────────────────────────────────────

    def generate_my_connection_token(self) -> str:
        """
        Generate token carrying the username and display name.
        """
        token_data = {
            "user_id":      self._km.user_id,
            "display_name": self.my_identity.get("display_name", "Sampark User"),
            "username":     self.my_identity.get("username", "sampark_user"),
            "ed25519_pub":  self._km.get_ed25519_public_bytes().hex(),
            "x25519_pub":   self._km.get_x25519_public_bytes().hex(),
            "avatar_letter": self.my_identity.get("display_name", "S")[0].upper() if self.my_identity.get("display_name") else "S",
        }
        encoded = base64.b64encode(json.dumps(token_data).encode("utf-8")).decode("utf-8")
        return f"NEXUS_DHT:{encoded}"

    def import_p2p_connection_token(self, token_string: str) -> dict:
        token_string = token_string.strip()

        if token_string.startswith("NEXUS_P2P:"):
            return self._to_json_safe(self._import_legacy_token(token_string))

        if not token_string.startswith("NEXUS_DHT:"):
            return {"status": "error", "message": "Invalid token format."}

        try:
            raw_b64  = token_string.split("NEXUS_DHT:")[1]
            data     = json.loads(base64.b64decode(raw_b64).decode("utf-8"))

            peer_user_id   = data["user_id"]
            display_name   = data.get("display_name", peer_user_id[:12])
            username       = data.get("username", display_name)
            ed25519_pub_hex = data.get("ed25519_pub", "")
            x25519_pub_hex  = data.get("x25519_pub", "")

            # SAFETY LOCK: Prevent importing your own identity card
            if peer_user_id == self._km.user_id:
                return {"status": "error", "message": "Cannot connect to yourself."}

            # Enforce chat name to be the username as requested
            chat_title_name = username if username else display_name

            with self._db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO users
                        (uuid, public_id, display_name, username, status, user_id, public_key, x25519_public)
                    VALUES (?, ?, ?, ?, 'online', ?, ?, ?)
                    ON CONFLICT(user_id) DO UPDATE SET
                        display_name  = excluded.display_name,
                        username      = excluded.username,
                        public_key    = excluded.public_key,
                        x25519_public = excluded.x25519_public,
                        status        = 'online'
                """, (
                    str(uuid.uuid4()), peer_user_id, display_name, username,
                    peer_user_id,
                    self._safe_fromhex(ed25519_pub_hex),
                    self._safe_fromhex(x25519_pub_hex),
                ))

                cursor.execute("""
                    INSERT INTO friend_requests (sender_id, receiver_id, status)
                    VALUES (?, ?, 'accepted')
                    ON CONFLICT(sender_id, receiver_id) DO UPDATE SET status = 'accepted'
                """, (peer_user_id, self._km.user_id))

                cursor.execute("""
                    INSERT INTO chats (chat_uuid, chat_name, chat_type, peer_user_id, is_archived, is_pinned)
                    VALUES (?, ?, 'direct', ?, 0, 0)
                    ON CONFLICT(chat_uuid) DO UPDATE SET
                        chat_name = excluded.chat_name,
                        peer_user_id = excluded.peer_user_id
                """, (peer_user_id, chat_title_name, peer_user_id))

                cursor.execute("""
                    INSERT INTO friends (user1, user2) VALUES (?, ?)
                    ON CONFLICT(user1, user2) DO NOTHING
                """, (peer_user_id, self._km.user_id))
                conn.commit()

            if x25519_pub_hex:
                try:
                    aes_key = MessageEncryption.derive_shared_secret(
                        self._km.x25519_private_key, bytes.fromhex(x25519_pub_hex)
                    )
                    with self._db.get_connection() as conn:
                        MessageEncryption.save_shared_secret(conn, peer_user_id, aes_key)
                except Exception as e:
                    self._logger.warning(f"Shared secret calculation failed: {e}")

            if self._window:
                self._window.evaluate_js("if(window.onFriendRequestReceived) window.onFriendRequestReceived();")
                self._window.evaluate_js(f"if(window.onIncomingMessage) window.onIncomingMessage('{peer_user_id}');")

            threading.Thread(target=self._send_handshake_async, args=(peer_user_id,), daemon=True).start()

            res = {
                "status":  "success",
                "message": f"Link established with {chat_title_name}!",
                "peer": {
                    "public_id":    peer_user_id,
                    "user_id":      peer_user_id,
                    "display_name": chat_title_name,
                }
            }
            return self._to_json_safe(res)

        except Exception as e:
            return {"status": "error", "message": f"Token error: {e}"}

    def _import_legacy_token(self, token_string: str) -> dict:
        try:
            raw_b64 = token_string.split("NEXUS_P2P:")[1]
            data    = json.loads(base64.b64decode(raw_b64).decode("utf-8"))
            peer_id = data.get("public_id", "")
            ip      = data.get("ip", "")
            port    = int(data.get("port", 9090))

            if peer_id == self._km.user_id:
                return {"status": "error", "message": "Cannot connect to yourself."}

            with self._db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO users
                        (uuid, public_id, display_name, username, status, ip, port, user_id)
                    VALUES (?, ?, ?, ?, 'online', ?, ?, ?)
                    ON CONFLICT(user_id) DO UPDATE SET
                        display_name = excluded.display_name,
                        username = excluded.username,
                        status = 'online',
                        ip = excluded.ip,
                        port = excluded.port
                """, (str(uuid.uuid4()), peer_id, data.get("display_name", peer_id),
                      peer_id, ip, port, peer_id))
                cursor.execute("""
                    INSERT INTO chats (chat_uuid, chat_name, chat_type, peer_user_id)
                    VALUES (?, ?, 'direct', ?)
                    ON CONFLICT(chat_uuid) DO UPDATE SET chat_name = excluded.chat_name
                """, (peer_id, data.get("display_name", peer_id), peer_id))
                cursor.execute("""
                    INSERT INTO friend_requests (sender_id, receiver_id, status)
                    VALUES (?, ?, 'accepted')
                    ON CONFLICT(sender_id, receiver_id) DO UPDATE SET status = 'accepted'
                """, (peer_id, self.my_identity["public_id"]))
                cursor.execute("""
                    INSERT INTO friends (user1, user2) VALUES (?, ?)
                    ON CONFLICT(user1, user2) DO NOTHING
                """, (peer_id, self.my_identity["public_id"]))
                conn.commit()

            packet = {
                "type":         "friend_request",
                "sender_id":    self.my_identity["public_id"],
                "display_name": self.my_identity["display_name"],
                "username":     self.my_identity["username"],
                "port":         self._transport._tcp_port
            }
            self._transport.send_packet(ip, port, packet)
            res = {"status": "success", "message": f"Legacy token imported for {peer_id}",
                   "peer": {"public_id": peer_id, "display_name": data.get("display_name", peer_id)}}
            return self._to_json_safe(res)
        except Exception as e:
            return {"status": "error", "message": f"Legacy token import error: {e}"}

    def _send_handshake_async(self, peer_user_id: str):
        record = self.query_global_directory(peer_user_id)
        if record:
            packet = {
                "type":         "friend_request",
                "sender_id":    self._km.user_id,
                "display_name": self.my_identity.get("display_name", ""),
                "username":     self.my_identity.get("username", ""),
                "ed25519_pub":  self._km.get_ed25519_public_bytes().hex(),
                "x25519_pub":   self._km.get_x25519_public_bytes().hex(),
                "port":         self._transport._tcp_port,
            }
            self._logger.info(f"Dispatching dynamic handshake to resolved route -> {record['ip']}:{record['port']}")
            self._transport.send_packet(record["ip"], int(record["port"]), packet)

    # ──────────────────────────────────────────────
    #  Global directory
    # ──────────────────────────────────────────────

    def query_global_directory(self, target_id: str) -> dict | None:
        """
        Smart Prioritised Resolver:
        1. Check Kademlia Routing Table
        2. Check LAN broadcast tables
        3. Check local database tables
        4. Query DHT WAN.
        """
        target_id = target_id.strip()

        # 1. Check Kademlia routing table
        if hasattr(self, '_routing_table') and self._routing_table:
            for peer in self._routing_table.get_all_peers():
                if peer["node_id"] == target_id:
                    res = {
                        "ip": peer["ip"],
                        "port": int(peer["port"]),
                        "display_name": target_id,
                        "username": target_id,
                        "public_id": target_id
                    }
                    self._logger.info(f"Resolved local Kademlia route for {target_id[:12]}... -> {peer['ip']}:{peer['port']}")
                    return self._to_json_safe(res)

        # 2. Check LAN broadcast routing table
        rt = self._transport.local_routing_table
        if target_id in rt:
            res = {
                "ip": rt[target_id]["ip"],
                "port": int(rt[target_id]["port"]),
                "display_name": rt[target_id].get("display_name", target_id),
                "username": rt[target_id].get("display_name", target_id),
                "public_id": target_id
            }
            self._logger.info(f"Resolved LAN Broadcast route for {target_id[:12]}... -> {rt[target_id]['ip']}:{rt[target_id]['port']}")
            return self._to_json_safe(res)

        # 3. Check local SQLite DB
        with self._db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT ip, port, display_name, username, user_id FROM users "
                "WHERE (user_id = ? OR LOWER(public_id) = LOWER(?)) AND ip IS NOT NULL LIMIT 1",
                (target_id, target_id)
            )
            row = cursor.fetchone()
            if row and row["ip"]:
                res = {"ip": row["ip"], "port": int(row["port"]),
                       "display_name": row["display_name"], "username": row["username"], "public_id": target_id}
                self._logger.info(f"Resolved database cached route for {target_id[:12]}... -> {row['ip']}:{row['port']}")
                return self._to_json_safe(res)

        # 4. Query global DHT (WAN)
        self._logger.info(f"DHT Resolve fallback started for {target_id[:12]}...")
        record = self._dht_node.find_value_sync(target_id, timeout=8.0)
        if record:
            resolved_ip = record["ip"]
            resolved_port = int(record["port"])

            my_wan_ip = self._get_non_blocking_ip()
            if resolved_ip == my_wan_ip:
                self._logger.info(f"Redirecting hairpin WAN packet to Loopback 127.0.0.1 for local instance on port {resolved_port}")
                resolved_ip = "127.0.0.1"

            res = {"ip": resolved_ip, "port": resolved_port,
                   "display_name": target_id, "username": target_id, "public_id": target_id}
            return self._to_json_safe(res)

        return None

    def get_discovered_nearby_users(self) -> list:
        result = []
        for peer_id, val in self._transport.local_routing_table.items():
            if peer_id == self._km.user_id:
                continue # Skip self in LAN search too
            result.append({
                "public_id":    peer_id,
                "user_id":      peer_id,
                "display_name": val.get("display_name", peer_id),
                "ip":           val.get("ip", ""),
                "port":         val.get("port", 0),
            })
        return self._to_json_safe(result)

    # ──────────────────────────────────────────────
    #  Friend Request Workflows
    # ──────────────────────────────────────────────

    def dispatch_friend_request(self, target_public_id: str) -> dict:
        target_id = target_public_id.strip()

        if target_id == self._km.user_id:
            return {"status": "error", "message": "Cannot connect to yourself."}

        record = self.query_global_directory(target_id)
        if not record:
            return {"status": "offline_or_not_found",
                    "message": "User not reachable on local DHT routing table."}

        with self._db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO friend_requests (sender_id, receiver_id, status)
                VALUES (?, ?, 'pending')
                ON CONFLICT(sender_id, receiver_id) DO UPDATE SET status = 'pending'
            """, (self._km.user_id, target_id))
            conn.commit()

        packet = {
            "type":         "friend_request",
            "sender_id":    self._km.user_id,
            "display_name": self.my_identity.get("display_name", ""),
            "username":     self.my_identity.get("username", ""),
            "ed25519_pub":  self._km.get_ed25519_public_bytes().hex(),
            "x25519_pub":   self._km.get_x25519_public_bytes().hex(),
            "port":         self._transport._tcp_port,
        }
        success = self._transport.send_packet(record["ip"], int(record["port"]), packet)
        if success:
            res = {"status": "success", "message": f"Handshake sent to {target_id[:16]}…"}
            return self._to_json_safe(res)
        res = {"status": "success", "message": "Request queued — peer will sync on reconnect."}
        return self._to_json_safe(res)

    def receive_incoming_friend_request(self, packet: dict):
        try:
            sender_id   = packet.get("sender_id") or ""
            
            # SAFETY LOCK: Prevent loopbacks or echoed handshakes
            if not sender_id or sender_id == self._km.user_id:
                return

            sender_name = packet.get("display_name") or sender_id[:12]
            sender_user = packet.get("username") or sender_name
            ed_pub_hex  = packet.get("ed25519_pub") or ""
            x25519_hex  = packet.get("x25519_pub") or ""
            port        = packet.get("port") or 7777
            ip          = packet.get("sender_ip") or packet.get("ip") or ""

            chat_title_name = sender_user if sender_user else sender_name

            with self._db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO users
                        (uuid, public_id, display_name, username, status, user_id, public_key, x25519_public, ip, port)
                    VALUES (?, ?, ?, ?, 'online', ?, ?, ?, ?, ?)
                    ON CONFLICT(user_id) DO UPDATE SET
                        status        = 'online',
                        display_name  = excluded.display_name,
                        username      = excluded.username,
                        x25519_public = excluded.x25519_public,
                        ip            = COALESCE(excluded.ip, ip),
                        port          = COALESCE(excluded.port, port)
                """, (
                    str(uuid.uuid4()), sender_id, sender_name, sender_user,
                    sender_id,
                    self._safe_fromhex(ed_pub_hex),
                    self._safe_fromhex(x25519_hex),
                    ip if ip else None,
                    int(port) if port else None
                ))
                
                cursor.execute("""
                    INSERT INTO friend_requests (sender_id, receiver_id, status)
                    VALUES (?, ?, 'accepted')
                    ON CONFLICT(sender_id, receiver_id) DO UPDATE SET status = 'accepted'
                """, (sender_id, self._km.user_id))

                cursor.execute("""
                    INSERT INTO chats (chat_uuid, chat_name, chat_type, peer_user_id, is_archived, is_pinned)
                    VALUES (?, ?, 'direct', ?, 0, 0)
                    ON CONFLICT(chat_uuid) DO UPDATE SET
                        chat_name = excluded.chat_name,
                        peer_user_id = excluded.peer_user_id
                """, (sender_id, chat_title_name, sender_id))

                cursor.execute("""
                    INSERT INTO friends (user1, user2) VALUES (?, ?)
                    ON CONFLICT(user1, user2) DO NOTHING
                """, (sender_id, self._km.user_id))
                conn.commit()

            if x25519_hex:
                try:
                    aes_key = MessageEncryption.derive_shared_secret(
                        self._km.x25519_private_key, bytes.fromhex(x25519_hex)
                    )
                    with self._db.get_connection() as conn:
                        MessageEncryption.save_shared_secret(conn, sender_id, aes_key)
                except Exception:
                    pass

            # Send mutual verification back automatically
            record = self.query_global_directory(sender_id)
            if record:
                verify_packet = {
                    "type":         "friend_accepted",
                    "sender_id":    self._km.user_id,
                    "display_name": self.my_identity.get("display_name", ""),
                    "username":     self.my_identity.get("username", ""),
                    "ed25519_pub":  self._km.get_ed25519_public_bytes().hex(),
                    "x25519_pub":   self._km.get_x25519_public_bytes().hex(),
                    "port":         self._transport._tcp_port,
                }
                self._transport.send_packet(record["ip"], int(record["port"]), verify_packet)

            self.trigger_desktop_notification("Connection Request", f"{chat_title_name} connected.")
            if self._window:
                self._window.evaluate_js("if(window.onFriendRequestReceived) window.onFriendRequestReceived();")
                self._window.evaluate_js("if(window.syncChatDirectory) window.syncChatDirectory();")
                self._window.evaluate_js(f"if(window.onIncomingMessage) window.onIncomingMessage('{sender_id}');")
        except Exception as e:
            self._logger.error(f"Error in receive_incoming_friend_request: {e}", exc_info=True)

    def handle_request_action(self, sender_id: str, action: str) -> dict:
        status_map   = {"accept": "accepted", "reject": "rejected"}
        mapped       = status_map.get(action, "rejected")

        with self._db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT username, display_name FROM users WHERE user_id = ? LIMIT 1", (sender_id,)
            )
            row = cursor.fetchone()
            username = row["username"] if (row and row["username"]) else (row["display_name"] if row else sender_id[:12])

            cursor.execute(
                "UPDATE friend_requests SET status = ? WHERE sender_id = ? AND receiver_id = ?",
                (mapped, sender_id, self._km.user_id)
            )
            if mapped == "accepted":
                cursor.execute("""
                    INSERT INTO friends (user1, user2) VALUES (?, ?)
                    ON CONFLICT(user1, user2) DO NOTHING
                """, (sender_id, self._km.user_id))
                cursor.execute("""
                    INSERT INTO chats (chat_uuid, chat_name, chat_type, peer_user_id, is_archived, is_pinned) VALUES (?, ?, 'direct', ?, 0, 0)
                    ON CONFLICT(chat_uuid) DO UPDATE SET chat_name = excluded.chat_name
                """, (sender_id, username, sender_id))
            conn.commit()

        if mapped == "accepted":
            record = self.query_global_directory(sender_id)
            if record:
                packet = {
                    "type":         "friend_accepted",
                    "sender_id":    self._km.user_id,
                    "display_name": self.my_identity.get("display_name", ""),
                    "username":     self.my_identity.get("username", ""),
                    "ed25519_pub":  self._km.get_ed25519_public_bytes().hex(),
                    "x25519_pub":   self._km.get_x25519_public_bytes().hex(),
                    "port":         self._transport._tcp_port,
                }
                self._transport.send_packet(record["ip"], int(record["port"]), packet)

        if self._window:
            self._window.evaluate_js("if(window.onFriendRequestReceived) window.onFriendRequestReceived();")
            self._window.evaluate_js("if(window.syncChatDirectory) window.syncChatDirectory();")
        return {"status": "success"}

    def receive_incoming_friend_acceptance(self, packet: dict):
        try:
            sender_id  = packet.get("sender_id") or ""
            
            # SAFETY LOCK: Prevent self-verification loops
            if not sender_id or sender_id == self._km.user_id:
                return

            sender_name = packet.get("display_name") or sender_id[:12]
            sender_user = packet.get("username") or sender_name
            x25519_hex = packet.get("x25519_pub") or ""
            ed_pub_hex = packet.get("ed25519_pub") or ""
            port        = packet.get("port") or 7777
            ip          = packet.get("sender_ip") or packet.get("ip") or ""

            chat_title_name = sender_user if sender_user else sender_name

            with self._db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO users
                        (uuid, public_id, display_name, username, status, user_id, public_key, x25519_public, ip, port)
                    VALUES (?, ?, ?, ?, 'online', ?, ?, ?, ?, ?)
                    ON CONFLICT(user_id) DO UPDATE SET 
                        status        = 'online', 
                        username      = excluded.username,
                        display_name  = excluded.display_name,
                        x25519_public = excluded.x25519_public,
                        ip            = COALESCE(excluded.ip, ip),
                        port          = COALESCE(excluded.port, port)
                """, (
                    str(uuid.uuid4()), sender_id, sender_name, sender_user,
                    sender_id,
                    self._safe_fromhex(ed_pub_hex),
                    self._safe_fromhex(x25519_hex),
                    ip if ip else None,
                    int(port) if port else None
                ))
                cursor.execute("""
                    INSERT INTO friend_requests (sender_id, receiver_id, status) VALUES (?, ?, 'accepted')
                    ON CONFLICT(sender_id, receiver_id) DO UPDATE SET status = 'accepted'
                """, (sender_id, self._km.user_id))

                cursor.execute("""
                    INSERT INTO friends (user1, user2) VALUES (?, ?)
                    ON CONFLICT(user1, user2) DO NOTHING
                """, (sender_id, self._km.user_id))

                cursor.execute("""
                    INSERT INTO chats (chat_uuid, chat_name, chat_type, peer_user_id, is_archived, is_pinned) VALUES (?, ?, 'direct', ?, 0, 0)
                    ON CONFLICT(chat_uuid) DO UPDATE SET chat_name = excluded.chat_name
                """, (sender_id, chat_title_name, sender_id))
                conn.commit()

            if x25519_hex:
                try:
                    aes_key = MessageEncryption.derive_shared_secret(
                        self._km.x25519_private_key, bytes.fromhex(x25519_hex)
                    )
                    with self._db.get_connection() as conn:
                        MessageEncryption.save_shared_secret(conn, sender_id, aes_key)
                except Exception:
                    pass

            self.trigger_desktop_notification("Link Accepted", f"{chat_title_name} accepted your request.")
            if self._window:
                self._window.evaluate_js("if(window.syncChatDirectory) window.syncChatDirectory();")
                self._window.evaluate_js(f"if(window.onIncomingMessage) window.onIncomingMessage('{sender_id}');")
        except Exception as e:
            self._logger.error(f"Error in receive_incoming_friend_acceptance: {e}", exc_info=True)

    def get_pending_friend_requests(self) -> list:
        with self._db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT fr.sender_id, u.display_name, u.username
                FROM friend_requests fr
                JOIN users u ON fr.sender_id = u.user_id
                WHERE fr.receiver_id = ? AND fr.status = 'pending'
            """, (self._km.user_id,))
            res = [dict(r) for r in cursor.fetchall()]
            return self._to_json_safe(res)

    # ──────────────────────────────────────────────
    #  Messaging & Attachments
    # ──────────────────────────────────────────────

    def transmit_outbound_message(self, chat_uuid: str, message_text: str) -> dict:
        with self._db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT peer_user_id FROM chats WHERE chat_uuid = ? LIMIT 1", (chat_uuid,)
            )
            row = cursor.fetchone()
            peer_user_id = row["peer_user_id"] if row and row["peer_user_id"] else chat_uuid

        res = self._msg_handler.send_message(chat_uuid, message_text, peer_user_id)
        return self._to_json_safe(res)

    def _open_file_dialog_fallback(self) -> str | None:
        try:
            import tkinter as tk
            from tkinter import filedialog
            
            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            
            file_path = filedialog.askopenfilename(title="Select File to Share")
            root.destroy()
            return file_path if file_path else None
        except Exception as e:
            self._logger.warning(f"Headless Tkinter dialogue also raised: {e}")
            return None

    def select_and_send_attachment(self, chat_uuid: str) -> dict:
        if not self._window:
            return {"status": "error", "message": "GUI window handle is empty."}

        file_path = None
        try:
            file_paths = self._window.create_file_dialog(dialog_type=WEBVIEW_DIALOG_TYPE, allow_multiple=False)
            if file_paths and len(file_paths) > 0:
                file_path = file_paths[0]
        except Exception as e:
            self._logger.warning(f"Falling back to Tkinter file dialogue: {e}")
            file_path = self._open_file_dialog_fallback()
        
        if not file_path:
            return {"status": "cancelled"}

        try:
            # Read file bytes directly for binary transmission over TCP socket
            with open(file_path, "rb") as f:
                file_bytes = f.read()
            
            # Enforce safe 10MB limit to prevent transport channel congestion
            if len(file_bytes) > 10 * 1024 * 1024:
                return {"status": "error", "message": "File size exceeds 10MB transmission limit."}

            b64_data = base64.b64encode(file_bytes).decode("utf-8")
            file_name = os.path.basename(file_path)
            file_size = len(file_bytes)
            ext = os.path.splitext(file_name)[1].lower()
            
            file_type = "documents"
            if ext in ['.jpg', '.jpeg', '.png', '.gif', '.webp']:
                file_type = "images"
            elif ext in ['.mp4', '.avi', '.mkv', '.mov']:
                file_type = "videos"
            elif ext in ['.mp3', '.wav', '.ogg', '.flac']:
                file_type = "audio"

            # Package attachment inside raw meta tag alongside base64 content
            meta_payload = f"[ATTACHMENT|{file_name}|{file_type}|{file_size}|{b64_data}]"
            
            # Transmit structured packet
            res = self.transmit_outbound_message(chat_uuid, meta_payload)
            
            # Clean database to avoid massive base64 storage bloat locally
            if res.get("status") in ["sent", "queued"]:
                msg_uuid = res.get("message_uuid")
                clean_payload = f"[ATTACHMENT|{file_name}|{file_type}|{file_size}]"
                with self._db.get_connection() as conn:
                    conn.cursor().execute(
                        "UPDATE messages SET message = ? WHERE message_uuid = ?",
                        (clean_payload, msg_uuid)
                    )
                    conn.commit()

            return self._to_json_safe(res)
        except Exception as e:
            self._logger.error(f"Failed to process and send attachment: {e}")
            return {"status": "error", "message": str(e)}

    def receive_incoming_message(self, packet: dict):
        self._msg_handler.receive_message(packet)

    def register_remote_ack(self, message_uuid: str):
        with self._db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE messages SET state = 'delivered' WHERE message_uuid = ?", (message_uuid,))
            cursor.execute("UPDATE message_queue SET status = 'sent' WHERE message_uuid = ?", (message_uuid,))
            cursor.execute("""
                INSERT INTO ack_records (message_uuid) VALUES (?)
                ON CONFLICT(message_uuid) DO NOTHING
            """, (message_uuid,))
            conn.commit()
        if self._window:
            self._window.evaluate_js(
                f"if(window.onMessageAckReceived) window.onMessageAckReceived('{message_uuid}');"
            )

    # ──────────────────────────────────────────────
    #  E2E Chat Cleanups & Deletions
    # ──────────────────────────────────────────────

    def clear_chat_history(self, chat_uuid: str) -> dict:
        try:
            with self._db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM messages WHERE chat_uuid = ?", (chat_uuid,))
                cursor.execute("UPDATE chats SET last_message = '', unread_count = 0 WHERE chat_uuid = ?", (chat_uuid,))
                conn.commit()
            return {"status": "success"}
        except Exception as e:
            self._logger.error(f"Clear chat error: {e}")
            return {"status": "error", "message": str(e)}

    def delete_chat_session(self, chat_uuid: str) -> dict:
        try:
            with self._db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM messages WHERE chat_uuid = ?", (chat_uuid,))
                cursor.execute("DELETE FROM chats WHERE chat_uuid = ?", (chat_uuid,))
                cursor.execute("DELETE FROM friends WHERE user1 = ? OR user2 = ?", (chat_uuid, chat_uuid))
                cursor.execute("DELETE FROM friend_requests WHERE sender_id = ? OR receiver_id = ?", (chat_uuid, chat_uuid))
                cursor.execute("DELETE FROM users WHERE user_id = ?", (chat_uuid,))
                conn.commit()
            return {"status": "success"}
        except Exception as e:
            self._logger.error(f"Delete chat error: {e}")
            return {"status": "error", "message": str(e)}

    # ──────────────────────────────────────────────
    #  DHT status
    # ──────────────────────────────────────────────

    def get_dht_status(self) -> dict:
        res = {
            "peer_count":    self._routing_table.peer_count(),
            "user_id":       self._km.user_id,
            "user_id_short": self._km.user_id[:16] + "…",
            "public_ip":     self._get_non_blocking_ip(),
            "tcp_port":      self._transport._tcp_port if hasattr(self, '_transport') else 7777,
            "encryption":    True,
        }
        return self._to_json_safe(res)

    # ──────────────────────────────────────────────
    #  Database Reads & Writes
    # ──────────────────────────────────────────────

    def get_chats(self) -> list:
        with self._db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM chats ORDER BY is_pinned DESC, updated_at DESC")
            res = [dict(r) for r in cursor.fetchall()]
            return self._to_json_safe(res)

    def update_chat_status(self, chat_id: str, field: str, value) -> dict:
        if field not in ['is_pinned', 'is_archived', 'chat_name', 'draft_text']:
            return {"status": "error"}
        with self._db.get_connection() as conn:
            conn.cursor().execute(
                f"UPDATE chats SET {field} = ?, updated_at = CURRENT_TIMESTAMP WHERE chat_uuid = ?",
                (value, chat_id)
            )
            conn.commit()
        return {"status": "success"}

    def load_messages(self, chat_uuid: str) -> list:
        with self._db.get_connection() as conn:
            cursor = conn.cursor()
            # Order strictly by the autoincrement ID primary key to prevent sorting issues with NULL timestamps
            cursor.execute(
                "SELECT * FROM messages WHERE chat_uuid = ? ORDER BY id ASC", (chat_uuid,)
            )
            res = [dict(r) for r in cursor.fetchall()]
            return self._to_json_safe(res)

    def delete_message(self, msg_id: int) -> dict:
        with self._db.get_connection() as conn:
            conn.cursor().execute("DELETE FROM messages WHERE id = ?", (msg_id,))
            conn.commit()
        return {"status": "success"}

    def fetch_storage_dashboard(self) -> dict:
        res = self._storage.get_storage_metrics()
        return self._to_json_safe(res)

    def fetch_user_identity_card(self) -> dict:
        card = dict(self.my_identity)
        card["user_id"]       = self._km.user_id
        card["user_id_short"] = self._km.user_id[:16] + "…"
        card["dht_peers"]     = self._routing_table.peer_count()
        card["encryption"]    = True
        return self._to_json_safe(card)

    def trigger_desktop_notification(self, title: str, body: str):
        if self._window:
            t = title.replace("'", "\\'")
            b = body.replace("'", "\\'")
            self._window.evaluate_js(
                f"if(window.showLocalNotification) window.showLocalNotification('{t}', '{b}');"
            )

    def load_profile(self) -> dict:
        res = self._config.load_profile()
        return self._to_json_safe(res)

    def save_profile(self, profile_data: dict) -> dict:
        result = self._config.save_profile(profile_data)
        self.my_identity = self._build_identity()
        
        if self._window:
            try:
                self._window.set_title("Sampark Kranti")
            except Exception as e:
                self._logger.warning(f"Could not update window title: {e}")
                
            self._window.evaluate_js("if(window.onProfileUpdated) window.onProfileUpdated();")
            
        res = {"status": "success" if result else "error"}
        return self._to_json_safe(res)

    def load_settings(self) -> dict:
        res = self._config.load_settings()
        return self._to_json_safe(res)

    def save_settings(self, settings_data: dict) -> bool:
        return self._config.save_settings(settings_data)

    def log_frontend_message(self, level: str, message: str) -> bool:
        self._logger.info(f"[JS] [{level}] {message}")
        return True