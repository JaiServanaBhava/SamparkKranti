import json
import time
import base64
import logging
import os
import threading
import uuid

from crypto.encryption import MessageEncryption
from crypto.keys import CryptoKeyManager

logger = logging.getLogger("sampark.messaging.handler")

MAX_RETRIES     = 10
BASE_BACKOFF    = 4
MAX_BACKOFF     = 300


class MessageHandler:
    def __init__(self, bridge, key_manager: CryptoKeyManager):
        self._bridge = bridge
        self._km     = key_manager
        self._enc    = MessageEncryption()

        self._queue_thread = threading.Thread(
            target=self._offline_queue_loop, daemon=True, name="sampark-msg-queue"
        )
        self._queue_thread.start()

    # ──────────────────────────────────────────────
    #  Outbound
    # ──────────────────────────────────────────────

    def send_message(self, chat_uuid: str, message_text: str,
                     peer_user_id: str) -> dict:
        msg_uuid = self._bridge.generate_uuidv7()

        self._store_message(msg_uuid, chat_uuid, message_text, "sending")

        # Prioritize smart routing tables directly
        record = self._bridge.query_global_directory(peer_user_id)
        if not record:
            record = self._fallback_resolve(peer_user_id)

        if not record:
            self._enqueue(msg_uuid, peer_user_id, chat_uuid, message_text)
            self._update_message_state(msg_uuid, "queued")
            return {"status": "queued", "message_uuid": msg_uuid}

        ip, port = record["ip"], int(record["port"])

        packet = self._build_encrypted_packet(msg_uuid, chat_uuid, message_text, peer_user_id)
        success = self._bridge._transport.send_packet(ip, port, packet)

        if success:
            self._update_message_state(msg_uuid, "sent")
            self._store_ack_queue(msg_uuid, peer_user_id, json.dumps(packet), "sent")
            return {"status": "sent", "message_uuid": msg_uuid}
        else:
            self._enqueue(msg_uuid, peer_user_id, chat_uuid, message_text)
            self._update_message_state(msg_uuid, "queued")
            return {"status": "queued", "message_uuid": msg_uuid}

    def _store_ack_queue(self, msg_uuid, dest_id, payload, status):
        pass

    # ──────────────────────────────────────────────
    #  Inbound
    # ──────────────────────────────────────────────

    def receive_message(self, packet: dict):
        sender_id       = packet.get("sender_id", "")
        
        # SAFETY CHECK: Block loopback messages from ourselves
        if sender_id == self._km.user_id:
            return

        sender_name     = packet.get("sender_name", sender_id[:12])
        sender_username = packet.get("sender_username", sender_name)
        msg_uuid        = packet.get("message_uuid", "")
        chat_uuid       = sender_id
        sender_pub_hex  = packet.get("ed25519_pub", "")
        sig_hex         = packet.get("signature", "")
        payload_b64     = packet.get("payload", "")
        x25519_pub_hex  = packet.get("x25519_pub", "")
        port            = packet.get("port", 7777)
        ip              = packet.get("sender_ip", packet.get("ip", ""))

        if not all([sender_id, msg_uuid, payload_b64]):
            return

        if sender_pub_hex and sig_hex:
            try:
                pub_bytes = bytes.fromhex(sender_pub_hex)
                sig_bytes = bytes.fromhex(sig_hex)
                payload_bytes = base64.b64decode(payload_b64)
                if not self._km.verify(pub_bytes, sig_bytes, payload_bytes):
                    logger.warning("Invalid packet signature dropped.")
                    return
            except Exception:
                return

        plaintext = self._decrypt_incoming(
            payload_b64, sender_id, x25519_pub_hex, chat_uuid
        )

        if plaintext is None:
            plaintext = packet.get("message", "[Encrypted Payload]")

        # Process binary file attachment if stream tag is detected
        db_plaintext = plaintext
        if plaintext.startswith("[ATTACHMENT|") and plaintext.endswith("]"):
            parts = plaintext[12:-1].split("|")
            if len(parts) >= 4:
                file_name = parts[0]
                file_type = parts[1]
                file_size = parts[2]
                b64_data  = parts[3]
                try:
                    # Write decoded file content to local disk directories directly
                    dest_dir = os.path.join("downloads", file_type)
                    os.makedirs(dest_dir, exist_ok=True)
                    dest_path = os.path.join(dest_dir, file_name)
                    
                    file_bytes = base64.b64decode(b64_data)
                    with open(dest_path, "wb") as f:
                        f.write(file_bytes)
                    
                    # Store descriptive tags in DB without massive Base64 strings to keep it clean
                    db_plaintext = f"[ATTACHMENT|{file_name}|{file_type}|{file_size}]"
                except Exception as e:
                    logger.error(f"Failed to write downloaded attachment to local disk: {e}")

        with self._bridge._db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM processed_messages WHERE message_uuid = ?", (msg_uuid,)
            )
            if cursor.fetchone():
                return

            # Determine localized username handles
            cursor.execute("SELECT username, display_name FROM users WHERE user_id = ? LIMIT 1", (sender_id,))
            user_row = cursor.fetchone()
            chat_title = sender_username
            if user_row:
                chat_title = user_row["username"] if user_row["username"] else user_row["display_name"]
            
            if not chat_title:
                chat_title = sender_username if sender_username else sender_name

            # Dynamic IP routing update with strict conflict resolutions
            cursor.execute("""
                INSERT INTO users (uuid, public_id, display_name, username, status, user_id, ip, port)
                VALUES (?, ?, ?, ?, 'online', ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    status = 'online',
                    display_name = COALESCE(excluded.display_name, display_name),
                    username = COALESCE(excluded.username, username),
                    ip = COALESCE(excluded.ip, ip),
                    port = COALESCE(excluded.port, port)
            """, (str(uuid.uuid4()), sender_id, sender_name, sender_username, sender_id, ip if ip else None, int(port) if port else None))

            cursor.execute("""
                INSERT INTO chats (chat_uuid, chat_name, chat_type, peer_user_id, is_archived, is_pinned) 
                VALUES (?, ?, 'direct', ?, 0, 0)
                ON CONFLICT(chat_uuid) DO UPDATE SET
                    chat_name = COALESCE(excluded.chat_name, chat_name)
            """, (chat_uuid, chat_title, sender_id))

            # Strictly save with TIMESTAMP default values to ensure chronological queries work
            cursor.execute("""
                INSERT OR IGNORE INTO messages
                    (message_uuid, chat_uuid, sender_id, message, state, is_encrypted, created_at)
                VALUES (?, ?, ?, ?, 'delivered', 1, CURRENT_TIMESTAMP)
            """, (msg_uuid, chat_uuid, sender_id, db_plaintext))

            cursor.execute(
                "INSERT OR IGNORE INTO processed_messages (message_uuid) VALUES (?)", (msg_uuid,)
            )
            conn.commit()

        self._bridge.trigger_desktop_notification(
            "New Message", f"{chat_title}: {db_plaintext[:60]}"
        )
        if self._bridge._window:
            self._bridge._window.evaluate_js(
                f"if(window.onIncomingMessage) window.onIncomingMessage('{sender_id}');"
            )

        self._send_ack(sender_id, msg_uuid)

    # ──────────────────────────────────────────────
    #  Offline queue loop
    # ──────────────────────────────────────────────

    def _offline_queue_loop(self):
        retry_counts: dict[str, int] = {}
        retry_times:  dict[str, float] = {}

        while True:
            time.sleep(2.0)
            try:
                with self._bridge._db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT * FROM message_queue WHERE status = 'queued' LIMIT 20"
                    )
                    backlog = [dict(r) for r in cursor.fetchall()]

                for item in backlog:
                    msg_uuid = item["message_uuid"]
                    dest_id  = item["destination_id"]
                    count    = retry_counts.get(msg_uuid, 0)
                    next_try = retry_times.get(msg_uuid, 0)

                    if time.time() < next_try:
                        continue

                    if count >= MAX_RETRIES:
                        self._mark_queue_failed(msg_uuid)
                        retry_counts.pop(msg_uuid, None)
                        retry_times.pop(msg_uuid, None)
                        continue

                    record = self._bridge.query_global_directory(dest_id)
                    if not record:
                        record = self._fallback_resolve(dest_id)

                    if record:
                        payload = json.loads(item["payload"])
                        success = self._bridge._transport.send_packet(
                            record["ip"], int(record["port"]), payload
                        )
                        if success:
                            self._dequeue_success(msg_uuid)
                            retry_counts.pop(msg_uuid, None)
                            retry_times.pop(msg_uuid, None)
                            continue

                    backoff = min(BASE_BACKOFF * (2 ** count), MAX_BACKOFF)
                    retry_counts[msg_uuid] = count + 1
                    retry_times[msg_uuid]  = time.time() + backoff

            except Exception as e:
                logger.error(f"Offline queue loop error: {e}")

    # ──────────────────────────────────────────────
    #  Encryption helpers
    # ──────────────────────────────────────────────

    def _build_encrypted_packet(self, msg_uuid: str, chat_uuid: str,
                                  message_text: str, peer_user_id: str) -> dict:
        aes_key = self._get_or_derive_shared_secret(peer_user_id, chat_uuid)

        if aes_key:
            payload_bytes = self._enc.encrypt_message(message_text, aes_key)
            payload_b64   = base64.b64encode(payload_bytes).decode("utf-8")
            sig           = self._km.sign(payload_bytes).hex()
            is_encrypted  = True
        else:
            payload_b64  = base64.b64encode(message_text.encode("utf-8")).decode("utf-8")
            sig          = ""
            is_encrypted = False

        return {
            "v":            2,
            "type":         "text",
            "message_uuid": msg_uuid,
            "chat_uuid":    chat_uuid,
            "sender_id":    self._bridge.my_identity["user_id"],
            "sender_name":  self._bridge.my_identity.get("display_name", ""),
            "sender_username": self._bridge.my_identity.get("username", ""),
            "payload":      payload_b64,
            "signature":    sig,
            "ed25519_pub":  self._km.get_ed25519_public_bytes().hex(),
            "x25519_pub":   self._km.get_x25519_public_bytes().hex(),
            "is_encrypted": is_encrypted,
            "timestamp":    time.time(),
            "port":         self._bridge._transport._tcp_port
        }

    def _decrypt_incoming(self, payload_b64: str, sender_id: str,
                           x25519_pub_hex: str, chat_uuid: str) -> str | None:
        try:
            payload_bytes = base64.b64decode(payload_b64)

            aes_key = None
            if x25519_pub_hex:
                try:
                    peer_x25519_pub = bytes.fromhex(x25519_pub_hex)
                    aes_key = self._enc.derive_shared_secret(
                        self._km.x25519_private_key, peer_x25519_pub
                    )
                    with self._bridge._db.get_connection() as conn:
                        self._enc.save_shared_secret(conn, chat_uuid, aes_key)
                except Exception:
                    pass

            if aes_key is None:
                with self._bridge._db.get_connection() as conn:
                    aes_key = self._enc.load_shared_secret(conn, chat_uuid)

            if aes_key:
                return self._enc.decrypt_message(payload_bytes, aes_key)
            else:
                return payload_bytes.decode("utf-8")
        except Exception as e:
            logger.warning(f"Decryption failed for {sender_id[:12]}…: {e}")
            return None

    def _get_or_derive_shared_secret(self, peer_user_id: str, chat_uuid: str) -> bytes | None:
        with self._bridge._db.get_connection() as conn:
            cached = self._enc.load_shared_secret(conn, chat_uuid)
            if cached:
                return cached

        with self._bridge._db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT x25519_public FROM users WHERE user_id = ? LIMIT 1", (peer_user_id,)
            )
            row = cursor.fetchone()
            if row and row[0]:
                try:
                    aes_key = self._enc.derive_shared_secret(
                        self._km.x25519_private_key, row[0]
                    )
                    self._enc.save_shared_secret(conn, chat_uuid, aes_key)
                    return aes_key
                except Exception as e:
                    logger.warning(f"Shared secret derivation failed: {e}")

        return None

    # ──────────────────────────────────────────────
    #  ACK
    # ──────────────────────────────────────────────

    def _send_ack(self, sender_id: str, msg_uuid: str):
        record = self._bridge.query_global_directory(sender_id)
        if not record:
            record = self._fallback_resolve(sender_id)
        if record:
            ack_packet = {
                "type":         "msg_ack",
                "sender_id":    self._bridge.my_identity.get("user_id", ""),
                "message_uuid": msg_uuid,
            }
            self._bridge._transport.send_packet(record["ip"], int(record["port"]), ack_packet)

    # ──────────────────────────────────────────────
    #  Address resolution fallback
    # ──────────────────────────────────────────────

    def _fallback_resolve(self, user_id: str) -> dict | None:
        try:
            with self._bridge._db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT ip, port FROM users WHERE user_id = ? AND ip IS NOT NULL LIMIT 1",
                    (user_id,)
                )
                row = cursor.fetchone()
                if row and row[0]:
                    return {"ip": row[0], "port": int(row[1])}
        except Exception:
            pass

        rt = self._bridge._transport.local_routing_table
        if user_id in rt:
            return rt[user_id]

        return None

    # ──────────────────────────────────────────────
    #  DB helpers
    # ──────────────────────────────────────────────

    def _store_message(self, msg_uuid, chat_uuid, text, state):
        with self._bridge._db.get_connection() as conn:
            conn.cursor().execute("""
                INSERT OR IGNORE INTO messages
                    (message_uuid, chat_uuid, sender_id, message, state, is_encrypted, created_at)
                VALUES (?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
            """, (msg_uuid, chat_uuid,
                  self._bridge.my_identity.get("user_id",
                      self._bridge.my_identity.get("public_id", "")),
                  text, state))
            conn.commit()

    def _update_message_state(self, msg_uuid, state):
        with self._bridge._db.get_connection() as conn:
            conn.cursor().execute(
                "UPDATE messages SET state = ? WHERE message_uuid = ?", (state, msg_uuid)
            )
            conn.commit()

    def _enqueue(self, msg_uuid, dest_id, chat_uuid, text):
        payload = json.dumps(self._build_encrypted_packet(msg_uuid, chat_uuid, text, dest_id))
        with self._bridge._db.get_connection() as conn:
            conn.cursor().execute("""
                INSERT OR IGNORE INTO message_queue
                    (message_uuid, destination_id, payload, status)
                VALUES (?, ?, ?, 'queued')
            """, (msg_uuid, dest_id, payload))
            conn.commit()

    def _dequeue_success(self, msg_uuid):
        with self._bridge._db.get_connection() as conn:
            conn.cursor().execute(
                "UPDATE message_queue SET status = 'sent' WHERE message_uuid = ?", (msg_uuid,)
            )
            conn.cursor().execute(
                "UPDATE messages SET state = 'delivered' WHERE message_uuid = ?", (msg_uuid,)
            )
            conn.cursor().execute("""
                INSERT INTO ack_records (message_uuid) VALUES (?)
                ON CONFLICT(message_uuid) DO NOTHING
            """, (msg_uuid,))
            conn.commit()
        if self._bridge._window:
            self._bridge._window.evaluate_js(
                f"if(window.onMessageAckReceived) window.onMessageAckReceived('{msg_uuid}');"
            )

    def _mark_queue_failed(self, msg_uuid):
        with self._bridge._db.get_connection() as conn:
            conn.cursor().execute(
                "UPDATE message_queue SET status = 'failed' WHERE message_uuid = ?", (msg_uuid,)
            )
            conn.cursor().execute(
                "UPDATE messages SET state = 'failed' WHERE message_uuid = ?", (msg_uuid,)
            )
            conn.commit()