

import asyncio
import json
import base64
import time
import hashlib
import logging
import threading

logger = logging.getLogger("nexus.dht.node")

RECORD_TTL          = 7200    # seconds — 2 hours
REPUBLISH_INTERVAL  = 1800    # seconds — 30 minutes
ALPHA               = 3       # Kademlia concurrent lookup parallelism
K                   = 20      # k-bucket size


class DHTNode:
    """
    DHT node logic — routing, storage, and lookups.

    Parameters
    ----------
    node_id      : str  — our 64-char hex User ID
    routing_table: RoutingTable
    transport    : AsyncTransport  (set via set_transport() after construction)
    key_manager  : CryptoKeyManager
    """

    def __init__(self, node_id: str, routing_table, key_manager):
        self._id            = node_id
        self._rt            = routing_table
        self._km            = key_manager
        self._transport     = None      # injected after transport starts
        self._loop          = None      # asyncio event loop reference

        # Local DHT value store: { user_id → record_dict }
        self._store: dict[str, dict] = {}
        self._store_lock = threading.Lock()

        # Republish timer
        self._republish_task = None

    def set_transport(self, transport, loop: asyncio.AbstractEventLoop):
        self._transport = transport
        self._loop      = loop

    # ──────────────────────────────────────────────
    #  Outbound RPCs
    # ──────────────────────────────────────────────

    async def ping(self, ip: str, port: int) -> bool:
        """Send a PING and return True if we get a PONG."""
        packet = self._make_packet("ping", {})
        resp   = await self._send_and_wait(ip, port, packet, timeout=3.0)
        if resp and resp.get("type") == "pong":
            self._rt.add_peer(resp.get("sender_id", ""), ip, port)
            return True
        return False

    async def find_node(self, target_id: str) -> list[dict]:
        """
        Iterative FIND_NODE: return k closest peers to target_id.
        Queries ALPHA nodes at a time, converging on the target.
        """
        seen     = set()
        closest  = self._rt.find_closest(target_id, K)
        to_query = list(closest)

        for _ in range(20):   # max iterations
            batch = [p for p in to_query if p["node_id"] not in seen][:ALPHA]
            if not batch:
                break

            tasks = [self._query_find_node(p["ip"], p["port"], target_id) for p in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for p, result in zip(batch, results):
                seen.add(p["node_id"])
                if isinstance(result, list):
                    for new_peer in result:
                        if new_peer["node_id"] not in seen:
                            self._rt.add_peer(new_peer["node_id"], new_peer["ip"], new_peer["port"])
                            to_query.append(new_peer)

            to_query.sort(key=lambda x: int(x["node_id"], 16) ^ int(target_id, 16))

        return self._rt.find_closest(target_id, K)

    async def store(self, user_id: str, ip: str, port: int):
        """
        Publish our address record to the K closest peers to our User ID.
        Signs the record with our Ed25519 private key.
        """
        record = self._make_signed_record(user_id, ip, port)

        # Also store locally
        with self._store_lock:
            self._store[user_id] = record

        # Find K closest nodes and ask them to STORE
        closest = await self.find_node(user_id)
        tasks   = [self._send_store(p["ip"], p["port"], record) for p in closest[:K]]
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info(f"DHT STORE: published {user_id[:12]}… → {ip}:{port} to {len(closest)} peers")

    async def find_value(self, user_id: str) -> dict | None:
        """
        Iterative FIND_VALUE: search the DHT for a user_id's address record.
        Returns the verified record dict, or None if not found.
        """
        # Check local store first
        with self._store_lock:
            if user_id in self._store:
                record = self._store[user_id]
                if self._is_record_fresh(record) and self._verify_record(record):
                    return record

        seen     = set()
        closest  = self._rt.find_closest(user_id, K)
        to_query = list(closest)

        for _ in range(20):
            batch = [p for p in to_query if p["node_id"] not in seen][:ALPHA]
            if not batch:
                break

            tasks   = [self._query_find_value(p["ip"], p["port"], user_id) for p in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for p, result in zip(batch, results):
                seen.add(p["node_id"])
                if isinstance(result, dict):
                    if result.get("type") == "found_value":
                        record = result.get("record")
                        if record and self._verify_record(record) and self._is_record_fresh(record):
                            # Cache locally for fast future lookups
                            with self._store_lock:
                                self._store[user_id] = record
                            return record
                    elif result.get("type") == "closest_nodes":
                        for new_peer in result.get("nodes", []):
                            if new_peer["node_id"] not in seen:
                                self._rt.add_peer(new_peer["node_id"], new_peer["ip"], new_peer["port"])
                                to_query.append(new_peer)

            to_query.sort(key=lambda x: int(x["node_id"], 16) ^ int(user_id, 16))

        logger.warning(f"DHT FIND_VALUE: {user_id[:12]}… not found in network.")
        return None

    # ──────────────────────────────────────────────
    #  Synchronous wrappers (for use from bridge.py)
    # ──────────────────────────────────────────────

    def find_value_sync(self, user_id: str, timeout: float = 8.0) -> dict | None:
        """Thread-safe blocking wrapper around find_value()."""
        if self._loop is None:
            return None
        future = asyncio.run_coroutine_threadsafe(self.find_value(user_id), self._loop)
        try:
            return future.result(timeout=timeout)
        except Exception as e:
            logger.warning(f"find_value_sync failed: {e}")
            return None

    def store_sync(self, user_id: str, ip: str, port: int):
        """Thread-safe blocking wrapper around store()."""
        if self._loop is None:
            return
        future = asyncio.run_coroutine_threadsafe(self.store(user_id, ip, port), self._loop)
        try:
            future.result(timeout=10.0)
        except Exception as e:
            logger.warning(f"store_sync failed: {e}")

    # ──────────────────────────────────────────────
    #  Inbound RPC handler (called by transport)
    # ──────────────────────────────────────────────

    async def handle_dht_packet(self, packet: dict, sender_ip: str, sender_port: int) -> dict | None:
        """
        Dispatch an inbound DHT packet.
        Returns a response packet to be sent back, or None.
        """
        ptype     = packet.get("type")
        sender_id = packet.get("sender_id", "")

        # Always update routing table on receipt
        if sender_id and sender_id != self._id:
            self._rt.add_peer(sender_id, sender_ip, sender_port)

        if ptype == "ping":
            return self._make_packet("pong", {})

        elif ptype == "find_node":
            target  = packet.get("target_id", "")
            closest = self._rt.find_closest(target, K)
            return self._make_packet("closest_nodes", {"nodes": closest})

        elif ptype == "store":
            record = packet.get("record")
            if record and self._verify_record(record):
                uid = record.get("user_id")
                if uid:
                    with self._store_lock:
                        existing = self._store.get(uid)
                        # Only accept if newer than what we have
                        if not existing or record["timestamp"] > existing["timestamp"]:
                            self._store[uid] = record
            return self._make_packet("store_ack", {})

        elif ptype == "find_value":
            target = packet.get("target_id", "")
            with self._store_lock:
                record = self._store.get(target)
            if record and self._is_record_fresh(record):
                return self._make_packet("found_value", {"record": record})
            else:
                closest = self._rt.find_closest(target, K)
                return self._make_packet("closest_nodes", {"nodes": closest})

        return None

    # ──────────────────────────────────────────────
    #  Republish loop
    # ──────────────────────────────────────────────

    async def start_republish_loop(self, my_ip_getter, my_port: int):
        """
        Coroutine — republishes our address to the DHT every REPUBLISH_INTERVAL.
        my_ip_getter is a callable that returns our current public IP string.
        """
        while True:
            try:
                ip = my_ip_getter()
                await self.store(self._id, ip, my_port)
                logger.info(f"DHT republish: {self._id[:12]}… → {ip}:{my_port}")
            except Exception as e:
                logger.warning(f"DHT republish error: {e}")
            await asyncio.sleep(REPUBLISH_INTERVAL)

    # ──────────────────────────────────────────────
    #  Record signing & verification
    # ──────────────────────────────────────────────

    def _make_signed_record(self, user_id: str, ip: str, port: int) -> dict:
        ts      = time.time()
        payload = f"{user_id}{ip}{port}{ts:.3f}".encode("utf-8")
        sig     = self._km.sign(payload)
        return {
            "user_id":     user_id,
            "ip":          ip,
            "port":        port,
            "timestamp":   ts,
            "ed25519_pub": self._km.get_ed25519_public_bytes().hex(),
            "signature":   sig.hex(),
        }

    def _verify_record(self, record: dict) -> bool:
        try:
            user_id    = record["user_id"]
            ip         = record["ip"]
            port       = record["port"]
            ts         = record["timestamp"]
            pub_hex    = record["ed25519_pub"]
            sig_hex    = record["signature"]

            pub_bytes = bytes.fromhex(pub_hex)
            sig_bytes = bytes.fromhex(sig_hex)
            payload   = f"{user_id}{ip}{port}{ts:.3f}".encode("utf-8")

            # Check the user_id is actually SHA256 of the claimed public key
            expected_id = hashlib.sha256(pub_bytes).hexdigest()
            if expected_id != user_id:
                logger.warning("DHT record: user_id mismatch (possible spoof).")
                return False

            return self._km.verify(pub_bytes, sig_bytes, payload)
        except Exception as e:
            logger.warning(f"DHT record verification failed: {e}")
            return False

    @staticmethod
    def _is_record_fresh(record: dict) -> bool:
        return (time.time() - record.get("timestamp", 0)) < RECORD_TTL

    # ──────────────────────────────────────────────
    #  Low-level helpers
    # ──────────────────────────────────────────────

    def _make_packet(self, ptype: str, payload: dict) -> dict:
        packet = {"type": ptype, "sender_id": self._id}
        packet.update(payload)
        return packet

    async def _send_and_wait(self, ip: str, port: int, packet: dict,
                              timeout: float = 4.0) -> dict | None:
        if self._transport is None:
            return None
        try:
            return await self._transport.send_and_receive(ip, port, packet, timeout)
        except Exception:
            return None

    async def _query_find_node(self, ip: str, port: int, target_id: str) -> list:
        packet = self._make_packet("find_node", {"target_id": target_id})
        resp   = await self._send_and_wait(ip, port, packet)
        if resp and resp.get("type") == "closest_nodes":
            return resp.get("nodes", [])
        return []

    async def _send_store(self, ip: str, port: int, record: dict):
        packet = self._make_packet("store", {"record": record})
        await self._send_and_wait(ip, port, packet, timeout=3.0)

    async def _query_find_value(self, ip: str, port: int, target_id: str) -> dict:
        packet = self._make_packet("find_value", {"target_id": target_id})
        resp   = await self._send_and_wait(ip, port, packet)
        return resp or {}