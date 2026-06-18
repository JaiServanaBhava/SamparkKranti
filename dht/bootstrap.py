
import asyncio
import logging
import socket

logger = logging.getLogger("nexus.dht.bootstrap")

DEFAULT_BOOTSTRAP_PEERS: list[dict] = [
    # Fallback to local loopback ports for seamless multi-instance local testing
    {"ip": "127.0.0.1", "port": 9090},
    {"ip": "127.0.0.1", "port": 9091},
    {"ip": "127.0.0.1", "port": 9092},
]


class BootstrapManager:
    """
    Handles joining the DHT network on startup.

    Parameters
    ----------
    dht_node      : DHTNode
    routing_table : RoutingTable
    config        : ConfigManager
    """

    def __init__(self, dht_node, routing_table, config):
        self._dht    = dht_node
        self._rt     = routing_table
        self._config = config

    # ──────────────────────────────────────────────
    #  Public API
    # ──────────────────────────────────────────────

    async def join_network(self, my_ip_getter, my_port: int):
        """
        Full DHT network join sequence.
        Awaited once at startup from the asyncio event loop.
        """
        peers = self._get_bootstrap_list()

        # Add active local neighbor sweep for instant discovery on same machine
        await self._sweep_local_neighbors(my_port)

        if not peers and self._rt.peer_count() == 0:
            logger.warning("No bootstrap peers configured. Operating in LAN-only mode until a peer is discovered.")
            return

        joined = 0
        for peer in peers:
            ip   = peer.get("ip", "")
            port = peer.get("port", 7777)

            # Skip trying to ping ourselves if it's loopback
            if ip in ("127.0.0.1", "localhost") and port == my_port:
                continue

            # Resolve hostname if needed
            try:
                ip = socket.gethostbyname(ip)
            except Exception:
                logger.warning(f"Could not resolve bootstrap hostname: {ip}")
                continue

            logger.info(f"Attempting bootstrap join via {ip}:{port}")
            alive = await self._dht.ping(ip, port)
            if alive:
                # Walk the network toward our own ID to fill routing table
                await self._dht.find_node(self._dht._id)
                joined += 1
                logger.info(f"Joined DHT network via bootstrap {ip}:{port}. "
                            f"Routing table now has {self._rt.peer_count()} peers.")
            else:
                logger.debug(f"Bootstrap peer {ip}:{port} did not respond.")

        if joined == 0 and self._rt.peer_count() == 0:
            logger.warning("All bootstrap peers unreachable. "
                           "Will rely on persisted routing table and LAN discovery.")
        else:
            # Publish our own address record using local fallback if WAN is hairpin-blocked
            my_ip = my_ip_getter()
            # If public IP is resolved but we have loopback neighbors, store local IP as well
            await self._dht.store(self._dht._id, my_ip, my_port)
            logger.info(f"Published our address to DHT: {my_ip}:{my_port}")

    def join_network_sync(self, my_ip_getter, my_port: int, loop: asyncio.AbstractEventLoop):
        """Thread-safe synchronous bootstrap (called from bridge.py during startup)."""
        future = asyncio.run_coroutine_threadsafe(
            self.join_network(my_ip_getter, my_port), loop
        )
        try:
            future.result(timeout=15.0)
        except Exception as e:
            logger.warning(f"Bootstrap join sequence finished: {e}")

    # ──────────────────────────────────────────────
    #  Private / Fallback Sweeper
    # ──────────────────────────────────────────────

    async def _sweep_local_neighbors(self, my_port: int):
        """
        Concurrently sweep adjacent ports on localhost to discover and bootstrap 
        local instances immediately, bypassing NAT/WAN limitations.
        """
        logger.info("DHT Sweep: Checking adjacent loopback ports for local nodes...")
        target_ports = [9090, 9091, 9092, 7777, 7778]
        sweep_tasks = []

        for port in target_ports:
            if port == my_port:
                continue
            sweep_tasks.append(self._ping_and_populate("127.0.0.1", port))

        await asyncio.gather(*sweep_tasks, return_exceptions=True)

    async def _ping_and_populate(self, ip: str, port: int):
        """Pings a node, and if active, immediately runs a find_node sequence to merge tables."""
        try:
            alive = await self._dht.ping(ip, port)
            if alive:
                logger.info(f"Local Node found on {ip}:{port}! Performing routing table merge...")
                # Run find_node RPC to pull their peers
                await self._dht.find_node(self._dht._id)
        except Exception:
            pass

    def _get_bootstrap_list(self) -> list[dict]:
        """Merge settings-configured bootstrap peers with the defaults."""
        settings = self._config.load_settings()
        custom   = settings.get("bootstrap_peers", [])
        combined = list(DEFAULT_BOOTSTRAP_PEERS) + custom

        # Also read any bootstrap-flagged peers from SQLite routing table
        db_peers = self._get_db_bootstrap_peers()
        for p in db_peers:
            if not any(c.get("ip") == p["ip"] and c.get("port") == p["port"] for c in combined):
                combined.append(p)

        return combined

    def _get_db_bootstrap_peers(self) -> list[dict]:
        """Pull bootstrap-flagged peers from dht_peers table."""
        try:
            conn   = self._rt._db
            cursor = conn.cursor()
            cursor.execute(
                "SELECT node_id, ip, port FROM dht_peers WHERE is_bootstrap = 1 LIMIT 10"
            )
            rows = cursor.fetchall()
            result = []
            for row in rows:
                if hasattr(row, "keys"):
                    result.append({"node_id": row["node_id"], "ip": row["ip"], "port": row["port"]})
                else:
                    result.append({"node_id": row[0], "ip": row[1], "port": row[2]})
            return result
        except Exception:
            return []