import socket
import json
import threading
import time
import urllib.request

class NetworkNode:
    def __init__(self, bridge, tcp_port=9090, udp_port=9099):
        self._bridge = bridge
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.local_routing_table = {}  # ID -> {ip, port, display_name}
        self.public_wan_ip = "127.0.0.1"
        self._running = True

    def start(self):
        # Resolve public IP dynamically
        threading.Thread(target=self._resolve_public_ip, daemon=True).start()
        
        # Start local network TCP listener
        threading.Thread(target=self._start_tcp_listener, daemon=True).start()
        
        # Start local network UDP auto-discovery listener
        threading.Thread(target=self._start_udp_listener, daemon=True).start()
        
        # Start local network UDP auto-discovery beacon
        threading.Thread(target=self._start_udp_beacon, daemon=True).start()

    def _resolve_public_ip(self):
        """Discovers the external IP of the user dynamically."""
        for service in ["https://api.ipify.org", "https://ipinfo.io/ip"]:
            try:
                with urllib.request.urlopen(service, timeout=4) as response:
                    self.public_wan_ip = response.read().decode('utf-8').strip()
                    self._bridge._logger.info(f"Resolved WAN Coordinate IP: {self.public_wan_ip}")
                    return
            except Exception:
                continue
        # Fallback to local routing IP if completely offline
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.public_wan_ip = s.getsockname()[0]
            s.close()
        except Exception:
            self.public_wan_ip = "127.0.0.1"

    def get_public_ip(self):
        return self.public_wan_ip

    def resolve_user_address(self, target_id):
        """Inspects local routing table or queries database coordinates of connected friends."""
        if target_id in self.local_routing_table:
            return self.local_routing_table[target_id]
        
        # Pull saved details from SQLite to prevent need for manual reconnects
        with self._bridge._db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE public_id = ? LIMIT 1", (target_id,))
            row = cursor.fetchone()
            if row and row["status"] == "online":
                # We can assume last resolved route details (if offline queue has backlog)
                # To be absolutely sure, global registry will update this
                pass
        return None

    def _start_tcp_listener(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("0.0.0.0", self.tcp_port))
            server.listen(5)
            self._bridge._logger.info(f"P2P Link established. Listening on Port TCP {self.tcp_port}")
        except Exception as e:
            self._bridge._logger.critical(f"Failed to start TCP listener: {e}")
            return

        while self._running:
            try:
                conn, addr = server.accept()
                threading.Thread(target=self._handle_tcp_connection, args=(conn, addr), daemon=True).start()
            except Exception:
                break

    def _handle_tcp_connection(self, conn, addr):
        buffer = b""
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                buffer += data
                
            if buffer:
                packet = json.loads(buffer.decode('utf-8'))
                self._dispatch_received_packet(packet, addr[0])
        except Exception as e:
            self._bridge._logger.warning(f"Error handling inbound connection payload: {e}")
        finally:
            conn.close()

    def _dispatch_received_packet(self, packet, sender_ip):
        p_type = packet.get("type")
        if p_type == "friend_request":
            # Add dynamic routing details mapping
            self.local_routing_table[packet["sender_id"]] = {
                "ip": sender_ip,
                "port": packet["port"],
                "display_name": packet["display_name"]
            }
            self._bridge.receive_incoming_friend_request(packet)
        elif p_type == "text":
            self._bridge.receive_incoming_message(packet)

    def send_packet(self, ip, port, packet):
        """Sends data payload over the TCP network channel to another client node."""
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(4.0)
            client.connect((ip, int(port)))
            client.sendall(json.dumps(packet).encode('utf-8'))
            client.close()
            return True
        except Exception as e:
            self._bridge._logger.warning(f"Unreachable P2P channel on client {ip}:{port} - {e}")
            return False

    # --- LAN AUTO-DISCOVERY SUB-SYSTEM ---

    def _start_udp_listener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", self.udp_port))
        except Exception as e:
            self._bridge._logger.critical(f"Failed to bind UDP Discoverer socket: {e}")
            return

        while self._running:
            try:
                data, addr = sock.recvfrom(2048)
                packet = json.loads(data.decode('utf-8'))
                if packet.get("public_id") != self._bridge.my_identity["public_id"]:
                    self.local_routing_table[packet["public_id"]] = {
                        "ip": addr[0],
                        "port": packet["port"],
                        "display_name": packet["display_name"]
                    }
            except Exception:
                pass

    def _start_udp_beacon(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        while self._running:
            try:
                payload = {
                    "public_id": self._bridge.my_identity["public_id"],
                    "display_name": self._bridge.my_identity["display_name"],
                    "port": self.tcp_port
                }
                sock.sendto(json.dumps(payload).encode('utf-8'), ("255.255.255.255", self.udp_port))
            except Exception:
                pass
            time.sleep(3.0)