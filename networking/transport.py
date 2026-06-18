
import asyncio
import socket
import struct
import json
import logging
import threading
import time
import urllib.request
import re

logger = logging.getLogger("nexus.networking.transport")

class AsyncTransport:
    def __init__(self, bridge, tcp_port=7777):
        self._bridge = bridge
        self._tcp_port = tcp_port
        self._loop = None
        self._thread = None
        self._server = None
        self._active_connections = {}  # { (ip, port): (reader, writer) }
        self.local_routing_table = {}  # { user_id: { "ip": ip, "port": port, "display_name": name } }
        self._public_ip = "127.0.0.1"

    def start(self):
        """Start the asyncio event loop inside a background thread."""
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def _run_loop(self):
        """Thread worker executing the asyncio event loop."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        
        # Trigger background WAN port mapping via UPnP
        self._loop.run_until_complete(self._setup_upnp())
        
        # Resolve Public IP in the loop
        self._loop.run_until_complete(self._resolve_public_ip())
        
        # Start TCP Server
        self._loop.run_until_complete(self._start_server())
        
        logger.info(f"Transport thread fully running on loop. Port: {self._tcp_port}")
        self._loop.run_forever()

    async def _start_server(self):
        """Instantiate the TCP server."""
        try:
            self._server = await asyncio.start_server(
                self._handle_inbound_client, "0.0.0.0", self._tcp_port
            )
            logger.info(f"TCP server listening on port {self._tcp_port}")
        except Exception as e:
            logger.error(f"Failed to start TCP server on port {self._tcp_port}: {e}")

    # ──────────────────────────────────────────────
    #  Inbound Connection Handler & Frame Reader
    # ──────────────────────────────────────────────

    async def _handle_inbound_client(self, reader, writer):
        """Handle incoming frame-prefixed payloads asynchronously."""
        peer_addr = writer.get_extra_info('peername')
        logger.debug(f"Inbound TCP connection established from: {peer_addr}")
        
        try:
            while True:
                # 1. Read 4-byte big-endian length prefix
                length_bytes = await reader.readexactly(4)
                if not length_bytes:
                    break
                
                payload_length = struct.unpack("!I", length_bytes)[0]
                
                # 2. Read exactly the amount of bytes specified in the header
                payload_bytes = await reader.readexactly(payload_length)
                packet_str = payload_bytes.decode('utf-8')
                packet = json.loads(packet_str)
                
                # 3. Route packet
                await self._dispatch_packet(packet, peer_addr[0], writer)
        except asyncio.IncompleteReadError:
            logger.debug(f"Peer {peer_addr} closed the connection stream.")
        except Exception as e:
            logger.warning(f"Connection error handling {peer_addr}: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _dispatch_packet(self, packet, sender_ip, writer):
        """Send packet data up to the APIBridge routing systems."""
        ptype = packet.get("type", "")
        sender_id = packet.get("sender_id", "")
        
        # Handle simple routing table updates
        if sender_id:
            self.local_routing_table[sender_id] = {
                "ip": sender_ip,
                "port": packet.get("port", self._tcp_port),
                "display_name": packet.get("display_name", sender_id[:12])
            }

        # Intercept DHT packets and process them directly in the dht_node
        if ptype.startswith("dht_") or ptype in ["ping", "find_node", "store", "find_value"]:
            if hasattr(self._bridge, '_dht_node') and self._bridge._dht_node:
                resp = await self._bridge._dht_node.handle_dht_packet(
                    packet, sender_ip, packet.get("port", self._tcp_port)
                )
                if resp:
                    await self._send_packet_via_writer(writer, resp)
            return

        # Handle direct handshake / friendship exchanges
        if ptype == "friend_request":
            self._bridge.receive_incoming_friend_request(packet)
        elif ptype == "friend_accepted":
            self._bridge.receive_incoming_friend_acceptance(packet)
        elif ptype == "text":
            self._bridge.receive_incoming_message(packet)
        elif ptype == "msg_ack":
            self._bridge.register_remote_ack(packet.get("message_uuid", ""))

    # ──────────────────────────────────────────────
    #  Outbound Senders & RPC Await Loops
    # ──────────────────────────────────────────────

    def send_packet(self, ip, port, packet) -> bool:
        """Synchronously schedule an outbound TCP package transmission (fire-and-forget)."""
        if not self._loop:
            return False
        fut = asyncio.run_coroutine_threadsafe(self._send_packet_async(ip, port, packet), self._loop)
        try:
            return fut.result(timeout=6.0)
        except Exception as e:
            logger.warning(f"Failed to send packet to {ip}:{port} : {e}")
            return False

    async def _send_packet_async(self, ip, port, packet) -> bool:
        """Asynchronously connect, write length-prefixed frame, and close stream."""
        try:
            reader, writer = await asyncio.open_connection(ip, port)
            await self._send_packet_via_writer(writer, packet)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception as e:
            logger.debug(f"TCP packet send error to {ip}:{port} : {e}")
            return False

    async def _send_packet_via_writer(self, writer, packet):
        """Helper to write length-prefixed binary frames safely."""
        try:
            payload = json.dumps(packet).encode('utf-8')
            length_prefix = struct.pack("!I", len(payload))
            writer.write(length_prefix + payload)
            await writer.drain()
        except Exception as e:
            logger.warning(f"Error writing to output stream: {e}")

    async def send_and_receive(self, ip, port, packet, timeout=4.0) -> dict | None:
        """Send a request frame and await an immediate response on the same TCP channel (RPC pattern)."""
        try:
            reader, writer = await asyncio.open_connection(ip, port)
            # Write request
            await self._send_packet_via_writer(writer, packet)
            
            # Read response
            length_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
            payload_length = struct.unpack("!I", length_bytes)[0]
            payload_bytes = await asyncio.wait_for(reader.readexactly(payload_length), timeout=timeout)
            
            resp = json.loads(payload_bytes.decode('utf-8'))
            writer.close()
            await writer.wait_closed()
            return resp
        except Exception:
            # Silence expected network lookup timeouts
            return None

    # ──────────────────────────────────────────────
    #  UPnP Port Mapping System (No AWS / Cloud Hosting Required)
    # ──────────────────────────────────────────────

    async def _setup_upnp(self):
        """Pure-Python UPnP client. Discovers router gateway and requests TCP port mapping."""
        logger.info("Starting automated UPnP router configuration...")
        try:
            await asyncio.get_event_loop().run_in_executor(None, self._run_upnp_discovery)
        except Exception as e:
            logger.warning(f"UPnP automated mapping failed: {e}")

    def _run_upnp_discovery(self):
        """Thread worker executing UPnP SSDP search and SOAP map calls."""
        # 1. Simple Service Discovery Protocol (SSDP) Probe
        ssdp_request = (
            'M-SEARCH * HTTP/1.1\r\n'
            'HOST: 239.255.255.250:1900\r\n'
            'MAN: "ssdp:discover"\r\n'
            'MX: 2\r\n'
            'ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n'
        ).encode('utf-8')

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        
        soap_url = None
        try:
            sock.sendto(ssdp_request, ('239.255.255.250', 1900))
            while True:
                data, addr = sock.recvfrom(2048)
                resp = data.decode('utf-8', errors='ignore')
                match = re.search(r'LOCATION:\s*(http://[^\r\n]+)', resp, re.IGNORECASE)
                if match:
                    soap_url = match.group(1)
                    break
        except socket.timeout:
            logger.warning("SSDP Discovery timed out. No UPnP compatible router found.")
        finally:
            sock.close()

        if not soap_url:
            return

        # 2. Query XML configuration to locate Control URL
        try:
            req = urllib.request.Request(soap_url, headers={'User-Agent': 'Nexus-Client'})
            with urllib.request.urlopen(req, timeout=3.0) as response:
                xml_data = response.read().decode('utf-8', errors='ignore')

            # Search control URL path inside IGD specification
            control_match = re.search(r'<controlURL>([^<]*WANIPConnection[^<]*)</controlURL>', xml_data, re.IGNORECASE)
            if not control_match:
                control_match = re.search(r'<controlURL>([^<]*WANCommonInterface[^<]*)</controlURL>', xml_data, re.IGNORECASE)
            if not control_match:
                control_match = re.search(r'<controlURL>([^<]*)</controlURL>', xml_data, re.IGNORECASE)

            if not control_match:
                logger.warning("Failed to locate SOAP control path inside router schema.")
                return

            control_path = control_match.group(1)
            # Reconstruct full endpoint URL
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(soap_url)
            control_url = urlunparse((parsed.scheme, parsed.netloc, control_path, '', '', ''))

            # 3. Dispatch SOAP Port Mapping Payload
            local_ip = self._get_local_ip()
            soap_body = f"""<?xml version="1.0"?>
            <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <s:Body>
            <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
                <NewRemoteHost></NewRemoteHost>
                <NewExternalPort>{self._tcp_port}</NewExternalPort>
                <NewProtocol>TCP</NewProtocol>
                <NewInternalPort>{self._tcp_port}</NewInternalPort>
                <NewInternalClient>{local_ip}</NewInternalClient>
                <NewEnabled>1</NewEnabled>
                <NewPortMappingDescription>Nexus P2P DHT</NewPortMappingDescription>
                <NewLeaseDuration>0</NewLeaseDuration>
            </u:AddPortMapping>
            </s:Body>
            </s:Envelope>"""

            headers = {
                'Content-Type': 'text/xml; charset="utf-8"',
                'SOAPACTION': '"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"',
                'User-Agent': 'Nexus-Client'
            }

            post_req = urllib.request.Request(control_url, data=soap_body.encode('utf-8'), headers=headers, method='POST')
            with urllib.request.urlopen(post_req, timeout=3.0) as soap_resp:
                if soap_resp.status in [200, 201]:
                    logger.info(f"UPnP SUCCESS: Port {self._tcp_port} has been dynamically mapped at the router!")
        except Exception as ex:
            logger.warning(f"SOAP port mapping request failed: {ex} (Your router may have UPnP disabled).")

    # ──────────────────────────────────────────────
    #  IP Utilities & Getters
    # ──────────────────────────────────────────────

    def _get_local_ip(self):
        """Get host machine LAN IP."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    async def _resolve_public_ip(self):
        """Asynchronously resolve public WAN IP through reliable zero-fee APIs."""
        apis = [
            "https://api.ipify.org",
            "https://ident.me",
            "https://icanhazip.com"
        ]
        
        def check_api(url):
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3.0) as res:
                    return res.read().decode('utf-8').strip()
            except Exception:
                return None

        for api in apis:
            resolved = await asyncio.get_event_loop().run_in_executor(None, check_api, api)
            if resolved:
                self._public_ip = resolved
                logger.info(f"Resolved public IP: {self._public_ip}")
                return
        
        # Fallback LAN IP
        self._public_ip = self._get_local_ip()

    def get_public_ip(self) -> str:
        """Returns resolved public IP address."""
        return self._public_ip