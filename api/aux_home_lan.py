"""
AUX Home local network (LAN) discovery and Broadlink protocol queries.

Discovers AC devices on the local network via active ARP scanning and queries them
directly using the Broadlink protocol, bypassing cloud cache lag (~8-11 minutes).

Device type: 0x4E2A (HVAC class in broadlink library)
Protocol: Broadlink HVAC over TCP port 80

Active discovery strategy:
1. Determine local interface(s) and subnet(s) via `ip route`
2. Send ARP requests to all possible IPs in the subnet(s)
3. Match responses against known AC MAC addresses
4. Query responding devices via Broadlink HVAC protocol

This ensures automatic discovery without requiring users to manually find IP addresses.

Reference:
- AC device type: 0x4E2A (hvac)
- AC MAC addresses: known from the API (34:8E:89:75:73:BD, etc.)
- Query method: broadlink.gendevice(0x4E2A, (ip, 80), mac_bytes).auth() + .get_ac_info()
"""

import asyncio
import ipaddress
import logging
import re
import struct
import subprocess
from typing import Optional

# Try to import broadlink, but don't fail if not available
try:
    import broadlink
    HAS_BROADLINK = True
except ImportError:
    HAS_BROADLINK = False

_LOGGER = logging.getLogger(__package__)


def _get_local_subnets() -> list[str]:
    """
    Determine local network subnet(s) using 'ip route'.

    Parses the output to find all active networks reachable without a gateway.
    Typical output line: "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100"

    Returns:
        List of subnet CIDR notations (e.g. ['192.168.1.0/24', '10.0.0.0/8']).
        Empty list if unable to determine.
    """
    try:
        result = subprocess.run(
            ["/sbin/ip", "route"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if result.returncode != 0:
            _LOGGER.warning("ip route failed: %s", result.stderr)
            return []

        subnets = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            # Look for lines like "192.168.1.0/24 dev eth0 proto kernel"
            # (connected directly without a gateway)
            if " dev " in line and " proto kernel" in line and " via " not in line:
                parts = line.split()
                if parts:
                    subnet_str = parts[0]
                    # Verify it's a valid CIDR notation
                    try:
                        ipaddress.ip_network(subnet_str, strict=False)
                        subnets.append(subnet_str)
                        _LOGGER.debug("Found local subnet: %s", subnet_str)
                    except ValueError:
                        pass

        return subnets

    except subprocess.TimeoutExpired:
        _LOGGER.warning("ip route timed out")
        return []
    except Exception as exc:
        _LOGGER.warning("Failed to determine local subnets: %s", exc)
        return []


def _parse_arp_output(arp_output: str) -> dict:
    """
    Parse 'arp -a' output and return a dict of MAC → IP mappings.

    Expected format per line:
      hostname (192.168.1.1) at 34:8e:89:75:73:bd [ether] on eth0
    or
      ? (192.168.1.1) at 34:8e:89:75:73:bd [ether] on eth0
    """
    mac_to_ip = {}
    for line in arp_output.strip().split("\n"):
        if not line.strip():
            continue
        # Extract IP from (x.x.x.x) and MAC from xx:xx:...
        ip_match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
        mac_match = re.search(
            r"([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})",
            line,
        )
        if ip_match and mac_match:
            ip = ip_match.group(1)
            mac = mac_match.group(1).lower()
            mac_to_ip[mac] = ip
    return mac_to_ip


async def _arping_single(ip: str, timeout: float = 0.5) -> Optional[str]:
    """
    Send a single ARP request to an IP and return the MAC address if it responds.

    Uses the 'arping' command to send ARP requests (faster and more direct
    than relying on the ARP cache alone).

    Args:
        ip: IP address to query (e.g. '192.168.1.100')
        timeout: Timeout for arping command in seconds

    Returns:
        MAC address in lowercase if the device responds, None otherwise.
    """
    try:
        result = await asyncio.to_thread(
            subprocess.run,
            ["/usr/sbin/arping", "-c", "1", "-w", str(int(timeout * 1000)), ip],
            capture_output=True,
            text=True,
            timeout=timeout + 1,
        )

        # arping output line format: "ARPING from 192.168.1.100 (34:8e:89:75:73:bd)"
        # or "Unicast reply from 192.168.1.100 [34:8e:89:75:73:BD]"
        # Look for MAC in square brackets or parentheses
        for line in result.stdout.split("\n"):
            mac_match = re.search(
                r"[\[\(]([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})[\]\)]",
                line,
            )
            if mac_match:
                return mac_match.group(1).lower()

        return None

    except Exception as exc:
        _LOGGER.debug("arping to %s failed: %s", ip, exc)
        return None


async def discover_acs_via_arp(known_macs: list[str]) -> dict[str, str]:
    """
    Discover AC devices on the local network via passive ARP table scan.

    Checks the current ARP cache (fast, requires prior network activity).
    Does NOT send new ARP requests — useful as a fallback after active discovery.

    Args:
        known_macs: List of MAC addresses to look for (e.g. ['34:8e:89:75:73:bd'])

    Returns:
        Dict mapping MAC → IP for discovered devices.
        Empty dict if no devices found or arp command fails.
    """
    try:
        # Run 'arp -a' to get current ARP table
        result = await asyncio.to_thread(
            subprocess.run,
            ["/sbin/arp", "-a"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            _LOGGER.warning("ARP scan failed: %s", result.stderr)
            return {}

        # Parse output and find matches
        mac_to_ip = _parse_arp_output(result.stdout)
        discovered = {}

        for mac in known_macs:
            mac_lower = mac.lower()
            if mac_lower in mac_to_ip:
                discovered[mac_lower] = mac_to_ip[mac_lower]
                _LOGGER.debug("AUX Home LAN: found %s at %s", mac_lower, mac_to_ip[mac_lower])

        return discovered

    except subprocess.TimeoutExpired:
        _LOGGER.warning("ARP scan timed out")
        return {}
    except Exception as exc:
        _LOGGER.warning("ARP scan failed: %s", exc)
        return {}


async def discover_acs_active(known_macs: list[str], timeout: float = 30.0) -> dict[str, str]:
    """
    Actively discover AC devices on the local network by sending ARP requests.

    This is the primary discovery method for end users. It:
    1. Determines the local subnet(s) using 'ip route'
    2. Sends ARP requests to all possible IPs in each subnet
    3. Matches responses against known AC MAC addresses

    This method doesn't require ACs to have been active recently —
    it will wake them up on the network automatically.

    Args:
        known_macs: List of MAC addresses to look for (e.g. ['34:8e:89:75:73:bd'])
        timeout: Total timeout for the entire discovery process in seconds

    Returns:
        Dict mapping MAC → IP for discovered devices.
        Empty dict if no devices found or discovery times out.
    """
    try:
        # Step 1: Determine local subnets
        subnets = _get_local_subnets()
        if not subnets:
            _LOGGER.warning("AUX Home: could not determine local subnets")
            return {}

        _LOGGER.debug("AUX Home: scanning subnets for ACs: %s", subnets)

        # Step 2: Generate list of IPs to scan
        ips_to_scan = []
        for subnet_str in subnets:
            try:
                network = ipaddress.ip_network(subnet_str, strict=False)

                # Skip very large subnets (e.g. /8, /16) to avoid scanning too many IPs
                # A /24 has 254 hosts, /16 has 65534, /8 has 16 million.
                # Realistically, home ACs are in /24 or /23 subnets.
                num_hosts = network.num_addresses - 2  # Exclude network and broadcast
                if num_hosts > 1000:
                    _LOGGER.warning(
                        "AUX Home: skipping large subnet %s (%d hosts) "
                        "to avoid excessive ARP traffic",
                        subnet_str, num_hosts,
                    )
                    continue

                # Exclude network and broadcast addresses
                host_ips = list(network.hosts())
                ips_to_scan.extend([str(ip) for ip in host_ips])
                _LOGGER.debug(
                    "AUX Home: will scan %d IPs in subnet %s",
                    len(host_ips), subnet_str,
                )

            except ValueError as exc:
                _LOGGER.warning("Invalid subnet %s: %s", subnet_str, exc)

        if not ips_to_scan:
            _LOGGER.warning("AUX Home: no valid IPs to scan in subnets %s", subnets)
            return {}

        _LOGGER.debug("AUX Home: will scan %d IPs", len(ips_to_scan))

        # Step 3: Send ARP requests in parallel with timeout
        # Use a semaphore to limit concurrent arping requests
        semaphore = asyncio.Semaphore(20)  # Max 20 parallel requests

        async def _scan_with_sem(ip):
            async with semaphore:
                return ip, await _arping_single(ip)

        start_time = asyncio.get_event_loop().time()
        remaining_timeout = timeout

        scan_tasks = [_scan_with_sem(ip) for ip in ips_to_scan]
        results = []

        try:
            results = await asyncio.wait_for(
                asyncio.gather(*scan_tasks, return_exceptions=True),
                timeout=remaining_timeout,
            )
        except asyncio.TimeoutError:
            _LOGGER.warning(
                "AUX Home: active ARP scan timed out after %.1fs",
                timeout,
            )
            # Continue with partial results
            pass

        # Step 4: Match responses against known MACs
        discovered = {}
        for item in results:
            if isinstance(item, Exception):
                continue
            if not isinstance(item, tuple) or len(item) != 2:
                continue

            ip, mac = item
            if mac is None:
                continue

            # Check if this MAC is one of our known ACs
            for known_mac in known_macs:
                if mac == known_mac.lower():
                    discovered[mac] = ip
                    _LOGGER.info(
                        "AUX Home: discovered AC %s at %s via active ARP scan",
                        mac, ip,
                    )

        elapsed = asyncio.get_event_loop().time() - start_time
        _LOGGER.debug(
            "AUX Home: active ARP scan completed in %.1fs, found %d AC(s)",
            elapsed,
            len(discovered),
        )
        return discovered

    except Exception as exc:
        _LOGGER.error("AUX Home: active discovery failed: %s", exc)
        return {}


def _build_broadlink_query_packet() -> bytes:
    """
    Build a Broadlink query packet to request AC status.

    Packet structure (13 bytes):
      [0] 0xBB: Broadlink magic header
      [1-5]: 0x000680 0x0000 (command/flags)
      [6-10]: 0x040051 0x0100 (query params)
      [11-12]: 0x00e9 (placeholder checksum, overwritten by device)

    The actual packet observed in production: bb0006800000040051010000e97d

    Returns:
        13-byte Broadlink query packet as bytes.
    """
    # Build the fixed packet structure
    packet = bytearray([
        0xBB,  # Magic header
        0x00, 0x06, 0x80,  # Command/flags
        0x00, 0x00,  # Padding
        0x04, 0x00, 0x51,  # Query params
        0x01, 0x00, 0x00,  # More params
    ])
    return bytes(packet)


async def query_device_lan(
    device_ip: str,
    device_password: str = "",
    timeout: float = 3.0,
) -> str:
    """
    Query an AC device directly on the local network using Broadlink protocol.

    Sends a raw Broadlink query packet to the AC's local IP via UDP
    and returns the response hex string (same format as cloud status.running).

    Args:
        device_ip: Local IP address of the AC device
        device_password: Device password (included in packet; currently unused in query)
        timeout: Socket timeout in seconds

    Returns:
        Response hex string (e.g. 'bb0006800000...'), or empty string on failure.
    """
    query_packet = _build_broadlink_query_packet()

    try:
        # Create UDP socket
        loop = asyncio.get_event_loop()
        transport, protocol = await asyncio.wait_for(
            loop.create_datagram_endpoint(
                lambda: _BroadlinkQueryProtocol(timeout),
                remote_addr=(device_ip, 6053),
            ),
            timeout=timeout,
        )
    except Exception as exc:
        _LOGGER.warning(
            "AUX Home LAN: failed to create UDP socket to %s:6053 — %s", device_ip, exc
        )
        return ""

    try:
        # Send query packet
        transport.sendto(query_packet)

        # Wait for response
        response_hex = await asyncio.wait_for(
            protocol.response_future,
            timeout=timeout,
        )
        return response_hex

    except asyncio.TimeoutError:
        _LOGGER.warning("AUX Home LAN: query to %s timed out", device_ip)
        return ""
    except Exception as exc:
        _LOGGER.warning("AUX Home LAN: query to %s failed — %s", device_ip, exc)
        return ""
    finally:
        transport.close()


class _BroadlinkQueryProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for Broadlink device queries."""

    def __init__(self, timeout: float):
        self.timeout = timeout
        self.response_future = asyncio.Future()
        self._timeout_handle = None

    def connection_made(self, transport):
        self._transport = transport
        # Schedule timeout
        loop = asyncio.get_event_loop()
        self._timeout_handle = loop.call_later(
            self.timeout,
            self._on_timeout
        )

    def datagram_received(self, data, addr):
        if not self.response_future.done():
            self._timeout_handle.cancel()
            response_hex = data.hex()
            _LOGGER.debug(
                "AUX Home LAN: received response from %s:%s — %d bytes: %s",
                addr[0], addr[1], len(data), response_hex,
            )
            self.response_future.set_result(response_hex)

    def error_received(self, exc):
        _LOGGER.warning("AUX Home LAN: UDP error — %s", exc)
        if not self.response_future.done():
            self.response_future.set_exception(exc)

    def connection_lost(self, exc):
        if exc and not self.response_future.done():
            self.response_future.set_exception(exc)

    def _on_timeout(self):
        if not self.response_future.done():
            self.response_future.set_exception(asyncio.TimeoutError())


# Known AUX Home AC MACs (from API responses)
# Note: Hostnames are AC-SMT-<MAC_suffix> (e.g. AC-SMT-75-73-bd for woonkamer)
KNOWN_AC_MACS = [
    "34:8e:89:75:73:bd",  # AC woonkamer (hostname: AC-SMT-75-73-bd.fritz.box, IP: 172.16.100.210)
    "34:8e:89:75:77:a1",  # AC slaapkamer (hostname: AC-SMT-75-77-a1.fritz.box, IP: 172.16.100.230)
]


async def discover_all_acs() -> dict[str, str]:
    """
    Discover all known AUX Home ACs on the local network.

    Returns:
        Dict mapping MAC → IP for discovered devices.
    """
    return await discover_acs_via_arp(KNOWN_AC_MACS)


def _mac_string_to_bytes(mac_string: str) -> bytes:
    """
    Convert MAC address string to bytes.

    Args:
        mac_string: MAC address as string (e.g. '34:8e:89:75:73:bd')

    Returns:
        MAC address as bytes (e.g. b'4\x8e\x89us\xbd')
    """
    return bytes(int(x, 16) for x in mac_string.split(':'))


async def query_device_broadlink(
    device_ip: str,
    device_mac: str,
    device_password: str = "",
) -> dict:
    """
    Query an AUX AC device using the Broadlink HVAC protocol.

    Uses the python-broadlink library (device type 0x4E2A for HVAC).
    This is the correct protocol for AUX AC devices.

    Args:
        device_ip: IP address of the AC device
        device_mac: MAC address as string (e.g. '34:8e:89:75:73:bd')
        device_password: Device password (used for authentication)

    Returns:
        Dict with AC status/info, or empty dict on failure.

    Raises:
        ImportError if broadlink library is not installed.
    """
    if not HAS_BROADLINK:
        _LOGGER.error(
            "AUX Home: broadlink library not installed. "
            "Install with: pip install broadlink"
        )
        return {}

    try:
        # Convert MAC string to bytes
        mac_bytes = _mac_string_to_bytes(device_mac)

        # Create Broadlink HVAC device (0x4E2A is the device type for AUX AC)
        device = broadlink.gendevice(
            0x4E2A,
            (device_ip, 80),
            mac_bytes,
        )

        _LOGGER.debug("AUX Home: created Broadlink device for %s", device_mac)

        # Authenticate with the device
        await asyncio.to_thread(device.auth)
        _LOGGER.debug("AUX Home: authenticated with device at %s", device_ip)

        # Get AC status/info
        ac_info = await asyncio.to_thread(device.get_ac_info)
        _LOGGER.debug("AUX Home: got AC info from %s: %s", device_ip, ac_info)

        return ac_info or {}

    except ImportError:
        _LOGGER.error("AUX Home: broadlink library not installed")
        return {}
    except Exception as exc:
        _LOGGER.warning(
            "AUX Home: Broadlink query failed for %s: %s",
            device_ip, exc,
        )
        return {}
