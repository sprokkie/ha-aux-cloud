"""
Broadlink HVAC testing module for AUX Home devices.

Use this inside Home Assistant to test LAN connectivity to AC devices.
This module has access to the local network where ACs are located.
"""

import asyncio
import logging
from typing import Dict, Any

try:
    import broadlink
    HAS_BROADLINK = True
except ImportError:
    HAS_BROADLINK = False

_LOGGER = logging.getLogger(__name__)


async def test_ac_broadlink(
    device_ip: str,
    device_mac: str,
    timeout: int = 10,
) -> Dict[str, Any]:
    """
    Test Broadlink HVAC connection to an AUX AC device.

    This function should be called from within Home Assistant to ensure
    it has network access to the AC device on the local LAN.

    Args:
        device_ip: IP address of the AC device
        device_mac: MAC address as string (e.g. '34:8e:89:75:73:bd')
        timeout: Connection timeout in seconds

    Returns:
        Dict with test results:
        {
            "success": bool,
            "device_ip": str,
            "device_mac": str,
            "error": str or None,
            "ac_info": dict or None,
        }
    """
    if not HAS_BROADLINK:
        return {
            "success": False,
            "device_ip": device_ip,
            "device_mac": device_mac,
            "error": "broadlink library not installed",
            "ac_info": None,
        }

    try:
        # Convert MAC to bytes
        mac_bytes = bytes.fromhex(device_mac.replace(':', ''))

        _LOGGER.debug(
            "Broadlink test: connecting to %s (%s)",
            device_ip, device_mac,
        )

        # Create HVAC device (0x4E2A)
        device = broadlink.gendevice(0x4E2A, (device_ip, 80), mac_bytes)
        _LOGGER.debug("Device created: %s", device)

        # Run auth in thread pool (blocking)
        await asyncio.to_thread(device.auth)
        _LOGGER.debug("Auth successful for %s", device_ip)

        # Get AC info
        ac_info = await asyncio.to_thread(device.get_ac_info)
        _LOGGER.debug("AC info for %s: %s", device_ip, ac_info)

        return {
            "success": True,
            "device_ip": device_ip,
            "device_mac": device_mac,
            "error": None,
            "ac_info": ac_info,
        }

    except broadlink.exceptions.NetworkTimeoutError as e:
        error_msg = f"Network timeout: {e}"
        _LOGGER.warning("Broadlink test failed for %s: %s", device_ip, error_msg)
        return {
            "success": False,
            "device_ip": device_ip,
            "device_mac": device_mac,
            "error": error_msg,
            "ac_info": None,
        }

    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        _LOGGER.error("Broadlink test failed for %s: %s", device_ip, error_msg)
        return {
            "success": False,
            "device_ip": device_ip,
            "device_mac": device_mac,
            "error": error_msg,
            "ac_info": None,
        }


async def test_all_known_acs() -> Dict[str, Dict[str, Any]]:
    """
    Test all known AUX Home AC devices.

    Returns:
        Dict with device MAC → test result mapping.
    """
    devices = [
        {
            "name": "AC woonkamer",
            "ip": "172.16.100.210",
            "mac": "34:8e:89:75:73:bd",
        },
        {
            "name": "AC slaapkamer",
            "ip": "172.16.100.230",
            "mac": "34:8e:89:75:77:a1",
        },
    ]

    results = {}

    for device in devices:
        result = await test_ac_broadlink(
            device["ip"],
            device["mac"],
        )
        results[device["name"]] = result

    return results
