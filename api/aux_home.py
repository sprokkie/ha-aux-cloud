"""AUX Home API client (eu-smthome-api.aux-global.com)."""

import asyncio
import base64
import json
import logging
import time

import aiohttp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from . import aux_home_lan

_LOGGER = logging.getLogger(__package__)

AUX_HOME_SERVER_EU = "https://eu-smthome-api.aux-global.com"

# Dummy family used to satisfy the coordinator's family-based device loop
_AUX_HOME_FAMILY_ID = "aux_home_default"

# AUX Home devices report productKey "00010001" which maps to the standard
# AC_GENERIC product ID used by the rest of the integration.
_AUX_HOME_AC_PRODUCT_ID = "000000000000000000000000c0620000"


def _encrypt_account(email: str) -> str:
    """
    Dynamically encrypt email using AES-ECB (key from app binary).
    Formula: base64(AES_ECB_encrypt(email, "4083aux63e3444a2"))
    """
    key = b'4083aux63e3444a2'
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(email.encode('utf-8'), 16)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode()


class AuxHomeApiError(Exception):
    """Exception raised when AUX Home API calls fail."""


def _decode_running_hex(running_hex: str) -> dict:
    """
    Decode the status.running hex string returned by GET /app/user_device into
    the params dict format expected by HA entity platforms.

    Protocol layout verified against live mitmproxy captures (two devices,
    one off and one heating at 19°C):

      [0]   0xBB  magic header
      [6]   target temperature in BCD  (0x19 → 19°C; params['temp'] = bcd * 10)
      [10]  ambient temperature °C      (23 → 23°C; params['envtemp'] = byte×10)
      [11]  bit0 = power (1=on, 0=off)
      [14]  fan speed raw              (7=auto → stored as 0)
      [13]  active mode: 1=fan, 2=heat, 3=cool(est), 4=dry(est), 0=idle/auto
      [15]  device-specific constant (NOT the mode — ignore)
    """
    if not running_hex:
        return {}
    try:
        b = bytes.fromhex(running_hex)
    except ValueError:
        _LOGGER.warning("AUX Home: cannot decode running hex '%s'", running_hex)
        return {}

    if len(b) < 27:
        return {}

    params: dict = {}

    # Power: byte[11] bit 0
    params["pwr"] = 1 if (b[11] & 0x01) else 0

    # AC mode: byte[11] bits 5-7 (mask 0xE0)
    # AUX Cloud modes: 0=cool, 1=heat, 2=dry, 3=fan, 4=auto
    _AUX_HOME_MODE_MAP = {
        0x00: 0,  # AUTO
        0x20: 1,  # COOL
        0x40: 2,  # DRY
        0x80: 4,  # HEAT
        0xC0: 6,  # FAN
    }
    params["ac_mode"] = _AUX_HOME_MODE_MAP.get(b[11] & 0xE0, 0)

    # Fan speed: determined from (b[13], b[14]) together because b[14] alone is ambiguous
    # (e.g. b[14]=0x0e appears for both mid-lower and turbo with different b[13] values).
    # Confirmed (b[13], b[14]) → ac_mark mappings:
    #   (0x00, 0x00) → auto      (off/idle)
    #   (0x01, 0x07) → low       (confirmed)
    #   (0x01, 0x08) → mute      (confirmed)
    #   (0x03, 0x0d) → mid lower (confirmed)
    #   (0x03, 0x0e) → mid lower (confirmed, sub-step 2)
    #   (0x04, 0x13) → medium    (confirmed)
    #   (0x05, 0x18) → mid higher(confirmed)
    #   (0x06, 0x04) → high      (confirmed)
    #   (0x07, 0x0e) → turbo     (confirmed)
    # AUX Cloud ac_mark: 0=auto, 1=low, 6=mid lower, 2=medium, 7=mid higher, 3=high, 4=turbo, 5=mute
    _AUX_HOME_FAN_MAP = {
        (0x00, 0x00): 0,  # auto/off
        (0x01, 0x07): 5,  # SILENT (mute) - confirmed by polling
        (0x01, 0x0d): 1,  # LOW - confirmed by polling
        (0x03, 0x0d): 6,  # MID-LOW - confirmed by polling
        (0x03, 0x0e): 6,  # MID-LOW sub-step
        (0x04, 0x13): 2,  # MID (medium) - confirmed by polling
        (0x04, 0x14): 0,  # AUTO - confirmed by polling
        (0x05, 0x18): 7,  # MID-HIGH - confirmed by polling
        (0x06, 0x04): 3,  # HIGH - confirmed by polling
        (0x07, 0x0e): 4,  # TURBO - confirmed by polling
    }
    params["ac_mark"] = _AUX_HOME_FAN_MAP.get((b[13], b[14]), 0)

    # Target temperature: byte[6] is binary in 0.5°C steps with offset 7°C.
    # temp = b[6] / 2 + 7  (e.g. 0x19=25 → 25/2+7 = 19.5°C)
    # Stored internally as °C * 10 for compatibility with the rest of the integration.
    params["temp"] = b[6] * 5 + 70

    # Ambient temperature: from ESPHome AUX component source
    # b[15] = integer part (offset by 0x20)
    # b[31] lower nibble = decimal part (0-9)
    # Result in °C * 10 (e.g. 21.5°C = 215)
    params["envtemp"] = (b[15] - 0x20) * 10 + (b[31] & 0x0F)

    # Eco mode: byte[11] bit 7
    params["ecomode"] = 1 if (b[11] & 0x80) else 0

    _LOGGER.debug("AUX Home: decoded params from running hex: %s", params)
    return params


class AuxHomeAPI:
    """
    API client for the AUX Home app (smthome backend).

    Uses Bearer token authentication: the same Bearer token built from
    credentials for the login POST is reused on all subsequent requests.
    """

    # Proactively re-login when the session is older than this many seconds.
    # The server expires the session cache in roughly 5 minutes; refresh at 4.
    _SESSION_TTL = 240

    def __init__(self, region: str = "aux_home_eu"):
        self.url = AUX_HOME_SERVER_EU
        self.region = region
        self.email = None
        self.password = None
        self.userid = None
        # Must be populated for the coordinator's family loop
        self.families = None
        # The Bearer token built from credentials is the auth token reused on all calls
        self._auth_token = None
        self._logged_in = False
        self._login_time: float = 0.0
        # Serialise re-login attempts so concurrent requests don't each spawn a login
        self._relogin_lock = asyncio.Lock()
        # Optimistic param cache: device_id → {param: value} set by control commands.
        # Merged into decoded params on the next get_devices poll so the UI reflects
        # changes immediately without waiting for the server to update the running hex.
        self._optimistic: dict = {}
        self._optimistic_ttl: dict = {}   # device_id → expiry monotonic time
        self._last_running_hex: dict = {}  # device_id → last seen running hex

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_headers(self, **kwargs):
        # Exact headers observed in mitmproxy capture from the AUX Home app.
        # No Content-Type — the login POST has an empty body and the app omits it.
        headers = {
            "user-agent": "AUXAC/2.2.0 (iPhone; iOS 26.3.1; Scale/3.00)",
            "os": "2",
            "country": "NLD",
            "aid": "1",
        }
        # Include the stored Bearer token on all requests once authenticated
        if self._auth_token and "Authorization" not in kwargs:
            headers["Authorization"] = f"Bearer {self._auth_token}"
        headers.update(kwargs)
        return headers

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        headers: dict = None,
        data: dict = None,
        params: dict = None,
        ssl: bool = False,
        _reauth: bool = True,
    ):
        url = f"{self.url}/{endpoint}"
        _LOGGER.debug("AUX Home: %s %s", method, url)
        async with aiohttp.ClientSession() as session:
            async with session.request(
                method=method,
                url=url,
                headers=headers or self._get_headers(),
                json=data if data and method.upper() != "GET" else None,
                params=params,
                ssl=ssl,
                # Prevent aiohttp adding headers the app does not send;
                # Content-Type is still injected automatically when json= is used.
                skip_auto_headers={"Accept", "Accept-Encoding"},
            ) as response:
                response_text = await response.text()
                _LOGGER.debug("AUX Home response from %s: %.500s", endpoint, response_text)
                try:
                    json_data = json.loads(response_text)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"AUX Home: failed to parse JSON from {endpoint}: {response_text}"
                    ) from exc

        # Re-authenticate transparently on session-expired errors (60106)
        # but only for non-login calls to avoid infinite recursion.
        # The lock ensures that when many requests expire at once only one
        # re-login actually runs; the others wait and reuse the new token.
        if (
            _reauth
            and endpoint not in ("app/auth/getPubkey", "app/auth/login/pwd")
            and isinstance(json_data, dict)
            and json_data.get("code") == 60106
            and self.email
        ):
            async with self._relogin_lock:
                # Another coroutine may have already refreshed the token while
                # we were waiting for the lock — only re-login if still needed.
                if not self.is_logged_in():
                    _LOGGER.debug("AUX Home: session expired (60106), re-authenticating")
                    await self.login(self.email, self.password)
            return await self._make_request(
                method=method,
                endpoint=endpoint,
                data=data,
                params=params,
                ssl=ssl,
                _reauth=False,
            )

        return json_data

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    async def _get_pubkey(self) -> tuple[str, object]:
        """
        GET /app/auth/getPubkey — returns (pubkey_b64, rsa_public_key_object).
        The server generates a fresh RSA-1024 keypair on each call.
        """
        json_data = await self._make_request(
            method="GET",
            endpoint="app/auth/getPubkey",
            ssl=False,
            _reauth=False,
        )
        pubkey_b64 = json_data.get("data") or ""
        if not pubkey_b64:
            raise AuxHomeApiError(f"AUX Home: no public key in getPubkey response: {json_data}")
        pub = serialization.load_der_public_key(base64.b64decode(pubkey_b64))
        return pubkey_b64, pub

    async def login(self, email: str = None, password: str = None):
        """
        Authenticate with the AUX Home backend using the two-step RSA login.

        Step 1: GET /app/auth/getPubkey  → fresh RSA-1024 public key
        Step 2: POST /app/auth/login/pwd → RSA-encrypted password + fixed AES-encrypted account

        The account field is the AES-encrypted email (hardcoded from mitmproxy capture;
        the AES key is embedded in the app binary).  The password is RSA-encrypted with
        PKCS1v15 using the server's fresh public key.

        On success: response data.token.token is stored as the Bearer token for all
        subsequent API calls.  A 60106 on any later call triggers a transparent re-login.
        """
        if email is not None:
            self.email = email
        if password is not None:
            self.password = password

        self._logged_in = False
        self._auth_token = None

        # Step 1: get fresh RSA public key
        pubkey_b64, pub = await self._get_pubkey()

        # Step 2: RSA-encrypt the plaintext password (PKCS1 v1.5)
        encrypted_password = base64.b64encode(
            pub.encrypt(self.password.encode("utf-8"), rsa_padding.PKCS1v15())
        ).decode()

        # The account field is the AES-encrypted email (dynamic encryption using key from app binary)
        encrypted_account = _encrypt_account(self.email)

        body = {
            "account": encrypted_account,
            "password": encrypted_password,
            "ts": str(int(time.time() * 1000)),
            "publicKeyBase64": pubkey_b64,
        }

        json_data = await self._make_request(
            method="POST",
            endpoint="app/auth/login/pwd",
            data=body,
            ssl=False,
            _reauth=False,
        )

        if not isinstance(json_data, dict):
            raise AuxHomeApiError(f"AUX Home login: unexpected response: {json_data}")

        code = json_data.get("code")
        if code not in (0, "0", 200, "200"):
            raise AuxHomeApiError(f"AUX Home login failed (code={code}): {json_data}")

        inner = json_data.get("data") or {}
        app_user = inner.get("appUser") or {}
        token_obj = inner.get("token") or {}

        self.userid = str(app_user.get("uid") or "aux_home_user")
        self._auth_token = token_obj.get("token")
        if not self._auth_token:
            raise AuxHomeApiError(f"AUX Home login: no token in response: {json_data}")

        self._logged_in = True
        self._login_time = time.monotonic()
        _LOGGER.debug("AUX Home login successful, user=%s", self.userid)
        return True

    def is_logged_in(self) -> bool:
        if not self._logged_in or not self._auth_token:
            return False
        # Treat the session as expired a bit before the server does
        return (time.monotonic() - self._login_time) < self._SESSION_TTL

    # ------------------------------------------------------------------
    # Device discovery
    # ------------------------------------------------------------------

    async def get_families(self):
        """
        Return a single dummy family so the coordinator's family loop works
        without modification.  AUX Home has no concept of families.
        """
        if self.families is None:
            self.families = {}
        self.families[_AUX_HOME_FAMILY_ID] = {
            "id": _AUX_HOME_FAMILY_ID,
            "name": "AUX Home",
            "rooms": [],
            "devices": [],
        }
        return [{"familyid": _AUX_HOME_FAMILY_ID, "name": "AUX Home"}]

    async def get_devices(
        self,
        familyid: str = None,
        shared: bool = False,
        selected_devices: list = None,
    ):
        """
        Fetch devices from AUX Home.

        GET /app/user_device?getStatus=1

        Shared devices are not a concept in AUX Home, so shared=True
        always returns an empty list.
        """
        if shared:
            return []

        json_data = await self._make_request(
            method="GET",
            endpoint="app/user_device",
            params={"getStatus": "1"},
            ssl=False,
        )

        # Extract raw device list — handle several common response shapes
        raw_devices = []
        if isinstance(json_data, dict):
            inner = json_data.get("data") or json_data
            if isinstance(inner, list):
                raw_devices = inner
            elif isinstance(inner, dict):
                raw_devices = (
                    inner.get("devices")
                    or inner.get("deviceList")
                    or inner.get("list")
                    or []
                )

        devices = []
        for raw in raw_devices:
            if not isinstance(raw, dict):
                continue

            device_id = str(
                raw.get("deviceId")
                or raw.get("did")
                or raw.get("devId")
                or raw.get("id")
                or ""
            )
            if not device_id:
                _LOGGER.warning("AUX Home: skipping device with no ID: %s", raw)
                continue

            if selected_devices and device_id not in selected_devices:
                continue

            # "alias" is the user-assigned name in the AUX Home app
            friendly_name = str(
                raw.get("alias")
                or raw.get("deviceName")
                or raw.get("name")
                or device_id
            )
            mac = str(raw.get("mac") or raw.get("macAddress") or "")
            # Map AUX Home productKey to the AC_GENERIC product ID that the
            # integration's entity platforms recognise.  All AUX Home AC
            # devices report productKey "00010001".
            product_id = _AUX_HOME_AC_PRODUCT_ID

            # "online" is a boolean field returned when getStatus=1
            state = 1 if raw.get("online") else 0

            # Extract AC state from status sub-object
            status_obj = raw.get("status") or {}
            _LOGGER.debug("Raw device state: %s", raw)
            running_hex = str(status_obj.get("running") or "")
            control_hex = str(status_obj.get("control") or "")

            # Decode running hex into the params dict expected by HA entities.
            params = _decode_running_hex(running_hex)

            # If the device pushed a new running hex since last poll, it means the
            # device itself reported fresh state — clear the optimistic cache so we
            # don't override the real state with our stale command values.
            last_hex = self._last_running_hex.get(device_id)
            if running_hex and last_hex and running_hex != last_hex:
                _LOGGER.debug(
                    "AUX Home: running hex changed for %s — clearing optimistic cache",
                    device_id,
                )
                self._optimistic.pop(device_id, None)
                self._optimistic_ttl.pop(device_id, None)
            self._last_running_hex[device_id] = running_hex

            # Merge any pending optimistic updates (from recent control commands)
            # so the UI reflects changes before the server running hex updates.
            now = time.monotonic()
            if device_id in self._optimistic:
                if now < self._optimistic_ttl.get(device_id, 0):
                    params.update(self._optimistic[device_id])
                else:
                    self._optimistic.pop(device_id, None)
                    self._optimistic_ttl.pop(device_id, None)

            device = {
                "endpointId": device_id,
                "friendlyName": friendly_name,
                "productId": product_id,
                "mac": mac,
                "devSession": str(raw.get("devSession") or raw.get("token") or ""),
                "devicetypeFlag": str(raw.get("deviceType") or raw.get("type") or "0"),
                "roomId": str(raw.get("roomId") or ""),
                "cookie": raw.get("cookie") or "",
                "state": state,
                # Device password used for local/cloud control
                "password": str(raw.get("password") or ""),
                # Hex state strings from the status object
                "running": running_hex,
                "control": control_hex,
                # Params decoded from status.running hex
                "params": params,
                "last_updated": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                # Preserve the full raw payload for future mapping
                "_aux_home_raw": raw,
            }
            devices.append(device)

        _LOGGER.debug("AUX Home: found %d device(s)", len(devices))
        return devices

    # ------------------------------------------------------------------
    # LAN discovery and direct device queries (bypasses server cache)
    # ------------------------------------------------------------------

    async def discover_devices_on_lan(
        self,
        mac_list: list = None,
        active: bool = True,
        timeout: float = 30.0,
    ) -> dict[str, str]:
        """
        Discover AC devices on the local network.

        By default uses active ARP scanning (sends ARP requests), which doesn't
        require the ACs to have been active recently. Falls back to passive ARP
        table scan if active scan times out or is disabled.

        Args:
            mac_list: List of MAC addresses to search for (e.g. ['34:8e:89:75:73:bd']).
                     If None, uses the known AUX Home AC MACs.
            active: If True (default), actively sends ARP requests to the subnet.
                   If False, only checks the existing ARP cache (faster but may miss devices).
            timeout: Timeout for active discovery in seconds (only if active=True).

        Returns:
            Dict mapping MAC → local IP for devices found on the LAN.
            Empty dict if no devices discovered.
        """
        if mac_list is None:
            mac_list = aux_home_lan.KNOWN_AC_MACS

        # Try active discovery first (if enabled)
        if active:
            discovered = await aux_home_lan.discover_acs_active(mac_list, timeout=timeout)
            if discovered:
                _LOGGER.debug("AUX Home: active LAN discovery found %d device(s)", len(discovered))
                return discovered

        # Fallback to passive ARP table scan
        discovered = await aux_home_lan.discover_acs_via_arp(mac_list)
        _LOGGER.debug("AUX Home: passive ARP discovery found %d device(s)", len(discovered))
        return discovered

    async def query_device_state_lan(
        self,
        device_ip: str,
        device_mac: str = None,
        device_password: str = "",
        use_broadlink: bool = True,
    ) -> dict:
        """
        Query an AC device directly on the local network.

        Returns the device's current state via a direct LAN query, bypassing the
        cloud server's ~8-11 minute cache lag.

        Tries two methods in order:
        1. Broadlink HVAC protocol (if library available and device_mac provided)
        2. Raw UDP Broadlink query (fallback)

        Args:
            device_ip: Local IP address of the AC device
            device_mac: MAC address of device (required for Broadlink HVAC method)
            device_password: Device password (used for Broadlink auth)
            use_broadlink: If True, try Broadlink HVAC first (recommended)

        Returns:
            Decoded params dict (same format as _decode_running_hex), or empty dict on failure.
        """
        # Try Broadlink HVAC protocol first (more reliable)
        if use_broadlink and device_mac:
            ac_info = await aux_home_lan.query_device_broadlink(
                device_ip,
                device_mac,
                device_password=device_password,
            )
            if ac_info:
                _LOGGER.debug(
                    "AUX Home LAN: Broadlink query to %s returned: %s",
                    device_ip, ac_info,
                )
                return ac_info

        # Fallback: raw UDP Broadlink query
        response_hex = await aux_home_lan.query_device_lan(
            device_ip,
            device_password=device_password,
        )

        if response_hex:
            params = _decode_running_hex(response_hex)
            _LOGGER.debug(
                "AUX Home LAN: UDP query to %s decoded params: %s",
                device_ip, params,
            )
            return params

        return {}

    # ------------------------------------------------------------------
    # Live device query (bypasses server cache)
    # ------------------------------------------------------------------

    async def query_device_state(self, device_id: str, product_key: str, password: str = "") -> dict:
        """
        Query the AC device directly for its current state.

        POST /app/device/through/commonQuery
        Body: {"deviceId": "<id>", "productKey": "<key>", "dst": 1, "password": "<passcode>"}

        Unlike GET /app/user_device which returns a server-side cache,
        this endpoint proxies the query through to the physical device
        and returns its live state.

        Returns a decoded params dict (same format as _decode_running_hex),
        or an empty dict on failure.
        """
        body = {
            "deviceId": device_id,
            "productKey": product_key,
            "dst": 1,
        }
        if password:
            body["password"] = password

        try:
            json_data = await self._make_request(
                method="POST",
                endpoint="app/device/through/commonQuery",
                data=body,
                ssl=False,
            )

            _LOGGER.debug(
                "AUX Home: commonQuery response for %s: %s", device_id, json_data
            )

            if not isinstance(json_data, dict):
                _LOGGER.warning(
                    "AUX Home: commonQuery non-dict response for %s: %s",
                    device_id, json_data,
                )
                return {}

            code = json_data.get("code")
            if code not in (0, "0", 200, "200"):
                _LOGGER.warning(
                    "AUX Home: commonQuery failed code=%s for %s: %s",
                    code, device_id, json_data,
                )
                return {}

            # Try to find a running hex in the response
            data = json_data.get("data") or {}
            running_hex = ""
            if isinstance(data, dict):
                status = data.get("status") or {}
                running_hex = str(
                    status.get("running")
                    or data.get("running")
                    or ""
                )

            if running_hex:
                params = _decode_running_hex(running_hex)
                _LOGGER.debug(
                    "AUX Home: commonQuery decoded params for %s: %s",
                    device_id, params,
                )
                return params

            # Response format unknown — log in full for analysis
            _LOGGER.warning(
                "AUX Home: commonQuery returned no running hex for %s — "
                "full response: %s",
                device_id, json_data,
            )
            return {}

        except Exception as exc:
            _LOGGER.warning(
                "AUX Home: commonQuery failed for %s: %s", device_id, exc
            )
            return {}

    # ------------------------------------------------------------------
    # Device control (not yet mapped — stubs for interface compatibility)
    # ------------------------------------------------------------------

    async def get_device_params(self, device: dict, params: list = None):
        """
        Retrieve live device parameters by fetching fresh status from the API.

        Calls GET /app/user_device?getStatus=1, finds the matching device by
        endpointId, and decodes the status.running hex into params.
        Falls back to the cached value on the device dict if the API call fails.
        """
        device_id = device.get("endpointId")

        try:
            json_data = await self._make_request(
                method="GET",
                endpoint="app/user_device",
                params={"getStatus": "1"},
                ssl=False,
            )

            raw_devices = []
            if isinstance(json_data, dict):
                inner = json_data.get("data") or json_data
                if isinstance(inner, list):
                    raw_devices = inner

            for raw in raw_devices:
                raw_id = str(raw.get("deviceId") or raw.get("did") or "")
                if raw_id == device_id:
                    status_obj = raw.get("status") or {}
                    running_hex = str(status_obj.get("running") or "")
                    return _decode_running_hex(running_hex)

            _LOGGER.warning("AUX Home: device %s not found in fresh device list", device_id)

        except Exception as exc:
            _LOGGER.warning("AUX Home: get_device_params failed for %s: %s", device_id, exc)

        # Fallback to cached params
        return device.get("params") or {}

    async def set_device_params(self, device: dict, values: dict):
        """
        Send parameter changes to a device.

        POST /app/device/v2/control
        Body: {"intent": {field: value, ...}, "dst": 1, "deviceId": "<id>"}

        AUX Home uses different intent field names and value scales from the
        AUX Cloud param names used internally by HA entities.  Confirmed via
        APK decompilation (DEX string table + bytecode analysis):

          AUX Cloud param  → AUX Home intent field  notes
          ─────────────────────────────────────────────────────────
          pwr (0/1)        → on_off (0/1)
          temp (°C×10)     → temperature (°C integer)
          ac_mark          → wind_speed
          ecomode          → eco
          ac_display/scr   → screen
          (clean)          → clean
          ac_mode          → air_con_func  (APK-confirmed key; values: 0=auto,1=cool,2=dry,4=heat,6=fan)
        """
        # AUX Cloud mode → AUX Home air_con_func value (APK-confirmed)
        # AUX Cloud: 0=cool, 1=heat, 2=dry, 3=fan, 4=auto
        # AUX Home:  1=cool, 4=heat, 2=dry, 6=fan, 0=auto
        _CLOUD_TO_AUX_HOME_MODE = {0: 1, 1: 4, 2: 2, 3: 6, 4: 0}

        # AUX Cloud fan speed → AUX Home wind_speed
        # AUX Cloud: 0=auto, 1=low, 6=mid lower, 2=medium, 7=mid higher, 3=high, 4=turbo, 5=mute
        # AUX Home: wind_speed values are IDENTICAL to ac_mark (verified from device responses)
        _CLOUD_TO_AUX_HOME_FAN = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7}

        # Translate AUX Cloud param names → AUX Home intent field names
        # Confirmed from APK DEX bytecode analysis (classes.dex string table).
        _PARAM_MAP = {
            "pwr":        "on_off",
            "ac_mark":    "wind_speed",
            "ecomode":    "eco",
            "scrdisp":    "screen",       # AC_SCREEN_DISPLAY
            "ac_screen":  "screen",
            "ac_display": "screen",
            "ac_slp":     "sleep_mode",   # AC_SLEEP
            "ac_vdir":    "up_down_swing",     # AC_SWING_VERTICAL
            "ac_hdir":    "left_right_swing",  # AC_SWING_HORIZONTAL
            "ac_clean":   "clean",        # AC_CLEAN
            "ac_health":  "healthy",      # AC_HEALTH
            "comfwind":   "comfort_wind", # AC_COMFORTABLE_WIND
            "pwrlimit":   "power_limit",  # AC_POWER_LIMIT
        }

        intent = {}
        for key, val in values.items():
            if key == "temp":
                # temp is stored as °C×10 internally; AUX Home expects plain °C integer
                intent["temperature"] = int(val) // 10
            elif key == "ac_mode":
                # Translate AUX Cloud mode → AUX Home air_con_func value (APK-confirmed key).
                aux_home_mode = _CLOUD_TO_AUX_HOME_MODE.get(int(val), int(val))
                intent["air_con_func"] = aux_home_mode
                _LOGGER.debug("AUX Home: ac_mode %s → air_con_func %s", val, aux_home_mode)
            elif key == "ac_mark":
                # Translate AUX Cloud fan speed → AUX Home wind_speed.
                # Sent as string to match the API's expected type.
                aux_home_fan = _CLOUD_TO_AUX_HOME_FAN.get(int(val), int(val))
                intent["wind_speed"] = str(aux_home_fan)
                _LOGGER.debug("AUX Home: ac_mark %s → wind_speed %s", val, aux_home_fan)
            else:
                intent_key = _PARAM_MAP.get(key, key)
                intent[intent_key] = val

        if not intent:
            _LOGGER.debug("AUX Home: set_device_params nothing to send for %s", values)
            return {}

        device_id = device.get("endpointId") or device.get("deviceId")
        if not device_id:
            _LOGGER.error("AUX Home: set_device_params called with no device ID")
            return {}

        # The AUX Home API rejects a combined on_off+mode intent with 60003.
        # Split them: send on_off first, then the rest.
        intents_to_send = []
        if "on_off" in intent and len(intent) > 1:
            intents_to_send.append({"on_off": intent.pop("on_off")})
        intents_to_send.append(intent)

        last_response = {}
        any_success = False
        for single_intent in intents_to_send:
            body = {"intent": single_intent, "dst": 1, "deviceId": device_id}
            _LOGGER.debug("AUX Home: control %s body=%s", device_id, body)
            json_data = await self._make_request(
                method="POST",
                endpoint="app/device/v2/control",
                data=body,
                ssl=False,
            )
            if not isinstance(json_data, dict):
                _LOGGER.error("AUX Home: control non-dict response: %s", json_data)
                continue
            code = json_data.get("code")
            if code not in (0, "0", 200, "200"):
                _LOGGER.error("AUX Home: control failed code=%s intent=%s response=%s", code, single_intent, json_data)
            else:
                _LOGGER.warning("AUX Home: control success code=%s intent=%s", code, single_intent)
                any_success = True
            last_response = json_data

        # Cache optimistic params so the next get_devices poll reflects the new
        # state before the server updates the running hex (TTL = 5 minutes).
        if any_success:
            self._optimistic.setdefault(device_id, {}).update(values)
            self._optimistic_ttl[device_id] = time.monotonic() + 90

        return last_response
