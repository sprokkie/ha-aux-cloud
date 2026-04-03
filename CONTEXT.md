# AuxCloud Integration - Project Context

**Last Updated:** 2026-04-02

This document contains ALL known information about the AuxCloud Home Assistant integration for AUX air conditioners and heat pumps. Use this to restore context in future sessions.

---

## API Server & Endpoints

**Base URL:** `https://eu-smthome-api.aux-global.com`

### Authentication
- **GET `/app/auth/getPubkey`**
  - Returns RSA public key (base64-encoded DER)
  - No authentication required
  - Used in two-step login flow

- **POST `/app/auth/login/pwd`**
  - Body: `{ account, password, ts, publicKeyBase64 }`
  - `account` = **PRE-COMPUTED AES-encrypted email** (NOT plaintext) — stored in app binary
    - `your-guest@example.com` → `<AES encrypted email>`
    - If plaintext email is sent: API returns `code=0` with empty devices list (fails silently)
  - `password` = RSA-encrypted (PKCS1v15) user password, base64-encoded
  - `ts` = timestamp in milliseconds
  - Response: `{ code: 200, data: { token: { token: "..." } } }`
  - Returns Bearer token used for all subsequent requests

### Device Operations
- **GET `/app/user_device?getStatus=1`** (required for status)
  - Response: `{ code: 200, data: [ { deviceId, alias, status: { running, control }, ... } ] }`
  - `data` is an **array** of devices (NOT an object with `.devices` sub-key)
  - Device name is in `alias` field (NOT `name`)
  - `status.running` = 27-byte hex string encoding device state
  - **NO `params` field in API response** — must manually decode `running` hex
  - Called by coordinator to refresh device state

- **POST `/app/device/v2/control`**
  - Body: `{ intent: {...}, dst: 1, deviceId: <endpoint_id> }`
  - `intent` = parameter changes (e.g. `{wind_speed: "6", on_off: 1}`)
  - Returns response with `code` (0/200 = success)
  - ⚠️ Cannot combine `on_off` + mode in single call (returns 60003 error) — split into separate requests

- **POST `/app/device/commonQuery`** ❌
  - **BROKEN:** Returns 500 error (root cause unknown)
  - Was supposed to enable faster device queries
  - Abandoned for now; using main `/app/user_device` instead

---

## Device Response Format (running_hex)

**Structure:** 27-byte hex string decoded to byte array

| Byte | Field | Encoding | Notes |
|------|-------|----------|-------|
| [0] | Magic | 0xBB | Constant header |
| [6] | Target temp | BCD | `b[6] * 5 + 70` = °C * 10 |
| [11] | Bit 0 = Power | Bitfield | 1=on, 0=off |
| [11] | Bit 7 = Eco | Bitfield | 1=eco on, 0=eco off |
| [13] | Mode group | Mixed | Also encodes fan speed group (see table below) |
| [14] | Fan speed sub | Mixed | Used with b[13] to determine fan speed |
| [26] | Ambient temp | Direct | °C * 10 (e.g. 0xbe=190=19.0°C) |

**Mode Encoding (b[13]):**
| b[13] | Mode |
|-------|------|
| 0x00 | Auto/Idle (ac_mode=4) |
| 0x01-0x07 | Heat (ac_mode=1) |
| 0x02 | Fan-only (ac_mode=3) |
| 0x03-0x07 | Heat with different fan groups |
| TODO | Cool (ac_mode=0) - not yet confirmed |
| TODO | Dry (ac_mode=2) - not yet confirmed |

---

## Confirmed Mappings

### AC Mode (ac_mode / air_con_func)

**Cloud representation (stored in HA):**
- 0 = Cool
- 1 = Heat
- 2 = Dry
- 3 = Fan-only
- 4 = Auto

**API transmission to AUX Home (air_con_func parameter):**
- 1 = Cool
- 4 = Heat
- 2 = Dry
- 6 = Fan-only
- 0 = Auto

**Mapping:** `{0: 1, 1: 4, 2: 2, 3: 6, 4: 0}`

**Device byte mapping (b[13]):**
- 0x00 = 4 (auto)
- 0x01-0x07 = 1 (heat) — specific value depends on fan speed
- 0x02 = 3 (fan-only)
- **TODO:** Cool and dry modes not yet tested on actual device

---

### Wind Speed (ac_mark / wind_speed)

**Cloud representation (stored in HA):**
- 0 = Auto
- 1 = Low
- 2 = Medium
- 3 = High
- 4 = Turbo
- 5 = Silent/Mute
- 6 = Mid-Low (between low and medium)
- 7 = Mid-High (between medium and high)

**API transmission to AUX Home (wind_speed parameter):**
- **SAME AS ac_mark** (verified 2026-04-02)
- `wind_speed=6` → mid-lower
- `wind_speed=2` → medium
- etc.

**Confirmed Fan Speed Mapping (b[13], b[14] bytes) — VERIFIED via polling (2026-04-02 to 2026-04-03):**

Decoding requires BOTH b[13] and b[14] bytes:
- LOW: b13=0x01, b14=0x07 (ac_mark=1)
- SILENT: b13=0x01, b14=0x07 (ac_mark=5) — same bytes as LOW
- MEDIUM: b13=0x04, b14=0x13 (ac_mark=2)
- AUTO: b13=0x04, b14=0x14 (ac_mark=0) — different from MEDIUM by b14 only
- MID-LOW: b13=0x03, b14=0x0d (ac_mark=6)
- MID-HIGH: b13=0x05, b14=0x18 (ac_mark=7)
- HIGH: b13=0x06, b14=0x04 (ac_mark=3)
- TURBO: b13=0x07, b14=0x0e (ac_mark=4)

**Device byte mapping (b[13], b[14]) — CONFIRMED via device captures:**

| b[13] | b[14] | ac_mark | Speed |
|-------|-------|---------|-------|
| 0x00 | 0x00 | 0 | Auto/Off |
| 0x01 | 0x07 | 1 | Low |
| 0x01 | 0x08 | 5 | Silent/Mute |
| 0x03 | 0x0d | 6 | Mid-Lower |
| 0x03 | 0x0e | 6 | Mid-Lower (sub-step) |
| 0x04 | 0x13 | 2 | Medium |
| 0x05 | 0x18 | 7 | Mid-Higher |
| 0x06 | 0x04 | 3 | High |
| 0x07 | 0x0e | 4 | Turbo |

**CRITICAL BUG FIXED (2026-04-02):** Old mapping in line 750 of `aux_home.py` was wrong:
```python
# OLD (WRONG):
_CLOUD_TO_AUX_HOME_FAN = {0: 4, 1: 0, 6: 1, 2: 1, 7: 2, 3: 2, 4: 5, 5: 3}
# This caused ac_mark=6 and ac_mark=2 to both send wind_speed=1

# NEW (CORRECT):
_CLOUD_TO_AUX_HOME_FAN = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7}
```

---

### Temperature

**Target Temperature:**
- **HA Param:** `AC_TEMPERATURE_TARGET` = "temp"
- **Storage:** Integer, °C * 10 (e.g. 190 = 19.0°C)
- **Device byte:** b[6] in BCD format
- **Calculation:** `b[6] * 5 + 70` = value to store

**Ambient Temperature (Room Temperature) — CONFIRMED (2026-04-03):**
- **HA Param:** `AC_TEMPERATURE_AMBIENT` = "envtemp"
- **Storage:** Integer, °C * 10 (e.g. 195 = 19.5°C)
- **Formula:** `(b[15] - 0x20) * 10 + (b[31] & 0x0F)`
  - b[15] = integer part with 0x20 offset
  - b[31] lower nibble (0-9) = decimal part
- **Source:** ESPHome AUX component (GrKoR/esphome_aux_ac_component)
- **Verification:** App 19.5°C matches HA 19.5°C ✅
- **Old formula (WRONG):** b[26] direct value — discarded after 2-hour polling study

---

## Parameter Mappings (Cloud ↔ API)

Cloud param name → AUX Home intent field:

| Cloud Param | API Field | Example Values |
|------------|-----------|-----------------|
| pwr | on_off | 0=off, 1=on |
| ac_mode | air_con_func | 0-6 (see mode mapping) |
| ac_mark | wind_speed | 0-7 (see fan speed mapping) |
| temp | temperature | integer (°C * 10) |
| envtemp | - | read-only (ambient) |
| ac_vdir | up_down_swing | 0=off, 1=on |
| ac_hdir | left_right_swing | 0=off, 1=on |
| ecomode | eco | 0=off, 1=on |
| ac_slp | sleep_mode | 0=off, 1=on |
| ac_clean | clean | 0=off, 1=on |
| scrdisp | screen | 0=off, 1=on |
| childlock | - | 0=off, 1=on |
| others | (passed as-is) | various |

---

## Code Architecture

### Key Files

**`api/aux_home.py` (Main API Client)**
- `AuxHomeAPI` class handles all cloud communication
- `_decode_running_hex()` — decodes device response bytes to params dict
- `async login()` — two-step RSA authentication
- `async get_devices()` — fetch all devices and status
- `async set_device_params()` — send control commands
- Session token management with 4-minute TTL
- Optimistic param caching (90s TTL)

**`api/aux_home_lan.py` (LAN Discovery - Experimental)**
- Active ARP scanning to find AC devices on local network
- Broadlink protocol queries (port 6053)
- Used to bypass cloud cache lag (~8-11 minutes)
- **Status:** Implemented but not yet deployed (needs Pi5 testing)

**`api/const.py` (Constants)**
- Device type IDs (AC_GENERIC, HEAT_PUMP)
- Parameter name constants
- ACFanSpeed enum
- API mode/param lists

**`const.py` (Integration Constants)**
- HA mode/fan mode mappings
- FAN_MODE_HA_TO_AUX, MODE_MAP_AUX_AC_TO_HA
- Domain, platforms, manufacturer info

**`climate.py` (HA Climate Entity)**
- AuxACClimateEntity — main AC control interface
- AuxHeatPumpClimateEntity — heat pump interface
- Supports: mode, fan, swing, temperature, power

**`config_flow.py`**
- Configuration entry UI
- Device selection
- TODO: Add LAN discovery option

---

## What Works ✓

- ✓ Cloud API authentication (RSA login)
- ✓ Device discovery and status polling
- ✓ Reading device state from running_hex bytes
- ✓ Climate entity basic controls (on/off, mode, temp)
- ✓ Fan speed setting (after 2026-04-02 fix)
- ✓ Swing modes (vertical/horizontal)
- ✓ Eco mode
- ✓ Sleep mode
- ✓ Display control
- ✓ Clean mode
- ✓ Optimistic caching (UI updates immediately)

---

## What Doesn't Work ❌

- ❌ `commonQuery` endpoint (returns 500 error)
  - Cause: Unknown (API issue or request format wrong)
  - Impact: Can't use faster device query method
  - Workaround: Use main `/app/user_device` endpoint

- ❌ Cool mode device byte mapping (not confirmed)
  - Device reports b[13] values for cool, but mapping unknown
  - Workaround: Use API mode selection, device handles it

- ❌ Dry mode device byte mapping (not confirmed)
  - Same as cool — API works but byte mapping unknown

- ❌ LAN protocol reverse engineering
  - AUX **does not use standard Broadlink** protocol
  - Uses proprietary AUXLink SDK (found via APK analysis)
  - LAN implementation exists but can't work until AUXLink is reverse-engineered
  - **Decision:** Abandoned LAN approach; cloud API is the practical solution

---

## Outstanding Issues & TODOs

### High Priority
1. **Test fan speed fix** (2026-04-02)
   - Set fan to mid_lower in HA
   - Verify device receives correct wind_speed value
   - Check that app shows "mid lower" not "medium"

2. **Confirm cool & dry mode bytes**
   - Set AC to cool mode, read b[13] values
   - Set AC to dry mode, read b[13] values
   - Add to decoding logic in `_decode_running_hex()`

### Medium Priority
3. **Debug commonQuery 500 error**
   - Try different request body formats
   - Check API change logs (if available)
   - May be deprecated endpoint

4. **Add LAN discovery UI option** (config_flow.py)
   - Option to enable/disable LAN discovery
   - Status: Not yet implemented

### Low Priority (Pi5 Only)
5. **Deploy and test LAN implementation**
   - Run on Pi5 with actual AC devices on LAN
   - Test ARP discovery finds devices
   - Test Broadlink UDP queries get response
   - Use for fallback/instant refresh

---

## Testing Methodology

### Device Byte Mapping Discovery
1. Set AC to specific mode/fan speed **physically**
2. Wait 30 seconds for device to sync
3. Call API `/app/user_device`
4. Extract `running_hex` from response
5. Decode bytes [13] and [14]
6. Record mapping
7. **Time per test:** ~11 minutes (cloud cache lag)

### Validation
- Cross-check reading (device → bytes) with writing (bytes → device)
- Ensure HA mode/fan mapping matches actual device behavior
- Monitor logs for `_decode_running_hex` output

---

## Known Constraints

- **Cloud Cache Lag:** 8-11 minutes between setting value and device status update
- **No Concurrent Control:** Cannot send on_off + mode change together (split into separate requests)
- **Session TTL:** 4 minutes — API client re-authenticates automatically
- **Device Support:** Only works with AUX devices using proprietary AUXLink SDK
- **Region:** Currently only EU endpoint configured (aux-global.com)

---

## Device Info

- **Product IDs (AC):** `000000000000000000000000c0620000`, `0000000000000000000000002a4e0000`
- **Product ID (Heat Pump):** `000000000000000000000000c3aa0000`
- **Protocol:** AUXLink SDK (proprietary, not standard Broadlink)
- **Discovery Method:** Cloud API only (LAN requires reverse engineering)

---

## Files & Structure

```
custom_components/aux_cloud/
├── CONTEXT.md (this file)
├── manifest.json
├── __init__.py
├── config_flow.py
├── const.py
├── util.py
├── climate.py
├── sensor.py
├── switch.py
├── select.py
├── number.py
├── water_heater.py
├── api/
│   ├── __init__.py
│   ├── aux_home.py (main API client)
│   ├── aux_home_lan.py (LAN discovery - experimental)
│   ├── aux_cloud.py
│   ├── aux_cloud_ws.py
│   ├── const.py
│   ├── util.py
│   └── broadlink_test.py
└── translations/
    └── en.json
```

---

## AES Encryption (CRITICAL)

**AES Key:** `4083aux63e3444a2` (extracted from app binary)
**Mode:** AES/ECB/PKCS5Padding
**Formula:** `account = base64(AES_ECB_encrypt(email, "4083aux63e3444a2"))`

**Verified Example:**
- Email: `your-guest@example.com`
- Account (encrypted): `<AES encrypted email>`

**IMPORTANT:** ANY email can now be encrypted dynamically using the AES key.
The hardcoded `_ACCOUNT_MAP` in `api/aux_home.py` (line 289) is **NO LONGER NEEDED** and should be replaced with dynamic AES encryption using `pycryptodome`.

---

## Guest Account

**Email:** `your-guest@example.com`
**Account Field:** `<AES encrypted email>` (computed dynamically via AES encryption)
**Password:** `<your password>` — do not guess, account will lock after 5 failed attempts

---

## Authentication Account Mapping (Legacy)

Previously hardcoded accounts (now obsolete with dynamic AES):
- `your-guest@example.com` → `<AES encrypted email>`
- `your-email@example.com` → `<AES encrypted email>`

These can be verified by encrypting the email with AES key `4083aux63e3444a2`.

---

## Important Commands

### Restart Home Assistant

**CORRECT command:**
```bash
curl -s -X POST http://supervisor/core/restart -H "Authorization: Bearer $SUPERVISOR_TOKEN"
```

**WRONG commands (do not use):**
- `ha restart`
- `ha core restart`
- `systemctl restart home-assistant`
- `systemctl restart home-assistant@homeassistant`

Always use the supervisor API curl command to restart HA.

---

## Temperature Research (2026-04-03 in progress)

**Goal:** Determine exact formula for room temperature from hex bytes b[26] and b[27].

**Method:**
- AC on heat mode in living room (woonkamer)
- Poll every 5 minutes for 2 hours (24 polls)
- Temperature rises from ~18°C to ~21°C overnight
- Track b[26] and b[27] to reverse-engineer encoding

**Known facts:**
- b[26] stores temperature×10 (e.g. 190 = 19.0°C)
- b[27] may contain decimal/fractional part
- b[26] lags behind app display by ~2-8 minutes (cloud cache)
- AC must be ON for updates to propagate to cloud

**Sample data (2026-04-03, 01:07:34 UTC):**
- App showed: 21.6°C
- b[26] = 190 (19.0°C)
- b[27] = 130
- Actual room temp: 19.6°C
- Lag: +2 minutes since last AC activity

**Poll script (saved to /config/temp_research.txt):**
Uses standard polling with 5-minute intervals, logs timestamp, b[26], b[27], and full hex string.

**Next steps:**
- Complete 24-poll cycle tomorrow morning
- Analyze b[27] values as temperature changes
- Determine if b[27] = (actual_temp - b[26]/10) × 10 or other formula
- Update decoding logic in aux_home.py if needed

---

## How to Update This Document

1. When implementing a feature, add it to the "What Works" section
2. When fixing a bug, update the relevant mapping/implementation section
3. When discovering new bytes/mappings, add to the mapping tables
4. When changing API behavior, update the endpoint documentation
5. Keep timestamps for significant changes
6. Don't remove old information — mark with strikethrough if obsolete

