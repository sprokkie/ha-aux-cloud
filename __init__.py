"""Aux Cloud integration for Home Assistant."""

import asyncio
from datetime import timedelta

import voluptuous as vol
from homeassistant.config_entries import SOURCE_IMPORT, ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, CONF_REGION
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api.aux_cloud import AuxCloudAPI
from .api.aux_home import AuxHomeAPI
from .api import aux_home_lan
from .const import (
    _LOGGER,
    DOMAIN,
    DATA_AUX_CLOUD_CONFIG,
    PLATFORMS,
    CONF_SELECTED_DEVICES,
)

MIN_TIME_BETWEEN_UPDATES = timedelta(seconds=30)

# Schema to include email and password (device selection is handled in config flow)
CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Required(CONF_EMAIL): cv.string,
                vol.Required(CONF_PASSWORD): cv.string,
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """
    AUX Cloud setup for configuration.yaml import.
    This is mainly kept for backward compatibility.
    UI configuration is recommended for better security.
    """
    if DOMAIN not in config:
        return True

    hass.data[DATA_AUX_CLOUD_CONFIG] = config.get(DOMAIN, {})

    if (
        not hass.config_entries.async_entries(DOMAIN)
        and hass.data[DATA_AUX_CLOUD_CONFIG]
    ):
        # Import from configuration.yaml if no config entry exists
        hass.async_create_task(
            hass.config_entries.flow.async_init(
                DOMAIN, context={"source": SOURCE_IMPORT}, data=config[DOMAIN]
            )
        )

        # Log a message about UI configuration being preferred
        _LOGGER.info(
            "AUX Cloud configured via configuration.yaml. For better security, "
            "it is recommended to configure this integration through the UI where "
            "credentials are stored encrypted."
        )

    return True


class AuxCloudCoordinator(DataUpdateCoordinator):
    """DataUpdateCoordinator for AUX Cloud."""

    def __init__(
        self,
        hass: HomeAssistant,
        api: AuxCloudAPI,
        email: str,
        password: str,
        selected_device_ids: list,
    ):
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name="AUX Cloud Coordinator",
            update_interval=MIN_TIME_BETWEEN_UPDATES,
        )
        self.api = api
        self.email = email
        self.password = password
        self.selected_device_ids = selected_device_ids
        self.devices = []

    def get_device_by_endpoint_id(self, endpoint_id: str):
        """Get a device by its endpoint ID."""
        return next(
            (
                device
                for device in self.data.get("devices", [])
                if device.get("endpointId") == endpoint_id
            ),
            None,
        )

    async def _try_broadlink_query(self, device: dict, mac: str) -> dict:
        """
        Try to query an AUX Home AC device via Broadlink HVAC protocol (LAN).

        This is much faster than cloud API (~instant vs 8-11 min lag).
        Falls back gracefully if Broadlink is unavailable or device not responding.

        Returns:
            Decoded params dict, or empty dict on failure.
        """
        try:
            # Try to discover device IP from ARP table / DNS
            discovered = await aux_home_lan.discover_acs_active(
                [mac],
                timeout=5,
            )

            if not discovered or mac not in discovered:
                _LOGGER.debug("Broadlink: device %s not found on LAN", mac)
                return {}

            device_ip = discovered[mac]
            _LOGGER.debug("Broadlink: found %s at %s", mac, device_ip)

            # Query device via Broadlink
            params = await aux_home_lan.query_device_broadlink(
                device_ip,
                mac,
                device_password=device.get("password", ""),
            )

            if params:
                _LOGGER.debug("Broadlink: got fresh params for %s: %s", mac, params)
                return params

            _LOGGER.debug("Broadlink: no params returned for %s", mac)
            return {}

        except Exception as e:
            _LOGGER.debug("Broadlink query failed for %s: %s", mac, e)
            return {}

    async def _async_update_data(self):
        """Fetch data from AUX Cloud."""
        _LOGGER.debug("Updating AUX Cloud data...")

        try:
            if not self.api.is_logged_in():
                _LOGGER.debug("Logging into AUX Cloud API...")
                login_success = await self.api.login(self.email, self.password)
                if not login_success:
                    raise UpdateFailed("Login to AUX Cloud API failed")

            if self.api.families is None:
                _LOGGER.debug("Fetching families from AUX Cloud API...")
                await self.api.get_families()

            # On first run (no devices cached yet), call get_devices() to
            # discover device IDs, names, product keys and other metadata.
            if not self.devices:
                _LOGGER.debug("No cached devices — running initial device discovery")
                device_tasks = []
                for family_id in self.api.families:
                    device_tasks.append(
                        self.api.get_devices(
                            family_id,
                            shared=False,
                            selected_devices=self.selected_device_ids,
                        )
                    )
                    device_tasks.append(
                        self.api.get_devices(
                            family_id,
                            shared=True,
                            selected_devices=self.selected_device_ids,
                        )
                    )
                results = await asyncio.gather(*device_tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, Exception):
                        _LOGGER.warning("AUX Cloud: device discovery failed: %s", result)
                        continue
                    for device in result:
                        if (
                            device["endpointId"] in self.selected_device_ids
                            or not self.selected_device_ids
                        ):
                            self.devices.append(device)
                _LOGGER.debug("Discovered %d device(s)", len(self.devices))

            # For AUX Home devices (0x4E2A HVAC), try direct LAN query first (instant)
            # For other devices, use cloud API
            got_fresh = False

            # Separate AUX Home from other devices
            aux_home_devices = [d for d in self.devices if isinstance(self.api, AuxHomeAPI)]
            other_devices = [d for d in self.devices if not isinstance(self.api, AuxHomeAPI)]

            # Try Broadlink LAN queries for AUX Home devices
            if aux_home_devices and isinstance(self.api, AuxHomeAPI):
                _LOGGER.debug("Trying Broadlink LAN queries for %d AUX Home device(s)", len(aux_home_devices))

                lan_tasks = []
                for device in aux_home_devices:
                    mac = device.get("mac", "").lower()
                    # Try to discover device IP via ARP + reverse DNS
                    lan_tasks.append(
                        self._try_broadlink_query(device, mac)
                    )

                lan_results = await asyncio.gather(*lan_tasks, return_exceptions=True)
                for device, lan_params in zip(aux_home_devices, lan_results):
                    if isinstance(lan_params, Exception):
                        _LOGGER.debug("Broadlink LAN query failed for %s: %s", device.get("mac"), lan_params)
                    elif lan_params:
                        device["params"] = lan_params
                        got_fresh = True
                        _LOGGER.debug("Got fresh params via Broadlink LAN for %s", device.get("mac"))

            # Fallback: query_device_state() for live state (cloud API)
            if hasattr(self.api, "query_device_state") and (other_devices or not got_fresh):
                query_devices = other_devices if other_devices else self.devices
                query_tasks = [
                    self.api.query_device_state(
                        device["endpointId"],
                        device.get("_aux_home_raw", {}).get("productKey", "00010001"),
                        device.get("_aux_home_raw", {}).get("password", ""),
                    )
                    for device in query_devices
                ]
                fresh_results = await asyncio.gather(*query_tasks, return_exceptions=True)
                for device, fresh_params in zip(query_devices, fresh_results):
                    if isinstance(fresh_params, Exception):
                        _LOGGER.warning(
                            "AUX Cloud: query_device_state failed for %s: %s",
                            device["endpointId"], fresh_params,
                        )
                    elif fresh_params:
                        device["params"] = fresh_params
                        got_fresh = True

            if not got_fresh:
                # query_device_state unavailable or failed — refresh from server cache
                device_tasks = []
                for family_id in self.api.families:
                    device_tasks.append(
                        self.api.get_devices(
                            family_id,
                            shared=False,
                            selected_devices=self.selected_device_ids,
                        )
                    )
                    device_tasks.append(
                        self.api.get_devices(
                            family_id,
                            shared=True,
                            selected_devices=self.selected_device_ids,
                        )
                    )
                results = await asyncio.gather(*device_tasks, return_exceptions=True)
                all_devices = []
                for result in results:
                    if isinstance(result, Exception):
                        _LOGGER.warning("AUX Cloud: device fetch failed: %s", result)
                        continue
                    for device in result:
                        if (
                            device["endpointId"] in self.selected_device_ids
                            or not self.selected_device_ids
                        ):
                            all_devices.append(device)
                self.devices = all_devices

            _LOGGER.debug("Fetched AUX Cloud data: %s devices", len(self.devices))
            return {"devices": self.devices}

        except Exception as e:
            raise UpdateFailed(f"Error updating AUX Cloud data: {e}") from e


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up AUX Cloud from a config entry."""
    region = entry.data.get(CONF_REGION, "eu")
    api = AuxHomeAPI(region=region) if region.startswith("aux_home") else AuxCloudAPI(region=region)
    email = entry.data.get(CONF_EMAIL)
    password = entry.data.get(CONF_PASSWORD)
    selected_device_ids = entry.data.get(CONF_SELECTED_DEVICES, [])

    if not email or not password:
        _LOGGER.error("Missing required credentials for AUX Cloud")
        return False

    coordinator = AuxCloudCoordinator(hass, api, email, password, selected_device_ids)

    # Attempt to log in
    try:
        login_success = await api.login(email, password)
        if not login_success:
            _LOGGER.error("Login to AUX Cloud API failed")
            return False
    except Exception as e:
        _LOGGER.error("Exception during login: %s", e)
        return False

    # Perform an initial update
    await coordinator.async_config_entry_first_refresh()

    # Store the coordinator for platform use
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        "coordinator": coordinator,
        "api": api,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload the config entry and platforms."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data.pop(DOMAIN)
    return unload_ok
