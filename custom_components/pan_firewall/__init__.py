"""PAN Firewall integration."""

from datetime import timedelta
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

import panos.firewall
import panos.policies

from .const import (
    DOMAIN,
    CONF_HOST,
    CONF_PORT,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_VSYS,
    CONF_VERIFY_SSL,
    DEFAULT_PORT,
    DEFAULT_VSYS,
    DEFAULT_VERIFY_SSL,
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["switch"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up PAN Firewall from a config entry."""
    fw = panos.firewall.Firewall(
        hostname=entry.data[CONF_HOST],
        api_username=entry.data[CONF_USERNAME],
        api_password=entry.data[CONF_PASSWORD],
        port=entry.data.get(CONF_PORT, DEFAULT_PORT),
        verify=entry.data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
    )

    # Fetch serial + model + version (required for Device Registry)
    def refresh_system():
        fw.refresh_system_info()
        return {
            "serial": getattr(fw, "serial", None),
            "model": getattr(fw, "model", None),
            "version": getattr(fw, "version", None),
        }

    try:
        info = await hass.async_add_executor_job(refresh_system)
        serial = info["serial"] or entry.data[CONF_HOST]
        _LOGGER.info(
            "✅ Connected to PAN firewall %s (model: %s, version: %s)",
            serial, info["model"], info["version"]
        )
    except Exception as err:
        _LOGGER.warning("Could not fetch system info, using hostname: %s", err)
        serial = entry.data[CONF_HOST]
        info = {"model": None, "version": None}

    coordinator = PanFirewallCoordinator(
        hass, fw, entry.data.get(CONF_VSYS, DEFAULT_VSYS)
    )

    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        "coordinator": coordinator,
        "fw": fw,
        "serial": serial,
        "model": info["model"],
        "version": info["version"],
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)
    return unload_ok


class PanFirewallCoordinator(DataUpdateCoordinator):
    """Data update coordinator for PAN Firewall rules."""

    def __init__(self, hass: HomeAssistant, fw, vsys: str):
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=300),
        )
        self.fw = fw
        self.vsys = vsys
        self.rulebase = None

    async def _async_update_data(self):
        def fetch_rules():
            if self.rulebase is None:
                self.rulebase = panos.policies.Rulebase()
                self.fw.add(self.rulebase)
            rules = panos.policies.SecurityRule.refreshall(self.rulebase)
            return {rule.name: rule for rule in rules}

        try:
            return await self.hass.async_add_executor_job(fetch_rules)
        except Exception as err:
            raise UpdateFailed(f"Error fetching rules: {err}") from err
