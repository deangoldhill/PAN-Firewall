"""PAN Firewall integration — DIAGNOSTIC MODE (logs raw XML responses)."""

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
    CONF_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["switch", "sensor"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    fw = panos.firewall.Firewall(
        hostname=entry.data[CONF_HOST],
        api_username=entry.data[CONF_USERNAME],
        api_password=entry.data[CONF_PASSWORD],
        port=entry.data.get(CONF_PORT, DEFAULT_PORT),
        verify=entry.data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
    )

    def refresh_system():
        system_info = fw.refresh_system_info()
        return {
            "serial": getattr(fw, "serial", None) or getattr(system_info, "serial", None) or entry.data[CONF_HOST],
            "model": getattr(system_info, "model", None) or getattr(system_info, "platform", None) or "PAN-OS Firewall",
            "version": getattr(system_info, "version", None),
        }

    try:
        info = await hass.async_add_executor_job(refresh_system)
        serial = info["serial"]
        _LOGGER.info("Connected to PAN firewall %s (model: %s, version: %s)", serial, info["model"], info["version"])
    except Exception as err:
        _LOGGER.warning("Could not fetch system info: %s", err)
        serial = entry.data[CONF_HOST]
        info = {"model": "PAN-OS Firewall", "version": "Unknown"}

    scan_interval = entry.data.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)

    coordinator = PanFirewallCoordinator(
        hass, fw, entry.data.get(CONF_VSYS, DEFAULT_VSYS), scan_interval
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
    def __init__(self, hass: HomeAssistant, fw, vsys: str, scan_interval: int):
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=scan_interval),
        )
        self.fw = fw
        self.vsys = vsys
        self.rulebase = None

    async def _async_update_data(self):
        def fetch_all():
            data = {}

            # Rules (should still work)
            try:
                if self.rulebase is None:
                    self.rulebase = panos.policies.Rulebase()
                    self.fw.add(self.rulebase)
                rules = panos.policies.SecurityRule.refreshall(self.rulebase)
                data["rules"] = {rule.name: rule for rule in rules}
            except Exception as e:
                _LOGGER.error("Rules fetch failed: %s", e)

            commands = {
                "dataplane_cpu": "show running resource-monitor second",
                "system_info": "show system info",
                "session_info": "show session info",
                "mp_cpu": "show system resources",
                "routes": "show routing route",
                "bgp_peers": "show routing protocol bgp peer",
            }

            for key, cmd in commands.items():
                try:
                    root = self.fw.op(cmd)
                    raw_xml = ET.tostring(root, encoding='unicode', method='xml')
                    _LOGGER.warning("RAW XML for '%s':\n%s\n---", cmd, raw_xml[:4000])  # truncate if too long
                except Exception as e:
                    _LOGGER.error("Command '%s' failed: %s", cmd, e)

            # Placeholder values (we'll fix parsing after seeing XML)
            data["dataplane_cpu"] = 0
            data["management_cpu"] = 0
            data["concurrent_connections"] = 0
            data["connections_per_second"] = 0
            data["total_throughput_kbps"] = 0
            data["number_of_routes"] = 0
            data["bgp_peers"] = 0
            data["system_info"] = {}

            return data

        try:
            return await self.hass.async_add_executor_job(fetch_all)
        except Exception as err:
            raise UpdateFailed(f"Fetch error: {err}") from err
