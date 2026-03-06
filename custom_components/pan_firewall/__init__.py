"""PAN Firewall integration — v1.2.6 (parsing matched to your exact XML)."""

from datetime import timedelta
import logging
import xml.etree.ElementTree as ET

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
        _LOGGER.info("✅ Connected to PAN firewall %s (model: %s, version: %s)", serial, info["model"], info["version"])
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

            # Security rules
            try:
                if self.rulebase is None:
                    self.rulebase = panos.policies.Rulebase()
                    self.fw.add(self.rulebase)
                rules = panos.policies.SecurityRule.refreshall(self.rulebase)
                data["rules"] = {rule.name: rule for rule in rules}
            except Exception as e:
                _LOGGER.error("Rules fetch failed: %s", e)
                data["rules"] = {}

            # Dataplane CPU (robust core parsing)
            try:
                root = self.fw.op("show running resource-monitor second")
                cores = []
                for elem in root.iter():
                    if "core" in elem.tag.lower() and elem.text:
                        try:
                            val = float(elem.text.strip())
                            if val > 0:
                                cores.append(val)
                        except ValueError:
                            pass
                data["dataplane_cpu"] = round(sum(cores) / len(cores), 1) if cores else 0.0
            except Exception as e:
                _LOGGER.error("Dataplane CPU failed: %s", e)
                data["dataplane_cpu"] = None

            # System info (direct tag parsing - matches your XML perfectly)
            try:
                root = self.fw.op("show system info")
                sys_dict = {}
                for elem in root.iter():
                    if elem.text and elem.text.strip():
                        key = elem.tag.replace("-", "_")
                        sys_dict[key] = elem.text.strip()
                data["system_info"] = sys_dict
            except Exception as e:
                _LOGGER.error("System info failed: %s", e)
                data["system_info"] = {}

            # Session info (exact tags from your XML: num-active, cps, kbps)
            try:
                root = self.fw.op("show session info")
                data["concurrent_connections"] = int(root.findtext('.//num-active') or 0)
                data["connections_per_second"] = int(root.findtext('.//cps') or 0)
                data["total_throughput_kbps"] = int(root.findtext('.//kbps') or 0)
            except Exception as e:
                _LOGGER.error("Session info failed: %s", e)
                data["concurrent_connections"] = data["connections_per_second"] = data["total_throughput_kbps"] = 0

            # Management CPU (parse %Cpu(s) line from top output)
            try:
                root = self.fw.op("show system resources")
                cpu_line = root.findtext('.//Cpu') or ""
                if cpu_line:
                    parts = cpu_line.split(',')
                    us = float(parts[0].split()[0]) if len(parts) > 0 else 0
                    sy = float(parts[1].split()[0]) if len(parts) > 1 else 0
                    data["management_cpu"] = round(us + sy, 1)  # approx management load
                else:
                    data["management_cpu"] = 0
            except Exception as e:
                _LOGGER.error("Management CPU failed: %s", e)
                data["management_cpu"] = None

            # Number of routes (count <entry>)
            try:
                root = self.fw.op("show routing route")
                data["number_of_routes"] = len(root.findall('.//entry'))
            except Exception as e:
                _LOGGER.error("Routes failed: %s", e)
                data["number_of_routes"] = 0

            # BGP peers (count <entry> with status)
            try:
                root = self.fw.op("show routing protocol bgp peer")
                data["bgp_peers"] = len(root.findall('.//entry'))
            except Exception as e:
                _LOGGER.error("BGP peers failed: %s", e)
                data["bgp_peers"] = 0

            return data

        try:
            return await self.hass.async_add_executor_job(fetch_all)
        except Exception as err:
            raise UpdateFailed(f"Error fetching firewall data: {err}") from err
