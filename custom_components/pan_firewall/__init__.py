"""PAN Firewall integration."""

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
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["switch", "sensor"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up PAN Firewall from a config entry."""
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

    coordinator = PanFirewallCoordinator(hass, fw, entry.data.get(CONF_VSYS, DEFAULT_VSYS))

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
    """Coordinator that fetches rules + all new sensor metrics."""

    def __init__(self, hass: HomeAssistant, fw, vsys: str):
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=30),  # Faster refresh for metrics (was 300s)
        )
        self.fw = fw
        self.vsys = vsys
        self.rulebase = None

    async def _async_update_data(self):
        """Fetch rules + all metrics in one job."""
        def fetch_all():
            data = {}

            # 1. Security rules (existing)
            if self.rulebase is None:
                self.rulebase = panos.policies.Rulebase()
                self.fw.add(self.rulebase)
            rules = panos.policies.SecurityRule.refreshall(self.rulebase)
            data["rules"] = {rule.name: rule for rule in rules}

            # 2. Dataplane CPU (user-specified command)
            try:
                root = self.fw.op('<show><running><resource-monitor><second></second></resource-monitor></running></show>')
                cores = []
                for elem in root.iter():
                    if elem.tag.startswith('core') and elem.text and elem.text.replace('.', '', 1).isdigit():
                        val = float(elem.text)
                        if val > 0:
                            cores.append(val)
                data["dataplane_cpu"] = round(sum(cores) / len(cores), 1) if cores else 0.0
            except Exception as e:
                _LOGGER.warning("DP CPU fetch failed: %s", e)
                data["dataplane_cpu"] = None

            # 3. System info (ALL elements as dict)
            try:
                root = self.fw.op('<show><system><info></info></system></show>')
                sys_dict = {child.tag: child.text.strip() if child.text else "" for child in root.findall('.//')}
                data["system_info"] = sys_dict
            except Exception as e:
                _LOGGER.warning("System info fetch failed: %s", e)
                data["system_info"] = {}

            # 4. Session info (concurrent + CPS + throughput)
            try:
                root = self.fw.op('<show><session><info></info></session></show>')
                data["concurrent_connections"] = int(root.findtext('.//number-of-active-sessions', '0'))
                data["connections_per_second"] = int(root.findtext('.//new-connection-establish-rate', '0').split()[0])
                data["total_throughput_kbps"] = int(root.findtext('.//throughput', '0').split()[0])
            except Exception:
                data["concurrent_connections"] = 0
                data["connections_per_second"] = 0
                data["total_throughput_kbps"] = 0

            # 5. Management plane CPU
            try:
                root = self.fw.op('<show><system><resources></resources></system></show>')
                mp_cpu_text = root.findtext('.//cpu', '0')
                data["management_cpu"] = int(mp_cpu_text.rstrip('%')) if '%' in mp_cpu_text else int(mp_cpu_text)
            except Exception:
                data["management_cpu"] = None

            # 6. Number of routes
            try:
                root = self.fw.op('<show><routing><route></route></routing></show>')
                data["number_of_routes"] = len(root.findall('.//entry'))
            except Exception:
                data["number_of_routes"] = 0

            # 7. BGP peers (works on both legacy and advanced-routing)
            try:
                root = self.fw.op('<show><routing><protocol><bgp><peer></peer></bgp></protocol></routing></show>')
                data["bgp_peers"] = len(root.findall('.//entry'))
            except Exception:
                try:
                    root = self.fw.op('<show><advanced-routing><bgp><peer><summary></summary></peer></bgp></advanced-routing></show>')
                    data["bgp_peers"] = len(root.findall('.//entry'))
                except Exception:
                    data["bgp_peers"] = 0

            return data

        try:
            return await self.hass.async_add_executor_job(fetch_all)
        except Exception as err:
            raise UpdateFailed(f"Error fetching firewall data: {err}") from err
