"""PAN Firewall integration - DIAGNOSTIC VERSION with full XML logging."""

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

    def _log_raw_xml(self, cmd: str, root):
        """Log raw XML for debugging."""
        try:
            xml_str = ET.tostring(root, encoding="unicode", method="xml")
            _LOGGER.info("🔍 RAW XML for '%s' (first 800 chars): %s", cmd, xml_str[:800])
        except Exception:
            _LOGGER.info("🔍 RAW XML for '%s' failed to stringify", cmd)

    async def _async_update_data(self):
        def fetch_all():
            data = {}

            # ==================== SECURITY RULES ====================
            try:
                if self.rulebase is None:
                    self.rulebase = panos.policies.Rulebase()
                    self.fw.add(self.rulebase)
                rules = panos.policies.SecurityRule.refreshall(self.rulebase)
                data["rules"] = {rule.name: rule for rule in rules}
                _LOGGER.info("✅ Rules loaded: %d rules", len(data["rules"]))
            except Exception as e:
                _LOGGER.error("Rules failed: %s", e)
                data["rules"] = {}

            # ==================== DATAPLANE CPU ====================
            cmd = '<show><running><resource-monitor><second></second></resource-monitor></running></show>'
            try:
                root = self.fw.op(cmd)
                self._log_raw_xml("resource-monitor", root)
                cores = []
                for elem in root.iter():
                    if "core" in elem.tag.lower() and elem.text and elem.text.replace(".", "", 1).replace("-", "", 1).isdigit():
                        val = float(elem.text)
                        if val > 0:
                            cores.append(val)
                data["dataplane_cpu"] = round(sum(cores) / len(cores), 1) if cores else 0.0
                _LOGGER.info("✅ Dataplane CPU = %s%% (%d active cores)", data["dataplane_cpu"], len(cores))
            except Exception as e:
                _LOGGER.error("DP CPU failed: %s", e)
                data["dataplane_cpu"] = None

            # ==================== SYSTEM INFO ====================
            cmd = '<show><system><info></info></system></show>'
            try:
                root = self.fw.op(cmd)
                self._log_raw_xml("system info", root)
                sys_dict = {}
                for elem in root.iter():
                    if elem.text and elem.text.strip() and not elem.tag.startswith("{"):
                        key = elem.tag.replace("-", "_").replace(":", "_")
                        sys_dict[key] = elem.text.strip()
                data["system_info"] = sys_dict
                _LOGGER.info("✅ System info fields loaded: %d", len(sys_dict))
            except Exception as e:
                _LOGGER.error("System info failed: %s", e)
                data["system_info"] = {}

            # ==================== SESSION INFO ====================
            cmd = '<show><session><info></info></session></show>'
            try:
                root = self.fw.op(cmd)
                self._log_raw_xml("session info", root)
                # Robust deep search
                active = root.find(".//number-of-active-sessions") or root.find(".//active-sessions")
                data["concurrent_connections"] = int(active.text) if active is not None and active.text else 0

                cps_elem = root.find(".//new-connection-establish-rate") or root.find(".//cps")
                data["connections_per_second"] = int("".join(filter(str.isdigit, (cps_elem.text or "0").split()[0]))) if cps_elem is not None else 0

                tp_elem = root.find(".//throughput") or root.find(".//kbps")
                data["total_throughput_kbps"] = int("".join(filter(str.isdigit, (tp_elem.text or "0").split()[0]))) if tp_elem is not None else 0

                _LOGGER.info("✅ Sessions: %s concurrent | %s cps | %s kbps",
                             data["concurrent_connections"], data["connections_per_second"], data["total_throughput_kbps"])
            except Exception as e:
                _LOGGER.error("Session info failed: %s", e)
                data["concurrent_connections"] = data["connections_per_second"] = data["total_throughput_kbps"] = 0

            # ==================== MANAGEMENT CPU ====================
            cmd = '<show><system><resources></resources></system></show>'
            try:
                root = self.fw.op(cmd)
                self._log_raw_xml("system resources", root)
                cpu_text = None
                for elem in root.iter():
                    if "cpu" in elem.tag.lower() and elem.text:
                        cpu_text = elem.text
                        break
                data["management_cpu"] = int(cpu_text.rstrip("%")) if cpu_text and "%" in cpu_text else int(cpu_text or 0)
                _LOGGER.info("✅ Management CPU = %s%%", data["management_cpu"])
            except Exception as e:
                _LOGGER.error("Management CPU failed: %s", e)
                data["management_cpu"] = None

            # ==================== ROUTES & BGP (kept as-is, with logs) ====================
            try:
                root = self.fw.op('<show><routing><route></route></routing></show>')
                self._log_raw_xml("routing route", root)
                data["number_of_routes"] = len(root.findall(".//entry"))
            except:
                data["number_of_routes"] = 0
            _LOGGER.info("✅ Routes = %s", data["number_of_routes"])

            try:
                root = self.fw.op('<show><routing><protocol><bgp><peer></peer></bgp></protocol></routing></show>')
                self._log_raw_xml("bgp peer", root)
                data["bgp_peers"] = len(root.findall(".//entry"))
            except:
                data["bgp_peers"] = 0
            _LOGGER.info("✅ BGP peers = %s", data["bgp_peers"])

            return data

        try:
            return await self.hass.async_add_executor_job(fetch_all)
        except Exception as err:
            raise UpdateFailed(f"Error fetching firewall data: {err}") from err
