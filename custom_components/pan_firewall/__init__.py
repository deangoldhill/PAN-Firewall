"""PAN Firewall integration."""

from datetime import timedelta
import logging
import xml.etree.ElementTree as ET
import re

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
    """Data update coordinator for PAN Firewall rules and metrics."""

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

            # Unified rulebase for security / NAT / decryption counts
            try:
                if self.rulebase is None:
                    self.rulebase = panos.policies.Rulebase()
                    self.fw.add(self.rulebase)

                all_rules = panos.policies.Rule.refreshall(self.rulebase)

                security_rules = {}
                nat_rules = {}
                decryption_rules = {}

                for rule in all_rules:
                    if isinstance(rule, panos.policies.SecurityRule):
                        security_rules[rule.name] = rule
                    elif isinstance(rule, panos.policies.NatRule):
                        nat_rules[rule.name] = rule
                    elif isinstance(rule, panos.policies.DecryptionRule):
                        decryption_rules[rule.name] = rule

                data["security_rules"] = security_rules
                data["nat_rules"] = nat_rules
                data["decryption_rules"] = decryption_rules

                _LOGGER.info(f"Loaded {len(security_rules)} security, {len(nat_rules)} NAT, {len(decryption_rules)} decryption rules")
            except Exception as e:
                _LOGGER.error(f"Rulebase fetch failed: {e}")
                data["security_rules"] = data["nat_rules"] = data["decryption_rules"] = {}

            # Dataplane CPU
            try:
                root = self.fw.op("show running resource-monitor second")
                total_util = 0.0
                count = 0
                for elem in root.iter():
                    if elem.text and '%' in elem.text:
                        try:
                            val = float(re.search(r'(\d+\.?\d*)%', elem.text).group(1))
                            if val > 0:
                                total_util += val
                                count += 1
                        except (AttributeError, ValueError):
                            pass
                data["dataplane_cpu"] = round(total_util / count, 1) if count > 0 else 0.0
            except Exception as e:
                _LOGGER.error("Dataplane CPU failed: %s", e)
                data["dataplane_cpu"] = None

            # System info
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

            # Session info
            try:
                root = self.fw.op("show session info")
                data["concurrent_connections"] = int(root.findtext('.//num-active') or 0)
                data["connections_per_second"] = int(root.findtext('.//cps') or 0)
                data["total_throughput_kbps"] = int(root.findtext('.//kbps') or 0)
            except Exception as e:
                _LOGGER.error("Session info failed: %s", e)
                data["concurrent_connections"] = data["connections_per_second"] = data["total_throughput_kbps"] = 0

            # Management CPU
            try:
                root = self.fw.op("show system resources")
                text = root.findtext('.') or ""
                match = re.search(r'%Cpu\(s\):\s*([\d.]+)\s*us,\s*([\d.]+)\s*sy', text)
                if match:
                    us = float(match.group(1))
                    sy = float(match.group(2))
                    data["management_cpu"] = round(us + sy, 1)
                else:
                    data["management_cpu"] = 0.0
            except Exception as e:
                _LOGGER.error("Management CPU failed: %s", e)
                data["management_cpu"] = None

            # Number of routes
            try:
                root = self.fw.op("show routing route")
                data["number_of_routes"] = len(root.findall('.//entry'))
            except Exception as e:
                _LOGGER.error("Routes failed: %s", e)
                data["number_of_routes"] = 0

            return data

        try:
            return await self.hass.async_add_executor_job(fetch_all)
        except Exception as err:
            raise UpdateFailed(f"Error fetching firewall data: {err}") from err
