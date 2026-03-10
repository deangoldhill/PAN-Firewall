"""Device tracker platform for PAN Firewall - tracks devices via DHCP leases."""
from __future__ import annotations

import logging
from datetime import timedelta
import xml.etree.ElementTree as ET

import requests
import urllib.parse

from homeassistant.components.device_tracker import ScannerEntity, SourceType
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
    UpdateFailed,
)

from .const import DOMAIN, CONF_HOST, CONF_API_KEY, CONF_VERIFY_TLS

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timedelta(seconds=30)


# --------------------------------------------------------------------------- #
# Platform setup
# --------------------------------------------------------------------------- #
async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up PAN Firewall device tracker from a config entry."""
    host       = config_entry.data[CONF_HOST]
    api_key    = config_entry.data[CONF_API_KEY]
    verify_tls = config_entry.data.get(CONF_VERIFY_TLS, True)

    coordinator = PanDhcpCoordinator(hass, host, api_key, verify_tls)
    await coordinator.async_config_entry_first_refresh()

    # Track which MAC addresses we have already added as entities
    known_macs: set[str] = set()

    @callback
    def _async_add_new_devices() -> None:
        """Add any newly discovered DHCP leases as tracker entities."""
        new_entities = []
        for mac, lease in coordinator.data.items():
            if mac not in known_macs:
                known_macs.add(mac)
                new_entities.append(PanDhcpDeviceTracker(coordinator, mac))
        if new_entities:
            async_add_entities(new_entities, update_before_add=False)

    # Add entities already present at startup
    _async_add_new_devices()

    # Add new devices as they appear on subsequent polls
    config_entry.async_on_unload(
        coordinator.async_add_listener(_async_add_new_devices)
    )


# --------------------------------------------------------------------------- #
# Coordinator — fetches all DHCP leases from the firewall
# --------------------------------------------------------------------------- #
class PanDhcpCoordinator(DataUpdateCoordinator):
    """Polls the PAN-OS XML API for DHCP leases on all interfaces."""

    def __init__(
        self,
        hass: HomeAssistant,
        host: str,
        api_key: str,
        verify_tls: bool,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name="PAN Firewall DHCP Leases",
            update_interval=SCAN_INTERVAL,
        )
        self._host       = host
        self._api_key    = api_key
        self._verify_tls = verify_tls
        self._base_url   = f"https://{host}/api"

    async def _async_update_data(self) -> dict[str, dict]:
        """Fetch leases; returns dict keyed by normalised MAC address."""
        return await self.hass.async_add_executor_job(self._fetch_leases)

    def _fetch_leases(self) -> dict[str, dict]:
        """Synchronous DHCP lease fetch — runs in executor thread."""
        op_cmd = (
            "<show><dhcp><server><lease>"
            "<interface>all</interface>"
            "</lease></server></dhcp></show>"
        )
        params = {
            "type": "op",
            "cmd":  op_cmd,
            "key":  self._api_key,
        }

        try:
            response = requests.get(
                self._base_url,
                params=params,
                verify=self._verify_tls,
                timeout=15,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise UpdateFailed(f"Error communicating with PAN-OS API: {exc}") from exc

        return self._parse_leases(response.text)

    @staticmethod
    def _parse_leases(xml_text: str) -> dict[str, dict]:
        """Parse XML response into a dict of {mac: lease_data}."""
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            raise UpdateFailed(f"Failed to parse DHCP XML response: {exc}") from exc

        leases: dict[str, dict] = {}

        # Group-by-interface structure: <interface name="eth1/2"><entry ...>
        for iface_el in root.findall(".//interface"):
            iface_name = (
                iface_el.get("name")
                or iface_el.findtext("name")
                or "unknown"
            )
            for entry in iface_el.findall("entry"):
                lease = {child.tag: (child.text or "").strip() for child in entry}
                lease["interface"] = iface_name
                mac = lease.get("mac", "").lower().replace("-", ":")
                if mac:
                    leases[mac] = lease

        # Fallback: flat <entry> list (single-interface firmware versions)
        if not leases:
            for entry in root.findall(".//entry"):
                lease = {child.tag: (child.text or "").strip() for child in entry}
                mac = lease.get("mac", "").lower().replace("-", ":")
                if mac:
                    leases[mac] = lease

        _LOGGER.debug("PAN Firewall DHCP: found %d active leases", len(leases))
        return leases


# --------------------------------------------------------------------------- #
# Entity — one per DHCP lease / MAC address
# --------------------------------------------------------------------------- #
class PanDhcpDeviceTracker(CoordinatorEntity, ScannerEntity):
    """Represents a device seen in PAN-OS DHCP leases."""

    def __init__(self, coordinator: PanDhcpCoordinator, mac: str) -> None:
        super().__init__(coordinator)
        self._mac = mac

    # ------------------------------------------------------------------ #
    # Core identity
    # ------------------------------------------------------------------ #
    @property
    def unique_id(self) -> str:
        return f"pan_dhcp_{self._mac.replace(':', '_')}"

    @property
    def name(self) -> str:
        lease = self._lease
        return lease.get("name") or lease.get("hostname") or self._mac

    # ------------------------------------------------------------------ #
    # ScannerEntity required properties
    # ------------------------------------------------------------------ #
    @property
    def is_connected(self) -> bool:
        """Device is considered home/present when its lease is active."""
        state = self._lease.get("state", "").lower()
        return state in ("active", "committed")

    @property
    def source_type(self) -> SourceType:
        return SourceType.ROUTER

    @property
    def mac_address(self) -> str:
        return self._mac

    @property
    def hostname(self) -> str | None:
        return self._lease.get("name") or self._lease.get("hostname")

    @property
    def ip_address(self) -> str | None:
        return self._lease.get("ip")

    # ------------------------------------------------------------------ #
    # Extra state attributes shown in HA
    # ------------------------------------------------------------------ #
    @property
    def extra_state_attributes(self) -> dict:
        lease = self._lease
        return {
            "ip":        lease.get("ip"),
            "mac":       self._mac,
            "interface": lease.get("interface"),
            "state":     lease.get("state"),
            "ttl":       lease.get("ttl"),
            "expiry":    lease.get("expiry"),
            "type":      lease.get("type"),
        }

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @property
    def _lease(self) -> dict:
        """Return the current lease data for this MAC, or empty dict."""
        return self.coordinator.data.get(self._mac, {})
