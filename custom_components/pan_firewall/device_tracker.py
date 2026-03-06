"""Device tracker platform for PAN Firewall DHCP leases."""

from homeassistant.components.device_tracker import SourceType, ScannerEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN


async def async_setup_entry(
    hass: HomeAssistant, entry, async_add_entities: AddEntitiesCallback
):
    """Set up device tracker entities from DHCP leases."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator = data["coordinator"]
    serial = data["serial"]

    entities = []

    for lease in coordinator.data.get("dhcp_leases", []):
        entities.append(
            PanFirewallDHCPDeviceTracker(
                coordinator=coordinator,
                lease=lease,
                serial=serial,
            )
        )

    async_add_entities(entities, update_before_add=True)


class PanFirewallDHCPDeviceTracker(CoordinatorEntity, ScannerEntity):
    """Device tracker entity based on DHCP lease with hostname."""

    def __init__(self, coordinator, lease: dict, serial: str):
        super().__init__(coordinator)
        self._lease = lease
        self._serial = serial

        hostname = lease["hostname"]
        self._attr_name = f"{hostname} (DHCP)"
        self._attr_unique_id = f"pan_{serial}_dhcp_{lease['mac'] or lease['ip']}"
        self._attr_icon = "mdi:lan-connect"

    @property
    def is_on(self) -> bool:
        """Return true if the device is considered at home (active lease)."""
        return self._lease["state"] == "committed"

    @property
    def source_type(self) -> SourceType:
        return SourceType.ROUTER

    @property
    def mac_address(self) -> str | None:
        mac = self._lease.get("mac")
        return mac if mac and mac != "unknown" else None

    @property
    def ip_address(self) -> str | None:
        return self._lease.get("ip")

    @property
    def extra_state_attributes(self):
        return {
            "hostname": self._lease["hostname"],
            "ip": self._lease["ip"],
            "mac": self._lease["mac"],
            "lease_time": self._lease["leasetime"],
            "state": self._lease["state"],
            "interface": self._lease["interface"],
        }

    @property
    def device_info(self):
        return {
            "identifiers": {(DOMAIN, self._serial)},
            "name": f"PAN Firewall {self._serial}",
            "manufacturer": "Palo Alto Networks",
            "model": self.coordinator.data.get("model", "PAN-OS Firewall"),
            "sw_version": self.coordinator.data.get("version", "Unknown"),
            "configuration_url": f"https://{self.coordinator.fw.hostname}",
            "entry_type": "service",
        }
