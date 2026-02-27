"""Sensor platform for PAN Firewall metrics."""

from homeassistant.components.sensor import SensorEntity, SensorDeviceClass, SensorStateClass
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers import device_registry as dr

from .const import DOMAIN


async def async_setup_entry(
    hass: HomeAssistant, entry, async_add_entities: AddEntitiesCallback
):
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator = data["coordinator"]
    serial = data["serial"]
    model = data["model"]
    version = data["version"]

    entities = []

    # Dynamic sensors from coordinator data
    metrics = {
        "dataplane_cpu": ("Dataplane CPU", "%", SensorDeviceClass.PERCENTAGE, SensorStateClass.MEASUREMENT),
        "management_cpu": ("Management CPU", "%", SensorDeviceClass.PERCENTAGE, SensorStateClass.MEASUREMENT),
        "concurrent_connections": ("Concurrent Connections", "sessions", None, SensorStateClass.MEASUREMENT),
        "connections_per_second": ("Connections per Second", "cps", None, SensorStateClass.MEASUREMENT),
        "total_throughput_kbps": ("Total Throughput", "Mbps", SensorDeviceClass.DATA_RATE, SensorStateClass.MEASUREMENT),
        "number_of_routes": ("Number of Routes", "routes", None, SensorStateClass.TOTAL),
        "bgp_peers": ("BGP Peers", "peers", None, SensorStateClass.TOTAL),
    }

    for key, (name, unit, device_class, state_class) in metrics.items():
        entities.append(
            PanFirewallSensor(
                coordinator=coordinator,
                key=key,
                name=name,
                unit=unit,
                device_class=device_class,
                state_class=state_class,
                serial=serial,
                model=model,
                version=version,
                fw=data["fw"],
            )
        )

    # System Info sensor (all fields as attributes)
    entities.append(
        PanFirewallSystemInfoSensor(
            coordinator=coordinator,
            serial=serial,
            model=model,
            version=version,
            fw=data["fw"],
        )
    )

    async_add_entities(entities, update_before_add=True)


class PanFirewallSensor(CoordinatorEntity, SensorEntity):
    """Generic sensor for numeric metrics."""

    def __init__(self, coordinator, key: str, name: str, unit: str | None, device_class, state_class, serial, model, version, fw):
        super().__init__(coordinator)
        self._key = key
        self._attr_name = name
        self._attr_unique_id = f"pan_{serial}_{key}"
        self._attr_native_unit_of_measurement = unit
        self._attr_device_class = device_class
        self._attr_state_class = state_class
        self._attr_icon = "mdi:shield"
        self._serial = serial
        self._model = model
        self._version = version
        self._fw = fw

    @property
    def native_value(self):
        if self._key == "total_throughput_kbps":
            return round(self.coordinator.data.get(self._key, 0) / 1000, 1)  # Kbps → Mbps
        return self.coordinator.data.get(self._key)

    @property
    def device_info(self):
        return dr.DeviceInfo(
            identifiers={(DOMAIN, self._serial)},
            name=f"PAN Firewall {self._serial}",
            manufacturer="Palo Alto Networks",
            model=self._model,
            sw_version=self._version,
            configuration_url=f"https://{self._fw.hostname}",
            entry_type=dr.DeviceEntryType.SERVICE,
        )


class PanFirewallSystemInfoSensor(CoordinatorEntity, SensorEntity):
    """Single sensor showing ALL system info fields as attributes."""

    def __init__(self, coordinator, serial, model, version, fw):
        super().__init__(coordinator)
        self._attr_name = "System Info"
        self._attr_unique_id = f"pan_{serial}_system_info"
        self._attr_icon = "mdi:information"
        self._serial = serial
        self._model = model
        self._version = version
        self._fw = fw

    @property
    def native_value(self):
        return "OK"  # Always "OK", real data in attributes

    @property
    def extra_state_attributes(self):
        return self.coordinator.data.get("system_info", {})

    @property
    def device_info(self):
        return dr.DeviceInfo(
            identifiers={(DOMAIN, self._serial)},
            name=f"PAN Firewall {self._serial}",
            manufacturer="Palo Alto Networks",
            model=self._model,
            sw_version=self._version,
            configuration_url=f"https://{self._fw.hostname}",
            entry_type=dr.DeviceEntryType.SERVICE,
        )
