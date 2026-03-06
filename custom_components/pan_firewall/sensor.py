"""Sensor platform for PAN Firewall metrics."""

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers import device_registry as dr

from .const import DOMAIN


async def async_setup_entry(
    hass: HomeAssistant, entry, async_add_entities: AddEntitiesCallback
):
    """Set up PAN Firewall sensor platform."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator = data["coordinator"]
    serial = data["serial"]
    model = data["model"]
    version = data["version"]

    entities = []

    # Numeric / general metrics
    metrics = {
        "dataplane_cpu": ("Dataplane CPU", "%", "percentage", SensorStateClass.MEASUREMENT),
        "management_cpu": ("Management CPU", "%", "percentage", SensorStateClass.MEASUREMENT),
        "concurrent_connections": ("Concurrent Connections", "sessions", None, SensorStateClass.MEASUREMENT),
        "connections_per_second": ("Connections per Second", "cps", None, SensorStateClass.MEASUREMENT),
        "total_throughput_kbps": ("Total Throughput", "Mbps", "data_rate", SensorStateClass.MEASUREMENT),
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

    # System info fields – filtered + special handling
    system_info = coordinator.data.get("system_info", {})

    # Always include these (core identity/info)
    always_include = {
        "hostname": "Hostname",
        "ip_address": "IP Address",
        "time": "Time",
        "uptime": "Uptime",
        "family": "Family",
        "model": "Model",
        "serial": "Serial",
        "sw_version": "Software Version",
        "app_version": "App Version",
        "av_version": "Antivirus Version",
        "threat_version": "Threat Version",
        "wildfire_version": "Wildfire Version",
        "device_dictionary_version": "Device Dictionary Version",
        "global_protect_client_package_version": "GlobalProtect Client Package Version",
        "logdb_version": "LogDB Version",
        "operational_mode": "Operational Mode",
        "platform_family": "Platform Family",
    }

    # Date mappings – moved to attributes
    date_mappings = {
        "app_version": ("app_release_date", "App Release Date"),
        "av_version": ("av_release_date", "AV Release Date"),
        "threat_version": ("threat_release_date", "Threat Release Date"),
        "wildfire_version": ("wildfire_release_date", "Wildfire Release Date"),
        "device_dictionary_version": ("device_dictionary_release_date", "Device Dictionary Release Date"),
        "global_protect_datafile_version": ("global_protect_datafile_release_date", "GlobalProtect Datafile Release Date"),
    }

    # VM-specific sensors – conditional
    vm_specific = {
        "vm_cap_tier": "VM Capacity Tier",
        "vm_cores": "VM Cores",
        "vm_cpuid": "VM CPU ID",
        "vm_license": "VM License",
        "vm_mem": "VM Memory (KB)",
        "vm_mode": "VM Mode",
        "vm_uuid": "VM UUID",
    }

    is_vm = system_info.get("platform_family", "").lower() == "vm"

    for key, friendly_name in always_include.items():
        if key in system_info:
            original_key = key
            if key == "wildfire_rt":
                friendly_name = "Wildfire Realtime"  # rename

            entities.append(
                PanFirewallSystemFieldSensor(
                    coordinator=coordinator,
                    key=original_key,
                    name=friendly_name,
                    serial=serial,
                    model=model,
                    version=version,
                    fw=data["fw"],
                )
            )

    # Add date attributes to version sensors (no standalone date sensors)
    for version_key, (date_key, date_name) in date_mappings.items():
        if version_key in system_info and date_key in system_info:
            # We don't create a new entity, but the attribute will be added in the entity's extra_state_attributes
            # (handled in PanFirewallSystemFieldSensor)
            pass

    # VM-specific entities only if platform_family == "vm"
    if is_vm:
        for key, friendly_name in vm_specific.items():
            if key in system_info:
                entities.append(
                    PanFirewallSystemFieldSensor(
                        coordinator=coordinator,
                        key=key,
                        name=friendly_name,
                        serial=serial,
                        model=model,
                        version=version,
                        fw=data["fw"],
                    )
                )

    async_add_entities(entities, update_before_add=True)


class PanFirewallSensor(CoordinatorEntity, SensorEntity):
    """Generic numeric sensor."""

    def __init__(self, coordinator, key: str, name: str, unit: str | None, device_class: str | None, state_class, serial, model, version, fw):
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
        val = self.coordinator.data.get(self._key)
        if self._key == "total_throughput_kbps" and val is not None:
            return round(val / 1000, 1)  # kbps → Mbps
        return val

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


class PanFirewallSystemFieldSensor(CoordinatorEntity, SensorEntity):
    """One sensor per selected system info field."""

    def __init__(self, coordinator, key: str, name: str, serial, model, version, fw):
        super().__init__(coordinator)
        self._key = key
        self._attr_name = name
        self._attr_unique_id = f"pan_{serial}_sys_{key}"
        self._attr_icon = "mdi:information-outline"
        self._serial = serial
        self._model = model
        self._version = version
        self._fw = fw

    @property
    def native_value(self):
        return self.coordinator.data.get("system_info", {}).get(self._key)

    @property
    def extra_state_attributes(self):
        """Add release dates as attributes to version sensors."""
        attrs = {}
        system_info = self.coordinator.data.get("system_info", {})

        date_map = {
            "wildfire_version": "wildfire_release_date",
            "threat_version": "threat_release_date",
            "app_version": "app_release_date",
            "av_version": "av_release_date",
            "device_dictionary_version": "device_dictionary_release_date",
            "global_protect_datafile_version": "global_protect_datafile_release_date",
        }

        if self._key in date_map:
            date_key = date_map[self._key]
            if date_key in system_info:
                attrs["release_date"] = system_info[date_key]

        return attrs

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
