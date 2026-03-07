"""Button platform for PAN Firewall."""

from homeassistant.components.button import ButtonEntity
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
    hostname = data["hostname"]
    model = data["model"]
    version = data["version"]

    entities = [
        PanFirewallCommitButton(
            coordinator=coordinator,
            serial=serial,
            hostname=hostname,
            model=model,
            version=version,
            fw=data["fw"],
        )
    ]

    async_add_entities(entities, update_before_add=True)


class PanFirewallCommitButton(CoordinatorEntity, ButtonEntity):
    """Button to trigger a manual commit."""

    def __init__(self, coordinator, serial, hostname, model, version, fw):
        super().__init__(coordinator)
        self._serial = serial
        self._hostname = hostname
        self._model = model
        self._version = version
        self._fw = fw

        self._attr_name = "Commit Now"
        self._attr_unique_id = f"pan_{serial}_commit_now"
        self._attr_icon = "mdi:upload"

    @property
    def device_info(self):
        return dr.DeviceInfo(
            identifiers={(DOMAIN, self._serial)},
            name=self._hostname,
            manufacturer="Palo Alto Networks",
            model=self._model,
            sw_version=self._version,
            configuration_url=f"https://{self._fw.hostname}",
            entry_type=dr.DeviceEntryType.SERVICE,
        )

    async def async_press(self) -> None:
        """Execute commit when button is pressed."""
        def do_commit():
            self._fw.commit(sync=True)
            return True

        await self.hass.async_add_executor_job(do_commit)
        await self.coordinator.async_request_refresh()  # Refresh all sensors
