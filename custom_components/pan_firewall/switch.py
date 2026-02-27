"""Switch platform for PAN Firewall rules."""

from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers import device_registry as dr

from .const import DOMAIN


async def async_setup_entry(
    hass: HomeAssistant, entry, async_add_entities: AddEntitiesCallback
):
    """Set up the PAN Firewall switch platform."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator = data["coordinator"]
    serial = data["serial"]
    model = data["model"]
    version = data["version"]

    entities = []

    # Only create switches from the actual rules (new structure)
    for rule_name in coordinator.data.get("rules", {}).keys():
        entities.append(
            PanFirewallRuleSwitch(
                coordinator=coordinator,
                rule_name=rule_name,
                fw=data["fw"],
                serial=serial,
                model=model,
                version=version,
            )
        )

    async_add_entities(entities, update_before_add=True)


class PanFirewallRuleSwitch(CoordinatorEntity, SwitchEntity):
    """Representation of a PAN Firewall rule switch."""

    def __init__(self, coordinator, rule_name: str, fw, serial: str, model: str, version: str):
        super().__init__(coordinator)
        self._rule_name = rule_name
        self._fw = fw
        self._serial = serial
        self._model = model
        self._version = version

        self._attr_name = rule_name
        self._attr_unique_id = f"pan_{serial}_{rule_name}".lower().replace(" ", "_").replace("/", "_")
        self._attr_icon = "mdi:shield-lock"
        self._attr_device_class = "switch"
        self._attr_has_entity_name = True

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

    @property
    def is_on(self) -> bool:
        rule = self.coordinator.data.get("rules", {}).get(self._rule_name)
        return rule is not None and not getattr(rule, "disabled", False)

    async def async_turn_on(self, **kwargs):
        await self._set_disabled(False)

    async def async_turn_off(self, **kwargs):
        await self._set_disabled(True)

    async def _set_disabled(self, disabled: bool):
        """Enable/disable rule + commit."""
        def set_and_commit():
            rule = self.coordinator.data.get("rules", {}).get(self._rule_name)
            if rule is None:
                raise ValueError(f"Rule '{self._rule_name}' not found")
            rule.disabled = disabled
            rule.apply()
            self._fw.commit(sync=True)
            return True

        await self.hass.async_add_executor_job(set_and_commit)
        await self.coordinator.async_request_refresh()
