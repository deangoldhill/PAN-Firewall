"""Switch platform for PAN Firewall rules."""

from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

async def async_setup_entry(
    hass: HomeAssistant, entry, async_add_entities: AddEntitiesCallback
):
    """Set up the PAN Firewall switch platform."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator = data["coordinator"]
    serial = data["serial"]  # This comes from the fixed __init__.py

    entities = []
    for rule_name in coordinator.data.keys():
        entities.append(
            PanFirewallRuleSwitch(
                coordinator=coordinator,
                rule_name=rule_name,
                fw=data["fw"],
                serial=serial,
            )
        )

    async_add_entities(entities, update_before_add=True)


class PanFirewallRuleSwitch(CoordinatorEntity, SwitchEntity):
    """Representation of a PAN Firewall rule switch."""

    def __init__(self, coordinator, rule_name: str, fw, serial: str):
        super().__init__(coordinator)
        self._rule_name = rule_name
        self._fw = fw

        self._attr_name = f"PAN Rule {rule_name}"
        self._attr_unique_id = f"pan_{serial}_{rule_name}".lower().replace(" ", "_").replace("/", "_")
        self._attr_icon = "mdi:shield-lock"
        self._attr_device_class = "switch"
        self._attr_has_entity_name = True

    @property
    def is_on(self) -> bool:
        """Return true if the rule is enabled."""
        rule = self.coordinator.data.get(self._rule_name)
        return rule is not None and not getattr(rule, "disabled", False)

    async def async_turn_on(self, **kwargs):
        """Enable the rule + commit."""
        await self._set_disabled(False)

    async def async_turn_off(self, **kwargs):
        """Disable the rule + commit."""
        await self._set_disabled(True)

    async def _set_disabled(self, disabled: bool):
        """Set disabled state and commit configuration."""
        def set_and_commit():
            rule = self.coordinator.data.get(self._rule_name)
            if rule is None:
                raise ValueError(f"Rule '{self._rule_name}' not found")
            rule.disabled = disabled
            rule.update()           # Push change to candidate config
            self._fw.commit(sync=True)  # BLOCKING commit (takes effect immediately)
            return True

        await self.hass.async_add_executor_job(set_and_commit)
        await self.coordinator.async_request_refresh()  # Refresh all entities
