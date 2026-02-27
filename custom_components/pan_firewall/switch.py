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

    entities = []
    for rule_name, rule_obj in coordinator.data.items():
        entities.append(
            PanFirewallRuleSwitch(
                coordinator=coordinator,
                rule_name=rule_name,
                rule_obj=rule_obj,
                fw=data["fw"],
            )
        )

    async_add_entities(entities)


class PanFirewallRuleSwitch(CoordinatorEntity, SwitchEntity):
    """Representation of a PAN Firewall rule switch."""

    def __init__(self, coordinator, rule_name: str, rule_obj, fw):
        super().__init__(coordinator)
        self._rule_name = rule_name
        self._rule_obj = rule_obj
        self._fw = fw
        self._attr_name = f"PAN Rule {rule_name}"
        self._attr_unique_id = f"{fw.serial_number}_{rule_name}"
        self._attr_icon = "mdi:shield-lock"

    @property
    def is_on(self) -> bool:
        """Return true if the rule is enabled."""
        # Refresh from latest coordinator data
        rule = self.coordinator.data.get(self._rule_name)
        return rule is not None and not rule.disabled

    async def async_turn_on(self, **kwargs):
        """Enable the rule."""
        await self._set_disabled(False)

    async def async_turn_off(self, **kwargs):
        """Disable the rule."""
        await self._set_disabled(True)

    async def _set_disabled(self, disabled: bool):
        """Set disabled state and commit."""
        def set_and_commit():
            # Get fresh rule object
            rule = self.coordinator.data.get(self._rule_name)
            if rule is None:
                raise ValueError("Rule not found")
            rule.disabled = disabled
            rule.update()                     # Push change to candidate config
            self._fw.commit(sync=True)        # Commit (blocks until done)
            return True

        await self.hass.async_add_executor_job(set_and_commit)
        await self.coordinator.async_request_refresh()  # Update all entities
