"""PAN Firewall integration."""

from datetime import timedelta
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
import panos.firewall
import panos.policies

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["switch"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up PAN Firewall from a config entry."""
    fw = panos.firewall.Firewall(
        hostname=entry.data[CONF_HOST],
        api_username=entry.data[CONF_USERNAME],
        api_password=entry.data[CONF_PASSWORD],
        port=entry.data.get(CONF_PORT, DEFAULT_PORT),
        verify=entry.data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
    )

    coordinator = PanFirewallCoordinator(hass, fw, entry.data.get(CONF_VSYS, DEFAULT_VSYS))

    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        "coordinator": coordinator,
        "fw": fw,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)
    return unload_ok


class PanFirewallCoordinator(DataUpdateCoordinator):
    """Data update coordinator for PAN Firewall rules."""

    def __init__(self, hass: HomeAssistant, fw, vsys: str):
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=300),
        )
        self.fw = fw
        self.vsys = vsys
        self.rulebase = None

    async def _async_update_data(self):
        """Fetch all security rules."""
        def fetch_rules():
            if self.rulebase is None:
                self.rulebase = panos.policies.Rulebase()
                self.fw.add(self.rulebase)
            rules = panos.policies.SecurityRule.refreshall(self.rulebase)
            return {rule.name: rule for rule in rules}

        try:
            return await self.hass.async_add_executor_job(fetch_rules)
        except Exception as err:
            raise UpdateFailed(f"Error fetching rules: {err}") from err
