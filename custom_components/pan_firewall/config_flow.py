"""Config flow for PAN Firewall."""

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError

import panos.firewall
from .const import (
    DOMAIN,
    CONF_VSYS,
    DEFAULT_VSYS,
    DEFAULT_PORT,
    CONF_VERIFY_SSL,
    DEFAULT_VERIFY_SSL,
    CONF_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    MIN_SCAN_INTERVAL,
)

class PanFirewallConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(
        self, user_input: dict | None = None
    ) -> FlowResult:
        errors = {}

        if user_input is not None:
            try:
                await self._validate_connection(user_input)
            except CannotConnect as err:
                errors["base"] = "cannot_connect"
            except Exception:
                errors["base"] = "unknown"
            else:
                await self.async_set_unique_id(user_input[CONF_HOST])
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=f"PAN Firewall {user_input[CONF_HOST]}",
                    data=user_input,
                )

        data_schema = vol.Schema(
            {
                vol.Required(CONF_HOST): str,
                vol.Optional(CONF_PORT, default=DEFAULT_PORT): int,
                vol.Required(CONF_USERNAME): str,
                vol.Required(CONF_PASSWORD): str,
                vol.Optional(CONF_VSYS, default=DEFAULT_VSYS): str,
                vol.Optional(CONF_VERIFY_SSL, default=DEFAULT_VERIFY_SSL): bool,
                vol.Optional(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): vol.All(
                    vol.Coerce(int), vol.Range(min=MIN_SCAN_INTERVAL)
                ),
            }
        )

        return self.async_show_form(
            step_id="user", data_schema=data_schema, errors=errors
        )

    async def _validate_connection(self, data: dict):
        def test_connection():
            fw = panos.firewall.Firewall(
                hostname=data[CONF_HOST],
                api_username=data[CONF_USERNAME],
                api_password=data[CONF_PASSWORD],
                port=data.get(CONF_PORT, DEFAULT_PORT),
                verify=data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
            )
            rulebase = fw.add(panos.policies.Rulebase())
            panos.policies.SecurityRule.refreshall(rulebase)
            return fw

        try:
            await self.hass.async_add_executor_job(test_connection)
        except Exception as err:
            raise CannotConnect from err


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""
