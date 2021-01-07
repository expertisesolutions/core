"""Config flow for Intelbras AMT Alarms integration."""
import logging

import voluptuous as vol

from homeassistant import config_entries, core, exceptions
from homeassistant.helpers import config_validation as cv

from . import AlarmHub
from .const import (
    CONF_AWAY_MODE_ENABLED,
    CONF_AWAY_PARTITION_1,
    CONF_AWAY_PARTITION_2,
    CONF_AWAY_PARTITION_3,
    CONF_AWAY_PARTITION_4,
    CONF_HOME_MODE_ENABLED,
    CONF_HOME_PARTITION_1,
    CONF_HOME_PARTITION_2,
    CONF_HOME_PARTITION_3,
    CONF_HOME_PARTITION_4,
    CONF_NIGHT_PARTITION_1,
    CONF_NIGHT_PARTITION_2,
    CONF_NIGHT_PARTITION_3,
    CONF_NIGHT_PARTITION_4,
    CONF_PASSWORD,
    CONF_PORT,
)
from .const import DOMAIN  # PARTITION_LIST,; pylint:disable=unused-import

_LOGGER = logging.getLogger(__name__)

partition_on = "Active"
partition_off = "Not active"
partition_none = "Don't care"
partition_vol = vol.In([partition_none, partition_on, partition_off])

user_schema = {
    vol.Required(CONF_PORT, default=9009): cv.port,
    CONF_PASSWORD: int,
}
night_partition_schema = {
    vol.Required(CONF_NIGHT_PARTITION_1, default=partition_on): partition_vol,
    vol.Required(CONF_NIGHT_PARTITION_2, default=partition_on): partition_vol,
    vol.Required(CONF_NIGHT_PARTITION_3, default=partition_on): partition_vol,
    vol.Required(CONF_NIGHT_PARTITION_4, default=partition_on): partition_vol,
}
away_mode_partition_schema = {
    vol.Required(CONF_AWAY_MODE_ENABLED, default=False): bool,
    vol.Required(CONF_AWAY_PARTITION_1, default=partition_on): partition_vol,
    vol.Required(CONF_AWAY_PARTITION_2, default=partition_on): partition_vol,
    vol.Required(CONF_AWAY_PARTITION_3, default=partition_on): partition_vol,
    vol.Required(CONF_AWAY_PARTITION_4, default=partition_on): partition_vol,
}
home_mode_partition_schema = {
    vol.Required(CONF_HOME_MODE_ENABLED, default=False): bool,
    vol.Required(CONF_HOME_PARTITION_1, default=partition_none): partition_vol,
    vol.Required(CONF_HOME_PARTITION_2, default=partition_none): partition_vol,
    vol.Required(CONF_HOME_PARTITION_3, default=partition_none): partition_vol,
    vol.Required(CONF_HOME_PARTITION_4, default=partition_none): partition_vol,
}
# TODO adjust the data schema to the data that you need
DATA_SCHEMA = vol.Schema(
    #    {
    user_schema,
    #        **partition_schema,
    #    }
)


def convert_input(data):
    """Convert input to configuration."""
    for i in [
        CONF_NIGHT_PARTITION_1,
        CONF_NIGHT_PARTITION_2,
        CONF_NIGHT_PARTITION_3,
        CONF_NIGHT_PARTITION_4,
        CONF_AWAY_PARTITION_1,
        CONF_AWAY_PARTITION_2,
        CONF_AWAY_PARTITION_3,
        CONF_AWAY_PARTITION_4,
        CONF_HOME_PARTITION_1,
        CONF_HOME_PARTITION_2,
        CONF_HOME_PARTITION_3,
        CONF_HOME_PARTITION_4,
    ]:
        if i in data:
            if data[i] == partition_on:
                data[i] = True
            elif data[i] == partition_off:
                data[i] = False
            else:
                del data[i]
    return data


async def validate_user_input(hass: core.HomeAssistant, data):
    """Validate the network input allows us to connect.

    Data has the keys from DATA_SCHEMA with values provided by the user.
    """
    # TODO validate the data can be used to set up a connection.

    # If your PyPI package is not built with async, pass your methods
    # to the executor:
    # await hass.async_add_executor_job(
    #     your_validate_func, data["username"], data["password"]
    # )

    hub = AlarmHub(data["port"], data["password"])

    if not await hub.wait_connection():
        hub.close()
        raise InvalidAuth

    hub.close()

    # If you cannot connect:
    # throw CannotConnect
    # If the authentication is wrong:
    # InvalidAuth

    # Return info that you want to store in the config entry.
    return {"title": "Name of the device"}


async def validate_night_mode_input(hass: core.HomeAssistant, data):
    """Validate the network input allows us to connect.

    Data has the keys from DATA_SCHEMA with values provided by the user.
    """
    # TODO validate the data can be used to set up a connection.

    # Return info that you want to store in the config entry.
    return {"title": "Name of the device"}


async def validate_away_mode_input(hass: core.HomeAssistant, data):
    """Validate the network input allows us to connect.

    Data has the keys from DATA_SCHEMA with values provided by the user.
    """
    # TODO validate the data can be used to set up a connection.

    # Return info that you want to store in the config entry.
    return {"title": "Name of the device"}


async def validate_home_mode_input(hass: core.HomeAssistant, data):
    """Validate the network input allows us to connect.

    Data has the keys from DATA_SCHEMA with values provided by the user.
    """
    # TODO validate the data can be used to set up a connection.

    # Return info that you want to store in the config entry.
    return {"title": "Name of the device"}


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Intelbras AMT Alarms."""

    VERSION = 1
    # TODO pick one of the available connection classes in homeassistant/config_entries.py
    CONNECTION_CLASS = config_entries.CONN_CLASS_LOCAL_PUSH

    # async def async_step_init(self, user_input=None):
    #     errors = {}
    #     return await self.async_step_net()

    async def async_step_home_mode(self, home_mode_input=None):
        """Show and handle home mode step."""
        errors = {}
        print("async_step_home_mode", home_mode_input)
        if home_mode_input is not None:
            try:
                info = await validate_home_mode_input(self.hass, home_mode_input)
                merge = self.user_input.copy()
                merge.update(self.night_mode_input)
                merge.update(self.away_mode_input)
                merge.update(home_mode_input)
                config = convert_input(merge)
                print("home_mode_input", home_mode_input)

                self.home_mode_input = home_mode_input

                return self.async_create_entry(title=info["title"], data=config)
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"

        try:
            r = self.async_show_form(
                step_id="home_mode",
                data_schema=vol.Schema(home_mode_partition_schema),
                errors=errors,
            )
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected exception")
            errors["base"] = "unknown"

        return r

    async def async_step_away_mode(self, away_mode_input=None):
        """Show and handle away mode step."""
        errors = {}
        print("async_step_away_mode", away_mode_input)
        if away_mode_input is not None:
            try:
                await validate_away_mode_input(self.hass, away_mode_input)
                print("away_mode_input", away_mode_input)

                self.away_mode_input = away_mode_input

                return await self.async_step_home_mode()
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"

        try:
            r = self.async_show_form(
                step_id="away_mode",
                data_schema=vol.Schema(away_mode_partition_schema),
                errors=errors,
            )
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected exception")
            errors["base"] = "unknown"

        return r

    async def async_step_night_mode(self, night_mode_input=None):
        """Show and handle night mode step."""
        errors = {}
        print("async_step_night_mode", night_mode_input)
        if night_mode_input is not None:
            try:
                await validate_night_mode_input(self.hass, night_mode_input)
                print("night_mode_input", night_mode_input)

                self.night_mode_input = night_mode_input

                return await self.async_step_away_mode()
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"

        try:
            r = self.async_show_form(
                step_id="night_mode",
                data_schema=vol.Schema(night_partition_schema),
                errors=errors,
            )
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected exception")
            errors["base"] = "unknown"

        return r

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}
        print("async_step_init", user_input)
        if user_input is not None:
            try:
                await validate_user_input(self.hass, user_input)
                print("user_input", user_input)
                # print("new user_input", config)

                self.user_input = user_input

                # return self.async_create_entry(title=info["title"], data=user_input)
                return await self.async_step_night_mode()
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"

        try:
            r = self.async_show_form(
                step_id="user", data_schema=vol.Schema(user_schema), errors=errors
            )
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected exception")
            errors["base"] = "unknown"

        return r


class CannotConnect(exceptions.HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(exceptions.HomeAssistantError):
    """Error to indicate there is invalid auth."""
