"""Platform for AMT Intelbras Alarms."""

from homeassistant.components.alarm_control_panel import AlarmControlPanelEntity
from homeassistant.components.alarm_control_panel.const import (
    SUPPORT_ALARM_ARM_AWAY,
    SUPPORT_ALARM_ARM_CUSTOM_BYPASS,
    SUPPORT_ALARM_ARM_HOME,
    SUPPORT_ALARM_ARM_NIGHT,
    SUPPORT_ALARM_TRIGGER,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (  # ATTR_ATTRIBUTION,; STATE_ALARM_ARMED_AWAY,
    STATE_ALARM_ARMED_HOME,
    STATE_ALARM_ARMED_NIGHT,
    STATE_ALARM_DISARMED,
)
from homeassistant.core import HomeAssistant

from .const import DOMAIN


def setup_platform(hass, config, add_entities, discovery_info=None):
    """Set up the alarm platform."""


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities
):
    """Set up Intelbras AMT Alarms from a config entry."""
    panel = AlarmPanel(hass.data[DOMAIN][entry.entry_id])
    async_add_entities([panel])
    # try:
    await panel.async_update()
    # except
    return True


class AlarmPanel(AlarmControlPanelEntity):
    """Representation of a alarm."""

    def __init__(self, hub):
        """Initialize the alarm."""
        self._state = None
        self._by = "Felipe"
        self.hub = hub

    async def async_alarm_arm_home(self, code=None):
        """Send arm home command."""
        await self.hub.send_test()

    @property
    def should_poll(self):
        """Declare this Entity as Push."""
        return False

    @property
    def unique_id(self):
        """Return the unique id for the sync module."""
        return "nhontehaontehoatnehoatn"

    @property
    def name(self):
        """Return the name of the panel."""
        return "Alarm panel"

    @property
    def state(self):
        """Return the state of the sensor."""
        print("state being read")
        return self._state

    @property
    def supported_features(self) -> int:
        """Return the list of supported features."""
        return (
            SUPPORT_ALARM_ARM_HOME
            | SUPPORT_ALARM_ARM_AWAY
            | SUPPORT_ALARM_ARM_NIGHT
            | SUPPORT_ALARM_TRIGGER
            | SUPPORT_ALARM_ARM_CUSTOM_BYPASS
        )

    @property
    def changed_by(self):
        """Last change triggered by."""
        return self._by

    @property
    def device_state_attributes(self):
        """Return the state attributes."""
        attr = {}
        # attr[ATTR_ATTRIBUTION] = DEFAULT_ATTRIBUTION
        return attr

    async def async_update(self):
        """Update the state of the device."""
        print("entity async update")
        await self.hub.async_update()
        self.hub_update()
        self.hub.listen_event(self)

    def hub_update(self):
        """Receive callback to update state from Hub."""
        print("hub_update")
        partitions = self.hub.get_partitions()
        if partitions[1]:
            self._state = STATE_ALARM_ARMED_NIGHT
        elif partitions[0] or partitions[2] or partitions[3]:
            self._state = STATE_ALARM_ARMED_HOME
        else:
            self._state = STATE_ALARM_DISARMED
        print("partitions ", partitions)
        self.async_write_ha_state()

    async def async_alarm_disarm(self, code=None):
        """Send disarm command."""
        await self.hub.async_alarm_disarm(code)
