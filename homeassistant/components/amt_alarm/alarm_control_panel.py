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
from homeassistant.const import (
    STATE_ALARM_ARMED_AWAY,
    STATE_ALARM_ARMED_HOME,
    STATE_ALARM_ARMED_NIGHT,
    STATE_ALARM_DISARMED,
    STATE_UNAVAILABLE,
)
from homeassistant.core import HomeAssistant

from .const import (
    CONF_AWAY_MODE_ENABLED,
    CONF_AWAY_PARTITION_LIST,
    CONF_HOME_MODE_ENABLED,
    CONF_HOME_PARTITION_LIST,
    CONF_NIGHT_PARTITION_LIST,
    DOMAIN,
)


def setup_platform(hass, config, add_entities, discovery_info=None):
    """Set up the alarm platform."""


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities
):
    """Set up Intelbras AMT Alarms from a config entry."""
    hub = hass.data[DOMAIN][entry.entry_id]
    panels = [AlarmPanel(hub)]
    for i in range(hub.max_partitions):
        panels.append(PartitionAlarmPanel(hub, i))

    for panel in panels:
        panel.update_state()

    async_add_entities(panels)

    return True


class AlarmPanel(AlarmControlPanelEntity):
    """Representation of a alarm."""

    def __init__(self, hub):
        """Initialize the alarm."""
        self._state = STATE_UNAVAILABLE
        self._by = "Felipe"
        self.hub = hub

    async def async_alarm_arm_night(self, code=None):
        """Send arm night command."""
        await self.hub.alarm_arm_night()

    async def async_alarm_arm_home(self, code=None):
        """Send arm home command."""
        await self.hub.alarm_arm_home()

    async def async_alarm_arm_away(self, code=None):
        """Send arm away command."""
        await self.hub.alarm_arm_away()

    async def async_added_to_hass(self):
        """Entity was added to Home Assistant."""
        self.hub.listen_event(self)

    async def async_will_remove_from_hass(self):
        """Entity was added to Home Assistant."""
        self.hub.remove_listen_event(self)

    @property
    def should_poll(self):
        """Declare this Entity as Push."""
        return False

    @property
    def unique_id(self):
        """Return the unique id for the sync module."""
        return self.name + ".alarm_panel"

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
    def device_info(self):
        """Return device information for this Entity."""
        return {
            "identifiers": {(DOMAIN, self.unique_id)},
            "name": self.name,
            "manufacturer": "Intelbras",
            "model": "AMTxxxx",
            "sw_version": "Unknown",
        }

    @property
    def device_state_attributes(self):
        """Return the state attributes."""
        return {"device_id": self.unique_id}

    async def async_update(self):
        """Update the state of the device."""
        print("entity async update")
        await self.hub.async_update()

    def update_state(self):
        """Update synchronously to current state."""
        partitions = self.hub.get_partitions()
        old_state = self._state
        if None in partitions:
            self._state = STATE_UNAVAILABLE
        elif not any(partitions):
            self._state = STATE_ALARM_DISARMED
        else:
            night_partition_check = [False] * self.hub.max_partitions
            away_partition_check = [False] * self.hub.max_partitions
            home_partition_check = [False] * self.hub.max_partitions

            for i in range(self.hub.max_partitions):
                if CONF_NIGHT_PARTITION_LIST[i] not in self.hub.config_entry.data:
                    night_partition_check[i] = True
                else:
                    night_partition_check[i] = (
                        self.hub.config_entry.data[CONF_NIGHT_PARTITION_LIST[i]]
                        == partitions[i]
                    )
                if CONF_AWAY_PARTITION_LIST[i] not in self.hub.config_entry.data:
                    away_partition_check[i] = True
                else:
                    away_partition_check[i] = (
                        self.hub.config_entry.data[CONF_AWAY_PARTITION_LIST[i]]
                        == partitions[i]
                    )
                if CONF_HOME_PARTITION_LIST[i] not in self.hub.config_entry.data:
                    home_partition_check[i] = True
                else:
                    home_partition_check[i] = (
                        self.hub.config_entry.data[CONF_HOME_PARTITION_LIST[i]]
                        == partitions[i]
                    )
            if all(night_partition_check):
                self._state = STATE_ALARM_ARMED_NIGHT
            elif self.hub.config_entry.data[CONF_AWAY_MODE_ENABLED] and all(
                away_partition_check
            ):
                self._state = STATE_ALARM_ARMED_AWAY
            elif self.hub.config_entry.data[CONF_HOME_MODE_ENABLED] and all(
                home_partition_check
            ):
                self._state = STATE_ALARM_ARMED_HOME
            else:
                self._state = STATE_ALARM_DISARMED

            print("partitions ", partitions)
            return self._state != old_state

    def hub_update(self):
        """Receive callback to update state from Hub."""
        print("hub_update")
        if self.update_state():
            self.async_write_ha_state()

    async def async_alarm_disarm(self, code=None):
        """Send disarm command."""
        await self.hub.async_alarm_disarm(code)


class PartitionAlarmPanel(AlarmControlPanelEntity):
    """Representation of a alarm."""

    def __init__(self, hub, index):
        """Initialize the alarm."""
        self.index = index
        self._state = STATE_UNAVAILABLE
        self._by = "Felipe"
        self.hub = hub

    async def async_alarm_arm_night(self, code=None):
        """Send arm night command."""
        await self.hub.send_arm_partition(self.index)

    async def async_alarm_arm_away(self, code=None):
        """Send arm night command."""
        await self.hub.send_arm_partition(self.index)

    async def async_alarm_arm_home(self, code=None):
        """Send arm night command."""
        await self.hub.send_arm_partition(self.index)

    async def async_added_to_hass(self):
        """Entity was added to Home Assistant."""
        self.hub.listen_event(self)

    async def async_will_remove_from_hass(self):
        """Entity was added to Home Assistant."""
        self.hub.remove_listen_event(self)

    @property
    def should_poll(self):
        """Declare this Entity as Push."""
        return False

    @property
    def panel_unique_id(self):
        """Return the unique id for the original panel."""
        return self.name + ".alarm_panel"

    @property
    def unique_id(self):
        """Return the unique id for the sync module."""
        return self.panel_unique_id + ".partition" + str(self.index)

    @property
    def name(self):
        """Return the name of the panel."""
        return "Alarm panel for partition " + str(self.index + 1)

    @property
    def state(self):
        """Return the state of the sensor."""
        print("state being read")
        return self._state

    @property
    def supported_features(self) -> int:
        """Return the list of supported features."""
        return (
            SUPPORT_ALARM_ARM_NIGHT
            | SUPPORT_ALARM_ARM_AWAY
            | SUPPORT_ALARM_ARM_HOME
            | SUPPORT_ALARM_TRIGGER
            | SUPPORT_ALARM_ARM_CUSTOM_BYPASS
        )

    @property
    def changed_by(self):
        """Last change triggered by."""
        return self._by

    @property
    def device_info(self):
        """Return device information for this Entity."""
        return {
            "identifiers": {(DOMAIN, self.unique_id)},
            "name": self.name,
            "manufacturer": "Intelbras",
            "model": "AMTxxxx",
            "sw_version": "Unknown",
            "via_device": (DOMAIN, self.panel_unique_id),
        }

    @property
    def device_state_attributes(self):
        """Return the state attributes."""
        return {"device_id": self.unique_id}

    async def async_update(self):
        """Update the state of the device."""
        print("entity async update")
        await self.hub.async_update()

    def update_state(self):
        """Update synchronously to current state."""
        partitions = self.hub.get_partitions()
        old_state = self._state
        if None in partitions:
            self._state = STATE_UNAVAILABLE
        elif partitions[self.index]:
            self._state = STATE_ALARM_ARMED_NIGHT
        else:
            self._state = STATE_ALARM_DISARMED
        print("partitions ", partitions)
        return self._state != old_state

    def hub_update(self):
        """Receive callback to update state from Hub."""
        print("hub_update")
        if self.update_state():
            self.async_write_ha_state()

    async def async_alarm_disarm(self, code=None):
        """Send disarm command."""
        # await self.hub.async_alarm_disarm(code)
