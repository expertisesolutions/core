"""The Intelbras AMT Alarms integration."""
import asyncio
import socket
import time

import crcengine
import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv

from .const import (
    AMT_EVENT_CODE_ATIVACAO_PARCIAL,
    AMT_EVENT_CODE_ATIVACAO_PELO_USUARIO,
    AMT_EVENT_CODE_ATIVACAO_POR_UMA_TECLA,
    AMT_EVENT_CODE_ATIVACAO_VIA_COMPUTADOR_OU_TELEFONE,
    AMT_EVENT_CODE_AUTO_ATIVACAO,
    AMT_EVENT_CODE_AUTO_DESATIVACAO,
    AMT_EVENT_CODE_DESATIVACAO_PELO_USUARIO,
    AMT_EVENT_CODE_DESATIVACAO_VIA_COMPUTADOR_OU_TELEFONE,
    CONF_AWAY_MODE_ENABLED,
    CONF_AWAY_PARTITION_1,
    CONF_AWAY_PARTITION_2,
    CONF_AWAY_PARTITION_3,
    CONF_AWAY_PARTITION_4,
    CONF_AWAY_PARTITION_LIST,
    CONF_HOME_MODE_ENABLED,
    CONF_HOME_PARTITION_1,
    CONF_HOME_PARTITION_2,
    CONF_HOME_PARTITION_3,
    CONF_HOME_PARTITION_4,
    CONF_HOME_PARTITION_LIST,
    CONF_NIGHT_PARTITION_1,
    CONF_NIGHT_PARTITION_2,
    CONF_NIGHT_PARTITION_3,
    CONF_NIGHT_PARTITION_4,
    CONF_NIGHT_PARTITION_LIST,
    CONF_PASSWORD,
    CONF_PORT,
    DOMAIN,
)

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Required(CONF_PORT): cv.port,
                vol.Optional(CONF_PASSWORD): int,
                vol.Optional(CONF_NIGHT_PARTITION_1): bool,
                vol.Optional(CONF_NIGHT_PARTITION_2): bool,
                vol.Optional(CONF_NIGHT_PARTITION_3): bool,
                vol.Optional(CONF_NIGHT_PARTITION_4): bool,
                vol.Optional(CONF_AWAY_MODE_ENABLED): bool,
                vol.Optional(CONF_AWAY_PARTITION_1): bool,
                vol.Optional(CONF_AWAY_PARTITION_2): bool,
                vol.Optional(CONF_AWAY_PARTITION_3): bool,
                vol.Optional(CONF_AWAY_PARTITION_4): bool,
                vol.Optional(CONF_HOME_MODE_ENABLED): bool,
                vol.Optional(CONF_HOME_PARTITION_1): bool,
                vol.Optional(CONF_HOME_PARTITION_2): bool,
                vol.Optional(CONF_HOME_PARTITION_3): bool,
                vol.Optional(CONF_HOME_PARTITION_4): bool,
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)

# TODO List the platforms that you want to support.
# For your initial PR, limit it to 1 platform.
PLATFORMS = ["alarm_control_panel", "sensor"]


async def async_setup(hass: HomeAssistant, config: dict):
    """Set up the Intelbras AMT Alarms component."""
    hass.data[DOMAIN] = {}
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Set up Intelbras AMT Alarms from a config entry."""
    # TODO Store an API object for your platforms to access
    alarm = AlarmHub(entry, entry.data["port"], entry.data["password"])
    hass.data[DOMAIN][entry.entry_id] = alarm

    await alarm.wait_connection()
    await alarm.async_update()

    for component in PLATFORMS:
        hass.async_create_task(
            hass.config_entries.async_forward_entry_setup(entry, component)
        )

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Unload a config entry."""
    unload_ok = all(
        await asyncio.gather(
            *[
                hass.config_entries.async_forward_entry_unload(entry, component)
                for component in PLATFORMS
            ]
        )
    )
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok


class AlarmHub:
    """Placeholder class to make tests pass.

    TODO Remove this placeholder class and replace with things from your PyPI package.
    """

    def __init__(self, config_entry, port, password=None):
        """Initialize."""
        if password is not None:
            self.password = str(password)
            if len(self.password) != 4 and len(self.password) != 6:
                raise ValueError

        self.config_entry = config_entry
        self.port = port
        self._timeout = 10.0

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.socket.bind(("", port))
        self.socket.listen(1)

        self.polling_task = None
        self.reading_task = None
        self.update_event = asyncio.Event()

        self.is_initialized = False
        self.crc = crcengine.create(0xAB, 8, 0, False, False, "", 0)
        self.disarm_crc = crcengine.create(0xAB, 8, 0, False, False, "", 0xFF)
        # self.disarm_crc = crcengine.create(0xBA, 8, 0, False, False, "", 0xFF)
        # self.disarm_crc = self.crc

        self.open_sensors = [None] * 48
        self.partitions = [None] * 4
        # self.open_sensors[0:47] = False

        # self.t2 = 0

        self.listeners = []

    @property
    def name(self):
        """Return unique name from device."""
        return "AMTAlarm"

    async def send_request_zones(self):
        """Send Request Information packet."""
        if self.password is None:
            raise ValueError

        buf = bytes([])
        buf = buf + b"\x0a\xe9\x21"

        buf = buf + self.password.encode("utf-8")

        if len(self.password) == 4:
            buf = buf + b"00"

        buf = buf + b"\x5b\x21\x00"
        crc = self.crc(buf)
        buf = buf[0 : len(buf) - 1] + bytes([crc])

        self.writer.write(buf)
        await self.writer.drain()

    async def send_arm_partition(self, partition):
        """Send Request Information packet."""

        # print("arm partition", partition+1)

        if self.password is None:
            raise ValueError

        buf = bytes([])
        buf = buf + b"\x0b\xe9\x21"

        buf = buf + self.password.encode("utf-8")

        if len(self.password) == 4:
            buf = buf + b"00"

        buf = buf + b"\x41"
        buf = buf + bytes([0x40 + partition + 1])
        buf = buf + b"\x21\x00"
        crc = self.crc(buf)
        buf = buf[0 : len(buf) - 1] + bytes([crc])
        print("arm partition req buf ", buf)

        self.writer.write(buf)
        await self.writer.drain()

    async def send_disarm_partition(self, partition):
        """Send Request Information packet."""

        # print("arm partition", partition+1)

        if self.password is None:
            raise ValueError

        buf = bytes([])
        buf = buf + b"\x0b\xe9\x21"

        buf = buf + self.password.encode("utf-8")

        if len(self.password) == 4:
            buf = buf + b"00"

        buf = buf + b"\x44"
        buf = buf + bytes([0x40 + partition + 1])
        buf = buf + b"\x21\x00"
        crc = self.disarm_crc(buf)
        buf = buf[0 : len(buf) - 1] + bytes([crc])
        print("disarm partition req buf ", buf)

        self.writer.write(buf)
        await self.writer.drain()

    async def send_test(self):
        """Send Reverse Engineering Test."""

        # unsigned char buffer[] = {0x0b, 0xe9, 0x21, /* senha */ 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, /* fim da senha */ 0x41, 0x40 + partition, 0x21, 0x00};
        # self.t1 = 0x44

        # while True: #if True: if self.password is None: raise
        # ValueError

        #     print("send test") buf = bytes([]) #buf = buf +
        #     b"\x0b\xe9" + bytes([0x21]) buf = buf + b"\x0a\xe9" +
        #     bytes([0x21])

        #     buf = buf + self.password.encode("utf-8") if
        #     len(self.password) == 4: buf = buf + b"00"

        #     buf = buf + bytes([self.t1]) #buf = buf + bytes([0x40 + 3+
        #     1]) buf = buf + bytes([0x21]) + b"\x00" self.t1 += 1

        #     crc = self.crc(buf) buf = buf[0 : len(buf) - 1] +
        #     bytes([crc]) print("buf length ", len(buf)) print("req buf
        #     ", buf)

        #     self.writer.write(buf) await self.writer.drain() await
        #     asyncio.sleep(1)

        #     print("wrote")

    async def __send_ack(self):
        self.writer.write(bytes([0xFE]))
        await self.writer.drain()

    def __handle_amt_event(self, event, partition, zone, client_id):
        if (
            event == AMT_EVENT_CODE_DESATIVACAO_PELO_USUARIO
            or event == AMT_EVENT_CODE_AUTO_DESATIVACAO
            or event == AMT_EVENT_CODE_DESATIVACAO_VIA_COMPUTADOR_OU_TELEFONE
        ):
            if partition == -1:
                self.partitions = [False] * 4
            else:
                self.partitions[partition] = False
        elif (
            event == AMT_EVENT_CODE_ATIVACAO_PELO_USUARIO
            or event == AMT_EVENT_CODE_AUTO_ATIVACAO
            or event == AMT_EVENT_CODE_ATIVACAO_VIA_COMPUTADOR_OU_TELEFONE
            or event == AMT_EVENT_CODE_ATIVACAO_POR_UMA_TECLA
            or event == AMT_EVENT_CODE_ATIVACAO_PARCIAL
        ):
            if partition == -1:
                self.partitions = [True] * 4
            else:
                self.partitions[partition] = True
        self.__call_listeners()

    async def __handle_packet(self, packet):

        cmd = packet[0]
        if cmd == 0xF7 and len(packet) == 1:
            print("cmd 0xf7: ", packet)
            await self.__send_ack()
        elif cmd == 0x94:
            print("cmd 0x94: ", packet)
            await self.__send_ack()
        elif cmd == 0xC4:
            print("cmd 0xc4: ", packet)
        elif cmd == 0xB0 and len(packet) == 17 and packet[1] == 0x12:
            print("cmd 0xb0: ", packet)

            def unescape_zero(i):
                return i if i != 0xA else 0

            client_id = (
                unescape_zero(packet[2]) * 1000
                + unescape_zero(packet[3]) * 100
                + unescape_zero(packet[4]) * 10
                + unescape_zero(packet[5])
            )
            ev_id = (
                unescape_zero(packet[8]) * 1000
                + unescape_zero(packet[9]) * 100
                + unescape_zero(packet[10]) * 10
                + unescape_zero(packet[11])
            )
            partition = unescape_zero(packet[12]) * 10 + unescape_zero(packet[13]) - 1
            zone = (
                unescape_zero(packet[14]) * 100
                + unescape_zero(packet[15]) * 10
                + unescape_zero(packet[16])
            )

            print("event", ev_id, "from partition", partition, "and zone", zone)
            self.__handle_amt_event(ev_id, partition, zone, client_id)

            await self.__send_ack()
        elif (
            cmd == 0xE9
            and len(packet) == 2
            and (packet[1] == 0xE5 or packet[1] == 0xFE)
        ):
            await self.__send_ack()
        elif cmd == 0xE9 and len(packet) == 2 and packet[1] == 0xE1:
            print("cmd 0xe9: ", packet)
            print("We are using wrong password?")
            await self.__send_ack()
        elif cmd == 0xE9 and len(packet) >= 3 * 8:
            for x in range(6):
                c = packet[x + 1]
                for i in range(8):
                    self.open_sensors[x * 8 + i] = (
                        True if ((c >> i) & 1) == 1 else False
                    )

            c = packet[1 + 8 + 8 + 8 + 3]
            for i in range(2):
                self.partitions[i] = True if ((c >> i) & 1) else False
                # if (c >> i) & 1:
                #     print("Partition ", i, " armed")
            c = packet[1 + 8 + 8 + 8 + 3 + 1]
            for i in range(2):
                self.partitions[i + 2] = True if ((c >> i) & 1) else False
                # if (c >> i) & 1:
                #     print("Partition ", i + 2, " armed")

            self.is_initialized = True
            self.update_event.set()
            self.__call_listeners()
        else:
            print("how to deal with ", packet, " ????")

    async def __handle_data(self):
        while len(self.outstanding_buffer) != 0:
            is_nope = self.outstanding_buffer[0] == 0xF7
            packet_size = 1 if is_nope else self.outstanding_buffer[0]
            packet_start = 1 if not is_nope else 0

            if not is_nope and len(self.outstanding_buffer) < packet_size + 1:
                break

            crc = packet_start
            buf = self.outstanding_buffer[packet_start : packet_size + packet_start]
            self.outstanding_buffer = self.outstanding_buffer[
                packet_start + packet_size + crc :
            ]

            assert len(buf) == packet_size

            # while is_nope or packet_size + 1 < self.outstanding_buffer.size
            # print ("is nope ", is_nope, " buf ", buf, " buf size ", len(buf), " packet_size ", packet_size, " self.outstanding_buffer size ", len(self.outstanding_buffer))
            await self.__handle_packet(buf)

    async def __handle_polling(self):
        """Handle read data from alarm."""

        if self.password is None:
            return
        else:
            while True:
                try:
                    await self.send_request_zones()
                    await asyncio.sleep(1)

                    if (
                        self._read_timestamp is not None
                        and time.monotonic() - self._read_timestamp >= self._timeout
                    ):
                        self.polling_task = None
                        await self.__accept_new_connection()
                        return

                except OSError:
                    self.polling_task = None
                    await self.__accept_new_connection()
                    return
                except Exception:
                    self.polling_task = None
                    await self.__accept_new_connection()
                    raise

    async def __handle_read_from_stream(self):
        """Handle read data from alarm."""

        while True:
            self._read_timestamp = time.monotonic()
            data = await self.reader.read(4096)
            if self.reader.at_eof():
                self.reading_task = None
                await self.__accept_new_connection()
                return

            self.outstanding_buffer += data

            try:
                await self.__handle_data()
            except Exception:
                self.read_task = None
                await self.__accept_new_connection()
                raise

    async def wait_connection(self) -> bool:
        """Test if we can authenticate with the host."""

        self.outstanding_buffer = bytes([])
        self.is_initialized = False

        loop = asyncio.get_event_loop()
        (self.client_socket, _) = await loop.sock_accept(self.socket)
        (self.reader, self.writer) = await asyncio.open_connection(
            None, sock=self.client_socket
        )

        return True

    async def async_alarm_disarm(self, code=None):
        """Send disarm command."""

    async def async_alarm_arm_night(self, code=None):
        """Send disarm command."""
        for i in range(4):
            if CONF_NIGHT_PARTITION_LIST[i] in self.config_entry.data:
                if self.config_entry.data[CONF_NIGHT_PARTITION_LIST[i]]:
                    await self.send_arm_partition(i)
            else:
                await self.send_arm_partition(i)

    async def async_alarm_arm_away(self, code=None):
        """Send disarm command."""
        if self.config_entry.data[CONF_AWAY_MODE_ENABLED]:
            for i in range(4):
                if CONF_AWAY_PARTITION_LIST[i] in self.config_entry.data:
                    if self.config_entry.data[CONF_AWAY_PARTITION_LIST[i]]:
                        self.send_arm_partition(i)
                else:
                    self.send_arm_partition(i)

    async def async_alarm_arm_home(self, code=None):
        """Send disarm command."""
        if self.config_entry.data[CONF_HOME_MODE_ENABLED]:
            for i in range(4):
                if CONF_HOME_PARTITION_LIST[i] in self.config_entry.data:
                    if self.config_entry.data[CONF_HOME_PARTITION_LIST[i]]:
                        await self.send_arm_partition(i)
                else:
                    await self.send_arm_partition(i)

    def close(self):
        """Close and free resources."""
        if self.writer is not None:
            self.writer.close()
        if self.socket is not None:
            self.socket.close()

    async def async_update(self):
        """Asynchronously update hub state."""
        if self.polling_task is None:
            self.polling_task = asyncio.create_task(self.__handle_polling())
        if self.reading_task is None:
            self.reading_task = asyncio.create_task(self.__handle_read_from_stream())

        if not self.is_initialized:
            await self.update_event.wait()
            self.update_event.clear()

    async def __accept_new_connection(self):
        self._read_timestamp = None
        if self.polling_task is not None:
            self.polling_task.cancel()
            self.polling_task = None
        if self.reading_task is not None:
            self.reading_task.cancel()
            self.reading_task = None
        if self.client_socket is not None:
            self.client_socket.close()

        await self.wait_connection()
        await self.async_update()

    def get_partitions(self):
        """Return partitions array."""
        return self.partitions

    def get_open_sensors(self):
        """Return motion sensors states."""
        return self.open_sensors

    def listen_event(self, listener):
        """Add object as listener."""
        if listener not in self.listeners:
            self.listeners.append(listener)

    def remove_listen_event(self, listener):
        """Add object as listener."""
        if listener in self.listeners:
            self.listeners.remove(listener)

    def __call_listeners(self):
        """Call all listeners."""
        for i in self.listeners:
            i.hub_update()

    @property
    def max_sensors(self):
        """Return the maximum number of sensors the platform may have."""
        return 48

    def is_sensor_configured(self, index):
        """Check if the numbered sensor is configured."""
        return True

    @property
    def max_partitions(self):
        """Return the maximum number of sensors the platform may have."""
        return 4

    def is_partition_configured(self, index):
        """Check if the numbered sensor is configured."""
        return True
