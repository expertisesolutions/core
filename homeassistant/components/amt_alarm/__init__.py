"""The Intelbras AMT Alarms integration."""
import asyncio
import errno
import socket

import crcengine
import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import (
    AMT_EVENT_CODE_ATIVACAO_PARCIAL,
    AMT_EVENT_CODE_ATIVACAO_PELO_USUARIO,
    AMT_EVENT_CODE_ATIVACAO_POR_UMA_TECLA,
    AMT_EVENT_CODE_ATIVACAO_VIA_COMPUTADOR_OU_TELEFONE,
    AMT_EVENT_CODE_AUTO_ATIVACAO,
    AMT_EVENT_CODE_AUTO_DESATIVACAO,
    AMT_EVENT_CODE_DESATIVACAO_PELO_USUARIO,
    AMT_EVENT_CODE_DESATIVACAO_VIA_COMPUTADOR_OU_TELEFONE,
    DOMAIN,
)

CONFIG_SCHEMA = vol.Schema({DOMAIN: vol.Schema({})}, extra=vol.ALLOW_EXTRA)

# TODO List the platforms that you want to support.
# For your initial PR, limit it to 1 platform.
PLATFORMS = ["alarm_control_panel"]


async def async_setup(hass: HomeAssistant, config: dict):
    """Set up the Intelbras AMT Alarms component."""
    hass.data[DOMAIN] = {}
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Set up Intelbras AMT Alarms from a config entry."""
    # TODO Store an API object for your platforms to access
    alarm = AlarmHub(entry.data["port"], entry.data["password"])
    hass.data[DOMAIN][entry.entry_id] = alarm

    print("setup")

    await alarm.wait_connection()

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

    def __init__(self, port, password=None):
        """Initialize."""
        if password is not None:
            self.password = str(password)
            if len(self.password) != 4 and len(self.password) != 6:
                raise ValueError

        self.port = port

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.socket.bind(("", port))
        self.socket.listen(1)

        self.outstanding_buffer = bytes([])
        self.polling_task = None
        self.update_event = asyncio.Event()

        self.is_outdated = True
        self.crc = crcengine.create(0xAB, 8, 0, False, False, "", 0)

        # print("crc test ", self.crc([0x0b,0xe9,0x21,0x35,0x38,0x31,0x30,0x30,0x30,0x41,0x41,0x21,0x00]))
        self.open_sensors = [False] * 48
        self.partitions = [False, False, False, False]
        # self.open_sensors[0:47] = False

        self.t1 = 0
        # self.t2 = 0

        self.listeners = []

    async def send_request_zones(self):
        """Send Request Information packet."""
        if self.password is None:
            raise ValueError

        print("request zones")
        buf = bytes([])
        buf = buf + b"\x0a\xe9\x21"
        print("request zones", buf)

        buf = buf + self.password.encode("utf-8")
        print("request zones", buf)

        if len(self.password) == 4:
            buf = buf + b"00"
        print("request zones", buf)

        buf = buf + b"\x5b\x21\x00"
        print("request zones", buf)
        crc = self.crc(buf)
        print("crc ", crc)
        print("buf length ", len(buf))
        buf = buf[0 : len(buf) - 1] + bytes([crc])
        print("buf length ", len(buf))
        print("req buf ", buf)

        self.writer.write(buf)
        await self.writer.drain()

        print("wrote")

    async def send_test(self):
        """Send Reverse Engineering Test."""

        # unsigned char buffer[] = {0x0b, 0xe9, 0x21, /* senha */ 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, /* fim da senha */ 0x41, 0x40 + partition, 0x21, 0x00};
        if self.password is None:
            raise ValueError

        print("send test")
        buf = bytes([])
        buf = buf + b"\x0b\xe9" + bytes([0x21])

        buf = buf + self.password.encode("utf-8")
        if len(self.password) == 4:
            buf = buf + b"00"

        buf = buf + b"\x40"
        buf = buf + bytes([0x40 + 3])
        buf = buf + bytes([self.t1]) + b"\x00"
        self.t1 += 1

        crc = self.crc(buf)
        buf = buf[0 : len(buf) - 1] + bytes([crc])
        print("buf length ", len(buf))
        print("req buf ", buf)

        self.writer.write(buf)
        await self.writer.drain()

        print("wrote")

    async def __send_ack(self):
        print("sent ack")
        self.writer.write(bytes([0xFE]))
        await self.writer.drain()

    def __handle_amt_event(self, event, partition, zone, client_id):
        print("handle event")
        print("partitions ", self.partitions)
        if (
            event == AMT_EVENT_CODE_DESATIVACAO_PELO_USUARIO
            or event == AMT_EVENT_CODE_AUTO_DESATIVACAO
            or event == AMT_EVENT_CODE_DESATIVACAO_VIA_COMPUTADOR_OU_TELEFONE
        ):
            self.partitions[partition] = False
        elif (
            event == AMT_EVENT_CODE_ATIVACAO_PELO_USUARIO
            or event == AMT_EVENT_CODE_AUTO_ATIVACAO
            or event == AMT_EVENT_CODE_ATIVACAO_VIA_COMPUTADOR_OU_TELEFONE
            or event == AMT_EVENT_CODE_ATIVACAO_POR_UMA_TECLA
            or event == AMT_EVENT_CODE_ATIVACAO_PARCIAL
        ):
            self.partitions[partition] = True
        print("partitions ", self.partitions)
        self.call_listeners()

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
            print("second print")
            self.__handle_amt_event(ev_id, partition, zone, client_id)
            print("third print")

            await self.__send_ack()
        elif (
            cmd == 0xE9
            and len(packet) == 2
            and (packet[1] == 0xE5 or packet[1] == 0xFE)
        ):
            print("cmd 0xe9: ", packet)
            await self.__send_ack()
        elif cmd == 0xE9 and len(packet) >= 3 * 8:
            print("cmd 0xe9 3*8: ", packet)

            for x in range(6):
                c = packet[x + 1]
                for i in range(8):
                    self.open_sensors[x * 8 + i] = (
                        True if ((c >> i) & 1) == 1 else False
                    )

            c = packet[1 + 8 + 8 + 8 + 3]
            for i in range(2):
                self.partitions[i] = True if ((c >> i) & 1) else False
                if (c >> i) & 1:
                    print("Partition ", i, " armed")
            c = packet[1 + 8 + 8 + 8 + 3 + 1]
            for i in range(2):
                self.partitions[i + 2] = True if ((c >> i) & 1) else False
                if (c >> i) & 1:
                    print("Partition ", i + 2, " armed")

            self.is_outdated = False
            self.update_event.set()
            self.call_listeners()
        else:
            print("how to deal ", packet)

    async def __handle_data(self):
        print("buffer size ", len(self.outstanding_buffer))

        while len(self.outstanding_buffer) != 0:
            is_nope = self.outstanding_buffer[0] == 0xF7
            packet_size = 1 if is_nope else self.outstanding_buffer[0]
            packet_start = 1 if not is_nope else 0

            if not is_nope and len(self.outstanding_buffer) < packet_size + 1:
                print("something is wrong")
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

        first_run = True

        while True:
            try:
                print("reading non blocking")
                self.socket.setblocking(False)
                msg = self.client_socket.recv(4096)
            except OSError as e:
                self.socket.setblocking(True)
                err = e.args[0]
                if err != errno.EAGAIN and err != errno.EWOULDBLOCK:
                    raise
                else:
                    print("no data")
                    if self.password is None:
                        await self.__send_ack()
                    elif self.is_outdated and first_run:
                        print("request")
                        await self.send_request_zones()
                        first_run = False

                    print("wait read data")

                    data = await self.reader.read(4096)
                    print("read data")
                    if self.reader.at_eof():
                        print("EOF")
                        return  # should accept new connection
                    self.outstanding_buffer += data
            else:
                self.socket.setblocking(True)
                print("array ", msg)
                self.outstanding_buffer += msg

                if self.is_outdated and first_run:  # may be called twice
                    print("request")
                    await self.send_request_zones()
                    first_run = False

            print("Handle read data from alarm ", len(self.outstanding_buffer))
            await self.__handle_data()

    async def wait_connection(self) -> bool:
        """Test if we can authenticate with the host."""

        print("wait")

        loop = asyncio.get_event_loop()
        (self.client_socket, _) = await loop.sock_accept(self.socket)
        (self.reader, self.writer) = await asyncio.open_connection(
            None, sock=self.client_socket
        )

        print("waited")

        return True

    async def async_alarm_disarm(self, code=None):
        """Send disarm command."""
        await self.send_test()

    def close(self):
        """Close and free resources."""
        if self.writer is not None:
            self.writer.close()
        if self.socket is not None:
            self.socket.close()

    async def async_update(self):
        """Asynchronously update hub state."""
        print("async_update")
        if self.polling_task is None:
            self.polling_task = asyncio.create_task(self.__handle_polling())
        print("async_update")

        if self.is_outdated:
            await self.update_event.wait()
        print("async_update")

    def get_partitions(self):
        """Return partitons array."""
        return self.partitions

    def listen_event(self, listener):
        """Add object as listener."""
        if listener not in self.listeners:
            self.listeners.append(listener)

    def __call_listeners(self):
        """Call all listeners."""
        for i in self.listeners:
            i.hub_update()
