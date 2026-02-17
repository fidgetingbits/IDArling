# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
import errno
import os
import socket
import ssl

from .client import Client
from .server import IntegratedServer
from ..module import Module
from ..shared.discovery import ServersDiscovery

fDebug = False
if fDebug:
    import pydevd_pycharm


class Network(Module):
    """
    This is the interface module. It is responsible for interacting with the
    server over the network. It manages the three sockets used with the plugin
    (client, discovery client, integrated server).
    """

    def __init__(self, plugin):
        super(Network, self).__init__(plugin)
        self._discovery = ServersDiscovery(plugin.logger)

        self._client = None
        self._server = None
        self._integrated = None

    @property
    def client(self):
        return self._client

    @property
    def server(self):
        return self._server

    @property
    def discovery(self):
        return self._discovery

    @property
    def connected(self):
        return self._client.connected if self._client else False

    @property
    def started(self):
        return bool(self._integrated)

    def _install(self):
        self._discovery.start()
        return True

    def _uninstall(self):
        self._discovery.stop()
        self.disconnect()
        return True

    def connect(self, server):
        if fDebug:
            pydevd_pycharm.settrace('localhost', port=2233, stdoutToServer=True, stderrToServer=True, suspend=True)
        """Connect to the specified server."""
        # Make sure we're not already connected
        if self._client:
            return

        self._client = Client(self._plugin)
        self._server = server.copy()  # Make a copy
        host = self._server["host"]
        if host == "0.0.0.0":  # Windows can't connect to 0.0.0.0
            host = "127.0.0.1"
        port = self._server["port"]
        no_ssl = self._server["no_ssl"]

        # Update the user interface
        self._plugin.interface.update()
        self._plugin.logger.info("Connecting to %s:%d..." % (host, port))

        # Create a new socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        # Wrap the socket in a SSL tunnel
        if not no_ssl:
            ctx = ssl.create_default_context()
            # XXX - add SSL cert/hostname check or support both through setting
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(
                sock, server_hostname=host, do_handshake_on_connect=True
            )
        self._client.wrap_socket(sock)

        # Set TCP keep-alive options
        cnt = self._plugin.config["keep"]["cnt"]
        intvl = self._plugin.config["keep"]["intvl"]
        idle = self._plugin.config["keep"]["idle"]
        self._client.set_keep_alive(cnt, intvl, idle)

        # Connect the socket
        sock.settimeout(0)  # No timeout
        sock.setblocking(0)  # No blocking
        try:
            err = sock.connect_ex((host, port))
            if err not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK):
                raise OSError(err, os.strerror(err), '')
        except OSError as e:
            self._plugin._logger.exception(e)
            self._client.terminate()

    def disconnect(self):
        """Disconnect from the current server."""
        # Make sure we aren't already disconnected
        if not self._client:
            return

        self._plugin.logger.info("Disconnecting...")
        self._client.terminate()

    def send_packet(self, packet):
        """Send a packet to the server."""
        if self.connected:
            return self._client.send_packet(packet)
        return None

    def start_server(self):
        """Start the integrated server."""
        if self._integrated:
            return

        self._plugin.logger.info("Starting the integrated server...")
        server = IntegratedServer(self._plugin)
        if not server.start("0.0.0.0"):
            return  # Couldn't start the server
        self._integrated = server
        integrated_arg = {
            "host": "0.0.0.0",
            "port": server.port,
            "no_ssl": True,
        }
        # Connect the client to the server
        self.disconnect()
        self.connect(integrated_arg)

    def stop_server(self):
        """Stop the integrated server."""
        if not self._integrated:
            return

        self._plugin.logger.info("Stopping the integrated server...")
        self.disconnect()
        self._integrated.stop()
        self._integrated = None
