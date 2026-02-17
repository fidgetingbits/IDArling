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
import logging
import os
import sys
import socket
import ssl
import threading
import bz2
import json
from functools import partial

from .commands import (
    CreateProject,
    CreateBinary,
    CreateSnapshot,
    DownloadFile,
    InviteToLocation,
    JoinSession,
    LeaveSession,
    ListProjects,
    ListBinaries,
    ListSnapshots,
    RenameBinary,
    UpdateFile,
    UpdateLocation,
    UpdateUserColor,
    UpdateUserName,
    DeleteProject,
    DeleteBinary,
    DeleteSnapshot,
)
from .discovery import ClientsDiscovery
from .packets import Command, Event
from .sockets import ClientSocket, ServerSocket
from .storage import Storage


class ServerClient(ClientSocket):
    """
    This class represents a client socket for the server. It implements all the
    handlers for the packet the client is susceptible to send.
    """

    def __init__(self, logger, parent=None):
        """

        @type parent: Server
        """

        ClientSocket.__init__(self, logger, parent)
        self._project = None
        self._binary = None
        self._snapshot = None
        self._name = None
        self._color = None
        self._ea = None
        self._handlers = {}

    @property
    def project(self):
        return self._project

    @property
    def binary(self):
        return self._binary

    @property
    def snapshot(self):
        return self._snapshot

    @property
    def name(self):
        return self._name

    @property
    def color(self):
        return self._color

    @property
    def ea(self):
        return self._ea

    def wrap_socket(self, sock):
        ClientSocket.wrap_socket(self, sock)

        # Setup command handlers
        self._handlers = {
            ListProjects.Query: self._handle_list_projects,
            ListBinaries.Query: self._handle_list_binaries,
            ListSnapshots.Query: self._handle_list_snapshots,
            CreateProject.Query: self._handle_create_project,
            CreateBinary.Query: self._handle_create_binary,
            CreateSnapshot.Query: self._handle_create_snapshot,
            UpdateFile.Query: self._handle_upload_file,
            DownloadFile.Query: self._handle_download_file,
            RenameBinary.Query: self._handle_rename_binary,
            JoinSession: self._handle_join_session,
            LeaveSession: self._handle_leave_session,
            UpdateLocation: self._handle_update_location,
            InviteToLocation: self._handle_invite_to_location,
            UpdateUserName: self._handle_update_user_name,
            UpdateUserColor: self._handle_update_user_color,
            DeleteProject.Query: self._handle_delete_project,
            DeleteBinary.Query: self._handle_delete_binary,
            DeleteSnapshot.Query: self._handle_delete_snapshot,
        }

        # Add host and port as a prefix to our logger
        prefix = "%s:%d" % sock.getpeername()

        class CustomAdapter(logging.LoggerAdapter):
            def process(self, msg, kwargs):
                return "(%s) %s" % (prefix, msg), kwargs

        self._logger = CustomAdapter(self._logger, {})

    def close_client(self, err=None, notify=True):
        # Notify other users that we disconnected
        self.parent().reject(self)
        if self._project and self._binary and self._snapshot and notify:
            self.parent().forward_users(self, LeaveSession(self.name, False))
        ClientSocket.close_connection(self, err)

    def recv_packet(self, packet):
        if isinstance(packet, Command):
            # Call the corresponding handler
            self._handlers[packet.__class__](packet)

        elif isinstance(packet, Event):
            if not self._project or not self._binary or not self._snapshot:
                self._logger.warning(
                    "Received a packet from an unsubscribed client"
                )
                return True

            # Check for de-synchronization
            tick = self.parent().storage.last_tick(
                self._project, self._binary, self._snapshot
            )
            if tick >= packet.tick:
                self._logger.warning("De-synchronization detected!")
                packet.tick = tick + 1

            # Save the event into the snapshot
            self.parent().storage.insert_event(self, packet)
            # Forward the event to the other users
            self.parent().forward_users(self, packet)

            # Ask for a snapshot of the snapshot if needed
            interval = self.parent().SNAPSHOT_INTERVAL
            if packet.tick and interval and packet.tick % interval == 0:

                def file_downloaded(reply):
                    file_name = "%s_%s_%s.i64" % (self._project, self._binary, self._snapshot)
                    file_path = self.parent().server_file(file_name)

                    # Write the file to disk
                    with open(file_path, "wb") as output_file:
                        output_file.write(reply.content)
                    self._logger.info("Auto-saved file %s" % file_name)

                d = self.send_packet(
                    DownloadFile.Query(self._project, self._binary, self._snapshot)
                )
                d.add_callback(file_downloaded)
                d.add_errback(self._logger.exception)
        else:
            return False
        return True

    def _handle_rename_binary(self, query):
        self._logger.info("Got rename binary request")
        binaries = self.parent().storage.select_binaries(query.project)
        for binary in binaries:
            if binary.name == query.new_name:
                self._logger.error("Attempt to rename binary to existing name")
                return

        # Grab the snapshot lock. This basically means no other client can be
        # connected for a rename to occur.
        db_update_locked = False
        for binary in binaries:
            if binary.name == query.old_name:
                self.parent().client_lock.acquire()
                # Only do the rename if we could lock the db. Otherwise we will
                # mess with other clients.
                db_update_locked = self.parent().db_update_lock.acquire(blocking=False)
                self.parent().client_lock.release()
                if db_update_locked:
                    self.parent().storage.update_binary_name(query.project, query.old_name, query.new_name)
                    self.parent().storage.update_snapshot_binary(query.project, query.old_name, query.new_name)
                    self.parent().storage.update_events_binary(query.project, query.old_name, query.new_name)

                    # We just changed the table entries so be sure to use new names 
                    # for queries
                    snapshots = self.parent().storage.select_snapshots(query.project, query.new_name)
                    for snapshot in snapshots:
                        old_file_name = "%s_%s_%s.i64" % (query.project, query.old_name, snapshot.name)
                        new_file_name = "%s_%s_%s.i64" % (query.project, query.new_name, snapshot.name)
                        old_file_path = self.parent().server_file(old_file_name)
                        new_file_path = self.parent().server_file(new_file_name)
                        # If a rename happens before a file is uploaded, the 
                        # idb won't exist
                        if os.path.exists(old_file_path):
                            self._logger.info("Renaming: %s to %s" % (old_file_path, new_file_name))
                            os.rename(old_file_path, new_file_path)
                        else:
                            self._logger.warning("Skipping file rename due to non existing file: %s" % old_file_path)

                    self.parent().db_update_lock.release()
                else:
                    self._logger.info("Skipping rename due to snapshot lock")

        # Resend an updated list of binary names since it just changed
        binaries = self.parent().storage.select_binaries(query.project)
        self.send_packet(RenameBinary.Reply(query, binaries, db_update_locked))

    def _handle_list_projects(self, query):
        self._logger.info("Got list projects request")
        projects = self.parent().storage.select_projects()
        self.send_packet(ListProjects.Reply(query, projects))

    def _handle_list_binaries(self, query):
        self._logger.info("Got list binaries request")
        binaries = self.parent().storage.select_binaries(query.project)
        self.send_packet(ListBinaries.Reply(query, binaries))

    def _handle_list_snapshots(self, query):
        self._logger.info("Got list snapshots request")
        snapshots = self.parent().storage.select_snapshots(query.project, query.binary)
        for snapshot in snapshots:
            snapshot_info = snapshot.project, snapshot.binary, snapshot.name
            file_name = "%s_%s_%s.i64" % (snapshot_info)
            file_path = self.parent().server_file(file_name)
            if os.path.isfile(file_path):
                snapshot.tick = self.parent().storage.last_tick(*snapshot_info)
            else:
                snapshot.tick = -1
        self.send_packet(ListSnapshots.Reply(query, snapshots))

    def _handle_create_project(self, query):
        self.parent().storage.insert_project(query.project)
        self.send_packet(CreateProject.Reply(query))

    def _handle_create_binary(self, query):
        self.parent().storage.insert_binary(query.binary)
        self.send_packet(CreateBinary.Reply(query))

    def _handle_create_snapshot(self, query):
        self.parent().storage.insert_snapshot(query.snapshot)
        self.send_packet(CreateSnapshot.Reply(query))

    def _handle_upload_file(self, query):
        snapshot = self.parent().storage.select_snapshot(
            query.project, query.binary, query.snapshot
        )
        file_name = "%s_%s_%s.i64" % (query.project, snapshot.binary, snapshot.name)
        file_path = self.parent().server_file(file_name)

        # Write the file received to disk
        decompressed_content = bz2.decompress(query.content)
        with open(file_path, "wb") as output_file:
            output_file.write(decompressed_content)
        self._logger.info("Saved file %s" % file_name)
        self.send_packet(UpdateFile.Reply(query))

    def _handle_download_file(self, query):
        snapshot = self.parent().storage.select_snapshot(
            query.project, query.binary, query.snapshot
        )
        file_name = "%s_%s_%s.i64" % (query.project, snapshot.binary, snapshot.name)
        file_path = self.parent().server_file(file_name)

        # Read file from disk and sent it
        reply = DownloadFile.Reply(query)
        with open(file_path, "rb") as input_file:
            uncompressed_content = input_file.read()
        reply.content = bz2.compress(uncompressed_content)
        self._logger.info("Loaded file %s" % file_name)
        self.send_packet(reply)

    def _handle_join_session(self, packet):
        self._project = packet.project
        self._binary = packet.binary
        self._snapshot = packet.snapshot
        self._name = packet.name
        self._color = packet.color
        self._ea = packet.ea

        # Inform the other users that we joined
        packet.silent = False
        self.parent().forward_users(self, packet)

        # Inform ourselves about the other users
        for user in self.parent().get_users(self):
            self.send_packet(
                JoinSession(
                    packet.project,
                    packet.binary,
                    packet.snapshot,
                    packet.tick,
                    user.name,
                    user.color,
                    user.ea,
                )
            )

        # Send all missed events
        events = self.parent().storage.select_events(
            self._project, self._binary, self._snapshot, packet.tick
        )
        self._logger.debug("Sending %d missed events..." % len(events))
        for event in events:
            self.send_packet(event)
        self._logger.debug("Done sending %d missed events" % len(events))

    def _handle_leave_session(self, packet):
        # Inform others users that we are leaving
        packet.silent = False
        self.parent().forward_users(self, packet)

        self._project = None
        self._binary = None
        self._snapshot = None
        self._name = None
        self._color = None

    def _handle_update_location(self, packet):
        self.parent().forward_users(self, packet)

    def _handle_invite_to_location(self, packet):
        def matches(other):
            return other.name == packet.name or packet.name == "everyone"

        packet.name = self._name
        self.parent().forward_users(self, packet, matches)

    def _handle_update_user_name(self, packet):
        # FXIME: ensure the name isn't already taken
        self._name = packet.new_name
        self.parent().forward_users(self, packet)

    def _handle_update_user_color(self, packet):
        self.parent().forward_users(self, packet)

    def _delete_project_files(self, project):
        binaries = self.parent().storage.select_binaries(project)
        for binary in binaries:
            self._delete_binary_files(project, binary.name)

    def _delete_binary_files(self, project, binary):
        snapshots = self.parent().storage.select_snapshots(project, binary)
        for db in snapshots:
            self._delete_snapshot_files(project, binary, db.name)

    def _delete_snapshot_files(self, project, binary, snapshot):
        file_name = "%s_%s_%s.i64" % (project, binary, snapshot)
        file_path = self.parent().server_file(file_name)
        try:
            os.remove(file_path)
        except FileNotFoundError:
            pass

    def _handle_delete_project(self, packet):
        def match_project(user, project):
            return user.project == project

        if  len(self.parent().get_users(self,partial(match_project, project=packet.project))):
            self.send_packet(DeleteProject.Reply(packet, False))
        else:
            self._delete_project_files(packet.project)
            self.parent().storage.delete_project(packet.project)
            # self.parent().forward_users(self,packet,partial(match_project,project=packet.project))
            self.send_packet(DeleteProject.Reply(packet, True))

    def _handle_delete_binary(self,packet):
        def match_user(user, project, binary):
            return user.project == project and user.binary == binary

        if  len(self.parent().get_users(self, partial(match_user, project=packet.project, binary=packet.binary))):
            self.send_packet(DeleteBinary.Reply(packet, False))
        else:
            self._delete_binary_files(packet.project, packet.binary)
            self.parent().storage.delete_binary(packet.project, packet.binary)
            # self.parent().forward_users(self,packet,partial(match_user, project=packet.project,binary=packet.binary))
            self.send_packet(DeleteBinary.Reply(packet, True))

    def _handle_delete_snapshot(self, packet):
        def match_user(user, project, binary, snapshot):
            return user.project == project and user.binary == binary and user.snapshot == snapshot

        if len(self.parent().get_users(self,partial(match_user, project=packet.project, binary=packet.binary,snapshot=packet.snapshot))):
            self.send_packet(DeleteSnapshot.Reply(packet, False))
        else:
            self._delete_snapshot_files(packet.project, packet.binary, packet.snapshot)
            self.parent().storage.delete_snapshot(packet.project, packet.binary, packet.snapshot)
            # self.parent().forward_users(self, packet)
            self.send_packet(DeleteSnapshot.Reply(packet, True))

class Migrate(object):

    # This migration typically took ~2h with a database with 140k+ events
    def do1(server):
        server._logger.warning("Migration do1(), please don't interrupt that process...")

        server._logger.warning("Migration do1(): saving old db...")
        if os.path.exists(server.server_file("database_1.db")):
            server._logger.error("Migration do1(): database_1.db already exist!")
            sys.exit(1)
        os.rename(server.server_file("database.db"), server.server_file("database_1.db"))

        server._logger.warning("Migration do1(): loading old db...")
        old_storage = Storage(server.server_file("database_1.db"))
        old_level1_rows = old_storage._select_all("groups")
        old_level2_rows = old_storage._select_all("projects")
        old_level3_rows = old_storage._select_all("databases")
        old_events_rows = old_storage._select_all("events")

        new_storage = Storage(server.server_file("database.db"))
        new_storage.initialize()

        server._logger.warning("Migration do1(): inserting projects...")
        new_storage._insert_all("projects", old_level1_rows)

        server._logger.warning("Migration do1(): inserting binaries...")
        new_level2_rows = []
        for row in old_level2_rows:
            row["project"] = row.pop("group_name")
            new_level2_rows.append(row)
        new_storage._insert_all("binaries", new_level2_rows)

        server._logger.warning("Migration do1(): inserting snapshots...")
        new_level3_rows = []
        for row in old_level3_rows:
            row["binary"] = row.pop("project")
            row["project"] = row.pop("group_name")
            new_level3_rows.append(row)
        new_storage._insert_all("snapshots", new_level3_rows)

        server._logger.warning("Migration do1(): inserting events...")
        i = 1
        for row in old_events_rows:
            if i % 1000 == 0:
                server._logger.warning("Migration do1(): %d events done..." % i)
            row["snapshot"] = row.pop("database")
            row["binary"] = row.pop("project")
            row["project"] = row.pop("group_name")
            new_storage._insert("events", row)
            i += 1

        server._logger.warning("Migration do1(): done")

class Server(ServerSocket):
    """
    This class represents a server socket for the server. It is used by both
    the integrated and dedicated server implementations. It doesn't do much.
    """

    SNAPSHOT_INTERVAL = 0  # ticks

    def __init__(self, logger, parent=None, level=None):
        ServerSocket.__init__(self, logger, parent)
        self._ssl = None
        self._clients = []

        # Load the configuration
        self._config_path = self.server_file("config_server.json")
        self._config = self.default_config()
        self.load_config()
        if level != None:
            self._logger.setLevel(level)
        else:
            self._logger.setLevel(self._config["level"])
        self.save_config()

        # Check if any migration
        self.migrate()

        # Initialize the storage
        self._storage = Storage(self.server_file("database.db"))
        self._storage.initialize()

        self._discovery = ClientsDiscovery(logger)
        # A temporory lock to stop clients while updating other locks
        self.client_lock = threading.Lock()
        # A long term lock that stops breaking database updates when multiple
        # clients are connected
        self.db_update_lock = threading.Lock()

    @property
    def config_path(self):
        return self._config_path

    @property
    def config(self):
        return self._config

    @property
    def storage(self):
        return self._storage

    @property
    def host(self):
        return self._socket.getsockname()[0]

    @property
    def port(self):
        return self._socket.getsockname()[1]

    @staticmethod
    def default_config():
        """
        Return the default configuration options. This is used to initialize
        the configuration file the first time the server is started
        """
        return {
            "level": logging.INFO,
            "migration": -1,
        }

    def migrate(self):
        migrationId = self.config["migration"]
        while migrationId >= 0:
            migrationId += 1
            method_name = "do%d" % migrationId
            try:
                method = getattr(Migrate, method_name)
            except AttributeError:
                break
            method(self)
            self.config["migration"] = migrationId
            self.save_config()

    def load_config(self):
        """
        Load the configuration file. It is a JSON file that contains all the
        settings of the server.
        """
        if not os.path.isfile(self.config_path):
            return
        with open(self.config_path, "rb") as config_file:
            try:
                self._config.update(json.loads(config_file.read()))
            except ValueError:
                self._logger.warning("Couldn't load config file")
                return
            self._logger.debug("Loaded config: %s" % self._config)

    def save_config(self):
        """Save the configuration file."""
        self._config["level"] = self._logger.level
        with open(self.config_path, "w") as config_file:
            config_file.write(json.dumps(self._config))
            self._logger.debug("Saved config: %s" % self._config)

    def start(self, host, port=0, ssl_=None):
        """Starts the server on the specified host and port."""
        self._logger.info("Starting the server on %s:%d" % (host, port))

        # Load the system certificate chain
        self._ssl = ssl_
        if self._ssl:
            cert, key = self._ssl
            self._ssl = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self._ssl.load_cert_chain(certfile=cert, keyfile=key)

        # Create, bind and set the socket options
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except socket.error as e:
            self._logger.warning("Could not start the server")
            self._logger.exception(e)
            return False
        sock.settimeout(0)  # No timeout
        sock.setblocking(0)  # No blocking
        sock.listen(5)
        self.set_socket(sock)

        # Start discovering clients
        host, port = sock.getsockname()
        self._discovery.start(host, port, self._ssl)
        return True

    def stop(self):
        """Terminates all the connections and stops the server."""
        self._logger.info("Stopping the server")
        self._discovery.stop()
        # Disconnect all clients
        for client in list(self._clients):
            client.close_client(notify=False)
        self.close_listener()
        try:
            self.db_update_lock.release()
        except RuntimeError:
            # It might not actually be locked
            pass
        return True

    def _accept(self, sock):
        """Called when an user connects."""
        client = ServerClient(self._logger, self)

        if self._ssl:
            # Wrap the socket in an SSL tunnel
            sock = self._ssl.wrap_socket(
                sock, server_side=True, do_handshake_on_connect=False
            )

        sock.settimeout(0)  # No timeout
        sock.setblocking(0)  # No blocking

        # If we already have at least one connection, lock the mutex that
        # prevents database updates like renaming. Connecting clients will
        # block until an existing blocking operation, like a porject rename, is
        # completed
        self.client_lock.acquire()
        if len(self._clients) == 1:
            self.db_update_lock.acquire()
        client.wrap_socket(sock)
        self._clients.append(client)
        self.client_lock.release()

    def reject(self, client):
        """Called when a user disconnects."""

        # Allow clients to update database again
        self.client_lock.acquire()
        self._clients.remove(client)
        if len(self._clients) <= 1:
            try:
                self.db_update_lock.release()
            except RuntimeError:
                pass

        self.client_lock.release()

    def get_users(self, client, matches=None):
        """Get the other users on the same snapshot."""
        users = []
        for user in self._clients:
            if (matches is None and
                (user.binary != client.binary
                or user.snapshot != client.snapshot)
            ):
                continue
            if user == client or (matches and not matches(user)):
                continue
            users.append(user)
        return users

    def forward_users(self, client, packet, matches=None):
        """Sends the packet to the other users on the same snapshot."""
        for user in self.get_users(client, matches):
            user.send_packet(packet)

    def server_file(self, filename):
        """Get the absolute path of a local resource."""
        raise NotImplementedError("server_file() not implemented")
