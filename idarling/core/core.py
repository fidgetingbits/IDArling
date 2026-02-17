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
import ctypes
import os
import sys

import ida_auto
import ida_diskio
import ida_idp
import ida_kernwin
import ida_netnode
import ida_typeinf

from PySide6.QtCore import QCoreApplication, QFileInfo  # noqa: I202

from .hooks import HexRaysHooks, IDBHooks, IDPHooks, UIHooks
from ..module import Module
from ..shared.commands import (
    JoinSession,
    LeaveSession,
    ListSnapshots,
    UpdateLocation,
)
from ..shared.local_types import ImportLocalType

if sys.version_info > (3,):
    long = int


class Core(Module):
    """
    This is the core module. It is responsible for interacting with the IDA
    kernel. It will handle hooking, sending, and replaying of user events.
    """

    NETNODE_NAME = "$ idarling"

    @staticmethod
    def get_ida_dll(app_name=None):
        if app_name is None:
            app_path = QCoreApplication.applicationFilePath()
            app_name = QFileInfo(app_path).fileName()
        idaname = "ida64" if "64" in app_name else "ida"
        if sys.platform == "win32":
            dllname, dlltype = idaname + ".dll", ctypes.windll
        elif sys.platform in ["linux", "linux2"]:
            dllname, dlltype = "lib" + idaname + ".so", ctypes.cdll
        elif sys.platform == "darwin":
            dllname, dlltype = "lib" + idaname + ".dylib", ctypes.cdll
        dllpath = ida_diskio.idadir(None)
        if not os.path.exists(os.path.join(dllpath, dllname)):
            dllpath = dllpath.replace("ida64", "ida")
        return dlltype[os.path.join(dllpath, dllname)]

    def __init__(self, plugin):
        super(Core, self).__init__(plugin)
        self._project = None
        self._binary = None
        self._snapshot = None
        self._tick = -1
        self._users = {}
        self._session_joined = False

        self._idb_hooks = None
        self._idp_hooks = None
        self._hxe_hooks = None

        self._idb_hooks_core = None
        self._idp_hooks_core = None
        self._ui_hooks_core = None
        self._view_hooks_core = None
        self._hooked = False

        self.local_type_map = {}
        self.delete_candidates = {}

    @property
    def project(self):
        return self._project

    @project.setter
    def project(self, project):
        self._project = project
        self.save_netnode()

    @property
    def binary(self):
        return self._binary

    @binary.setter
    def binary(self, binary):
        self._binary = binary
        self.save_netnode()

    @property
    def snapshot(self):
        return self._snapshot

    @snapshot.setter
    def snapshot(self, snapshot):
        self._snapshot = snapshot
        self.save_netnode()

    @property
    def tick(self):
        return self._tick

    @tick.setter
    def tick(self, tick):
        self._tick = tick
        self.save_netnode()

    def update_local_types_map(self):
        for i in range(1, ida_typeinf.get_ordinal_count(ida_typeinf.get_idati())):
            t = ImportLocalType(i)
            self.local_type_map[i] = t

    def add_user(self, name, user):
        self._users[name] = user
        self._plugin.interface.painter.refresh()
        self._plugin.interface.widget.refresh()

    def remove_user(self, name):
        user = self._users.pop(name)
        self._plugin.interface.painter.refresh()
        self._plugin.interface.widget.refresh()
        return user

    def get_user(self, name):
        return self._users[name]

    def get_users(self):
        return self._users

    def _install(self):
        # Instantiate the hooks
        self._idb_hooks = IDBHooks(self._plugin)
        self._idp_hooks = IDPHooks(self._plugin)
        self._hxe_hooks = HexRaysHooks(self._plugin)
        self._ui_hooks = UIHooks(self._plugin)

        core = self
        self._plugin.logger.debug("Installing core hooks")

        class IDBHooksCore(ida_idp.IDB_Hooks):
            def closebase(self):
                core._plugin.logger.trace("Closebase hook")
                core.leave_session()
                core.save_netnode()

                core.project = None
                core.binary = None
                core.snapshot = None
                core.ticks = 0
                return 0

        self._idb_hooks_core = IDBHooksCore()
        self._idb_hooks_core.hook()

        class IDPHooksCore(ida_idp.IDP_Hooks):
            def ev_get_bg_color(self, color, ea):
                #core._plugin.logger.trace("Get bg color hook")
                value = core._plugin.interface.painter.get_bg_color(ea)
                if value is not None:
                    ctypes.c_uint.from_address(long(color)).value = value
                    return 1
                return 0

            def ev_auto_queue_empty(self, arg):
                #core._plugin.logger.debug("Auto queue empty hook")
                if ida_auto.get_auto_state() == ida_auto.AU_NONE:
                    client = core._plugin.network.client
                    if client:
                        client.call_events()
                return super(self.__class__, self).ev_auto_queue_empty(arg)

        self._idp_hooks_core = IDPHooksCore()
        self._idp_hooks_core.hook()

        class UIHooksCore(ida_kernwin.UI_Hooks):
            def ready_to_run(self):
                core._plugin.logger.trace("Ready to run hook")
                core.load_netnode()
                core.join_session()
                # XXX - calling this function triggered lots of errors
                # when moving to Python 3
                core._plugin.interface.painter.ready_to_run()

            def get_ea_hint(self, ea):
                core._plugin.logger.trace("Get ea hint hook")
                return core._plugin.interface.painter.get_ea_hint(ea)

            def widget_visible(self, widget):
                core._plugin.logger.trace("Widget visible")
                core._plugin.interface.painter.widget_visible(widget)

        self._ui_hooks_core = UIHooksCore()
        self._ui_hooks_core.hook()

        class ViewHooksCore(ida_kernwin.View_Hooks):
            def view_loc_changed(self, view, now, was):
                # Even if it is a core hook, there is no point sending an
                # UpdateLocation if we are not in a valid session
                if not core._session_joined:
                    return
                #core._plugin.logger.trace("View loc changed hook")
                if now.plce.toea() != was.plce.toea():
                    name = core._plugin.config["user"]["name"]
                    color = core._plugin.config["user"]["color"]
                    core._plugin.network.send_packet(
                        UpdateLocation(name, now.plce.toea(), color)
                    )

        self._view_hooks_core = ViewHooksCore()
        self._view_hooks_core.hook()
        return True

    def _uninstall(self):
        self._plugin.logger.debug("Uninstalling core hooks")
        self._idb_hooks_core.unhook()
        self._ui_hooks_core.unhook()
        self._view_hooks_core.unhook()
        self.unhook_all()
        return True

    def hook_all(self):
        """Install all the user events hooks."""
        if self._hooked:
            return

        self._plugin.logger.debug("Installing hooks")
        self._idb_hooks.hook()
        self._idp_hooks.hook()
        self._hxe_hooks.hook()
        self._ui_hooks.hook()
        self._hooked = True
        self._plugin.core.update_local_types_map()

    def unhook_all(self):
        """Uninstall all the user events hooks."""
        if not self._hooked:
            return

        self._plugin.logger.debug("Uninstalling hooks")
        self._idb_hooks.unhook()
        self._idp_hooks.unhook()
        self._hxe_hooks.unhook()
        self._ui_hooks.unhook()
        self._hooked = False

    def load_netnode_old(self):
        self._plugin.logger.warning("Old idb detected, please save your idb as a new snapshot")
        node = ida_netnode.netnode(Core.NETNODE_NAME, 0, True)

        self._project = node.hashstr("group") or None
        self._binary = node.hashstr("project") or None
        self._snapshot = node.hashstr("database") or None
        self._tick = int(node.hashstr("tick") or "0")

        # Replacing old netnode in local idb
        node.kill()
        self.save_netnode()

    def load_netnode(self):
        """
        Load data from our custom netnode. Netnodes are the mechanism used by
        IDA to load and save information into an idb. IDArling uses its own
        netnode to remember which project, binary and snapshot an idb belongs to.
        """
        node = ida_netnode.netnode(Core.NETNODE_NAME, 0, True)
        if node.hashstr("database"):
            self.load_netnode_old()
        else:
            self._project = node.hashstr("project") or None
            self._binary = node.hashstr("binary") or None
            self._snapshot = node.hashstr("snapshot") or None
            self._tick = int(node.hashstr("tick") or "0")

        self._plugin.logger.debug(
            "Loaded netnode: project=%s, binary=%s, snapshot=%s, tick=%d"
            % (self._project, self._binary, self._snapshot, self._tick)
        )

    def save_netnode(self):
        """Save data into our custom netnode."""
        node = ida_netnode.netnode(Core.NETNODE_NAME, 0, True)

        # node.hashset does not work anymore with direct string
        # use of hashet_buf instead
        # (see https://github.com/idapython/src/blob/master/swig/netnode.i#L162)
        if self._project:
            node.hashset_buf("project", str(self._project))
        if self._binary:
            node.hashset_buf("binary", str(self._binary))
        if self._snapshot:
            node.hashset_buf("snapshot", str(self._snapshot))
        # We need the test to be non-zero as we need to reset and save tick=0 
        # when saving an IDB to a new snapshot
        if self._tick != -1:
            node.hashset_buf("tick", str(self._tick))

        self._plugin.logger.debug(
            "Saved netnode: project=%s, binary=%s, snapshot=%s, tick=%d"
            % (self._project, self._binary, self._snapshot, self._tick)
        )

    def join_session(self):
        """Join the collaborative session."""
        if self._project and self._binary and self._snapshot:
            if self._session_joined:
                self._plugin.logger.debug("Joining a new session")
            else:
                self._plugin.logger.debug("Joining session")

            def snapshots_listed(reply):
                if any(d.name == self._snapshot for d in reply.snapshots):
                    self._plugin.logger.debug("Snapshot is on the server")
                else:
                    self._plugin.logger.debug("Snapshot is not on the server")
                    return  # Do not go further

                name = self._plugin.config["user"]["name"]
                color = self._plugin.config["user"]["color"]
                ea = ida_kernwin.get_screen_ea()
                self._plugin.network.send_packet(
                    JoinSession(
                        self._project,
                        self._binary,
                        self._snapshot,
                        self._tick,
                        name,
                        color,
                        ea,
                    )
                )
                self._session_joined = True
                self.hook_all()
                self._users.clear()

            d = self._plugin.network.send_packet(
                ListSnapshots.Query(self._project, self._binary)
            )
            if d:
                d.add_callback(snapshots_listed)
                d.add_errback(self._plugin.logger.exception)
        else:
            self._plugin.logger.debug("Not joining any session yet")
            self._session_joined = False

    def leave_session(self):
        """Leave the collaborative session."""
        if not self._session_joined:
            self._plugin.logger.debug("Already left session")
            return

        self._plugin.logger.debug("Leaving session")
        if self._project and self._binary and self._snapshot:
            name = self._plugin.config["user"]["name"]
            self._plugin.network.send_packet(LeaveSession(name))
            self._users.clear()
            self.unhook_all()
        self._session_joined = False
