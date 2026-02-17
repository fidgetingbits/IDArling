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
import datetime
from functools import partial
import logging, time
import binascii
import platform

import ida_loader
import ida_nalt
import idc

from PySide6.QtCore import QRegularExpression, Qt, QDir  # noqa: I202
from PySide6.QtGui import QIcon, QRegularExpressionValidator
from PySide6.QtWidgets import (
    QCheckBox,
    QColorDialog,
    QComboBox,
    QDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget, QSizePolicy, QFileDialog,
)

# QHeaderView enum compatibility between PyQt5 and PySide6
try:
    _HV_Stretch = QHeaderView.ResizeMode.Stretch
    _HV_ResizeToContents = QHeaderView.ResizeMode.ResizeToContents
except AttributeError:
    _HV_Stretch = QHeaderView.Stretch
    _HV_ResizeToContents = QHeaderView.ResizeToContents

from ..shared.commands import (
    CreateProject,
    CreateBinary,
    CreateSnapshot,
    RenameBinary,
    ListProjects,
    ListBinaries,
    ListSnapshots,
    UpdateUserColor,
    UpdateUserName,
    DeleteProject,
    DeleteBinary,
    DeleteSnapshot,
)
from ..shared.models import Project, Binary, Snapshot


class OpenDialog(QDialog):
    """This dialog is shown to user to select which remote snapshot to load."""

    def __init__(self, plugin):
        super(OpenDialog, self).__init__()
        self._plugin = plugin
        self._projects = None
        self._binaries = None
        self._snapshots = None

        # General setup of the dialog
        self.setWindowTitle("Open from Remote Server")
        icon_path = self._plugin.plugin_resource("download.png")
        self.setWindowIcon(QIcon(icon_path))
        self.resize(1400, 450)

        # Setup of the layout and widgets
        layout = QVBoxLayout(self)
        main = QWidget(self)
        main_layout = QGridLayout(main)
        layout.addWidget(main)

        # Projects - left layout
        self._left_side = QWidget(main)
        self._left_layout = QVBoxLayout(self._left_side)
        self._projects_table = QTableWidget(0, 1, self._left_side)
        self._projects_table.setHorizontalHeaderLabels(("Projects",))
        self._projects_table.horizontalHeader().setSectionsClickable(False)
        self._projects_table.horizontalHeader().setStretchLastSection(True)
        self._projects_table.verticalHeader().setVisible(False)
        self._projects_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._projects_table.setSelectionMode(QTableWidget.SingleSelection)
        self._projects_table.itemSelectionChanged.connect(
            self._project_clicked
        )
        self._left_layout.addWidget(self._projects_table)
        main_layout.addWidget(self._left_side, 0, 0)
        main_layout.setColumnStretch(0, 1)

        self.delete_project_button = QPushButton("Delete Project", self._left_side)
        self.delete_project_button.setEnabled(False)
        self.delete_project_button.clicked.connect(self._delete_project_clicked)
        self._left_layout.addWidget(self.delete_project_button)

        # Binaries - middle layout
        self._middle_side = QWidget(main)
        self._middle_layout = QVBoxLayout(self._middle_side)
        self._binaries_table = QTableWidget(0, 1, self._middle_side)
        self._binaries_table.setHorizontalHeaderLabels(("Binary Files",))
        self._binaries_table.horizontalHeader().setSectionsClickable(False)
        self._binaries_table.horizontalHeader().setStretchLastSection(True)
        self._binaries_table.verticalHeader().setVisible(False)
        self._binaries_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._binaries_table.setSelectionMode(QTableWidget.SingleSelection)
        self._binaries_table.itemClicked.connect(
            self._binary_clicked
        )
        self._middle_layout.addWidget(self._binaries_table)
        main_layout.addWidget(self._middle_side, 0, 1)
        main_layout.setColumnStretch(1, 1)

        # Create a binary button
        self._rename_binary_button = QPushButton("Rename Binary File", self._middle_side)
        self._rename_binary_button.setEnabled(False)
        self._rename_binary_button.clicked.connect(self._rename_binary_button_clicked)
        self._middle_layout.addWidget(self._rename_binary_button)

        self._delete_binary_button = QPushButton(
            "Delete Binary File", self._middle_side
        )
        self._delete_binary_button.setEnabled(False)
        self._delete_binary_button.clicked.connect(
            self._delete_binary_clicked
        )
        self._middle_layout.addWidget(self._delete_binary_button)

        # Snapshots - right layout
        right_side = QWidget(main)
        right_layout = QVBoxLayout(right_side)
        details_project = QGroupBox("Details", right_side)
        details_layout = QGridLayout(details_project)
        self._file_label = QLabel("<b>File:</b>")
        details_layout.addWidget(self._file_label, 0, 0)
        self._hash_label = QLabel("<b>Hash:</b>")
        details_layout.addWidget(self._hash_label, 1, 0)
        details_layout.setColumnStretch(0, 1)
        self._type_label = QLabel("<b>Type:</b>")
        details_layout.addWidget(self._type_label, 0, 1)
        self._date_label = QLabel("<b>Date:</b>")
        details_layout.addWidget(self._date_label, 1, 1)
        details_layout.setColumnStretch(1, 1)
        right_layout.addWidget(details_project)
        main_layout.addWidget(right_side, 0, 2)
        main_layout.setColumnStretch(2, 2)

        # Snapshots table
        self._snapshots_project = QGroupBox("Database Snapshots", right_side)
        self._snapshots_layout = QVBoxLayout(self._snapshots_project)
        self._snapshots_table = QTableWidget(0, 3, self._snapshots_project)
        labels = ("Name", "Date", "Ticks")
        self._snapshots_table.setHorizontalHeaderLabels(labels)
        horizontal_header = self._snapshots_table.horizontalHeader()
        horizontal_header.setSectionsClickable(False)
        horizontal_header.setSectionResizeMode(0, _HV_Stretch)
        self._snapshots_table.verticalHeader().setVisible(False)
        self._snapshots_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._snapshots_table.setSelectionMode(QTableWidget.SingleSelection)
        self._snapshots_table.itemSelectionChanged.connect(
            self._snapshot_clicked
        )
        self._snapshots_table.itemDoubleClicked.connect(
            self._snapshot_double_clicked
        )
        self._snapshots_layout.addWidget(self._snapshots_table)

        self._delete_snapshot_button = QPushButton(
            "Delete Database Snapshot", self._snapshots_project
        )
        self._delete_snapshot_button.setEnabled(False)
        self._delete_snapshot_button.clicked.connect(
            self._delete_snapshot_clicked
        )
        self._snapshots_layout.addWidget(self._delete_snapshot_button)
        right_layout.addWidget(self._snapshots_project)

        # General buttons - bottom right "stretched" layout
        buttons_widget = QWidget(self)
        buttons_layout = QHBoxLayout(buttons_widget)
        buttons_layout.addStretch()

        # Open button
        self._accept_button = QPushButton("Open", buttons_widget)
        self._accept_button.setEnabled(False)
        # self.accept is a QDialog virtual method
        self._accept_button.clicked.connect(self.accept)

        # Cancel button
        cancel_button = QPushButton("Cancel", buttons_widget)
        # self.reject is a QDialog virtual method
        cancel_button.clicked.connect(self.reject)

        # Place buttons onto UI
        buttons_layout.addWidget(cancel_button)
        buttons_layout.addWidget(self._accept_button)
        layout.addWidget(buttons_widget)

        # Ask the server for the list of projects
        d = self._plugin.network.send_packet(ListProjects.Query())
        d.add_callback(self._projects_listed)
        d.add_errback(self._plugin.logger.exception)

    ##### PROJECTS #####

    def _projects_listed(self, reply):
        """Called when the projects list is received."""
        self._projects = sorted(reply.projects, key=lambda x: x.name) # sort projects by name
        #self._projects = sorted(reply.projects, key=lambda x: x.date, reverse=True) # sort projects by reverse date
        self._refresh_projects()

    def _refresh_projects(self):
        """Refreshes the projects table."""
        self._projects_table.setRowCount(len(self._projects))
        for i, project in enumerate(self._projects):
            item = QTableWidgetItem(project.name)
            item.setData(Qt.UserRole, project)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self._projects_table.setItem(i, 0, item)

    def _project_clicked(self):
        self._plugin.logger.debug("OpenDialog._project_clicked()")
        """Called when a project item is clicked."""
        project = self._projects_table.selectedItems()[0].data(Qt.UserRole)

        # Ask the server for the list of binaries
        d = self._plugin.network.send_packet(ListBinaries.Query(project.name))
        d.add_callback(partial(self._binaries_listed))
        d.add_errback(self._plugin.logger.exception)

        self.delete_project_button.setEnabled(True)

    def _delete_project_clicked(self):
        self._plugin.logger.debug("OpenDialog._delete_project_clicked()")
        project = self._projects_table.selectedItems()[0].data(Qt.UserRole)
        d = self._plugin.network.send_packet(DeleteProject.Query(project.name))
        d.add_callback(partial(self._project_deleted, project))
        d.add_errback(self._plugin.logger.exception)

    def _project_deleted(self, project, reply):
        if reply.deleted:
            for e in self._projects:
                if e.name == project.name:
                    self._projects.remove(e)
            self._refresh_projects()
        else:
            QMessageBox.about(self, "IDArling Error", "Unable to delete.\n"
                                                      "Likely more than one client connected to target?")

    ##### BINARIES #####

    def _binaries_listed(self, reply):
        self._plugin.logger.debug("OpenDialog._binaries_listed()")
        """Called when the binaries list is received."""
        self._binaries = sorted(reply.binaries, key=lambda x: x.name) # sort binary by name
        #self._binaries = sorted(reply.binaries, key=lambda x: x.date, reverse=True) # sort binary by reverse date
        self._refresh_binaries()

    def _refresh_binaries(self):
        self._plugin.logger.debug("OpenDialog._refresh_binaries()")
        """Refreshes the binaries table."""
        self._binaries_table.setRowCount(len(self._binaries))
        for i, binary in enumerate(self._binaries):
            item = QTableWidgetItem(binary.name)
            item.setData(Qt.UserRole, binary)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self._binaries_table.setItem(i, 0, item)

    def _binary_clicked(self):
        """Called when a binary item is clicked."""
        self._plugin.logger.debug("OpenDialog._binary_clicked()")
        if len(self._binaries) == 0:
            self._plugin.logger.info("No binary to display yet 2")
            return  # no binary in the project yet

        project = self._projects_table.selectedItems()[0].data(Qt.UserRole)
        binary_items = self._binaries_table.selectedItems()
        if not binary_items:
            self._plugin.logger.info("No selected item 2")
            return
        binary = binary_items[0].data(Qt.UserRole)
        self._file_label.setText("<b>File:</b> %s" % str(binary.file))
        self._hash_label.setText("<b>Hash:</b> %s" % str(binary.hash))
        self._type_label.setText("<b>Type:</b> %s" % str(binary.type))
        self._date_label.setText("<b>Date:</b> %s" % str(binary.date))

        # Ask the server for the list of snapshots
        d = self._plugin.network.send_packet(ListSnapshots.Query(project.name, binary.name))
        d.add_callback(partial(self._snapshots_listed))
        d.add_errback(self._plugin.logger.exception)
        self._rename_binary_button.setEnabled(True)
        self._delete_binary_button.setEnabled(True)

    def _delete_binary_clicked(self):
        self._plugin.logger.debug("OpenDialog._delete_binary_clicked()")
        project = self._projects_table.selectedItems()[0].data(Qt.UserRole)
        binary_items = self._binaries_table.selectedItems()
        if not binary_items:
            self._plugin.logger.info("No selected item 2")
            return
        binary = binary_items[0].data(Qt.UserRole)
        d = self._plugin.network.send_packet(DeleteBinary.Query(project.name, binary.name))
        d.add_callback(partial(self._binary_deleted, binary))
        d.add_errback(self._plugin.logger.exception)

    def _binary_deleted(self, binary, reply):
        if reply.deleted:
            for e in self._binaries:
                if e.name == binary.name:
                    self._binaries.remove(e)
            self._refresh_binaries()
            self._snapshots_table.clearContents()
        else:
            QMessageBox.about(self, "IDArling Error", "Unable to delete.\n"
                                                      "Likely more than one client connected to target?")

    def _rename_binary_button_clicked(self, _):
        current_binary = self._binaries_table.selectedItems()[0].data(Qt.UserRole).name
        dialog = RenameBinaryDialog(self._plugin, "Rename binary", current_binary)
        dialog.accepted.connect(partial(self._rename_binary_dialog_accepted, dialog))
        dialog.exec_()

    def _rename_binary_dialog_accepted(self, dialog):
        project = self._projects_table.selectedItems()[0].data(Qt.UserRole).name
        old_name = self._binaries_table.selectedItems()[0].data(Qt.UserRole).name
        new_name = dialog.get_result()
        self._plugin.logger.info("Request to rename to %s to %s in project: %s" % (old_name, new_name, project))
        # Send the packet to the server with the new name
        d = self._plugin.network.send_packet(RenameBinary.Query(project, old_name, new_name))
        d.add_callback(self._binary_renamed)
        d.add_errback(self._plugin.logger.exception)

    def _binary_renamed(self, reply):
        self._renamed = reply.renamed
        if self._renamed:
            self._binaries = self.sort_binaries(reply.binaries)
            self._refresh_binaries()
        else:
            self._plugin.logger.debug("Create binary dialog")
            QMessageBox.about(self, "IDArling Error", "Unable to rename.\n"
                    "Likely more than one client connected?")

    ##### SNAPSHOTS #####

    def _snapshots_listed(self, reply):
        """Called when the snapshots list is received."""
        self._snapshots = self.sort_snapshots(reply.snapshots)
        self._refresh_snapshots()

    def _refresh_snapshots(self):
        """Refreshes the table of snapshots."""

        def create_item(text, snapshot):
            item = QTableWidgetItem(text)
            item.setData(Qt.UserRole, snapshot)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            if snapshot.tick == -1:
                item.setFlags(item.flags() & ~Qt.ItemIsEnabled)
            return item

        self._snapshots_table.setRowCount(len(self._snapshots))
        for i, snapshot in enumerate(self._snapshots):
            self._snapshots_table.setItem(
                i, 0, create_item(snapshot.name, snapshot)
            )
            self._snapshots_table.setItem(
                i, 1, create_item(snapshot.date, snapshot)
            )
            tick = str(snapshot.tick) if snapshot.tick != -1 else "<none>"
            self._snapshots_table.setItem(i, 2, create_item(tick, snapshot))

    def _snapshot_clicked(self):
        self._accept_button.setEnabled(True)
        self._delete_snapshot_button.setEnabled(True)

    def _delete_snapshot_clicked(self):
        self._plugin.logger.debug("OpenDialog._delete_snapshot_clicked()")
        project = self._projects_table.selectedItems()[0].data(Qt.UserRole)
        binary_items = self._binaries_table.selectedItems()
        if not binary_items:
            self._plugin.logger.info("No selected item 2")
            return
        binary = binary_items[0].data(Qt.UserRole)
        snapshot = self._snapshots_table.selectedItems()[0].data(Qt.UserRole)
        d = self._plugin.network.send_packet(DeleteSnapshot.Query(project.name, binary.name, snapshot.name))
        d.add_callback(partial(self._snapshot_deleted, snapshot))
        d.add_errback(self._plugin.logger.exception)

    def _snapshot_deleted(self, snapshot, reply):
        if reply.deleted:
            for e in self._snapshots:
                if e.name == snapshot.name:
                    self._snapshots.remove(e)
            self._refresh_snapshots()
        else:
            QMessageBox.about(self, "IDArling Error", "Unable to delete.\n"
                                                      "Likely more than one client connected to target?")

    def _snapshot_double_clicked(self):
        binary_type = self._binaries_table.selectedItems()[0].data(Qt.UserRole).type
        # For now we are only detecting some bad matching between IDA architecture
        # and the disassembled binary's architecture but we would need to 
        # actually save a binary architecture (32-bit or 64-bit) to support all
        # cases
        # E.g. below we support "Portable executable for 80386 (PE)" vs 
        # "Portable executable for AMD64 (PE)"
        # ida.exe vs ida64.exe can be determined using idc.BADADDR trick
        if (idc.BADADDR == 0xffffffffffffffff and "80386" in binary_type) \
         or (idc.BADADDR == 0xffffffff and "AMD64" in binary_type):
            QMessageBox.about(self, "IDArling Error", "Wrong architecture!\n"
                    "You must use the right version of IDA/IDA64,")
            return
        self.accept()

    ##### HELPERS #####

    def get_result(self):
        """Get the binary and snapshot selected by the user."""
        project = self._projects_table.selectedItems()[0].data(Qt.UserRole)
        binary = self._binaries_table.selectedItems()[0].data(Qt.UserRole)
        snapshot = self._snapshots_table.selectedItems()[0].data(Qt.UserRole)
        return project, binary, snapshot

    # XXX - Make x.name configurable based on clicking on columns
    def sort_binaries(self, binaries):
        #return sorted(binaries, key=lambda x: x.date, reverse=True) # sort binary by reverse date
        return sorted(binaries, key=lambda x: x.name)

    # XXX - Make x.date configurable based on clicking on columns
    def sort_snapshots(self, snapshots):
        return sorted(snapshots, key=lambda x: x.date, reverse=True) # sort snapshots by reverse date

class SaveDialog(OpenDialog):
    """
    This save dialog is shown to user to select which remote snapshot to save. We
    extend the open dialog to reuse most of the UI setup code.
    """

    def __init__(self, plugin):
        super(SaveDialog, self).__init__(plugin)
        self._project = None
        self._binary = None

        # General setup of the dialog
        self.setWindowTitle("Save to Remote Server")
        icon_path = self._plugin.plugin_resource("upload.png")
        self.setWindowIcon(QIcon(icon_path))

        # Change the accept button text
        self._accept_button.setText("Save")

        # Add a button to create a project
        create_project_button = QPushButton("Create Project", self._left_side)
        create_project_button.clicked.connect(self._create_project_clicked)
        self._left_layout.addWidget(create_project_button)

        # Add a button to create a binary
        self._create_binary_button = QPushButton(
            "Create Binary File", self._middle_side
        )
        self._create_binary_button.setEnabled(False)
        self._create_binary_button.clicked.connect(
            self._create_binary_clicked
        )
        self._middle_layout.addWidget(self._create_binary_button)

        # Add a button to create a snapshot
        self._create_snapshot_button = QPushButton(
            "Create Database Snapshot", self._snapshots_project
        )
        self._create_snapshot_button.setEnabled(False)
        self._create_snapshot_button.clicked.connect(
            self._create_snapshot_clicked
        )
        self._snapshots_layout.addWidget(self._create_snapshot_button)

    ##### PROJECTS #####

    # XXX - not needed?
    def _refresh_projects(self):
        super(SaveDialog, self)._refresh_projects()
        for row in range(self._projects_table.rowCount()):
            item = self._projects_table.item(row, 0)
            project = item.data(Qt.UserRole)
            pass

    def _project_clicked(self):
        super(SaveDialog, self)._project_clicked()
        self._project = self._projects_table.selectedItems()[0].data(
            Qt.UserRole
        )
        self._create_binary_button.setEnabled(True)

    def _create_project_clicked(self):
        dialog = CreateProjectDialog(self._plugin)
        dialog.accepted.connect(partial(self._create_project_accepted, dialog))
        dialog.exec_()

    def _create_project_accepted(self, dialog):
        """Called when the project creation dialog is accepted."""
        name = dialog.get_result()
        # Ensure we don't already have a project with that name
        if any(project.name == name for project in self._projects):
            failure = QMessageBox()
            failure.setIcon(QMessageBox.Warning)
            failure.setStandardButtons(QMessageBox.Ok)
            failure.setText("A project with that name already exists!")
            failure.setWindowTitle("New Project")
            icon_path = self._plugin.plugin_resource("upload.png")
            failure.setWindowIcon(QIcon(icon_path))
            failure.exec_()
            return

        # Get all the information we need and sent it to the server
        date_format = "%Y/%m/%d %H:%M"
        date = datetime.datetime.now().strftime(date_format)
        project = Project(name, date)
        d = self._plugin.network.send_packet(CreateProject.Query(project))
        d.add_callback(partial(self._project_created, project))
        d.add_errback(self._plugin.logger.exception)

    def _project_created(self, project, _):
        """Called when the create project reply is received."""
        self._projects.append(project)
        self._refresh_projects()
        row = len(self._projects) - 1
        self._projects_table.selectRow(row)
        self._accept_button.setEnabled(False)

    ##### BINARIES #####

    def _refresh_binaries(self):
        self._plugin.logger.debug("SaveDialog._refresh_binaries()")
        super(SaveDialog, self)._refresh_binaries()
        self._plugin.logger.debug("SaveDialog._refresh_binaries() continue")

        if len(self._binaries) == 0:
            self._plugin.logger.info("No binary to display yet 3")
            return  # no binary in the project yet

        hash = ida_nalt.retrieve_input_file_md5()
        if hash.endswith(b'\x00'):
            hash = hash[0:-1]
        # This decode is safe, because we have an hash in hex format
        hash = binascii.hexlify(hash).decode('utf-8')
        for row in range(self._binaries_table.rowCount()):
            item = self._binaries_table.item(row, 0)
            binary = item.data(Qt.UserRole)
            if binary.hash != hash:
                item.setFlags(item.flags() & ~Qt.ItemIsEnabled)

    def _binary_clicked(self):
        self._plugin.logger.debug("SaveDialog._binary_clicked()")
        super(SaveDialog, self)._binary_clicked()
        self._plugin.logger.debug("SaveDialog._binary_clicked() continue")
        binary_items = self._binaries_table.selectedItems()
        if not binary_items:
            self._plugin.logger.info("No selected item 2")
            return
        self._binary = binary_items[0].data(Qt.UserRole)
        self._create_snapshot_button.setEnabled(True)

    def _create_binary_clicked(self):
        dialog = CreateBinaryDialog(self._plugin)
        dialog.accepted.connect(partial(self._create_binary_accepted, dialog))
        dialog.exec_()

    def _create_binary_accepted(self, dialog):
        """Called when the binary creation dialog is accepted."""
        name = dialog.get_result()
        # Ensure we don't already have a binary with that name
        # Note: 2 different projects can have two binaries with the same name
        # and it will effectively be 2 different binaries
        if any(binary.name == name for binary in self._binaries):
            failure = QMessageBox()
            failure.setIcon(QMessageBox.Warning)
            failure.setStandardButtons(QMessageBox.Ok)
            failure.setText("A binary with that name already exists!")
            failure.setWindowTitle("New Binary")
            icon_path = self._plugin.plugin_resource("upload.png")
            failure.setWindowIcon(QIcon(icon_path))
            failure.exec_()
            return

        # Get all the information we need and sent it to the server
        hash = ida_nalt.retrieve_input_file_md5()
        # Remove the trailing null byte, if exists
        if hash.endswith(b'\x00'):
            hash = hash[0:-1]
        # This decode is safe, because we have an hash in hex format
        hash = binascii.hexlify(hash).decode('utf-8')
        file = ida_nalt.get_root_filename()
        ftype = ida_loader.get_file_type_name()
        date_format = "%Y/%m/%d %H:%M"
        date = datetime.datetime.now().strftime(date_format)
        binary = Binary(self._project.name, name, hash, file, ftype, date)
        d = self._plugin.network.send_packet(CreateBinary.Query(binary))
        d.add_callback(partial(self._binary_created, binary))
        d.add_errback(self._plugin.logger.exception)

    def _binary_created(self, binary, _):
        """Called when the create binary reply is received."""
        self._binaries.append(binary)
        self._refresh_binaries()
        row = len(self._binaries) - 1
        self._binaries_table.selectRow(row)
        self._accept_button.setEnabled(False)

    ##### SNAPSHOTS #####

    def _refresh_snapshots(self):
        super(SaveDialog, self)._refresh_snapshots()
        for row in range(self._snapshots_table.rowCount()):
            for col in range(3):
                item = self._snapshots_table.item(row, col)
                item.setFlags(item.flags() | Qt.ItemIsEnabled)

    def _create_snapshot_clicked(self):
        """Called when the create snapshot button is clicked."""
        dialog = CreateSnapshotDialog(self._plugin)
        dialog.accepted.connect(
            partial(self._create_snapshot_accepted, dialog)
        )
        dialog.exec_()

    def _create_snapshot_accepted(self, dialog):
        """Called when the snapshot creation dialog is accepted."""
        name = dialog.get_result()

        # Ensure we don't already have a snapshot with that name
        if any(snapshot.name == name for snapshot in self._snapshots):
            failure = QMessageBox()
            failure.setIcon(QMessageBox.Warning)
            failure.setStandardButtons(QMessageBox.Ok)
            failure.setText("A snapshot with that name already exists!")
            failure.setWindowTitle("New Snapshot")
            icon_path = self._plugin.plugin_resource("upload.png")
            failure.setWindowIcon(QIcon(icon_path))
            failure.exec_()
            return

        # Get all the information we need and sent it to the server
        date_format = "%Y/%m/%d %H:%M"
        date = datetime.datetime.now().strftime(date_format)
        snapshot = Snapshot(self._project.name, self._binary.name, name, date, -1)
        d = self._plugin.network.send_packet(CreateSnapshot.Query(snapshot))
        d.add_callback(partial(self._snapshot_created, snapshot))
        d.add_errback(self._plugin.logger.exception)

    def _snapshot_created(self, snapshot, _):
        """Called when the new snapshot reply is received."""
        self._snapshots.append(snapshot)
        self._refresh_snapshots()
        row = len(self._snapshots) - 1
        self._snapshots_table.selectRow(row)

class CreateProjectDialog(QDialog):
    """The dialog shown when an user wants to create a project."""

    def __init__(self, plugin):
        super(CreateProjectDialog, self).__init__()
        self._plugin = plugin

        # General setup of the dialog
        self._plugin.logger.debug("Create project dialog")
        self.setWindowTitle("Create Project")
        icon_path = plugin.plugin_resource("upload.png")
        self.setWindowIcon(QIcon(icon_path))
        self.resize(100, 100)

        # Set up the layout and widgets
        layout = QVBoxLayout(self)

        self._nameLabel = QLabel("<b>Project Name</b>")
        layout.addWidget(self._nameLabel)
        self._nameEdit = QLineEdit()
        self._nameEdit.setValidator(QRegularExpressionValidator(QRegularExpression("[a-zA-Z0-9-]+")))
        layout.addWidget(self._nameEdit)

        buttons = QWidget(self)
        buttons_layout = QHBoxLayout(buttons)
        create_button = QPushButton("Create")
        create_button.clicked.connect(self.accept)
        buttons_layout.addWidget(create_button)
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        buttons_layout.addWidget(cancel_button)
        layout.addWidget(buttons)

    def get_result(self):
        """Get the name entered by the user."""
        return self._nameEdit.text()


class CreateBinaryDialog(CreateProjectDialog):
    """The dialog shown when an user wants to create a binary. We extend the
    create binary dialog to avoid duplicating the UI setup code.
    """

    def __init__(self, plugin):
        super(CreateBinaryDialog, self).__init__(plugin)
        #self._plugin.logger.debug("Create binary dialog")
        self.setWindowTitle("Create Binary File")
        self._nameLabel.setText("<b>Binary Name</b>")


class CreateSnapshotDialog(CreateProjectDialog):
    """
    The dialog shown when an user wants to create a snapshot. We extend the
    create binary dialog to avoid duplicating the UI setup code.
    """

    def __init__(self, plugin):
        super(CreateSnapshotDialog, self).__init__(plugin)
        #self._plugin.logger.debug("Create snapshot dialog")
        self.setWindowTitle("Create Database Snapshot")
        self._nameLabel.setText("<b>Snapshot Name</b>")


class SettingsDialog(QDialog):
    """
    The dialog allowing an user to configure the plugin. It has multiple tabs
    used to group the settings by category (general, network, etc.).
    """

    def __init__(self, plugin):
        super(SettingsDialog, self).__init__()
        self._plugin = plugin

        # General setup of the dialog
        self._plugin.logger.debug("Showing settings dialog")
        self.setWindowTitle("Settings")
        icon_path = self._plugin.plugin_resource("settings.png")
        self.setWindowIcon(QIcon(icon_path))
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowCloseButtonHint)

        window_widget = QWidget(self)
        window_layout = QVBoxLayout(window_widget)
        tabs = QTabWidget(window_widget)
        window_layout.addWidget(tabs)

        # "General Settings" tab
        tab = QWidget(tabs)
        layout = QFormLayout(tab)
        layout.setFormAlignment(Qt.AlignVCenter)
        tabs.addTab(tab, "General Settings")

        user_widget = QWidget(tab)
        user_layout = QHBoxLayout(user_widget)
        layout.addRow(user_widget)

        # User color
        self._color_button = QPushButton("")
        self._color_button.setFixedSize(50, 30)

        def color_button_activated(_):
            self._set_color(qt_color=QColorDialog.getColor().rgb())

        self._color = self._plugin.config["user"]["color"]
        self._set_color(ida_color=self._color)
        self._color_button.clicked.connect(color_button_activated)
        user_layout.addWidget(self._color_button)

        # User name
        self._name_line_edit = QLineEdit()
        name = self._plugin.config["user"]["name"]
        self._name_line_edit.setText(name)
        user_layout.addWidget(self._name_line_edit)

        dir_combo_box = QWidget(tab)
        dir_combo_box_layout = QGridLayout()
        browseButton = self._createButton("&Browse...", self._browse_button_clicked)
        self.directoryComboBox = self._createComboBox(self._plugin.config["files_dir"])
        directoryLabel = QLabel("Files directory:")
        dir_combo_box_layout.addWidget(directoryLabel, 0, 0)
        dir_combo_box_layout.addWidget(self.directoryComboBox, 0, 1)
        dir_combo_box_layout.addWidget(browseButton, 0, 2)
        dir_combo_box.setLayout(dir_combo_box_layout)
        layout.addRow(dir_combo_box)

        text = "Disable all user cursors"
        self._disable_all_cursors_checkbox = QCheckBox(text)
        layout.addRow(self._disable_all_cursors_checkbox)
        navbar_checked = not self._plugin.config["cursors"]["navbar"]
        funcs_checked = not self._plugin.config["cursors"]["funcs"]
        disasm_checked = not self._plugin.config["cursors"]["disasm"]
        all_checked = navbar_checked and funcs_checked and disasm_checked
        self._disable_all_cursors_checkbox.setChecked(all_checked)

        def state_changed(state):
            enabled = state == Qt.Unchecked
            self._disable_navbar_cursors_checkbox.setChecked(not enabled)
            self._disable_navbar_cursors_checkbox.setEnabled(enabled)
            self._disable_funcs_cursors_checkbox.setChecked(not enabled)
            self._disable_funcs_cursors_checkbox.setEnabled(enabled)
            self._disable_disasm_cursors_checkbox.setChecked(not enabled)
            self._disable_disasm_cursors_checkbox.setEnabled(enabled)

        self._disable_all_cursors_checkbox.stateChanged.connect(state_changed)

        style_sheet = """QCheckBox{ margin-left: 20px; }"""

        text = "Disable navigation bar user cursors"
        self._disable_navbar_cursors_checkbox = QCheckBox(text)
        layout.addRow(self._disable_navbar_cursors_checkbox)
        self._disable_navbar_cursors_checkbox.setChecked(navbar_checked)
        self._disable_navbar_cursors_checkbox.setEnabled(not all_checked)
        self._disable_navbar_cursors_checkbox.setStyleSheet(style_sheet)

        text = "Disable functions window user cursors"
        self._disable_funcs_cursors_checkbox = QCheckBox(text)
        layout.addRow(self._disable_funcs_cursors_checkbox)
        self._disable_funcs_cursors_checkbox.setChecked(funcs_checked)
        self._disable_funcs_cursors_checkbox.setEnabled(not all_checked)
        self._disable_funcs_cursors_checkbox.setStyleSheet(style_sheet)

        text = "Disable disassembly view user cursors"
        self._disable_disasm_cursors_checkbox = QCheckBox(text)
        layout.addRow(self._disable_disasm_cursors_checkbox)
        self._disable_disasm_cursors_checkbox.setChecked(disasm_checked)
        self._disable_disasm_cursors_checkbox.setEnabled(not all_checked)
        self._disable_disasm_cursors_checkbox.setStyleSheet(style_sheet)

        text = "Allow other users to send notifications"
        self._notifications_checkbox = QCheckBox(text)
        layout.addRow(self._notifications_checkbox)
        checked = self._plugin.config["user"]["notifications"]
        self._notifications_checkbox.setChecked(checked)

        # Log level
        debug_level_label = QLabel("Logging level: ")
        self._debug_level_combo_box = QComboBox()
        self._debug_level_combo_box.addItem("CRITICAL", logging.CRITICAL)
        self._debug_level_combo_box.addItem("ERROR", logging.ERROR)
        self._debug_level_combo_box.addItem("WARNING", logging.WARNING)
        self._debug_level_combo_box.addItem("INFO", logging.INFO)
        self._debug_level_combo_box.addItem("DEBUG", logging.DEBUG)
        self._debug_level_combo_box.addItem("TRACE", logging.TRACE)
        level = self._plugin.config["level"]
        index = self._debug_level_combo_box.findData(level)
        self._debug_level_combo_box.setCurrentIndex(index)
        layout.addRow(debug_level_label, self._debug_level_combo_box)

        # "Network Settings" tab
        tab = QWidget(tabs)
        layout = QVBoxLayout(tab)
        tab.setLayout(layout)
        tabs.addTab(tab, "Network Settings")

        top_widget = QWidget(tab)
        layout.addWidget(top_widget)
        top_layout = QHBoxLayout(top_widget)

        self._servers = list(self._plugin.config["servers"])
        self._servers_table = QTableWidget(len(self._servers), 3, self)
        top_layout.addWidget(self._servers_table)
        for i, server in enumerate(self._servers):
            # Server host and port
            item = QTableWidgetItem("%s:%d" % (server["host"], server["port"]))
            item.setData(Qt.UserRole, server)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            # XXX - This prevented editing a server entry for your current 
            # server because the row cannot be selected properly with 
            # SingleSelection option selected
            #if self._plugin.network.server == server:
            #    item.setFlags((item.flags() & ~Qt.ItemIsSelectable))
            self._servers_table.setItem(i, 0, item)

            # Server has SSL enabled?
            ssl_checkbox = QTableWidgetItem()
            state = Qt.Unchecked if server["no_ssl"] else Qt.Checked
            ssl_checkbox.setCheckState(state)
            ssl_checkbox.setFlags((ssl_checkbox.flags() & ~Qt.ItemIsEditable))
            ssl_checkbox.setFlags((ssl_checkbox.flags() & ~Qt.ItemIsUserCheckable))
            self._servers_table.setItem(i, 1, ssl_checkbox)

            # Auto-connect enabled?
            auto_checkbox = QTableWidgetItem()
            state = Qt.Unchecked if not server["auto_connect"] else Qt.Checked
            auto_checkbox.setCheckState(state)
            auto_checkbox.setFlags((auto_checkbox.flags() & ~Qt.ItemIsEditable))
            auto_checkbox.setFlags((auto_checkbox.flags() & ~Qt.ItemIsUserCheckable))
            self._servers_table.setItem(i, 2, auto_checkbox)

        self._servers_table.setHorizontalHeaderLabels(("Servers", "SSL",
                    "Auto"))
        horizontal_header = self._servers_table.horizontalHeader()
        horizontal_header.setSectionsClickable(False)
        horizontal_header.setSectionResizeMode(0, _HV_Stretch)
        horizontal_header.setSectionResizeMode(1, _HV_ResizeToContents)
        horizontal_header.setSectionResizeMode(2, _HV_ResizeToContents)
        self._servers_table.verticalHeader().setVisible(False)
        self._servers_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._servers_table.setSelectionMode(QTableWidget.SingleSelection)
        self._servers_table.itemClicked.connect(self._server_clicked)
        self._servers_table.itemDoubleClicked.connect(
            self._server_double_clicked
        )
        self._servers_table.setMaximumHeight(100)

        buttons_widget = QWidget(top_widget)
        buttons_layout = QVBoxLayout(buttons_widget)
        top_layout.addWidget(buttons_widget)

        # Add server button
        self._add_button = QPushButton("Add Server")
        self._add_button.clicked.connect(self._add_button_clicked)
        buttons_layout.addWidget(self._add_button)

        # Edit server button
        self._edit_button = QPushButton("Edit Server")
        self._edit_button.setEnabled(False)
        self._edit_button.clicked.connect(self._edit_button_clicked)
        buttons_layout.addWidget(self._edit_button)

        # Delete server button
        self._delete_button = QPushButton("Delete Server")
        self._delete_button.setEnabled(False)
        self._delete_button.clicked.connect(self._delete_button_clicked)
        buttons_layout.addWidget(self._delete_button)

        bottom_widget = QWidget(tab)
        bottom_layout = QFormLayout(bottom_widget)
        layout.addWidget(bottom_widget)

        # TCP Keep-Alive settings
        keep_cnt_label = QLabel("Keep-Alive Count: ")
        self._keep_cnt_spin_box = QSpinBox(bottom_widget)
        self._keep_cnt_spin_box.setRange(0, 86400)
        self._keep_cnt_spin_box.setValue(self._plugin.config["keep"]["cnt"])
        self._keep_cnt_spin_box.setSuffix(" packets")
        bottom_layout.addRow(keep_cnt_label, self._keep_cnt_spin_box)

        keep_intvl_label = QLabel("Keep-Alive Interval: ")
        self._keep_intvl_spin_box = QSpinBox(bottom_widget)
        self._keep_intvl_spin_box.setRange(0, 86400)
        self._keep_intvl_spin_box.setValue(
            self._plugin.config["keep"]["intvl"]
        )
        self._keep_intvl_spin_box.setSuffix(" seconds")
        bottom_layout.addRow(keep_intvl_label, self._keep_intvl_spin_box)

        keep_idle_label = QLabel("Keep-Alive Idle: ")
        self._keep_idle_spin_box = QSpinBox(bottom_widget)
        self._keep_idle_spin_box.setRange(0, 86400)
        self._keep_idle_spin_box.setValue(self._plugin.config["keep"]["idle"])
        self._keep_idle_spin_box.setSuffix(" seconds")
        bottom_layout.addRow(keep_idle_label, self._keep_idle_spin_box)

        # Buttons commons to all tabs
        actions_widget = QWidget(self)
        actions_layout = QHBoxLayout(actions_widget)

        # Cancel = do not save the changes and close the dialog
        def cancel(_):
            self.reject()

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(cancel)
        actions_layout.addWidget(cancel_button)

        # Reset = reset all settings from all tabs to default values
        reset_button = QPushButton("Reset")
        reset_button.clicked.connect(self._reset)
        actions_layout.addWidget(reset_button)

        # Save = save the changes and close the dialog
        def save(_):
            self._commit()
            self.accept()

        save_button = QPushButton("Save")
        save_button.clicked.connect(save)
        actions_layout.addWidget(save_button)
        window_layout.addWidget(actions_widget)

        # Do not allow the user to resize the dialog
        self.setFixedSize(
            window_widget.sizeHint().width(), window_widget.sizeHint().height()
        )

    def _set_color(self, ida_color=None, qt_color=None):
        """Sets the color of the user color button."""
        # IDA represents colors as 0xBBGGRR
        if ida_color is not None:
            r = ida_color & 255
            g = (ida_color >> 8) & 255
            b = (ida_color >> 16) & 255

        # Qt represents colors as 0xRRGGBB
        if qt_color is not None:
            r = (qt_color >> 16) & 255
            g = (qt_color >> 8) & 255
            b = qt_color & 255

        ida_color = r | g << 8 | b << 16
        qt_color = r << 16 | g << 8 | b

        # Set the stylesheet of the button
        css = "QPushButton {background-color: #%06x; color: #%06x;}"
        self._color_button.setStyleSheet(css % (qt_color, qt_color))
        self._color = ida_color

    def _server_clicked(self, _):
        self._edit_button.setEnabled(True)
        self._delete_button.setEnabled(True)

    def _server_double_clicked(self, _):
        item = self._servers_table.selectedItems()[0]
        server = item.data(Qt.UserRole)
        # If not the current server, connect to it
        if (
            not self._plugin.network.connected
            or self._plugin.network.server != server
        ):
            self._plugin.network.stop_server()
            self._plugin.network.connect(server)
        self.accept()

    def _add_button_clicked(self, _):
        dialog = ServerInfoDialog(self._plugin, "Add server")
        dialog.accepted.connect(partial(self._add_dialog_accepted, dialog))
        dialog.exec_()

    def _edit_button_clicked(self, _):
        selected = self._servers_table.selectedItems()
        if len(selected) == 0:
            self._plugin.logger.warning("No server selected")
            return
        item = selected[0]
        server = item.data(Qt.UserRole)
        dialog = ServerInfoDialog(self._plugin, "Edit server", server)
        dialog.accepted.connect(partial(self._edit_dialog_accepted, dialog))
        dialog.exec_()

    def _delete_button_clicked(self, _):
        item = self._servers_table.selectedItems()[0]
        server = item.data(Qt.UserRole)
        self._servers.remove(server)
        self._plugin.save_config()
        self._servers_table.removeRow(item.row())
        self.update()

    def _add_dialog_accepted(self, dialog):
        """Called when the dialog to add a server is accepted."""
        server = dialog.get_result()
        self._servers.append(server)
        row_count = self._servers_table.rowCount()
        self._servers_table.insertRow(row_count)

        new_server = QTableWidgetItem(
            "%s:%d" % (server["host"], server["port"])
        )
        new_server.setData(Qt.UserRole, server)
        new_server.setFlags(new_server.flags() & ~Qt.ItemIsEditable)
        self._servers_table.setItem(row_count, 0, new_server)

        new_checkbox = QTableWidgetItem()
        state = Qt.Unchecked if server["no_ssl"] else Qt.Checked
        new_checkbox.setCheckState(state)
        new_checkbox.setFlags((new_checkbox.flags() & ~Qt.ItemIsEditable))
        new_checkbox.setFlags(new_checkbox.flags() & ~Qt.ItemIsUserCheckable)
        self._servers_table.setItem(row_count, 1, new_checkbox)
        self.update()

    def _edit_dialog_accepted(self, dialog):
        """Called when the dialog to edit a server is accepted."""
        server = dialog.get_result()
        item = self._servers_table.selectedItems()[0]
        self._servers[item.row()] = server

        item.setText("%s:%d" % (server["host"], server["port"]))
        item.setData(Qt.UserRole, server)
        item.setFlags(item.flags() & ~Qt.ItemIsEditable)

        checkbox = self._servers_table.item(item.row(), 1)
        state = Qt.Unchecked if server["no_ssl"] else Qt.Checked
        checkbox.setCheckState(state)
        self.update()

    def _reset(self, _):
        """Resets all the form elements to their default value."""
        config = self._plugin.default_config()

        self._name_line_edit.setText(config["user"]["name"])
        self._set_color(ida_color=config["user"]["color"])

        navbar_checked = not config["cursors"]["navbar"]
        funcs_checked = not config["cursors"]["funcs"]
        disasm_checked = not config["cursors"]["disasm"]
        all_checked = navbar_checked and funcs_checked and disasm_checked
        self._disable_all_cursors_checkbox.setChecked(all_checked)

        self._disable_navbar_cursors_checkbox.setChecked(navbar_checked)
        self._disable_navbar_cursors_checkbox.setEnabled(not all_checked)
        self._disable_funcs_cursors_checkbox.setChecked(funcs_checked)
        self._disable_funcs_cursors_checkbox.setEnabled(not all_checked)
        self._disable_disasm_cursors_checkbox.setChecked(disasm_checked)
        self._disable_disasm_cursors_checkbox.setEnabled(not all_checked)

        checked = config["user"]["notifications"]
        self._notifications_checkbox.setChecked(checked)

        index = self._debug_level_combo_box.findData(config["level"])
        self._debug_level_combo_box.setCurrentIndex(index)

        del self._servers[:]
        self._servers_table.clearContents()
        self._keep_cnt_spin_box.setValue(config["keep"]["cnt"])
        self._keep_intvl_spin_box.setValue(config["keep"]["intvl"])
        self._keep_idle_spin_box.setValue(config["keep"]["idle"])

    def _commit(self):
        """Commits all the changes made to the form elements."""
        name = self._name_line_edit.text()
        if self._plugin.config["user"]["name"] != name:
            old_name = self._plugin.config["user"]["name"]
            self._plugin.network.send_packet(UpdateUserName(old_name, name))
            self._plugin.config["user"]["name"] = name

        if self._plugin.config["user"]["color"] != self._color:
            name = self._plugin.config["user"]["name"]
            old_color = self._plugin.config["user"]["color"]
            packet = UpdateUserColor(name, old_color, self._color)
            self._plugin.network.send_packet(packet)
            self._plugin.config["user"]["color"] = self._color
            self._plugin.interface.widget.refresh()

        all_ = self._disable_all_cursors_checkbox.isChecked()
        checked = self._disable_navbar_cursors_checkbox.isChecked()
        self._plugin.config["cursors"]["navbar"] = not all_ and not checked
        checked = self._disable_funcs_cursors_checkbox.isChecked()
        self._plugin.config["cursors"]["funcs"] = not all_ and not checked
        checked = self._disable_disasm_cursors_checkbox.isChecked()
        self._plugin.config["cursors"]["disasm"] = not all_ and not checked

        checked = self._notifications_checkbox.isChecked()
        self._plugin.config["user"]["notifications"] = checked

        index = self._debug_level_combo_box.currentIndex()
        level = self._debug_level_combo_box.itemData(index)
        self._plugin.logger.setLevel(level)
        self._plugin.config["level"] = level

        self._plugin.config["servers"] = self._servers
        cnt = self._keep_cnt_spin_box.value()
        self._plugin.config["keep"]["cnt"] = cnt
        intvl = self._keep_intvl_spin_box.value()
        self._plugin.config["keep"]["intvl"] = intvl
        idle = self._keep_idle_spin_box.value()
        self._plugin.config["keep"]["idle"] = idle
        if self._plugin.network.client:
            self._plugin.network.client.set_keep_alive(cnt, intvl, idle)

        files_path = self.directoryComboBox.currentText()
        self._plugin.config["files_dir"] = files_path

        self._plugin.save_config()

    def _createButton(self, text, member):
        button = QPushButton(text)
        button.clicked.connect(member)
        return button

    def _createComboBox(self,text):
        comboBox = QComboBox()
        comboBox.setEditable(True)
        comboBox.addItem(text)
        comboBox.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        return comboBox

    def _browse_button_clicked(self):
        directory = QFileDialog.getExistingDirectory(self, "Find Files",
                self.directoryComboBox.currentText())

        if directory:
            if self.directoryComboBox.findText(directory) == -1:
                self.directoryComboBox.addItem(directory)

            self.directoryComboBox.setCurrentIndex(self.directoryComboBox.findText(directory))

class RenameBinaryDialog(QDialog):
    """The dialog shown when an user wants to rename a binary."""

    def __init__(self, plugin, title, current_value, server=None):
        super(RenameBinaryDialog, self).__init__()
        self._plugin = plugin

        # General setup of the dialog
        self._plugin.logger.debug("Showing rename binary dialog")
        self.setWindowTitle(title)
        icon_path = plugin.plugin_resource("settings.png")
        self.setWindowIcon(QIcon(icon_path))
        self.resize(100, 100)

        # Setup the layout and widgets
        layout = QVBoxLayout(self)

        self._rename_binary_name_label = QLabel("<b>New Binary Name</b>")
        layout.addWidget(self._rename_binary_name_label)
        self._new_binary_name = QLineEdit()
        # Populate the field with the old name and already selected
        self._new_binary_name.setText(current_value)
        self._new_binary_name.setSelection(0, len(current_value))
        layout.addWidget(self._new_binary_name)

        self._add_button = QPushButton("OK")
        self._add_button.clicked.connect(self.accept)
        down_side = QWidget(self)
        buttons_layout = QHBoxLayout(down_side)
        buttons_layout.addWidget(self._add_button)
        self._cancel_button = QPushButton("Cancel")
        self._cancel_button.clicked.connect(self.reject)
        buttons_layout.addWidget(self._cancel_button)
        layout.addWidget(down_side)

    def get_result(self):
        return self._new_binary_name.text()

class ServerInfoDialog(QDialog):
    """The dialog shown when an user creates or edits a server."""

    def __init__(self, plugin, title, server=None):
        super(ServerInfoDialog, self).__init__()
        self._plugin = plugin

        # General setup of the dialog
        self._plugin.logger.debug("Showing server info dialog")
        self.setWindowTitle(title)
        icon_path = plugin.plugin_resource("settings.png")
        self.setWindowIcon(QIcon(icon_path))
        self.resize(100, 100)

        # Setup the layout and widgets
        layout = QVBoxLayout(self)

        self._server_name_label = QLabel("<b>Server Host</b>")
        layout.addWidget(self._server_name_label)
        self._server_name = QLineEdit()
        self._server_name.setPlaceholderText("127.0.0.1")
        layout.addWidget(self._server_name)

        self._server_name_label = QLabel("<b>Server Port</b>")
        layout.addWidget(self._server_name_label)
        self._server_port = QLineEdit()
        self._server_port.setPlaceholderText("31013")
        layout.addWidget(self._server_port)

        self._no_ssl_checkbox = QCheckBox("Disable SSL")
        layout.addWidget(self._no_ssl_checkbox)

        self._auto_connect_checkbox = QCheckBox("Auto-connect on startup")
        layout.addWidget(self._auto_connect_checkbox)

        # Set the form elements values if we have a base
        if server is not None:
            self._server_name.setText(server["host"])
            self._server_port.setText(str(server["port"]))
            self._no_ssl_checkbox.setChecked(server["no_ssl"])
            self._auto_connect_checkbox.setChecked(server["auto_connect"])

        down_side = QWidget(self)
        buttons_layout = QHBoxLayout(down_side)
        self._add_button = QPushButton("OK")
        self._add_button.clicked.connect(self.accept)
        buttons_layout.addWidget(self._add_button)
        self._cancel_button = QPushButton("Cancel")
        self._cancel_button.clicked.connect(self.reject)
        buttons_layout.addWidget(self._cancel_button)
        layout.addWidget(down_side)

    def get_result(self):
        """Get the server resulting from the form elements values."""
        return {
            "host": self._server_name.text() or "127.0.0.1",
            "port": int(self._server_port.text() or "31013"),
            "no_ssl": self._no_ssl_checkbox.isChecked(),
            "auto_connect": self._auto_connect_checkbox.isChecked(),
        }
