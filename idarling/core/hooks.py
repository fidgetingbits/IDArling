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
# import ctypes
import pickle

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_nalt
import idc
import ida_netnode
import ida_pro
import ida_segment
import ida_typeinf

fDebug = False
if fDebug:
    import pydevd_pycharm
import sys
sys.setrecursionlimit(10000)

from . import events as evt  # noqa: I100,I202
from .events import Event  # noqa: I201
from ..shared.local_types import ParseTypeString, ImportLocalType


class Hooks(object):
    """
    This is a common class for all client hooks. It adds an utility method to
    send an user event to all other clients through the server.
    """

    def __init__(self, plugin):
        self._plugin = plugin

    def _send_packet(self, event):
        """Sends a packet to the server."""
        # Check if it comes from the auto-analyzer
        if ida_auto.get_auto_state() == ida_auto.AU_NONE:
            self._plugin.network.send_packet(event)
        else:
            #self._plugin.logger.debug("Ignoring a packet")
            pass

# See idasdk74.zip: idasdk74/include/idp.hpp for methods' documentation
# See C:\Program Files\IDA Pro 7.4\python\3\ida_idp.py for methods' prototypes
# The order for methods below is the same as the idp.hpp file to ease making changes
class IDBHooks(Hooks, ida_idp.IDB_Hooks):
    def __init__(self, plugin):
        ida_idp.IDB_Hooks.__init__(self)
        Hooks.__init__(self, plugin)
        self.last_local_type = None

    def auto_empty_finally(self):
        self._plugin.logger.debug("auto_empty_finally() not implemented yet")
        return 0

    def auto_empty(self):
        self._plugin.logger.debug("auto_empty() not implemented yet")
        return 0

    def local_types_changed(self):
        changed_types = []
        # self._plugin.logger.trace(self._plugin.core.local_type_map)
        for i in range(1, ida_typeinf.get_ordinal_count(ida_typeinf.get_idati())):
            t = ImportLocalType(i)
            if t and t.name and idc.get_struc_id(t.name) == ida_idaapi.BADADDR and idc.get_enum(t.name) == ida_idaapi.BADADDR:
                if i in self._plugin.core.local_type_map:
                    t_old = self._plugin.core.local_type_map[i]
                    if t_old and not t.isEqual(t_old):
                        changed_types.append((t_old.to_tuple(),t.to_tuple()))
                    elif t_old is None and i in self._plugin.core.delete_candidates:
                        if not self._plugin.core.delete_candidates[i].isEqual(t):
                            changed_types.append((self._plugin.core.delete_candidates[i].to_tuple(), t.to_tuple()))
                        del self._plugin.core.delete_candidates[i]

                else:
                    changed_types.append((None,t.to_tuple()))
            if t is None:
                assert i in self._plugin.core.local_type_map
                if i in self._plugin.core.local_type_map:
                    t_old = self._plugin.core.local_type_map[i]
                    if t_old != t:
                        self._plugin.core.delete_candidates[i] = t_old
                    elif i in self._plugin.core.delete_candidates:
                        #changed_types.append((self._plugin.core.delete_candidates[i],None))
                        del self._plugin.core.delete_candidates[i]

                    # t_old = self._plugin.core.local_type_map[i]
                    # changed_types.append((t_old,None))
        # self._plugin.logger.trace(changed_types)
        if fDebug:
            pydevd_pycharm.settrace('localhost', port=2233, stdoutToServer=True, stderrToServer=True, suspend=False)
        self._plugin.logger.trace("Changed_types: %s"%list(map(lambda x: (x[0][0] if x[0] else None, x[1][0] if x[1] else None),changed_types)))
        if len(changed_types) > 0:
            self._send_packet(evt.LocalTypesChangedEvent(changed_types))
        self._plugin.core.update_local_types_map()
        return 0
        # XXX - old code below to delete?
        # from .core import Core

        # dll = Core.get_ida_dll()

        # get_idati = dll.get_idati
        # get_idati.argtypes = []
        # get_idati.restype = ctypes.c_void_p

        # get_numbered_type = dll.get_numbered_type
        # get_numbered_type.argtypes = [
        #     ctypes.c_void_p,
        #     ctypes.c_uint32,
        #     ctypes.POINTER(ctypes.c_char_p),
        #     ctypes.POINTER(ctypes.c_char_p),
        #     ctypes.POINTER(ctypes.c_char_p),
        #     ctypes.POINTER(ctypes.c_char_p),
        #     ctypes.POINTER(ctypes.c_int),
        # ]
        # get_numbered_type.restype = ctypes.c_bool

        # local_types = []
        # py_ti = ida_typeinf.get_idati()
        # for py_ord in range(1, ida_typeinf.get_ordinal_qty(py_ti)):
        #     name = ida_typeinf.get_numbered_type_name(py_ti, py_ord)

        #     ti = get_idati()
        #     ordinal = ctypes.c_uint32(py_ord)
        #     type = ctypes.c_char_p()
        #     fields = ctypes.c_char_p()
        #     cmt = ctypes.c_char_p()
        #     fieldcmts = ctypes.c_char_p()
        #     sclass = ctypes.c_int()
        #     get_numbered_type(
        #         ti,
        #         ordinal,
        #         ctypes.pointer(type),
        #         ctypes.pointer(fields),
        #         ctypes.pointer(cmt),
        #         ctypes.pointer(fieldcmts),
        #         ctypes.pointer(sclass),
        #     )
        #     local_types.append(
        #         (
        #             py_ord,
        #             name,
        #             type.value,
        #             fields.value,
        #             cmt.value,
        #             fieldcmts.value,
        #             sclass.value,
        #         )
        #     )
        # self._send_packet(evt.LocalTypesChangedEvent(local_types))
        # return 0

    def ti_changed(self, ea, type, fname):
        self._plugin.logger.debug("ti_changed(ea = 0x%X, type = %s, fname = %s)" % (ea, type, fname))
        name = ""
        if idc.is_member_id(ea):
            name = idc.get_struc_name(ea)
        type = ida_typeinf.idc_get_type_raw(ea)
        self._send_packet(evt.TiChangedEvent(ea, (ParseTypeString(type[0]) if type else [], type[1] if type else None), name))
        return 0

    def op_ti_changed(self, ea, n, type, fnames):
        self._plugin.logger.debug("op_ti_changed() not implemented yet")
        return 0

    def op_type_changed(self, ea, n):
        self._plugin.logger.debug("op_type_changed(ea = %x, n = %d)" % (ea,n))
        def gather_enum_info(ea, n):
            id = ida_bytes.get_enum_id(ea, n)[0]
            serial = idc.get_enum_idx(id)
            return id, serial

        extra = {}
        mask = ida_bytes.MS_0TYPE if not n else ida_bytes.MS_1TYPE
        flags = ida_bytes.get_full_flags(ea)
        self._plugin.logger.debug("op_type_changed: flags = 0x%X)" % flags)
        def is_flag(type):
            return flags & mask == mask & type

        if is_flag(ida_bytes.hex_flag()):
            op = "hex"
        elif is_flag(ida_bytes.dec_flag()):
            op = "dec"
        elif is_flag(ida_bytes.char_flag()):
            op = "chr"
        elif is_flag(ida_bytes.bin_flag()):
            op = "bin"
        elif is_flag(ida_bytes.oct_flag()):
            op = "oct"
        elif is_flag(ida_bytes.off_flag()):
            op = "offset"
        elif is_flag(ida_bytes.enum_flag()):
            op = "enum"
            id, serial = gather_enum_info(ea, n)
            ename = idc.get_enum_name(id)
            extra["ename"] = Event.decode(ename)
            extra["serial"] = serial
        elif flags & ida_bytes.stroff_flag():
            op = "struct"
            path = ida_pro.tid_array(1)
            delta = ida_pro.sval_pointer()
            path_len = ida_bytes.get_stroff_path(
                path.cast(), delta.cast(), ea, n
            )
            spath = []
            for i in range(path_len):
                sname = idc.get_struc_name(path[i])
                spath.append(Event.decode(sname))
            extra["delta"] = delta.value()
            extra["spath"] = spath
        elif is_flag(ida_bytes.stkvar_flag()):
            op = "stkvar"
        # FIXME: No hooks are called when inverting sign
        # elif ida_bytes.is_invsign(ea, flags, n):
        #     op = 'invert_sign'
        else:
            return 0  # FIXME: Find a better way to do this
        self._send_packet(evt.OpTypeChangedEvent(ea, n, op, extra))
        return 0

    def enum_created(self, enum):
        name = idc.get_enum_name(enum)
        self._send_packet(evt.EnumCreatedEvent(enum, name))
        return 0

    # XXX - use enum_deleted(self, id) instead?
    def deleting_enum(self, id):
        self._send_packet(evt.EnumDeletedEvent(idc.get_enum_name(id)))
        return 0

    # XXX - use enum_renamed(self, id) instead?
    def renaming_enum(self, id, is_enum, newname):
        if is_enum:
            oldname = idc.get_enum_name(id)
        else:
            oldname = idc.get_enum_member_name(id)
        self._send_packet(evt.EnumRenamedEvent(oldname, newname, is_enum))
        return 0

    def enum_bf_changed(self, id):
        bf_flag = 1 if idc.is_bf(id) else 0
        ename = idc.get_enum_name(id)
        self._send_packet(evt.EnumBfChangedEvent(ename, bf_flag))
        return 0

    def enum_cmt_changed(self, tid, repeatable_cmt):
        cmt = idc.get_enum_cmt(tid, repeatable_cmt)
        emname = idc.get_enum_name(tid)
        self._send_packet(evt.EnumCmtChangedEvent(emname, cmt, repeatable_cmt))
        return 0

    def enum_member_created(self, id, cid):
        ename = idc.get_enum_name(id)
        name = idc.get_enum_member_name(cid)
        value = idc.get_enum_member_value(cid)
        bmask = idc.get_enum_member_bmask(cid)
        self._send_packet(
            evt.EnumMemberCreatedEvent(ename, name, value, bmask)
        )
        return 0

    # XXX - use enum_member_deleted(self, id, cid) instead?
    def deleting_enum_member(self, id, cid):
        ename = idc.get_enum_name(id)
        value = idc.get_enum_member_value(cid)
        serial = idc.get_enum_member_serial(cid)
        bmask = idc.get_enum_member_bmask(cid)
        self._send_packet(
            evt.EnumMemberDeletedEvent(ename, value, serial, bmask)
        )
        return 0

    def struc_created(self, tid):
        name = idc.get_struc_name(tid)
        is_union = idc.is_union(tid)
        self._send_packet(evt.StrucCreatedEvent(tid, name, is_union))
        return 0

    # XXX - use struc_deleted(self, struc_id) instead?
    def deleting_struc(self, sptr):
        sname = idc.get_struc_name(sptr.id)
        self._send_packet(evt.StrucDeletedEvent(sname))
        return 0

    def struc_align_changed(self, sptr):
        self._plugin.logger.debug("struc_align_changed() not implemented yet")
        return 0

    # XXX - use struc_renamed(self, sptr) instead?
    def renaming_struc(self, id, oldname, newname):
        self._send_packet(evt.StrucRenamedEvent(oldname, newname))
        return 0

    # XXX - use struc_expanded(self, sptr) instead 
    def expanding_struc(self, sptr, offset, delta):
        sname = idc.get_struc_name(sptr.id)
        self._send_packet(evt.ExpandingStrucEvent(sname, offset, delta))
        return 0

    def struc_member_created(self, sptr, mptr):
        extra = {}
        sname = idc.get_struc_name(sptr.id)
        fieldname = idc.get_member_name(mptr.id)
        offset = 0 if mptr.unimem() else mptr.soff
        flag = mptr.flag
        nbytes = mptr.eoff if mptr.unimem() else mptr.eoff - mptr.soff
        mt = ida_nalt.opinfo_t()
        is_not_data = idc.retrieve_member_info(mt, mptr)
        if is_not_data:
            if flag & ida_bytes.off_flag():
                extra["target"] = mt.ri.target
                extra["base"] = mt.ri.base
                extra["tdelta"] = mt.ri.tdelta
                extra["flags"] = mt.ri.flags
                self._send_packet(
                    evt.StrucMemberCreatedEvent(
                        sname, fieldname, offset, flag, nbytes, extra
                    )
                )
            elif flag & ida_bytes.enum_flag():
                extra["serial"] = mt.ec.serial
                extra["tid"] = mt.ec.tid
                self._send_packet(
                    evt.StrucMemberCreatedEvent(
                        sname, fieldname, offset, flag, nbytes, extra
                    )
                )
            elif flag & ida_bytes.stru_flag():
                extra["struc_name"] = idc.get_struc_name(mt.tid)
                if flag & ida_bytes.strlit_flag():
                    extra["strtype"] = mt.strtype
                self._send_packet(
                    evt.StrucMemberCreatedEvent(
                        sname, fieldname, offset, flag, nbytes, extra
                    )
                )
        else:
            self._send_packet(
                evt.StrucMemberCreatedEvent(
                    sname, fieldname, offset, flag, nbytes, extra
                )
            )
        return 0

    def struc_member_deleted(self, sptr, off1, off2):
        sname = idc.get_struc_name(sptr.id)
        self._send_packet(evt.StrucMemberDeletedEvent(sname, off2))
        return 0

    # XXX - use struc_member_renamed(self, sptr, mptr) instead?
    def renaming_struc_member(self, sptr, mptr, newname):
        sname = idc.get_struc_name(sptr.id)
        offset = mptr.soff
        self._send_packet(evt.StrucMemberRenamedEvent(sname, offset, newname))
        return 0

    def struc_member_changed(self, sptr, mptr):
        extra = {}

        sname = idc.get_struc_name(sptr.id)
        flag = mptr.flag
        mt = ida_nalt.opinfo_t()
        is_not_data = idc.retrieve_member_info(mt, mptr)
        if is_not_data:
            if flag & ida_bytes.off_flag():
                extra["target"] = mt.ri.target
                extra["base"] = mt.ri.base
                extra["tdelta"] = mt.ri.tdelta
                extra["flags"] = mt.ri.flags
                self._send_packet(
                    evt.StrucMemberChangedEvent(
                        sname, mptr.soff, mptr.eoff, flag, extra
                    )
                )
            elif flag & ida_bytes.enum_flag():
                extra["serial"] = mt.ec.serial
                extra["tid"] = mt.ec.tid
                self._send_packet(
                    evt.StrucMemberChangedEvent(
                        sname, mptr.soff, mptr.eoff, flag, extra
                    )
                )
            elif flag & ida_bytes.stru_flag():
                extra["struc_name"] = idc.get_struc_name(mt.tid)
                if flag & ida_bytes.strlit_flag():
                    extra["strtype"] = mt.strtype
                self._send_packet(
                    evt.StrucMemberChangedEvent(
                        sname, mptr.soff, mptr.eoff, flag, extra
                    )
                )
        else:
            self._send_packet(
                evt.StrucMemberChangedEvent(
                    sname, mptr.soff, mptr.eoff, flag, extra
                )
            )
        return 0

    def struc_cmt_changed(self, id, repeatable_cmt):
        fullname = idc.get_struc_name(id)
        if "." in fullname:
            sname, smname = fullname.split(".", 1)
        else:
            sname = fullname
            smname = ""
        cmt = idc.get_struc_cmt(id, repeatable_cmt)
        self._send_packet(
            evt.StrucCmtChangedEvent(sname, smname, cmt, repeatable_cmt)
        )
        return 0

    def segm_added(self, s):
        self._send_packet(
            evt.SegmAddedEvent(
                ida_segment.get_segm_name(s),
                ida_segment.get_segm_class(s),
                s.start_ea,
                s.end_ea,
                s.orgbase,
                s.align,
                s.comb,
                s.perm,
                s.bitness,
                s.flags,
            )
        )
        return 0

    # The flags argument was added in IDA 7.7
    def segm_deleted(self, start_ea, end_ea, flags=0):
        self._send_packet(evt.SegmDeletedEvent(start_ea, flags))
        return 0

    def segm_start_changed(self, s, oldstart):
        self._send_packet(evt.SegmStartChangedEvent(s.start_ea, oldstart))
        return 0

    def segm_end_changed(self, s, oldend):
        self._send_packet(evt.SegmEndChangedEvent(s.end_ea, s.start_ea))
        return 0

    def segm_name_changed(self, s, name):
        self._send_packet(evt.SegmNameChangedEvent(s.start_ea, name))
        return 0

    def segm_class_changed(self, s, sclass):
        self._send_packet(evt.SegmClassChangedEvent(s.start_ea, sclass))
        return 0

    def segm_attrs_updated(self, s):
        self._send_packet(
            evt.SegmAttrsUpdatedEvent(s.start_ea, s.perm, s.bitness)
        )
        return 0

    def segm_moved(self, from_ea, to_ea, size, changed_netmap):
        self._send_packet(evt.SegmMoved(from_ea, to_ea, changed_netmap))
        return 0

    def allsegs_moved(self, info):
        self._plugin.logger.debug("allsegs_moved() not implemented yet")
        return 0

    def func_added(self, func):
        self._send_packet(evt.FuncAddedEvent(func.start_ea, func.end_ea))
        return 0

    def set_func_start(self, func, new_start):
        self._send_packet(evt.SetFuncStartEvent(func.start_ea, new_start))
        return 0

    def set_func_end(self, func, new_end):
        self._send_packet(evt.SetFuncEndEvent(func.start_ea, new_end))
        return 0

    def deleting_func(self, func):
        self._send_packet(evt.DeletingFuncEvent(func.start_ea))
        return 0

    def func_tail_appended(self, func, tail):
        self._send_packet(
            evt.FuncTailAppendedEvent(
                func.start_ea, tail.start_ea, tail.end_ea
            )
        )
        return 0

    def func_tail_deleted(self, func, tail_ea):
        self._send_packet(evt.FuncTailDeletedEvent(func.start_ea, tail_ea))
        return 0

    def tail_owner_changed(self, tail, owner_func, old_owner):
        self._send_packet(evt.TailOwnerChangedEvent(tail.start_ea, owner_func))
        return 0

    def func_noret_changed(self, pfn):
        self._plugin.logger.debug("func_noret_changed() not implemented yet")
        return 0

    def sgr_changed(self, start_ea, end_ea, regnum, value, old_value, tag):
        # FIXME: sgr_changed is not triggered when a segment register is
        # being deleted by the user, so we need to sent the complete list
        sreg_ranges = evt.SgrChanged.get_sreg_ranges(regnum)
        self._send_packet(evt.SgrChanged(regnum, sreg_ranges))
        return 0

    # def make_code(self, insn):
    #     self._send_packet(evt.MakeCodeEvent(insn.ea))
    #     return 0

    def make_data(self, ea, flags, tid, size):
        self._plugin.logger.debug("make_data(ea = %x, flags = %x, tid = %x, size = %x)" % (ea, flags, tid, size))
        # Note: MakeDataEvent.sname == '' is convention for BADNODE
        self._send_packet(evt.MakeDataEvent(ea, flags, size, idc.get_struc_name(tid) if tid != ida_netnode.BADNODE else ''))
        return 0

    def renamed(self, ea, new_name, local_name):
        self._plugin.logger.debug("renamed(ea = %x, new_name = %s, local_name = %d)" % (ea, new_name, local_name))
        # `idc.get_struc` was removed in newer IDA Python APIs; avoid calling it.
        # We only need to detect member-id or enum rename events here.
        if idc.is_member_id(ea) or idc.get_enum_name(ea):
            # Drop hook to avoid duplicate since already handled by the following hooks:
            # - renaming_struc_member() -> sends 'StrucMemberRenamedEvent'
            # - renaming_struc() -> sends 'StrucRenamedEvent' 
            # - renaming_enum() -> sends 'EnumRenamedEvent' 
            return 0 
        self._send_packet(evt.RenamedEvent(ea, new_name, local_name))
        return 0

    def byte_patched(self, ea, old_value):
        self._send_packet(
            evt.BytePatchedEvent(ea, ida_bytes.get_wide_byte(ea))
        )
        return 0

    def cmt_changed(self, ea, repeatable_cmt):
        cmt = ida_bytes.get_cmt(ea, repeatable_cmt)
        cmt = "" if not cmt else cmt
        self._send_packet(evt.CmtChangedEvent(ea, cmt, repeatable_cmt))
        return 0

    def range_cmt_changed(self, kind, a, cmt, repeatable):
        self._send_packet(evt.RangeCmtChangedEvent(kind, a, cmt, repeatable))
        return 0

    def extra_cmt_changed(self, ea, line_idx, cmt):
        self._send_packet(evt.ExtraCmtChangedEvent(ea, line_idx, cmt))
        return 0

    def item_color_changed(self, ea, color):
        # See #31 on fidgetingbits/IDArling
        #self._plugin.logger.debug("item_color_changed() not implemented yet")
        return 0

    def callee_addr_changed(self, ea, callee):
        self._plugin.logger.debug("callee_addr_changed() not implemented yet")
        return 0

    # def destroyed_items(self, ea1, ea2, will_disable_range):
    #     self._plugin.logger.debug("destroyed_items(ea1 = %x, ea2 = %x, will_disable_range = %d) not implemented yet" % (ea1, ea2, will_disable_range))
    #     return 0

    # def changing_op_type(self, ea, n, opinfo):
    #     self._plugin.logger.debug("changing_op_type(ea = %x, n = %d, opinfo = %s) not implemented yet" % (ea, n, opinfo))
    #     return 0

    def bookmark_changed(self, index, pos, desc):
        rinfo = pos.renderer_info()
        plce = pos.place()
        ea = plce.touval(pos)
        self._send_packet(evt.BookmarkChangedEvent(ea, index, desc))
        return 0

    def sgr_deleted(self, start_ea, end_ea, regnum):
        self._plugin.logger.debug("sgr_deleted() not implemented yet")
        return 0


class IDPHooks(Hooks, ida_idp.IDP_Hooks):
    def __init__(self, plugin):
        ida_idp.IDP_Hooks.__init__(self)
        Hooks.__init__(self, plugin)

    # def ev_undefine(self, ea):
    #     self._send_packet(evt.UndefinedEvent(ea))
    #     return ida_idp.IDP_Hooks.ev_undefine(self, ea)

    def ev_adjust_argloc(self, *args):
        return ida_idp.IDP_Hooks.ev_adjust_argloc(self, *args)

    # def ev_emu_insn(self,insn):
    #     self._plugin.logger.debug("ev_emu_insn(insn.ea = %X) not implemented yet"%insn.ea)
    #     return ida_idp.IDP_Hooks.ev_emu_insn(self, insn)
    #
    # def ev_auto_queue_empty(self,type):
    #     disp = ida_auto.auto_display_t()
    #     ida_auto.get_auto_display(disp)
    #     self._plugin.logger.debug("ev_auto_queue_empty(type = %d. disp.ea = %X, disp.type = %d, disp.state = %d"%(type,disp.ea,disp.type,disp.state))
    #     return ida_idp.IDP_Hooks.ev_auto_queue_empty(self, type)
    #
    # def ev_gen_regvar_def(self, outctx, v):
    #    self._send_packet(
    #        evt.GenRegvarDefEvent(outctx.bin_ea, v.canon, v.user, v.cmt)
    #    )
    #    return ida_idp.IDP_Hooks.ev_gen_regvar_def(self, outctx, v)


class HexRaysHooks(Hooks):
    def __init__(self, plugin):
        super(HexRaysHooks, self).__init__(plugin)
        self._available = None
        self._installed = False
        # We cache all HexRays data the first time we encounter a new function
        # and only send events to IDArling server if we didn't encounter the
        # specific data for a given function. This is just an optimization to 
        # reduce the amount of messages sent and replicated to other users
        self._cached_funcs = {}

    def hook(self):
        if self._available is None:
            if not ida_hexrays.init_hexrays_plugin():
                self._plugin.logger.info("Hex-Rays SDK is not available")
                self._available = False
            else:
                ida_hexrays.install_hexrays_callback(self._hxe_callback)
                self._available = True

        if self._available:
            self._installed = True

    def unhook(self):
        if self._available:
            self._installed = False

    def _hxe_callback(self, event, *_):
        if not self._installed:
            return 0

        if event == ida_hexrays.hxe_func_printed:
            ea = ida_kernwin.get_screen_ea()
            func = ida_funcs.get_func(ea)
            if func is None:
                return 0
            
            if func.start_ea not in self._cached_funcs.keys():
                self._cached_funcs[func.start_ea] = {}
                self._cached_funcs[func.start_ea]["labels"] = []
                self._cached_funcs[func.start_ea]["cmts"] = []
                self._cached_funcs[func.start_ea]["iflags"] = []
                self._cached_funcs[func.start_ea]["lvar_settings"] = []
                self._cached_funcs[func.start_ea]["numforms"] = []
            self._send_user_labels(func.start_ea)
            self._send_user_cmts(func.start_ea)
            self._send_user_iflags(func.start_ea)
            self._send_user_lvar_settings(func.start_ea)
            self._send_user_numforms(func.start_ea)
        return 0

    @staticmethod
    def _get_user_labels(ea):
        user_labels = ida_hexrays.restore_user_labels(ea)
        if user_labels is None:
            user_labels = ida_hexrays.user_labels_new()
        labels = []
        it = ida_hexrays.user_labels_begin(user_labels)
        while it != ida_hexrays.user_labels_end(user_labels):
            org_label = ida_hexrays.user_labels_first(it)
            name = ida_hexrays.user_labels_second(it)
            labels.append((org_label, Event.decode(name)))
            it = ida_hexrays.user_labels_next(it)
        ida_hexrays.user_labels_free(user_labels)
        return labels

    def _send_user_labels(self, ea):
        labels = HexRaysHooks._get_user_labels(ea)
        if labels != self._cached_funcs[ea]["labels"]:
            self._send_packet(evt.UserLabelsEvent(ea, labels))
            self._cached_funcs[ea]["labels"] = labels

    @staticmethod
    def _get_user_cmts(ea):
        user_cmts = ida_hexrays.restore_user_cmts(ea)
        if user_cmts is None:
            user_cmts = ida_hexrays.user_cmts_new()
        cmts = []
        it = ida_hexrays.user_cmts_begin(user_cmts)
        while it != ida_hexrays.user_cmts_end(user_cmts):
            tl = ida_hexrays.user_cmts_first(it)
            cmt = ida_hexrays.user_cmts_second(it)
            cmts.append(((tl.ea, tl.itp), Event.decode(str(cmt))))
            it = ida_hexrays.user_cmts_next(it)
        ida_hexrays.user_cmts_free(user_cmts)
        return cmts

    def _send_user_cmts(self, ea):
        cmts = HexRaysHooks._get_user_cmts(ea)
        if cmts != self._cached_funcs[ea]["cmts"]:
            self._send_packet(evt.UserCmtsEvent(ea, cmts))
            self._cached_funcs[ea]["cmts"] = cmts

    @staticmethod
    def _get_user_iflags(ea):
        user_iflags = ida_hexrays.restore_user_iflags(ea)
        if user_iflags is None:
            user_iflags = ida_hexrays.user_iflags_new()
        iflags = []
        it = ida_hexrays.user_iflags_begin(user_iflags)
        while it != ida_hexrays.user_iflags_end(user_iflags):
            cl = ida_hexrays.user_iflags_first(it)
            f = ida_hexrays.user_iflags_second(it)

            # FIXME: Temporary while Hex-Rays update their API
            def read_type_sign(obj):
                import ctypes
                import struct

                buf = ctypes.string_at(id(obj), 4)
                return struct.unpack("I", buf)[0]

            f = read_type_sign(f)
            iflags.append(((cl.ea, cl.op), f))
            it = ida_hexrays.user_iflags_next(it)
        ida_hexrays.user_iflags_free(user_iflags)
        return iflags

    def _send_user_iflags(self, ea):
        iflags = HexRaysHooks._get_user_iflags(ea)
        if iflags != self._cached_funcs[ea]["iflags"]:
            self._send_packet(evt.UserIflagsEvent(ea, iflags))
            self._cached_funcs[ea]["iflags"] = iflags

    @staticmethod
    def _get_user_lvar_settings(ea):
        dct = {}
        lvinf = ida_hexrays.lvar_uservec_t()
        ret = ida_hexrays.restore_user_lvar_settings(lvinf, ea)
        # print("_get_user_lvar_settings: ret = %x" % ret)
        if ret:
            dct["lvvec"] = []
            for lv in lvinf.lvvec:
                dct["lvvec"].append(HexRaysHooks._get_lvar_saved_info(lv))
            if hasattr(lvinf, "sizes"):
                dct["sizes"] = list(lvinf.sizes)
            dct["lmaps"] = []
            it = ida_hexrays.lvar_mapping_begin(lvinf.lmaps)
            while it != ida_hexrays.lvar_mapping_end(lvinf.lmaps):
                key = ida_hexrays.lvar_mapping_first(it)
                key = HexRaysHooks._get_lvar_locator(key)
                val = ida_hexrays.lvar_mapping_second(it)
                val = HexRaysHooks._get_lvar_locator(val)
                dct["lmaps"].append((key, val))
                it = ida_hexrays.lvar_mapping_next(it)
            dct["stkoff_delta"] = lvinf.stkoff_delta
            dct["ulv_flags"] = lvinf.ulv_flags
        return dct

    @staticmethod
    def _get_lvar_saved_info(lv):
        return {
            "ll": HexRaysHooks._get_lvar_locator(lv.ll),
            "name": Event.decode(lv.name),
            "type": HexRaysHooks._get_tinfo(lv.type),
            "cmt": Event.decode(lv.cmt),
            "flags": lv.flags,
        }

    @staticmethod
    def _get_tinfo(type):
        if type.empty():
            return None, None, None, None

        type, fields, fldcmts = type.serialize()
        fields = Event.decode_bytes(fields)
        fldcmts = Event.decode_bytes(fldcmts)
        parsed_list = Event.decode_bytes(pickle.dumps(ParseTypeString(type)))
        type = Event.decode_bytes(type)
        return type, fields, fldcmts, parsed_list

    @staticmethod
    def _get_lvar_locator(ll):
        return {
            "location": HexRaysHooks._get_vdloc(ll.location),
            "defea": ll.defea,
        }

    @staticmethod
    def _get_vdloc(location):
        return {
            "atype": location.atype(),
            "reg1": location.reg1(),
            "reg2": location.reg2(),
            "stkoff": location.stkoff(),
            "ea": location.get_ea(),
        }

    def _send_user_lvar_settings(self, ea):
        lvar_settings = HexRaysHooks._get_user_lvar_settings(ea)
        if lvar_settings != self._cached_funcs[ea]["lvar_settings"]:
            self._send_packet(evt.UserLvarSettingsEvent(ea, lvar_settings))
            self._cached_funcs[ea]["lvar_settings"] = lvar_settings

    @staticmethod
    def _get_user_numforms(ea):
        user_numforms = ida_hexrays.restore_user_numforms(ea)
        if user_numforms is None:
            user_numforms = ida_hexrays.user_numforms_new()
        numforms = []
        it = ida_hexrays.user_numforms_begin(user_numforms)
        while it != ida_hexrays.user_numforms_end(user_numforms):
            ol = ida_hexrays.user_numforms_first(it)
            nf = ida_hexrays.user_numforms_second(it)
            numforms.append(
                (
                    HexRaysHooks._get_operand_locator(ol),
                    HexRaysHooks._get_number_format(nf),
                )
            )
            it = ida_hexrays.user_numforms_next(it)
        ida_hexrays.user_numforms_free(user_numforms)
        return numforms

    @staticmethod
    def _get_operand_locator(ol):
        return {"ea": ol.ea, "opnum": ol.opnum}

    @staticmethod
    def _get_number_format(nf):
        return {
            "flags": nf.flags,
            "opnum": nf.opnum,
            "props": nf.props,
            "serial": nf.serial,
            "org_nbytes": nf.org_nbytes,
            "type_name": nf.type_name,
        }

    def _send_user_numforms(self, ea):
        numforms = HexRaysHooks._get_user_numforms(ea)
        if numforms != self._cached_funcs[ea]["numforms"]:
            self._send_packet(evt.UserNumformsEvent(ea, numforms))
            self._cached_funcs[ea]["numforms"] = numforms


class UIHooks(Hooks, ida_kernwin.UI_Hooks):
    def __init__(self,plugin):
        ida_kernwin.UI_Hooks.__init__(self)
        Hooks.__init__(self, plugin)
        self.actions = []

    def preprocess_action(self, name):
        ea = ida_kernwin.get_screen_ea()
        self._plugin.logger.debug("preprocess_action(name = %s). ea = 0x%X." % (name, ea))
        if name == "MakeUnknown":
            self.actions.append((name, ea))
        elif name == "MakeCode":
            self.actions.append((name, ea))
        return 0

    def postprocess_action(self):
        self._plugin.logger.debug("postprocess_action()")
        if len(self.actions):
            name, ea = self.actions.pop()
            if name == "MakeUnknown":
                flags = ida_bytes.get_full_flags(ea)
                if ida_bytes.is_unknown(flags):
                    self._send_packet(evt.MakeUnknown(ea))
            elif name == "MakeCode":
                flags = ida_bytes.get_full_flags(ea)
                if ida_bytes.is_code(flags):
                    self._send_packet(evt.MakeCodeEvent(ea))
