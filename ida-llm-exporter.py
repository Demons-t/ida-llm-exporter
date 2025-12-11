# ida-llm-exporter.py
# Offline export script for IDA 9.2
#
# Exports:
#   ida_export/
#     meta.json
#     segments.json
#     imports.json
#     exports.json
#     functions.jsonl
#     index.json
#     strings.jsonl
#     data.jsonl
#     data_index.json
#     types.json        (optional, only if you have user-defined local types and choose to export)
#     decomp/*.c        (if Hex-Rays is available)
#     asm/*.asm         (optional, if you choose to export assembly)
#     asm_index.json    (if assembly export is enabled)
#     sample.bin
#   ida_export.zip
#
# Notes:
# - Assembly export is useful when Hex-Rays decompilation is poor (packers, heavy obfuscation)
#   and you want flat disassembly for specific functions or address ranges.
# - types.json is only useful if you have created your own structs/enums/typedefs in IDA Local Types.
#   If you did not add any custom types, there is no reason to export types.json.

import os
import re
import io
import json
import time
import hashlib
import binascii
import zipfile
from datetime import datetime

import ida_ida
import ida_nalt
import ida_kernwin
import ida_bytes
import ida_funcs
import ida_name
import ida_xref
import ida_segment
import ida_ua
import ida_gdl
import ida_lines
import ida_loader
import ida_typeinf
import idautils
import idc

# Try to load Hex-Rays (if not installed, we just skip decompilation)
try:
    import ida_hexrays
    HAS_HEXRAYS = bool(ida_hexrays.init_hexrays_plugin())
except Exception:
    HAS_HEXRAYS = False


# =================== Generic helpers ===================

def ensure_dir(path: str):
    if not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)


def hex_ea(ea: int) -> str:
    return "0x%08X" % ea


def sanitize_name(name: str) -> str:
    """Return a filesystem-safe name (letters, digits and underscores only)."""
    return re.sub(r"[^\w]", "_", name)


def compute_file_hashes(path: str):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    crc = 0

    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            crc = binascii.crc32(chunk, crc)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "crc32": "0x%08X" % (crc & 0xFFFFFFFF),
    }


def copy_sample_bin(src_path: str, dst_path: str):
    with open(src_path, "rb") as src, open(dst_path, "wb") as dst:
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            dst.write(chunk)


def get_inf_info():
    if ida_ida.inf_is_64bit():
        bits = 64
    elif ida_ida.inf_is_32bit_exactly():
        bits = 32
    else:
        bits = 16

    procname = ida_ida.inf_get_procname()
    is_be = ida_ida.inf_is_be()

    return bits, procname, is_be


# =================== meta.json ===================

def export_meta(export_dir: str) -> dict:
    input_path = ida_nalt.get_input_file_path()
    file_name = os.path.basename(input_path)

    bits, procname, is_be = get_inf_info()
    arch = "%s-%d" % (procname, bits)
    imagebase = ida_nalt.get_imagebase()

    hashes = {}
    try:
        hashes = compute_file_hashes(input_path)
    except Exception as e:
        ida_kernwin.msg("Failed to compute file hashes: %s\n" % e)

    meta = {
        "file_name": file_name,
        "input_path": input_path,
        "imagebase": hex_ea(imagebase),
        "architecture": arch,
        "is_be": bool(is_be),
        "ida_version": ida_kernwin.get_kernel_version(),
        "timestamp_utc": datetime.utcnow().isoformat() + "Z",
    }
    meta.update(hashes)

    out_path = os.path.join(export_dir, "meta.json")
    with io.open(out_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    ida_kernwin.msg("Wrote meta.json\n")
    return meta


# =================== Functions export ===================

def get_xrefs_in(func_start_ea: int):
    """
    Return list of function start EAs that call this function (hex strings).
    """
    callers = set()
    for xref in idautils.XrefsTo(func_start_ea, ida_xref.XREF_FAR):
        f = ida_funcs.get_func(xref.frm)
        if f:
            callers.add(f.start_ea)
    return [hex_ea(ea) for ea in sorted(callers)]


def get_xrefs_out(func: ida_funcs.func_t):
    """
    Return callees of this function:
    [ { "ea": "0x...", "name": "..." }, ... ]
    """
    callees = {}
    for ea in idautils.FuncItems(func.start_ea):
        if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            continue
        for xref in idautils.XrefsFrom(ea, ida_xref.XREF_FAR):
            dst = xref.to
            if ida_bytes.is_code(ida_bytes.get_full_flags(dst)):
                name = ida_name.get_ea_name(dst) or ""
                if dst not in callees:
                    callees[dst] = name
    out = []
    for dst in sorted(callees.keys()):
        out.append({
            "ea": hex_ea(dst),
            "name": callees[dst],
        })
    return out


def get_comments_for_function(func: ida_funcs.func_t):
    """
    Collect function-level and instruction-level comments.
    """
    comments = []

    cmt = ida_funcs.get_func_cmt(func, False)
    if cmt:
        comments.append({
            "ea": hex_ea(func.start_ea),
            "kind": "func",
            "text": cmt,
        })
    cmt_rep = ida_funcs.get_func_cmt(func, True)
    if cmt_rep:
        comments.append({
            "ea": hex_ea(func.start_ea),
            "kind": "func_rep",
            "text": cmt_rep,
        })

    for ea in idautils.FuncItems(func.start_ea):
        anterior = ida_bytes.get_cmt(ea, False)
        if anterior:
            comments.append({
                "ea": hex_ea(ea),
                "kind": "anterior",
                "text": anterior,
            })
        repeatable = ida_bytes.get_cmt(ea, True)
        if repeatable:
            comments.append({
                "ea": hex_ea(ea),
                "kind": "repeatable",
                "text": repeatable,
            })

    return comments


def get_basic_blocks(func: ida_funcs.func_t):
    blocks = []
    try:
        fc = ida_gdl.FlowChart(func)
    except Exception:
        return blocks

    for block in fc:
        succs = [hex_ea(b.start_ea) for b in block.succs()]
        blocks.append({
            "start": hex_ea(block.start_ea),
            "end": hex_ea(block.end_ea),
            "succ": succs,
        })
    return blocks


def get_instructions(func: ida_funcs.func_t):
    """
    Export all instructions in the function:
      - ea
      - bytes (hex string)
      - mnem
      - opstr
      - size
      - cmt

    Also build a 'bytes_concat' string by concatenating all instruction bytes.
    """
    items = []
    bytes_concat_parts = []

    for ea in idautils.FuncItems(func.start_ea):
        if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            continue

        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)
        if size <= 0:
            continue

        mnem = ida_ua.print_insn_mnem(ea)
        disasm = idc.generate_disasm_line(ea, 0) or ""
        disasm = ida_lines.tag_remove(disasm)
        parts = disasm.split(None, 1)
        opstr = parts[1] if len(parts) == 2 else ""

        raw = ida_bytes.get_bytes(ea, size) or b""
        bytes_hex = binascii.hexlify(raw).decode("ascii")

        cmt = ida_bytes.get_cmt(ea, False) or ida_bytes.get_cmt(ea, True)

        items.append({
            "ea": hex_ea(ea),
            "bytes": bytes_hex,
            "mnem": mnem,
            "opstr": opstr,
            "size": size,
            "cmt": cmt if cmt else None,
        })
        bytes_concat_parts.append(bytes_hex)

    bytes_concat = "".join(bytes_concat_parts)
    return items, bytes_concat


def write_decomp_for_function(func: ida_funcs.func_t, decomp_dir: str):
    if not HAS_HEXRAYS:
        return None

    ea = func.start_ea
    name = ida_name.get_ea_name(ea) or "sub_%08X" % ea
    safe = sanitize_name(name)
    fname = "%s_%08X.c" % (safe, ea)
    rel_path = os.path.join("decomp", fname).replace("\\", "/")
    full_path = os.path.join(decomp_dir, fname)

    try:
        cfunc = ida_hexrays.decompile(ea)
        text = str(cfunc)
    except Exception as e:
        ida_kernwin.msg("Failed to decompile function %s: %s\n" % (name, e))
        return None

    with io.open(full_path, "w", encoding="utf-8") as f:
        f.write(text)

    return rel_path


def export_functions_and_index(export_dir: str):
    """
    Export:
      - functions.jsonl (one JSON record per function)
      - index.json      (mapping by_name / by_ea to functions.jsonl line index)
    """
    functions_path = os.path.join(export_dir, "functions.jsonl")
    index_path = os.path.join(export_dir, "index.json")
    decomp_dir = os.path.join(export_dir, "decomp")
    ensure_dir(decomp_dir)

    index_by_name = {}
    index_by_ea = {}

    func_eas = list(idautils.Functions())
    func_eas.sort()

    line_index = 0

    with io.open(functions_path, "w", encoding="utf-8") as f_out:
        for ea in func_eas:
            func = ida_funcs.get_func(ea)
            if not func:
                continue

            name = ida_name.get_ea_name(ea) or "sub_%08X" % ea
            proto = idc.get_type(ea) or ""

            start = func.start_ea
            end = func.end_ea
            ranges = [[hex_ea(start), hex_ea(end)]]

            xrefs_in = get_xrefs_in(ea)
            xrefs_out = get_xrefs_out(func)
            comments = get_comments_for_function(func)
            bbs = get_basic_blocks(func)
            insn, bytes_concat = get_instructions(func)
            decomp_path = write_decomp_for_function(func, decomp_dir)

            rec = {
                "ea": hex_ea(ea),
                "name": name,
                "prototype": proto,
                "ranges": ranges,
                "xrefs_in": xrefs_in,
                "xrefs_out": xrefs_out,
                "comments": comments,
                "bb": bbs,
                "insn": insn,
                "bytes_concat": bytes_concat,
            }
            if decomp_path:
                rec["decomp_path"] = decomp_path

            line = json.dumps(rec, ensure_ascii=False)
            f_out.write(line + "\n")

            sea = hex_ea(ea)
            index_by_name[name] = sea
            index_by_ea[sea] = line_index
            line_index += 1

    index_obj = {
        "by_name": index_by_name,
        "by_ea": index_by_ea,
    }
    with io.open(index_path, "w", encoding="utf-8") as f_idx:
        json.dump(index_obj, f_idx, indent=2, ensure_ascii=False)

    ida_kernwin.msg("Wrote functions.jsonl and index.json, total %d functions\n" % line_index)


# =================== strings.jsonl ===================

def export_strings(export_dir: str):
    """
    Export strings.jsonl:
    one record per string:
    {
      "ea": "0x...",
      "string": "...",
      "length": N,
      "strtype": int,
      "refs": [
        { "ea":"0x...", "func":"0x..."|null, "type": int },
        ...
      ]
    }
    """
    strings_path = os.path.join(export_dir, "strings.jsonl")

    s = idautils.Strings()
    s.setup(
        strtypes=[
            ida_nalt.STRTYPE_C,
            ida_nalt.STRTYPE_C_16,
            ida_nalt.STRTYPE_C_32,
        ]
    )

    count = 0
    with io.open(strings_path, "w", encoding="utf-8") as f_out:
        for st in s:
            ea = st.ea
            text = str(st)
            length = st.length
            strtype = st.strtype

            refs = []
            for xref in idautils.XrefsTo(ea):
                ref_ea = xref.frm
                func = ida_funcs.get_func(ref_ea)
                func_ea = hex_ea(func.start_ea) if func else None
                refs.append({
                    "ea": hex_ea(ref_ea),
                    "func": func_ea,
                    "type": xref.type,
                })

            rec = {
                "ea": hex_ea(ea),
                "string": text,
                "length": length,
                "strtype": strtype,
                "refs": refs,
            }
            line = json.dumps(rec, ensure_ascii=False)
            f_out.write(line + "\n")
            count += 1

    ida_kernwin.msg("Wrote strings.jsonl, total %d strings\n" % count)


# =================== data.jsonl + data_index.json ===================

def export_data(export_dir: str):
    """
    Export named global data items into:
      - data.jsonl (one record per named data item)
      - data_index.json (by_name index)
    """
    data_path = os.path.join(export_dir, "data.jsonl")
    data_index_path = os.path.join(export_dir, "data_index.json")

    by_name = {}
    count = 0

    with io.open(data_path, "w", encoding="utf-8") as f_out:
        for ea, name in idautils.Names():
            # Skip functions, only keep data symbols
            if ida_funcs.get_func(ea):
                continue

            flags = ida_bytes.get_full_flags(ea)
            if not ida_bytes.is_data(flags):
                continue

            seg = ida_segment.getseg(ea)
            if not seg:
                continue

            size = ida_bytes.get_item_size(ea)
            t = idc.get_type(ea) or ""

            refs = []
            for xref in idautils.XrefsTo(ea):
                ref_ea = xref.frm
                func = ida_funcs.get_func(ref_ea)
                func_ea = hex_ea(func.start_ea) if func else None
                refs.append({
                    "ea": hex_ea(ref_ea),
                    "func": func_ea,
                    "type": xref.type,
                })

            rec = {
                "ea": hex_ea(ea),
                "name": name,
                "size": size,
                "type": t,
                "segment": ida_segment.get_segm_name(seg) if seg else "",
                "refs": refs,
            }

            line = json.dumps(rec, ensure_ascii=False)
            f_out.write(line + "\n")
            count += 1

            by_name[name] = hex_ea(ea)

    with io.open(data_index_path, "w", encoding="utf-8") as f_idx:
        json.dump({"by_name": by_name}, f_idx, indent=2, ensure_ascii=False)

    ida_kernwin.msg("Wrote data.jsonl and data_index.json, total %d data items\n" % count)


# =================== imports.json ===================

def export_imports(export_dir: str):
    """
    Export import table information into imports.json:
    [
      {
        "module_index": 0,
        "module_name": "KERNEL32.dll",
        "imports": [
          { "ea": "0x...", "name": "CreateFileW", "ordinal": 123 },
          ...
        ]
      },
      ...
    ]
    """
    imports_path = os.path.join(export_dir, "imports.json")
    modules = []

    qty = ida_nalt.get_import_module_qty()
    for i in range(qty):
        mod_name = ida_nalt.get_import_module_name(i)
        if not mod_name:
            mod_name = "module_%d" % i

        module_rec = {
            "module_index": i,
            "module_name": mod_name,
            "imports": [],
        }

        def cb(ea, name, ord):
            module_rec["imports"].append({
                "ea": hex_ea(ea),
                "name": name,
                "ordinal": ord,
            })
            return True

        ida_nalt.enum_import_names(i, cb)
        modules.append(module_rec)

    with io.open(imports_path, "w", encoding="utf-8") as f:
        json.dump(modules, f, indent=2, ensure_ascii=False)

    ida_kernwin.msg("Wrote imports.json, total %d import modules\n" % len(modules))


# =================== exports.json ===================

def export_exports(export_dir: str):
    """
    Export export table information into exports.json:
    [
      {
        "index": 0,
        "ordinal": 1,
        "ea": "0x401000",
        "name": "DllMain"
      },
      ...
    ]
    """
    exports_path = os.path.join(export_dir, "exports.json")
    exports = []

    for index, ordinal, ea, name in idautils.Entries():
        exports.append({
            "index": index,
            "ordinal": ordinal,
            "ea": hex_ea(ea),
            "name": name,
        })

    with io.open(exports_path, "w", encoding="utf-8") as f:
        json.dump(exports, f, indent=2, ensure_ascii=False)

    ida_kernwin.msg("Wrote exports.json, total %d exports\n" % len(exports))


# =================== segments.json ===================

def export_segments(export_dir: str):
    """
    Export segment layout into segments.json:
    [
      {
        "name": ".text",
        "start": "0x00401000",
        "end": "0x0048A000",
        "size": 303104,
        "class": "CODE",
        "perm": { "r": true, "w": false, "x": true },
        "file_offset": 4096
      },
      ...
    ]
    """
    segments_path = os.path.join(export_dir, "segments.json")
    segments = []

    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg:
            continue

        name = ida_segment.get_segm_name(seg) or ""
        sclass = ida_segment.get_segm_class(seg) or ""
        start = seg.start_ea
        end = seg.end_ea
        size = end - start

        perm = seg.perm
        perms = {
            "r": bool(perm & ida_segment.SEGPERM_READ),
            "w": bool(perm & ida_segment.SEGPERM_WRITE),
            "x": bool(perm & ida_segment.SEGPERM_EXEC),
        }

        try:
            file_off = ida_loader.get_fileregion_offset(start)
        except Exception:
            file_off = -1

        if file_off < 0:
            file_off_val = None
        else:
            file_off_val = int(file_off)

        segments.append({
            "name": name,
            "start": hex_ea(start),
            "end": hex_ea(end),
            "size": size,
            "class": sclass,
            "perm": perms,
            "file_offset": file_off_val,
        })

    with io.open(segments_path, "w", encoding="utf-8") as f:
        json.dump(segments, f, indent=2, ensure_ascii=False)

    ida_kernwin.msg("Wrote segments.json, total %d segments\n" % len(segments))


# =================== Local types export (types.json) ===================

def count_local_user_types():
    """
    Count user-defined local types (structs/enums/typedefs) in the local type library (idati).
    We skip types coming from base TILs (system/SDK types).
    This is used to decide whether it is worth exporting types.json.
    """
    til = ida_typeinf.get_idati()
    if til is None:
        return 0

    limit = ida_typeinf.get_ordinal_limit(til)
    if limit <= 1:
        return 0

    count = 0
    for ordinal in range(1, limit):
        name = ida_typeinf.get_numbered_type_name(til, ordinal)
        if not name:
            continue

        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(til, ordinal):
            continue

        try:
            if tif.is_from_subtil():
                # Type comes from a base TIL (system/SDK), skip.
                continue
        except Exception:
            # If API is not available or fails, just treat it as local.
            pass

        count += 1

    return count


def export_types(export_dir: str):
    """
    Export user-defined local types into types.json.

    This is only useful if you (the analyst) have created your own structs/enums/typedefs
    in IDA's Local Types for this sample (for example: config structures, protocol headers,
    state enums). If you did not add any custom types, there is no point in exporting this file.

    Structure:
    {
      "structs": [
        {
          "name": "MY_CFG",
          "ordinal": 5,
          "is_union": false,
          "size": 32,
          "members": [
            { "name": "field1", "offset": 0, "type": "int" },
            ...
          ]
        }
      ],
      "enums": [
        {
          "name": "MY_ENUM",
          "ordinal": 7,
          "members": [
            { "name": "VAL1", "value": 1, "cmt": null },
            ...
          ]
        }
      ],
      "typedefs": [
        {
          "name": "MY_TYPEDEF",
          "ordinal": 9,
          "type": "void *"
        }
      ]
    }
    """
    types_path = os.path.join(export_dir, "types.json")

    til = ida_typeinf.get_idati()
    if til is None:
        ida_kernwin.msg("Failed to get local type library, skipping types.json\n")
        return

    limit = ida_typeinf.get_ordinal_limit(til)
    if limit <= 1:
        ida_kernwin.msg("No numbered types in local type library, skipping types.json\n")
        return

    structs = []
    enums = []
    typedefs = []

    for ordinal in range(1, limit):
        name = ida_typeinf.get_numbered_type_name(til, ordinal)
        if not name:
            continue

        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(til, ordinal):
            continue

        try:
            if tif.is_from_subtil():
                # Skip types that come from base TILs (system/SDK).
                continue
        except Exception:
            pass

        # Structs / unions
        if tif.is_struct() or tif.is_union():
            udt = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt):
                continue

            is_union = tif.is_union()
            members = []
            for udm in udt:
                try:
                    type_str = udm.type.dstr()
                except Exception:
                    type_str = ""
                members.append({
                    "name": udm.name,
                    "offset": int(udm.offset),
                    "type": type_str,
                })

            size = None
            try:
                if hasattr(udt, "total_size"):
                    size = int(udt.total_size)
            except Exception:
                size = None

            structs.append({
                "name": name,
                "ordinal": ordinal,
                "is_union": bool(is_union),
                "size": size,
                "members": members,
            })

        # Enums
        elif tif.is_enum():
            etd = ida_typeinf.enum_type_data_t()
            if not tif.get_enum_details(etd):
                continue

            members = []
            for edm in etd:
                members.append({
                    "name": edm.name,
                    "value": int(edm.value),
                    "cmt": edm.cmt if edm.cmt else None,
                })

            enums.append({
                "name": name,
                "ordinal": ordinal,
                "members": members,
            })

        # Typedefs
        elif tif.is_typedef():
            try:
                type_str = tif.dstr()
            except Exception:
                type_str = ""
            typedefs.append({
                "name": name,
                "ordinal": ordinal,
                "type": type_str,
            })

        # Other kinds (e.g. function prototypes) can be added later if desired.

    if not structs and not enums and not typedefs:
        ida_kernwin.msg("No user-defined local types found for export, skipping types.json\n")
        return

    obj = {
        "structs": structs,
        "enums": enums,
        "typedefs": typedefs,
    }

    with io.open(types_path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

    ida_kernwin.msg(
        "Wrote types.json: structs=%d, enums=%d, typedefs=%d\n"
        % (len(structs), len(enums), len(typedefs))
    )


# =================== Assembly export (asm/*.asm + asm_index.json) ===================

def format_bytes_hex(byte_string: bytes) -> str:
    if not byte_string:
        return ""
    hex_str = binascii.hexlify(byte_string).decode("ascii").upper()
    return " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))


def write_asm_range(start_ea: int, end_ea: int, out_fh, unit_header: str):
    """
    Dump linear disassembly (code and data) for [start_ea, end_ea) into out_fh.

    This is useful for:
      - heavily obfuscated / packed code where Hex-Rays output is poor;
      - verifying control-flow and exact instruction bytes;
      - sharing specific code regions with an AI or other tools.
    """
    seg = ida_segment.getseg(start_ea)
    seg_name = ida_segment.get_segm_name(seg) if seg else ""
    seg_class = ida_segment.get_segm_class(seg) if seg else ""
    perm = seg.perm if seg else 0

    perm_flags = []
    if perm & ida_segment.SEGPERM_READ:
        perm_flags.append("r")
    if perm & ida_segment.SEGPERM_WRITE:
        perm_flags.append("w")
    if perm & ida_segment.SEGPERM_EXEC:
        perm_flags.append("x")
    perm_str = "".join(perm_flags) if perm_flags else "-"

    out_fh.write("; unit: %s\n" % unit_header)
    out_fh.write("; segment: %s  class: %s  perm: %s\n" % (seg_name, seg_class, perm_str))
    out_fh.write("; generated_by: ida_export_offline_ida92_extended\n\n")

    ea = start_ea
    while ea < end_ea:
        flags = ida_bytes.get_full_flags(ea)
        if ida_bytes.is_unknown(flags):
            ea = ida_bytes.next_head(ea, end_ea)
            if ea == idc.BADADDR or ea >= end_ea:
                break
            continue

        size = ida_bytes.get_item_size(ea)
        if size <= 0:
            ea += 1
            continue

        raw = ida_bytes.get_bytes(ea, size) or b""
        bytes_fmt = format_bytes_hex(raw)

        disasm = idc.generate_disasm_line(ea, 0) or ""
        disasm = ida_lines.tag_remove(disasm)

        out_fh.write("%08X: %-24s %s\n" % (ea, bytes_fmt, disasm))

        ea += size


def parse_hex_ea_list(s: str):
    """
    Parse a comma-separated list of EAs, each can be:
      - 0x401000
      - 401000
    Returns list of integers.
    """
    result = []
    if not s:
        return result
    parts = [p.strip() for p in s.split(",") if p.strip()]
    for part in parts:
        try:
            if part.lower().startswith("0x"):
                ea = int(part, 16)
            else:
                ea = int(part, 16)
            result.append(ea)
        except Exception:
            ida_kernwin.msg("Failed to parse EA '%s', skipping\n" % part)
    return result


def parse_range_list(s: str):
    """
    Parse a string describing one or more ranges, format examples:
      0x401000-0x401300
      401000-401300
      0x401000-0x401300,0x402000-0x402050

    Returns list of (start_ea, end_ea) tuples.
    """
    ranges = []
    if not s:
        return ranges
    parts = [p.strip() for p in s.split(",") if p.strip()]
    for part in parts:
        if "-" not in part:
            ida_kernwin.msg("Invalid range format '%s', expected start-end\n" % part)
            continue
        start_str, end_str = [x.strip() for x in part.split("-", 1)]
        try:
            if start_str.lower().startswith("0x"):
                start_ea = int(start_str, 16)
            else:
                start_ea = int(start_str, 16)
            if end_str.lower().startswith("0x"):
                end_ea = int(end_str, 16)
            else:
                end_ea = int(end_str, 16)
            if end_ea <= start_ea:
                ida_kernwin.msg("Range '%s' has end <= start, skipping\n" % part)
                continue
            end_ea_internal = end_ea + 1
            ranges.append((start_ea, end_ea_internal))
        except Exception:
            ida_kernwin.msg("Failed to parse range '%s', skipping\n" % part)
    return ranges


def export_asm(export_dir: str):
    """
    Export linear disassembly into asm/*.asm and asm_index.json.

    There are three modes, selected interactively:

      1) By address ranges:
         - You specify one or more address ranges (for example, unpacking stubs, crypto loops).
         - The script exports each range as a separate .asm file.

      2) By functions:
         - You specify one or more functions (by name and/or EA).
         - The script exports each function's body (start_ea -> end_ea) as a separate .asm file.

      3) All code segments:
         - The script walks all segments classified as CODE and exports them as ranges.
         - This can produce large output for big binaries and should be used with care.

    Assembly export is useful when:
      - The sample uses a custom packer/self-decryptor and Hex-Rays cannot decompile the stub;
      - Heavy control-flow obfuscation makes pseudo-C unreadable;
      - You want to share specific disassembly slices with an AI or tools without exposing the entire IDB.
    """
    asm_dir = os.path.join(export_dir, "asm")
    ensure_dir(asm_dir)

    units = []  # for asm_index.json

    # Ask whether to export assembly at all
    ida_kernwin.msg(
        "Assembly export: useful for packed/obfuscated regions where Hex-Rays output is weak.\n"
    )
    ans = ida_kernwin.ask_yn(
        1,
        "Do you want to export flat disassembly (assembly)?\n"
        "Yes: choose ranges/functions/all\n"
        "No: skip assembly export"
    )
    if ans != 1:
        ida_kernwin.msg("Skipping assembly export\n")
        return

    # Mode selection: 1=ranges, 2=functions, 3=all code segments
    mode_str = ida_kernwin.ask_str(
        "3",
        0,
        "Select assembly export mode:\n"
        "1 = by address ranges\n"
        "2 = by functions\n"
        "3 = all code segments\n"
        "(enter 1, 2 or 3)"
    )
    if not mode_str:
        ida_kernwin.msg("No assembly export mode selected, skipping assembly\n")
        return

    mode_str = mode_str.strip()
    if mode_str not in ("1", "2", "3"):
        ida_kernwin.msg("Invalid assembly export mode '%s', skipping assembly\n" % mode_str)
        return

    mode = int(mode_str)

    # Mode 1: by address ranges
    if mode == 1:
        spec = ida_kernwin.ask_str(
            "",
            0,
            "Enter one or more address ranges to export, separated by commas.\n"
            "Examples:\n"
            "  0x401000-0x401300\n"
            "  0x401000-0x401300,0x402000-0x402050\n"
            "Ranges are [start, end) in hex."
        )
        ranges = parse_range_list(spec)
        if not ranges:
            ida_kernwin.msg("No valid ranges for assembly export, skipping\n")
            return

        for (start_ea, end_ea) in ranges:
            fname = "range_%08X_%08X.asm" % (start_ea, end_ea)
            rel_path = os.path.join("asm", fname).replace("\\", "/")
            full_path = os.path.join(asm_dir, fname)

            with io.open(full_path, "w", encoding="utf-8") as fh:
                unit_header = "range 0x%08X-0x%08X" % (start_ea, end_ea)
                write_asm_range(start_ea, end_ea, fh, unit_header)

            units.append({
                "kind": "range",
                "start": hex_ea(start_ea),
                "end": hex_ea(end_ea),
                "label": None,
                "path": rel_path,
            })
            ida_kernwin.msg("Wrote assembly for range 0x%08X-0x%08X\n" % (start_ea, end_ea))

    # Mode 2: by functions
    elif mode == 2:
        spec = ida_kernwin.ask_str(
            "",
            0,
            "Enter one or more functions to export, separated by commas.\n"
            "Each item can be a function name or a start EA in hex.\n"
            "Examples:\n"
            "  WinMain,sub_401000\n"
            "  0x401000,0x402000"
        )
        if not spec:
            ida_kernwin.msg("No functions specified, skipping assembly export\n")
            return

        items = [p.strip() for p in spec.split(",") if p.strip()]
        if not items:
            ida_kernwin.msg("No functions specified, skipping assembly export\n")
            return

        for item in items:
            ea = ida_name.get_name_ea(idc.BADADDR, item)
            func = None

            if ea != idc.BADADDR:
                func = ida_funcs.get_func(ea)
            else:
                # Try parse as hex EA
                try:
                    if item.lower().startswith("0x"):
                        ea = int(item, 16)
                    else:
                        ea = int(item, 16)
                    func = ida_funcs.get_func(ea)
                except Exception:
                    ea = ida_ida.BADADDR
                    func = None

            if not func:
                ida_kernwin.msg("Could not resolve function '%s', skipping\n" % item)
                continue

            start_ea = func.start_ea
            end_ea = func.end_ea
            name = ida_name.get_ea_name(start_ea) or "sub_%08X" % start_ea
            safe = sanitize_name(name)

            fname = "func_%s_%08X.asm" % (safe, start_ea)
            rel_path = os.path.join("asm", fname).replace("\\", "/")
            full_path = os.path.join(asm_dir, fname)

            with io.open(full_path, "w", encoding="utf-8") as fh:
                unit_header = "function %s (0x%08X - 0x%08X)" % (name, start_ea, end_ea)
                write_asm_range(start_ea, end_ea, fh, unit_header)

            units.append({
                "kind": "function",
                "name": name,
                "ea": hex_ea(start_ea),
                "path": rel_path,
            })
            ida_kernwin.msg("Wrote assembly for function %s at 0x%08X\n" % (name, start_ea))

    # Mode 3: all code segments
    elif mode == 3:
        ida_kernwin.msg(
            "Exporting assembly for all code segments. "
            "This may produce large output for big binaries.\n"
        )
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg:
                continue

            sclass = ida_segment.get_segm_class(seg) or ""
            if sclass != "CODE":
                continue

            start_ea = seg.start_ea
            end_ea = seg.end_ea
            name = ida_segment.get_segm_name(seg) or "seg_%08X" % start_ea
            safe = sanitize_name(name)

            fname = "seg_%s_%08X_%08X.asm" % (safe, start_ea, end_ea)
            rel_path = os.path.join("asm", fname).replace("\\", "/")
            full_path = os.path.join(asm_dir, fname)

            with io.open(full_path, "w", encoding="utf-8") as fh:
                unit_header = "segment %s (0x%08X - 0x%08X)" % (name, start_ea, end_ea)
                write_asm_range(start_ea, end_ea, fh, unit_header)

            units.append({
                "kind": "segment",
                "name": name,
                "start": hex_ea(start_ea),
                "end": hex_ea(end_ea),
                "path": rel_path,
            })
            ida_kernwin.msg("Wrote assembly for code segment %s (0x%08X - 0x%08X)\n"
                            % (name, start_ea, end_ea))

    # Write asm_index.json if we have any units
    if units:
        index_path = os.path.join(export_dir, "asm_index.json")
        with io.open(index_path, "w", encoding="utf-8") as f:
            json.dump({"units": units}, f, indent=2, ensure_ascii=False)
        ida_kernwin.msg("Wrote asm_index.json with %d units\n" % len(units))
    else:
        ida_kernwin.msg("No assembly units were produced, asm_index.json not created\n")


# =================== ZIP packaging ===================

def make_zip(export_dir: str):
    zip_path = os.path.join(os.path.dirname(export_dir), "ida_export.zip")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(export_dir):
            for fn in files:
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, export_dir)
                zf.write(full, rel)
    ida_kernwin.msg("Created archive %s\n" % zip_path)


# =================== main ===================

def main():
    input_path = ida_nalt.get_input_file_path()
    if not input_path:
        ida_kernwin.msg("Failed to get input file path\n")
        return

    base_dir = os.path.dirname(input_path)
    export_dir = os.path.join(base_dir, "ida_export")
    ensure_dir(export_dir)

    ida_kernwin.msg("Export directory: %s\n" % export_dir)

    start_time = time.time()

    export_meta(export_dir)
    export_segments(export_dir)
    export_imports(export_dir)
    export_exports(export_dir)
    export_functions_and_index(export_dir)
    export_strings(export_dir)
    export_data(export_dir)

    # Optional types export: only useful if you have created your own structs/enums/typedefs.
    local_type_count = count_local_user_types()
    if local_type_count > 0:
        ida_kernwin.msg(
            "Detected %d user-defined local types (structs/enums/typedefs).\n" % local_type_count
        )
        ans_types = ida_kernwin.ask_yn(
            1,
            "Export user-defined local types to types.json?\n"
            "This is only useful if you added your own structures/enums for this sample."
        )
        if ans_types == 1:
            export_types(export_dir)
        else:
            ida_kernwin.msg("Skipping types.json export\n")
    else:
        ida_kernwin.msg("No user-defined local types found, skipping types.json\n")

    # Optional assembly export
    export_asm(export_dir)

    # Copy original sample
    sample_out = os.path.join(export_dir, "sample.bin")
    try:
        copy_sample_bin(input_path, sample_out)
        ida_kernwin.msg("Copied sample to sample.bin\n")
    except Exception as e:
        ida_kernwin.msg("Failed to copy sample: %s\n" % e)

    # Package everything
    make_zip(export_dir)

    elapsed = time.time() - start_time
    ida_kernwin.msg("Export completed in %.1f seconds\n" % elapsed)


if __name__ == "__main__":
    main()
