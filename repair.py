#!/usr/bin/env python3
"""
Repair a PE / InstallShield PFTW file corrupted by FTP ASCII-mode upload.

The corruption inserted a 0x0a after every standalone 0x0d byte (CR not
already followed by LF), turning standalone CRs into CRLFs. To undo, we
identify and strip the inserted 0a bytes.

Repair is two-stage:
  1. Greedy alignment vs. a "WIP" reference file (which need not be perfect)
     using a 16-byte window-hash resync. Catches the bulk of FTP insertions
     for any region where the reference shares structure with the corrupted
     file. This is enough to restore the PE header and stock InstallShield
     content.
  2. CAB / CFDATA checksum validation for the appended payload. For each
     CFDATA block whose stored csum doesn't match the post-stage-1 data,
     try restoring each stage-1 insertion inside that block; accept the
     one that makes the stored csum match AND produces a valid MSZip
     decompression of the declared length.

Usage:
  python3 repair.py <corrupted> <reference_wip> <output>
"""

import struct
import sys
import zlib
from itertools import combinations
from pathlib import Path


# ---------- Stage 1: FTP-insertion alignment ----------

def align_against_reference(orig: bytes, ref: bytes, window: int = 16) -> list[int]:
    """Return list of orig offsets where 0a was inserted by FTP corruption.

    Walks orig and ref in parallel. When orig has 0d 0a but ref has standalone 0d,
    that's an FTP insertion. On content mismatch (e.g. in payload regions where
    the reference doesn't match), resync via window-hash lookup.
    """
    ref_idx: dict[bytes, int] = {}
    for j in range(len(ref) - window + 1):
        h = ref[j:j + window]
        if h not in ref_idx:
            ref_idx[h] = j

    insertions: list[int] = []
    i, j = 0, 0
    while i < len(orig) and j < len(ref):
        if (i + 1 < len(orig) and orig[i] == 0x0d and orig[i + 1] == 0x0a
                and ref[j] == 0x0d):
            if j + 1 < len(ref) and ref[j + 1] == 0x0a:
                i += 2; j += 2
            else:
                insertions.append(i + 1)
                i += 2; j += 1
            continue
        if orig[i] == ref[j]:
            i += 1; j += 1
            continue
        # Content mismatch: resync via window-hash
        resynced = False
        for skip in range(1, 4096):
            if i + skip + window > len(orig):
                break
            h = bytes(orig[i + skip:i + skip + window])
            new_j = ref_idx.get(h)
            if new_j is not None and new_j >= j:
                i += skip; j = new_j
                resynced = True
                break
        if not resynced:
            i += 1
    return insertions


def apply_insertions(orig: bytes, ins_set: set[int]) -> bytes:
    return bytes(b for k, b in enumerate(orig) if k not in ins_set)


# ---------- Stage 2: CFDATA checksum validation ----------

def cab_checksum(data: bytes) -> int:
    """Microsoft CAB CFDATA checksum (XOR uint32 LE, plus tail bytes shifted)."""
    csum = 0
    n = len(data)
    full = n - (n % 4)
    i = 0
    while i < full:
        csum ^= struct.unpack_from('<I', data, i)[0]
        i += 4
    rem = n - full
    ul = 0
    if rem == 3:
        ul = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2]
    elif rem == 2:
        ul = (data[i] << 8) | data[i + 1]
    elif rem == 1:
        ul = data[i]
    return (csum ^ ul) & 0xFFFFFFFF


def find_appended_cab(data: bytes) -> int | None:
    """Find the offset of an MSCF (CAB) header that appears after the PE sections."""
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    coff = e_lfanew + 4
    n_sections = struct.unpack_from('<H', data, coff + 2)[0]
    opt_size = struct.unpack_from('<H', data, coff + 16)[0]
    sec_table = coff + 20 + opt_size
    max_end = 0
    for k in range(n_sections):
        raw_size, raw_ptr = struct.unpack_from('<II', data, sec_table + k * 40 + 16)
        max_end = max(max_end, raw_ptr + raw_size)
    # Search for MSCF starting from end of last section
    pos = data.find(b'MSCF', max_end)
    return pos if pos != -1 else None


def build_orig_to_fixed(orig: bytes, ins_set: set[int]) -> tuple[list[int | None], list[int], int]:
    o2f: list[int | None] = [None] * (len(orig) + 1)
    fp = 0
    for op in range(len(orig)):
        if op in ins_set:
            o2f[op] = None
        else:
            o2f[op] = fp
            fp += 1
    o2f[len(orig)] = fp
    f2o = [0] * (fp + 1)
    for op in range(len(orig)):
        fo = o2f[op]
        if fo is not None:
            f2o[fo] = op
    f2o[fp] = len(orig)
    return o2f, f2o, fp


def validate_block(data: bytes, block_off: int, prev_uncomp: bytes) -> tuple[bool, bytes | None]:
    """Return (matches_csum_and_decompresses, decompressed_output)."""
    if block_off + 8 > len(data):
        return False, None
    csum_stored = struct.unpack_from('<I', data, block_off)[0]
    cb_data = struct.unpack_from('<H', data, block_off + 4)[0]
    cb_uncomp = struct.unpack_from('<H', data, block_off + 6)[0]
    if block_off + 8 + cb_data > len(data):
        return False, None
    check_data = bytes(data[block_off + 4:block_off + 8 + cb_data])
    if cab_checksum(check_data) != csum_stored:
        return False, None
    payload = bytes(data[block_off + 8:block_off + 8 + cb_data])
    if payload[:2] != b'CK':
        return False, None
    try:
        d = zlib.decompressobj(-15, zdict=prev_uncomp[-32768:] if prev_uncomp else b'')
        out = d.decompress(payload[2:]) + d.flush()
        if len(out) != cb_uncomp or d.unused_data:
            return False, None
        return True, out
    except Exception:
        return False, None


def stage2_cab_repair(orig: bytes, ins_set: set[int], cab_offset_in_fixed: int) -> tuple[set[int], list[int]]:
    """Walk CFDATA blocks; for each broken block, try restoring 1 (or 2) insertions inside it.

    Uses the cabinet checksum as oracle. Returns (updated_ins_set, restored_offsets).
    """
    fixed = bytearray(apply_insertions(orig, ins_set))
    o2f, f2o, _ = build_orig_to_fixed(orig, ins_set)

    folder_off = cab_offset_in_fixed + 36
    coff_cab_start = struct.unpack_from('<I', fixed, folder_off)[0]
    c_cf_data = struct.unpack_from('<H', fixed, folder_off + 4)[0]
    first_block = cab_offset_in_fixed + coff_cab_start

    restored: list[int] = []
    prev_uncomp = b''
    data_off = first_block

    for blk in range(c_cf_data):
        ok, out = validate_block(fixed, data_off, prev_uncomp)
        if ok:
            cb_data = struct.unpack_from('<H', fixed, data_off + 4)[0]
            prev_uncomp = out
            data_off += 8 + cb_data
            continue

        cb_data = struct.unpack_from('<H', fixed, data_off + 4)[0] if data_off + 8 <= len(fixed) else 0
        orig_blk_start = f2o[data_off] if data_off < len(f2o) else None
        end_fixed = min(data_off + 8 + cb_data + 16, len(fixed))
        orig_blk_end = f2o[end_fixed] if end_fixed < len(f2o) else len(orig)
        sorted_ins = sorted(ins_set)
        cands = [x for x in sorted_ins if orig_blk_start < x <= orig_blk_end]

        fix_found = False
        for cand in cands:
            ins_pos = o2f[cand - 1]
            if ins_pos is None or ins_pos + 1 <= data_off + 8:
                continue
            trial = bytes(fixed[:ins_pos + 1]) + b'\x0a' + bytes(fixed[ins_pos + 1:])
            ok2, out2 = validate_block(trial, data_off, prev_uncomp)
            if ok2:
                fixed = bytearray(trial)
                ins_set.discard(cand)
                o2f, f2o, _ = build_orig_to_fixed(orig, ins_set)
                restored.append(cand)
                prev_uncomp = out2
                new_cb_data = struct.unpack_from('<H', fixed, data_off + 4)[0]
                data_off += 8 + new_cb_data
                fix_found = True
                break

        if not fix_found:
            # Try pairs (rarely needed for this corruption pattern)
            for c1, c2 in combinations(cands, 2):
                p1, p2 = o2f[c1 - 1], o2f[c2 - 1]
                if p1 is None or p2 is None: continue
                if min(p1, p2) + 1 <= data_off + 8: continue
                pos = sorted([p1, p2])
                trial = (bytes(fixed[:pos[0] + 1]) + b'\x0a'
                         + bytes(fixed[pos[0] + 1:pos[1] + 1]) + b'\x0a'
                         + bytes(fixed[pos[1] + 1:]))
                ok2, out2 = validate_block(trial, data_off, prev_uncomp)
                if ok2:
                    fixed = bytearray(trial)
                    ins_set -= {c1, c2}
                    o2f, f2o, _ = build_orig_to_fixed(orig, ins_set)
                    restored.extend([c1, c2])
                    prev_uncomp = out2
                    new_cb_data = struct.unpack_from('<H', fixed, data_off + 4)[0]
                    data_off += 8 + new_cb_data
                    fix_found = True
                    break

        if not fix_found:
            raise RuntimeError(f"Stage 2 could not repair CFDATA block {blk} at fixed offset 0x{data_off:X}")

    return ins_set, restored


# ---------- Main ----------

def repair(orig: bytes, ref: bytes) -> tuple[bytes, dict]:
    insertions = align_against_reference(orig, ref)
    ins_set = set(insertions)
    stats = {'stage1_insertions': len(insertions)}

    fixed_stage1 = apply_insertions(orig, ins_set)
    # Find appended CAB and run stage 2 if present
    cab_off = find_appended_cab(fixed_stage1)
    if cab_off is not None and fixed_stage1[cab_off:cab_off + 4] == b'MSCF':
        ins_set, restored = stage2_cab_repair(orig, ins_set, cab_off)
        stats['cab_offset'] = cab_off
        stats['stage2_restored'] = restored
    else:
        stats['stage2_restored'] = []
    return apply_insertions(orig, ins_set), stats


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__); return 1
    orig_path, ref_path, out_path = (Path(p) for p in sys.argv[1:4])
    orig = orig_path.read_bytes()
    ref = ref_path.read_bytes()
    fixed, stats = repair(orig, ref)
    out_path.write_bytes(fixed)
    print(f"Input:  {orig_path.name} ({len(orig)} bytes)")
    print(f"Ref:    {ref_path.name} ({len(ref)} bytes)")
    print(f"Output: {out_path.name} ({len(fixed)} bytes)")
    print(f"Stage 1: stripped {stats['stage1_insertions']} FTP-inserted 0a bytes")
    if stats.get('cab_offset') is not None:
        print(f"Stage 2: appended CAB at 0x{stats['cab_offset']:X}")
        print(f"Stage 2: restored {len(stats['stage2_restored'])} bytes that were stage-1 false positives:")
        for off in stats['stage2_restored']:
            print(f"  orig offset 0x{off:X}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
