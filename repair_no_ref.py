#!/usr/bin/env python3
"""
Repair a PE + appended CAB file corrupted by FTP ASCII-mode upload, with NO
reference file required.

The corruption inserted 0x0a after every standalone 0x0d byte (CR not already
followed by LF). To undo without a reference:

  1. Aggressively strip every 0x0a that follows a 0x0d. This removes all 5,500+
     FTP insertions but also removes the ~50 legitimate 0d 0a pairs that
     existed in the original file (DOS stub, error message terminators in
     .rdata, RTF text in .rsrc, compressed-payload coincidences).
  2. Restore the legitimate 0d 0a in the DOS stub via the standard MSVC
     "\\r\\r\\n$" template.
  3. Restore legitimate 0d 0a pairs in PE string sections (.rdata, .rsrc) via
     ASCII-context heuristic: a 0d whose preceding byte AND following byte
     are both printable ASCII (or following byte is 0x00 for null-terminated
     strings) is almost certainly a stripped CRLF. The check on the preceding
     byte rules out UTF-16 strings (where 0d's preceding byte is 0x00).
  4. Walk the appended CAB's CFDATA blocks. For any block whose stored csum
     doesn't match the post-strip data, search nearby stripped 0a positions
     for the combination whose restoration both makes the csum match AND
     produces a valid MSZip decompression of the declared length.

The CAB CFDATA checksum is the oracle: it's a per-block hash that catches
single-byte differences, so the right restorations are uniquely determined.

Usage:
  python3 repair_no_ref.py <corrupted_input> <output>
"""

import struct
import sys
import zlib
from itertools import combinations
from pathlib import Path


# ---------- Strip + offset maps ----------

def aggressive_strip(orig: bytes) -> tuple[set[int], bytes]:
    """Strip every 0a that follows a 0d. Returns (strip_set, stripped_bytes)."""
    strip_set: set[int] = set()
    fixed = bytearray()
    for i, b in enumerate(orig):
        if b == 0x0a and i > 0 and orig[i - 1] == 0x0d:
            strip_set.add(i)
        else:
            fixed.append(b)
    return strip_set, bytes(fixed)


def build_maps(orig_len: int, strip_set: set[int]) -> tuple[list[int | None], list[int]]:
    """Return (orig_to_fixed, fixed_to_orig). Each is a list."""
    o2f: list[int | None] = [None] * (orig_len + 1)
    fp = 0
    for op in range(orig_len):
        if op in strip_set:
            o2f[op] = None
        else:
            o2f[op] = fp
            fp += 1
    o2f[orig_len] = fp
    f2o = [0] * (fp + 1)
    for op in range(orig_len):
        fo = o2f[op]
        if fo is not None:
            f2o[fo] = op
    f2o[fp] = orig_len
    return o2f, f2o


def apply_strips(orig: bytes, strip_set: set[int]) -> bytes:
    return bytes(b for k, b in enumerate(orig) if k not in strip_set)


# ---------- DOS stub fix ----------

def fix_dos_stub(orig: bytes, strip_set: set[int]) -> set[int]:
    """Restore the legitimate 0a in the standard MSVC DOS stub `\\r\\r\\n$` ending.

    After aggressive strip, what was `2e 0d 0d 0a 24` becomes `2e 0d 0d 24` (we
    stripped the 0a). Find that pattern and restore the 0a.
    """
    fixed = apply_strips(orig, strip_set)
    _, f2o = build_maps(len(orig), strip_set)
    # Look in the first 0x100 bytes (DOS header + stub area)
    search_end = min(0x100, len(fixed) - 4)
    for off in range(0x40, search_end):
        if fixed[off:off + 4] == b'\x2e\x0d\x0d\x24':
            # The 0a we want sits in orig right before the 0x24 byte
            target = f2o[off + 3] - 1
            if target in strip_set and orig[target] == 0x0a:
                return strip_set - {target}
    return strip_set


# ---------- PE string-section restoration ----------

def get_section_ranges(fixed: bytes, target_names: set[bytes]) -> list[tuple[int, int]]:
    """Return list of (raw_ptr, raw_ptr+raw_size) for sections whose name is in target_names."""
    e_lfanew = struct.unpack_from('<I', fixed, 0x3C)[0]
    coff = e_lfanew + 4
    n_sections = struct.unpack_from('<H', fixed, coff + 2)[0]
    opt_size = struct.unpack_from('<H', fixed, coff + 16)[0]
    sec_table = coff + 20 + opt_size
    ranges = []
    for k in range(n_sections):
        name = fixed[sec_table + k * 40:sec_table + k * 40 + 8].rstrip(b'\x00')
        if name in target_names:
            raw_size, raw_ptr = struct.unpack_from('<II', fixed, sec_table + k * 40 + 16)
            ranges.append((raw_ptr, raw_ptr + raw_size))
    return ranges


def _ansi_text_nearby(fixed: bytes, d_pos: int, window: int = 16,
                      min_run: int = 3, min_density: float = 0.50) -> bool:
    """Return True if d_pos is in an ANSI text region.

    Two conditions must hold over the +/- `window` bytes around d_pos:
      - At least one run of >= `min_run` consecutive printable ASCII bytes
        (rules out UTF-16, where printables alternate with nulls and never form
        runs of >= 2).
      - At least `min_density` fraction of the window is printable ASCII
        (rules out binary headers that happen to contain a short text tag like
        "vih8" or "RIFF" — the surrounding bytes are mostly binary).
    """
    start = max(0, d_pos - window)
    end = min(len(fixed), d_pos + window + 1)
    consecutive = 0
    max_run = 0
    printable_count = 0
    total = 0
    for i in range(start, end):
        if i == d_pos:
            consecutive = 0
            continue
        b = fixed[i]
        total += 1
        if 0x20 <= b <= 0x7E:
            consecutive += 1
            printable_count += 1
            if consecutive > max_run:
                max_run = consecutive
        else:
            consecutive = 0
    if total == 0:
        return False
    return max_run >= min_run and (printable_count / total) >= min_density


def restore_pe_strings(orig: bytes, strip_set: set[int]) -> tuple[set[int], list[int]]:
    """Restore 0d 0a pairs in PE string sections (.rdata, .rsrc) using context heuristics.

    For each 0d in fixed that lies within .rdata or .rsrc, restore if:
      - Primary heuristic: byte before is printable ASCII AND byte after is printable or 0x00.
        Catches the common case of `text\\r\\n\\0` string terminators and RTF text runs.
      - Secondary heuristic: 3+ consecutive printable ASCII bytes appear within 16 bytes
        either side. Catches `\\0\\0\\r\\0\\0TLOSS` (CRLF between null-padded strings in
        string tables). Distinguishes ANSI from UTF-16 (which never has 2 consecutive
        printables) and from random binary data.

    Skips .text (instruction bytes look like noise) and .data / .idata (rarely contain
    user-visible string data in MSVC builds).
    """
    fixed = apply_strips(orig, strip_set)
    o2f, _ = build_maps(len(orig), strip_set)
    ranges = get_section_ranges(fixed, {b'.rdata', b'.rsrc'})

    restored: list[int] = []
    for strip_orig in list(strip_set):
        d_orig = strip_orig - 1
        d_fixed = o2f[d_orig]
        if d_fixed is None or d_fixed <= 0 or d_fixed + 1 >= len(fixed):
            continue
        if not any(s <= d_fixed < e for s, e in ranges):
            continue
        before = fixed[d_fixed - 1]
        after = fixed[d_fixed + 1]
        primary = (0x20 <= before <= 0x7E) and ((0x20 <= after <= 0x7E) or after == 0x00)
        secondary = _ansi_text_nearby(fixed, d_fixed)
        if primary or secondary:
            restored.append(strip_orig)

    return strip_set - set(restored), restored


# ---------- CAB walking ----------

def cab_checksum(data: bytes) -> int:
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


def find_appended_cab(fixed: bytes) -> int | None:
    """Find the MSCF (CAB) header offset after the last PE section."""
    e_lfanew = struct.unpack_from('<I', fixed, 0x3C)[0]
    coff = e_lfanew + 4
    n_sections = struct.unpack_from('<H', fixed, coff + 2)[0]
    opt_size = struct.unpack_from('<H', fixed, coff + 16)[0]
    sec_table = coff + 20 + opt_size
    max_end = 0
    for k in range(n_sections):
        raw_size, raw_ptr = struct.unpack_from('<II', fixed, sec_table + k * 40 + 16)
        max_end = max(max_end, raw_ptr + raw_size)
    pos = fixed.find(b'MSCF', max_end)
    return pos if pos != -1 else None


def construct_block(orig: bytes, strip_set: set[int], orig_block_start: int) -> tuple[bytes, bytes, int] | None:
    """Build (header_8_bytes, payload_cb_data_bytes, end_orig_offset) for the block at orig_block_start.

    Walks orig from orig_block_start, skipping strip positions, taking the next 8 bytes as the header
    and then cb_data more bytes as the payload.
    """
    header = bytearray()
    pos = orig_block_start
    while len(header) < 8 and pos < len(orig):
        if pos not in strip_set:
            header.append(orig[pos])
        pos += 1
    if len(header) < 8:
        return None
    cb_data = struct.unpack_from('<H', header, 4)[0]
    payload = bytearray()
    while len(payload) < cb_data and pos < len(orig):
        if pos not in strip_set:
            payload.append(orig[pos])
        pos += 1
    if len(payload) < cb_data:
        return None
    return bytes(header), bytes(payload), pos


def validate_block(orig: bytes, strip_set: set[int], orig_block_start: int,
                   prev_uncomp: bytes) -> tuple[bool, bytes | None, int | None]:
    """Returns (ok, decompressed_output, end_orig_offset). ok = csum matches AND deflate works."""
    result = construct_block(orig, strip_set, orig_block_start)
    if result is None:
        return False, None, None
    header, payload, end_orig = result
    csum_stored = struct.unpack_from('<I', header, 0)[0]
    cb_data = struct.unpack_from('<H', header, 4)[0]
    cb_uncomp = struct.unpack_from('<H', header, 6)[0]
    check_data = header[4:] + payload
    if cab_checksum(check_data) != csum_stored:
        return False, None, end_orig
    if payload[:2] != b'CK':
        return False, None, end_orig
    try:
        d = zlib.decompressobj(-15, zdict=prev_uncomp[-32768:] if prev_uncomp else b'')
        out = d.decompress(payload[2:]) + d.flush()
        if len(out) != cb_uncomp or d.unused_data:
            return False, None, end_orig
        return True, out, end_orig
    except Exception:
        return False, None, end_orig


def cab_repair(orig: bytes, strip_set: set[int], cab_offset: int) -> tuple[set[int], list[int]]:
    """Walk CFDATA blocks; for each broken block, restore stripped 0a's using csum oracle.

    Returns (updated_strip_set, list_of_restored_orig_offsets).
    """
    fixed = apply_strips(orig, strip_set)
    o2f, f2o = build_maps(len(orig), strip_set)
    folder_off = cab_offset + 36
    coff_cab_start = struct.unpack_from('<I', fixed, folder_off)[0]
    c_cf_data = struct.unpack_from('<H', fixed, folder_off + 4)[0]
    first_block_fixed = cab_offset + coff_cab_start
    orig_block_start = f2o[first_block_fixed]

    restored: list[int] = []
    prev_uncomp = b''

    for blk in range(c_cf_data):
        ok, out, end_orig = validate_block(orig, strip_set, orig_block_start, prev_uncomp)
        if ok:
            prev_uncomp = out
            orig_block_start = end_orig
            continue

        # Establish a candidate strip range. Start with no-restoration end + buffer.
        no_restore = construct_block(orig, strip_set, orig_block_start)
        if no_restore is None:
            raise RuntimeError(f"Block {blk}: header unreadable")
        _, _, end_no_restore = no_restore
        buffer_end = min(end_no_restore + 64, len(orig))
        # Skip strips inside the 8-byte header (header bytes are at orig positions
        # taken sequentially from orig_block_start; if any strip falls inside, that's
        # very rare for random-ish CAB headers and we won't try restoring those).
        block_strips = sorted(s for s in strip_set if orig_block_start < s <= buffer_end)

        fix_found = False
        max_restore = min(6, len(block_strips) + 1)
        for n_restore in range(1, max_restore):
            if fix_found:
                break
            for combo in combinations(block_strips, n_restore):
                trial = strip_set - set(combo)
                ok2, out2, end_orig2 = validate_block(orig, trial, orig_block_start, prev_uncomp)
                if ok2:
                    strip_set = trial
                    restored.extend(combo)
                    prev_uncomp = out2
                    orig_block_start = end_orig2
                    fix_found = True
                    break

        if not fix_found:
            raise RuntimeError(
                f"CFDATA block {blk}: could not find restoration within {max_restore - 1} bytes "
                f"(had {len(block_strips)} candidates)"
            )

    return strip_set, restored


# ---------- Main ----------

def repair(orig: bytes) -> tuple[bytes, dict]:
    strip_set, _ = aggressive_strip(orig)
    stats = {'aggressive_strips': len(strip_set)}

    strip_set = fix_dos_stub(orig, strip_set)
    stats['dos_stub_restored'] = stats['aggressive_strips'] - len(strip_set)

    strip_set, pe_restored = restore_pe_strings(orig, strip_set)
    stats['pe_strings_restored'] = len(pe_restored)

    fixed = apply_strips(orig, strip_set)
    cab_off = find_appended_cab(fixed)
    if cab_off is None:
        stats['cab_offset'] = None
        return fixed, stats
    stats['cab_offset'] = cab_off

    strip_set, restored = cab_repair(orig, strip_set, cab_off)
    stats['cab_restorations'] = len(restored)
    stats['final_strips'] = len(strip_set)

    return apply_strips(orig, strip_set), stats


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 1
    orig_path, out_path = Path(sys.argv[1]), Path(sys.argv[2])
    orig = orig_path.read_bytes()
    fixed, stats = repair(orig)
    out_path.write_bytes(fixed)
    print(f"Input:  {orig_path.name} ({len(orig)} bytes)")
    print(f"Output: {out_path.name} ({len(fixed)} bytes)")
    print(f"Aggressively stripped:  {stats['aggressive_strips']} bytes")
    print(f"DOS stub restored:      {stats['dos_stub_restored']} byte(s)")
    print(f"PE string sections:     {stats['pe_strings_restored']} byte(s) restored")
    if stats.get('cab_offset') is not None:
        print(f"Appended CAB found at:  0x{stats['cab_offset']:X}")
        print(f"CAB CFDATA restored:    {stats['cab_restorations']} byte(s)")
        print(f"Final strip count:      {stats['final_strips']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
