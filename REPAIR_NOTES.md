# Repairing an FTP-ASCII-Corrupted Self-Extracting Installer

This walks through how `BullfrogPlug-In.exe` (a 1998 InstallShield PFTW installer pulled from the Wayback Machine) was repaired after FTP ASCII-mode corruption. The same approach generalizes to any binary file damaged by the same kind of upload mistake.

## TL;DR

- Corruption rule: every standalone `0x0D` (CR not followed by LF) had a `0x0A` inserted after it.
- Naive "strip every `0A` after `0D`" doesn't work — legitimate `0D 0A` pairs exist in the file (DOS stub, compressed-data coincidences) and must be preserved.
- Stage 1: align against a "good enough" reference file to identify ~99.9% of insertions.
- Stage 2: use the appended CAB's per-block checksums to find the handful of legitimate `0D 0A` pairs that stage 1 wrongly stripped.

## Inputs

| File | Size | Notes |
|---|---|---|
| `original/BullfrogPlug-In.exe` | 1,469,760 | The corrupted Wayback download |
| `manual WIP/BullfrogPlug-In.exe` | 1,464,214 | A "frankensteined" reference — parts from a different but related installer of the same era |

## Step 1: Identify the corruption pattern

Look at the DOS stub bytes. The standard MSVC stub ends with `mode.\r\r\n$`, which is `0D 0D 0A 24`. Compare:

```
Orig (corrupted): mode. 0D 0A 0D 0A 24
WIP (reference):  mode. 0D 0D 0A 24
```

The first `0D` (which had a non-`0A` byte after it in the original) became `0D 0A`. That's the FTP ASCII-mode "standalone CR → CRLF" normalization. The file grew by one byte at this position.

Count CR/LF patterns across the whole file:

```
Orig: 0d_then_0a: 5592    0a_alone: 5316    0d_alone:     0
WIP:  0d_then_0a:   47    0a_alone: 5315    0d_alone: 5545
```

Math: `5592 - 47 = 5545` extra CRLFs in the corrupted file, matching the WIP's `5545` standalone CRs and the size delta. The corruption rule is confirmed.

## Step 2: Stage-1 repair — align against the reference

Greedy walk through `orig` and `ref` simultaneously:

- If `orig[i:i+2] == b"\x0d\x0a"` and `ref[j] == 0x0d`:
  - If `ref[j+1] == 0x0a` → legitimate pair, advance both by 2
  - Else → FTP-inserted `0a`, mark for stripping
- On byte mismatch (content actually differs between files), resync via a 16-byte rolling-window hash lookup against `ref`

This works because:
- For the first ~86% of the file (stock InstallShield bootstrap files, common across installers from the same era), `orig` and `ref` are byte-identical after fixing FTP insertions
- For the differing parts (the actual Bullfrog game payload), the window-hash resync still finds enough common anchor points to keep total insertion count correct

Result: 5,545 insertions identified. Strip them → 1,464,215 bytes.

## Step 3: Discover stage-1 isn't quite right

`7z t` on the stage-1 output gives:

```
ERROR: Data Error : /disk1/data/Bullfrog.dat
Unexpected end of data
```

The repaired file is **7 bytes short** of the CAB's declared size (`cb_cabinet = 0x14C3D8` ending at file offset `0x16579E`, but our file ends at `0x165797`). Seven of our 5,545 "FTP insertions" were actually legitimate `0D 0A` pairs in the compressed payload — the reference file had different bytes at those positions, so alignment misclassified them.

## Step 4: Stage-2 repair — use CAB block checksums as the oracle

The appended CAB consists of CFDATA blocks, each with:
- 4-byte `csum` (XOR-based checksum of `cbData + cbUncomp + compressed_data`)
- 2-byte `cbData` (compressed payload length)
- 2-byte `cbUncomp` (decompressed length)
- `cbData` bytes of payload starting with `"CK"` then raw deflate

For each block:
1. Verify the stored `csum` matches the computed checksum of the current data.
2. If yes → move on.
3. If no → for each stage-1 insertion that falls inside this block's payload range, trial-restore that `0a` and re-check both:
   - The `csum` matches
   - The MSZip deflate decompresses to exactly `cbUncomp` bytes with no leftover input (using the previous block's output as the deflate dictionary — MSZip chains)
4. Accept the candidate that satisfies both.

**Important detail:** decompression length alone isn't sufficient. Several candidate positions can produce 32,768 bytes of plausible output (deflate's "last block" marker can land anywhere in a corrupted bit-stream). Only the correct restoration matches the stored `csum`.

Restorations found:

| CFDATA block | orig offset of restored `0a` |
|---|---|
| 22 | `0x9F2A1` |
| 29 | `0xD2F07` |
| 30 | `0xDA221` |
| 31 | `0xE4AAC` |
| 36 | `0x1088FE` |
| 42 | `0x132EFD` |
| 48 | `0x1637B1` |

All seven sit inside the `Bullfrog.dat` portion of the payload — the part unique to this installer that the WIP reference didn't share.

## Step 5: Verify

```
$ 7z t repaired/BullfrogPlug-In.exe
Everything is Ok

Files: 16
Size:       1611336
Compressed: 1464222
```

All 16 files extract cleanly, including the 915,526-byte `Bullfrog.dat`.

## Generalizing this

The two-stage approach works for any FTP-ASCII-corrupted file as long as you have:

1. **A reference file that's mostly similar to the target.** Doesn't need to be perfect — even a different-but-related file of the same compiler/installer family gives enough structural overlap for stage 1.
2. **A built-in integrity check on the payload.** For an InstallShield PFTW that's the CAB CFDATA checksum. Other formats with similar block-level checks: ZIP (CRC32 per file), 7z (CRC + SHA), gzip (Adler32 + final CRC32), MP4 atoms with `mfra`, etc. Without an integrity check, stage 2 has no oracle to validate candidate restorations.

If your file lacks both a reference and an internal checksum, you're stuck with the ambiguity: every `0D 0A` in the corrupted file could be either FTP-inserted or legitimate, and there's no principled way to choose.

## Reproducing the repair

```
python3 repair.py original/BullfrogPlug-In.exe "manual WIP/BullfrogPlug-In.exe" repaired/BullfrogPlug-In.exe
```

Output SHA-256: `7642116c8ecd304bfd280817a33f5a54ccc17ae7ef667444380c39d93356575c`

---

# Addendum: The Two Repair Scripts

Two scripts are included in this folder. Both produce a **byte-identical** output for the Bullfrog file (SHA-256 `7642116c…356575c`). They differ in what input they need and how they handle the ambiguity of legitimate `0D 0A` pairs.

## `repair.py` — reference-driven

**Usage:**
```
python3 repair.py <corrupted> <reference_wip> <output>
```

**Inputs needed:** the corrupted file AND a "good enough" reference (the frankensteined WIP, or any related installer with similar PE structure / stock InstallShield content).

**How it works:**

| Stage | Purpose | Oracle |
|---|---|---|
| 1 | Identify FTP insertions via byte-by-byte alignment against the reference; 16-byte window-hash resync when content diverges (e.g. frankensteined regions) | The reference's byte at each aligned position |
| 2 | For each appended CAB CFDATA block whose stored csum doesn't match, trial-restore stage-1 insertions inside that block until both csum and MSZip decompression validate | CAB CFDATA `csum` + deflate decompress-to-declared-length |

**Strengths:** stage 1 gets ~99.9% of insertions right in one pass when a similar-enough reference exists, so stage 2 has little to fix.

**Weaknesses:** requires a reference. If the reference is from an unrelated file the window-hash resync degrades and stage 1 becomes less helpful, though stage 2 will still rescue the CAB region.

## `repair_no_ref.py` — reference-free

**Usage:**
```
python3 repair_no_ref.py <corrupted> <output>
```

**Inputs needed:** just the corrupted file. No reference required.

**How it works:**

| Stage | Purpose | Oracle |
|---|---|---|
| 1 | Aggressively strip every `0A` that follows a `0D` (treat all as FTP insertions) | None — deliberate over-strip |
| 2 | Restore the legitimate `0D 0A` in the DOS stub | Standard MSVC `\r\r\n$` template at known offset |
| 3 | Restore CRLFs in PE string sections (`.rdata`, `.rsrc`) | Two-pronged heuristic: (a) byte-before printable AND byte-after printable-or-null, OR (b) ≥3 consecutive printable ASCII bytes AND ≥50% printable density in ±16-byte window. Distinguishes ANSI strings from UTF-16 (no consecutive printables) and binary headers with short text tags like `vih8` (low density) |
| 4 | Restore CRLFs in CAB CFDATA blocks | CAB CFDATA `csum` + deflate decompress-to-declared-length (same as `repair.py`'s stage 2) |

**Strengths:** zero external dependency. Works on any FTP-corrupted PE + appended CAB file in isolation.

**Weaknesses:** the PE-string heuristic in stage 3 is tuned for MSVC-compiled binaries with conventional `.rdata` / `.rsrc` content (error message tables, RTF resources, version info). Files with unusual section content (heavy UTF-16 string tables, embedded binary blobs in `.rdata`, custom resource formats) could see false positives or misses. Stage 4 still works regardless and guarantees the CAB extracts correctly.

## Pipeline comparison for the Bullfrog file

Both scripts converge on the same answer through different paths:

|  | `repair.py` | `repair_no_ref.py` |
|---|---|---|
| Initial strips | 5,545 (alignment-guided) | 5,592 (every `0A` after `0D`) |
| DOS stub restored | implicit (alignment got it right) | 1 byte (template) |
| PE-section restorations | implicit (alignment got them right) | 41 bytes (heuristic) |
| CAB-region restorations | 7 bytes (csum oracle) | 12 bytes (csum oracle) |
| Net change | -5,538 bytes | -5,538 bytes |
| Output size | 1,464,222 | 1,464,222 |
| Output SHA-256 | `7642116c…356575c` | `7642116c…356575c` |

The no-reference script does 7-zip-style "everything is broken until proven legitimate" and rebuilds via templates + heuristics + checksums. The reference-driven script trusts the reference for 99% of the file and only escalates to checksum validation for the CAB region where the reference was unreliable.

## When to use which

- **Have a reference of any kind?** Use `repair.py`. It's faster (one stage 1 pass) and more robust to unusual section content.
- **No reference at all?** Use `repair_no_ref.py`. It needs the file to be a PE+CAB with MSVC-conventional sections, but works standalone.
- **Different file type entirely (no PE or no CAB)?** Neither script is plug-and-play, but the staged approach (overstrip → template-fix structural regions → checksum-validate payload) generalizes. Swap the CAB walker for ZIP/7z/gzip block validation.
