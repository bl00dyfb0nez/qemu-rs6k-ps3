#!/usr/bin/env python3
"""ps3_disk_verify.py - read-only raw inspection or model-key heuristics.

The key-based mode derives an ATA pair and scores sampled sectors for structure.
It also recognizes a model-specific wrapped sector-0 block. Neither a heuristic
match nor a model block establishes retail-drive identity or compatibility.

    py scripts/ps3_disk_verify.py --device \\\\.\\PhysicalDrive1 \\
        --pck1 eid_root_key.bin --report .tmp/disk1.txt
    py scripts/ps3_disk_verify.py --device disk.img --pck1 a.bin --pck1 b.bin
    py scripts/ps3_disk_verify.py --device disk.img --inspect

`--inspect` is a read-only raw-sector inspection; it does not read a key,
decrypt sectors, or verify ownership. Its output is only a description of
sampled bytes, not evidence that a drive belongs to a console.

The device is opened for reading only, with 512-byte aligned reads. RAW reads
of \\\\.\\PhysicalDriveN need an elevated process. The optional report and
sector export write files separately. Key-based results are heuristics, not
proof of a console identity or retail-drive key compatibility.
"""
import argparse
import hashlib
import os
import sys

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.stderr.write("ps3_disk_verify.py needs pycryptodome (pip install pycryptodome)\n")
    raise SystemExit(4)

SECTOR = 512
ERK_SIZE = 48
MODEL_MAGIC = b"PS3ATA01"
MODEL_KEY_OFFS = (0x08, 0x28)
DATA_SECTORS = 1, 2, 3, 4, 8, 100, 1000, 10000, 100000, 200000   # sampled
PAIR_SCAN = True                # fall back to a block that carries its own pair

# The ways the derived ATA pair is used, all three from ps3encdec's main.c:
# the slim console's AES-128 XTS with the ATA _es16() swap, the FAT console's
# AES-192 CBC with a zero IV and the same swap, and the model's AES-256 XTS
# (kept so its own images still verify).
MODES = (("ENCDEC slim ATA (AES-128 XTS, bytes swapped)", "xts", 128, True),
         ("FAT ATA (AES-192 CBC, zero IV, bytes swapped)", "cbc", 192, True),
         ("model (AES-256 XTS)", "xts", 256, False))


# ---- AES pieces, the same ones ps3_encdec.py uses ------------------------

def ecb_encrypt(key, block):
    return AES.new(key, AES.MODE_ECB).encrypt(block)


def cbc_decrypt(key, iv, data):
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


def swap16(data):
    """Swap the two bytes of every 16-bit word - the ATA path's byte order.

    ps3encdec's ATA branch runs `_es16_buffer()` over each sector before it
    decrypts (and after it encrypts); the VFLASH branch does not.
    """
    out = bytearray(data)
    for i in range(0, len(out) - 1, 2):
        out[i], out[i + 1] = out[i + 1], out[i]
    return bytes(out)


def xts_decrypt(data_key, tweak_key, sector, buf, keybits=128, swap=False):
    """XTS-AES decrypt one sector: tweak = sector number, little-endian.

    `keybits` and `swap` are the ENCDEC device's: AES-128 over the first 16
    bytes of each derived key, and (ATA only) the 16-bit byte swap.
    """
    if swap:
        buf = swap16(buf)
    data_key = data_key[:keybits // 8]
    tweak_key = tweak_key[:keybits // 8]
    tw = bytearray(16)
    for i in range(8):
        tw[i] = (sector >> (8 * i)) & 0xFF
    tw = bytearray(ecb_encrypt(tweak_key, bytes(tw)))
    out = bytearray(buf)
    for off in range(0, len(out), 16):
        block = bytes(a ^ b for a, b in zip(out[off:off + 16], tw))
        block = AES.new(data_key, AES.MODE_ECB).decrypt(block)
        out[off:off + 16] = bytes(a ^ b for a, b in zip(block, tw))

        carry_in = carry_out = 0
        for i in range(16):
            carry_out = (tw[i] >> 7) & 1
            tw[i] = ((tw[i] << 1) + carry_in) & 0xFF
            carry_in = carry_out
        if carry_out:
            tw[0] ^= 0x87
    return bytes(out)


# ---- reading and looking -------------------------------------------------

def is_device(path):
    """True for a Windows device path, not a plain file.

    A doubled backslash, then a dot or a question mark, then a backslash: the
    `PhysicalDriveN` and `Volume{...}` spellings.  The separator is built with
    chr(92) so this comparison holds no escape sequences of its own.
    """
    bs = chr(92)
    return (len(path) > 4 and path[:2] == bs * 2 and path[2] in ".?"
            and path[3] == bs)


def read_sectors(device, first, count):
    """Read `count` sectors at `first`, through a raw handle.

    `open()` buffers, which a device does not want: a raw disk has to be read
    at its own alignment through a handle opened binary.  The errors are worth
    telling apart too - `PermissionError` is the ordinary "not elevated" case,
    while `ENOENT` from a physical drive that Get-Disk lists means the device
    namespace is not reachable from this process (a sandboxed shell), not that
    the disk is absent.
    """
    need = count * SECTOR
    try:
        fd = os.open(device, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    except PermissionError:
        raise SystemExit("%s: permission denied - a raw device needs an "
                         "elevated shell (an image file does not)" % device)
    except FileNotFoundError:
        raise SystemExit("%s: the device namespace is not reachable here "
                         "(elevate, or run outside a sandbox); the path is "
                         "not a plain file" % device)
    except OSError as e:
        raise SystemExit("%s: %s" % (device, e))
    try:
        os.lseek(fd, first * SECTOR, os.SEEK_SET)
        chunks, left = [], need
        while left:
            block = os.read(fd, min(left, 1 << 20))
            if not block:
                break
            chunks.append(block)
            left -= len(block)
        data = b"".join(chunks)
    except PermissionError:
        raise SystemExit("%s: permission denied - a raw device needs an "
                         "elevated shell (an image file does not)" % device)
    except OSError as e:
        raise SystemExit("%s: %s" % (device, e))
    finally:
        os.close(fd)
    if len(data) != need:
        raise SystemExit("%s: wanted %d bytes at sector %d, got %d"
                         % (device, need, first, len(data)))
    return data


def nonzero_runs(data):
    runs, start = [], None
    for i, b in enumerate(data):
        if b and start is None:
            start = i
        elif not b and start is not None:
            runs.append((start, i - start))
            start = None
    if start is not None:
        runs.append((start, len(data) - start))
    return runs


def ascii_runs(data, shortest=8):
    runs, start = [], None
    for i, b in enumerate(data):
        printable = 0x20 <= b <= 0x7E
        if printable and start is None:
            start = i
        elif not printable and start is not None:
            if i - start >= shortest:
                runs.append((start, i - start))
            start = None
    if start is not None and len(data) - start >= shortest:
        runs.append((start, len(data) - start))
    return runs


def zero_fraction(data):
    return data.count(0) / float(len(data)) if data else 0.0


def pair_candidates(plain):
    """(offset_a, offset_b, how) to try as (ATA data, ATA tweak).

    The model's block is PS3ATA01 at 0x00 and the pair at 0x08/0x28; a console's
    block is not documented here, so every 16-aligned pair is also a candidate -
    the data area itself says which pair is right, which is the point: a wrong
    ERK cannot make any of them open anything.
    """
    pairs = []
    if plain[:8] == MODEL_MAGIC:
        pairs.append((0x08, 0x28, "the model's PS3ATA01 layout"))
    for run_off, run_len in nonzero_runs(plain):
        if run_len == 32 and run_off + 32 <= len(plain):
            pairs.append((run_off, None, "a 32-byte run at 0x%X" % run_off))
    aligned = list(range(0, len(plain) - 32, 0x10))
    for a in aligned:
        for b in aligned:
            if a != b:
                pairs.append((a, b, "aligned windows 0x%X/0x%X" % (a, b)))
    return pairs


def structure(plain):
    """How much a decrypted sector looks like data rather than noise.

    A wrong key gives a uniform 512 bytes: about 2 zeros and no run of 12
    printable characters.  Anything well past that is plaintext.
    """
    text = sum(r[1] for r in ascii_runs(plain, 12))
    return len([b for b in plain if b == 0]), text


def describe(plain, shortest=8):
    runs = nonzero_runs(plain)
    text = ascii_runs(plain, shortest)
    bits = ["zeros %.0f%%" % (100 * zero_fraction(plain)),
            "%d nonzero run(s)" % len(runs)]
    if len(runs) <= 6:
        bits.append("runs " + ", ".join("0x%X+%d" % r for r in runs))
    if text:
        bits.append("ascii " + ", ".join("0x%X+%d" % r for r in text[:4]))
    return "; ".join(bits)


def id16(key):
    return hashlib.sha256(key).hexdigest()[:16]


def derived_ata(erk):
    """The ATA pair from PCK1: AES-256-CBC under the two SB-indiv seeds."""
    import ps3_encdec
    return ps3_encdec.derive(erk, ps3_encdec.SEEDS_DEFAULT)[2:4]


def ata_open(cipher, data_key, tweak_key, sector, buf, keybits=128, swap=True):
    """Decrypt one ATA sector the way the console's ATA path does.

    `cbc' is the FAT console: swap, then AES-192-CBC under the data key with a
    zero IV - the tweak key is not involved.  `xts' is the slim one.
    """
    if swap:
        buf = swap16(buf)
    if cipher == "cbc":
        return cbc_decrypt(data_key[:keybits // 8], bytes(16), buf)
    return xts_decrypt(data_key, tweak_key, sector, buf, keybits, False)


def sector_rows(cipher, data_key, tweak_key, samples, keybits=128, swap=True):
    """(hits, checked, first, rows) over the samples, decrypted with one pair.

    A sector that is all zeros in the raw device was never written: it carries
    no ciphertext, so no key can make it read as data and it must not count
    against the pair.  An unwritten drive would otherwise fail every candidate.
    """
    hits, checked, first, rows = 0, 0, None, []
    for sector, raw in samples.items():
        if not any(raw):
            rows.append((sector, None, raw))
            continue
        checked += 1
        plain = ata_open(cipher, data_key, tweak_key, sector, raw, keybits, swap)
        zeros, text = structure(plain)
        good = zeros >= 24 or text >= 24
        if good:
            hits += 1
            if first is None:
                first = (sector, zeros, text)
        rows.append((sector, good, plain))
    return hits, checked, first, rows


def block_pair(plain):
    """(a, b, how) for the pair a sector-0 block appears to carry, or Nones."""
    if plain[:8] == MODEL_MAGIC:
        return 0x08, 0x28, "the model's PS3ATA01 layout"
    runs = [r for r in nonzero_runs(plain) if r[1] == 32]
    if len(runs) >= 2:
        return runs[0][0], runs[1][0], \
            "the two 32-byte runs at 0x%X/0x%X" % (runs[0][0], runs[1][0])
    return None, None, None


def check_candidate(device, erk, label, samples):
    lines, ok = [], False
    s0 = read_sectors(device, 0, 1)
    wrapped = cbc_decrypt(erk[:32], erk[32:48], s0)
    lines.append("%s" % label)

    # A right pair opens *every* written sample into data; one lucky 15-byte
    # printable run in noise is not a hit (a 512-byte random sector has about
    # two zeros and no 24-byte run), so a pair must score on most of them.
    written = len([s for s in samples.values() if any(s)])
    needed = max(2, (written * 3 + 4) // 5)

    # 1. The pair the console would actually install: derived from PCK1, then
    #    used the way the ENCDEC device is told to use it (AES-128, ATA bytes
    #    swapped) and, second, the way the model does (AES-256, no swap).
    data_key, tweak_key = derived_ata(erk)
    best = None
    for how, cipher, keybits, swap in MODES:
        hits, checked, first, rows = sector_rows(cipher, data_key, tweak_key,
                                                samples, keybits, swap)
        lines.append("  derived   %s: %d of %d nonzero raw samples look structured"
                     % (how, hits, checked))
        if checked and hits >= needed and (best is None or hits > best[0]):
            best = (hits, how, cipher, keybits, first, rows)
    if best is not None:
        ok = True
        _, how, cipher, keybits, (sector, zeros, text), rows = best
        lines.append("  ATA data  id %s (derived, %s)"
                     % (id16(data_key), "AES-%d CBC" % keybits if cipher == "cbc"
                        else "AES-%d XTS" % keybits))
        lines.append("  ATA tweak id %s (derived, %s)"
                     % (id16(tweak_key), "unused by this mode" if cipher == "cbc"
                        else "AES-%d XTS" % keybits))
        lines.append("  heuristic %s: sector %d appears structured (%d zeros, "
                     "%d bytes of text)" % (how, sector, zeros, text))
        for sec, good, plain in rows:
            lines.append("  sector %-6d %s"
                         % (sec, "raw sector all zeros (skipped)" if good is None
                            else describe(plain)))

    # 2. Sector 0, wrapped under PCK1: confirmation, or a disk from elsewhere.
    if zero_fraction(wrapped) >= 0.25:
        pa, pb, how = block_pair(wrapped)
        if pa is None:
            lines.append("  key block mostly empty but carries no pair")
        elif wrapped[pa:pa + 32] == data_key and wrapped[pb:pb + 32] == tweak_key:
            ok = True
            lines.append("  key block %s carries the same pair" % how)
        else:
            lines.append("  key block %s carries a *different* pair "
                         "(model-layout observation only)" % how)
    else:
        lines.append("  sector 0  not a key block: %s" % describe(wrapped))

    # 3. Fallback: a block whose own pair opens the data (model images).
    if not ok and PAIR_SCAN:
        best, tried = None, 0
        for a, b, how in pair_candidates(wrapped):
            pairs = [(a, b)] if b is not None else \
                [(a, other) for other in range(0, len(wrapped) - 32, 0x10)
                 if other != a]
            for pa, pb in pairs:
                tried += 1
                hits, checked, first, rows = sector_rows("xts",
                                                        wrapped[pa:pa + 32],
                                                        wrapped[pb:pb + 32],
                                                        samples, 256, False)
                if checked and hits >= needed and (best is None or hits > best[0]):
                    best = (hits, pa, pb, how, first, rows)
        if best is not None:
            ok = True
            _, pa, pb, how, (sector, zeros, text), rows = best
            lines.append("  key block %s" % how)
            lines.append("  ATA data  id %s (0x%X)" % (id16(wrapped[pa:pa + 32]), pa))
            lines.append("  ATA tweak id %s (0x%X)" % (id16(wrapped[pb:pb + 32]), pb))
            lines.append("  heuristic sector %d appears structured (%d zeros, "
                         "%d bytes of text)" % (sector, zeros, text))
            for sec, good, plain in rows:
                lines.append("  sector %-6d %s"
                             % (sec, "raw sector all zeros (skipped)" if good is None
                                else describe(plain)))
        else:
            lines.append("  block     %d key pair(s) tried, none opens a sector"
                         % tried)

    if not ok and not written:
        lines.append("  verdict   inconclusive: no nonzero raw sector in samples")
        return None, lines
    lines.append("  verdict   %s" % ("heuristic or model-block match; not proof" if ok else
                                    "no heuristic match; inconclusive"))
    return ok, lines


def inspect_device(device):
    """Report only raw sampled-sector statistics; never access a key or write."""
    print("device %s" % device)
    print("mode   read-only raw inspection; no key or decryption")
    failed = 0
    for sector in (0,) + DATA_SECTORS:
        try:
            raw = read_sectors(device, sector, 1)
        except SystemExit as e:
            print("  sector %-6d unavailable: %s" % (sector, e))
            failed += 1
            continue
        print("  sector %-6d raw: %s" % (sector, describe(raw, 12)))
    if failed:
        print("result incomplete: %d of %d sectors could not be read"
              % (failed, len(DATA_SECTORS) + 1))
        return 4
    print("result inspection complete; disk identity and key compatibility not verified")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Read-only disk inspection and model key heuristics.")
    ap.add_argument("--device", required=True,
                    help=r"an image file, or \\.\PhysicalDriveN")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--inspect", action="store_true",
                      help="inspect raw sectors without keys or decryption")
    mode.add_argument("--pck1", action="append",
                      help="48-byte PCK1 (per-console key 1): file, - for "
                           "stdin, or hex; repeatable")
    ap.add_argument("--report", help="also write these findings here")
    ap.add_argument("--save-sector", metavar="FILE",
                    help="write the raw 512 bytes of sector 0 here (the device "
                         "is still only read)")
    args = ap.parse_args(argv)
    if args.inspect and (args.report or args.save_sector):
        ap.error("--inspect is read-only and cannot be combined with --report or --save-sector")

    # Raw device names are not stat-able, so a path in the Windows device
    # namespace passes here and the open reports the truth; a plain path has
    # to exist.  (`startswith("\\\\")` was two levels of escaping too deep: it
    # asked for four leading backslashes, so `\\.\PhysicalDrive1` was rejected
    # as missing before anything tried to open it.)
    if not is_device(args.device) and not os.path.exists(args.device):
        raise SystemExit("%s does not exist" % args.device)

    if args.inspect:
        return inspect_device(args.device)

    out, any_ok, inconclusive = [], False, False
    out.append("device %s" % args.device)
    out.append("warning heuristic results do not prove disk identity or key compatibility")

    raw0 = read_sectors(args.device, 0, 1)
    if args.save_sector:
        with open(args.save_sector, "wb") as f:
            f.write(raw0)
        out.append("sector 0 written to %s" % args.save_sector)
    out.append("sector 0 raw: %s" % describe(raw0))
    for i in range(0, 64, 16):
        row = raw0[i:i + 16]
        out.append("  %04X  %s  %s" % (i, " ".join("%02X" % b for b in row),
                                       "".join(chr(b) if 0x20 <= b < 0x7F else "."
                                               for b in row)))
    sigs = []
    if raw0[510:512] == b"\x55\xaa":
        sigs.append("MBR signature at 0x1FE")
    if not any(raw0):
        sigs.append("all zeros")
    for needle, name in ((b"PS3", "ascii PS3"), (b"NTFS", "NTFS"),
                         (b"EFI PART", "GPT"), (b"PS3ATA01", "the model's block")):
        if needle in raw0:
            sigs.append(name)
    out.append("sector 0 looks: %s"
               % (", ".join(sigs) if sigs else "no plaintext signature"))

    # The samples, before any key is tried: a PS3 disk is encrypted from LBA 0
    # to the end, so every one of them is uniform ciphertext.  Plaintext here
    # would mean the disk is not (or is no longer) a console's disk.
    samples = {}
    for sector in DATA_SECTORS:
        try:
            samples[sector] = read_sectors(args.device, sector, 1)
        except SystemExit as e:
            out.append("  sector %-6d %s" % (sector, e))
            continue
        out.append("  sector %-6d raw: %s"
                   % (sector, describe(samples[sector], 12)))
    for spec in args.pck1:
        if spec == "-":
            erk = sys.stdin.buffer.read(ERK_SIZE)
            label = "PCK1 from stdin"
        elif os.path.isfile(spec):
            with open(spec, "rb") as f:
                erk = f.read(ERK_SIZE + 1)
            label = "PCK1 %s" % os.path.basename(spec)
        else:
            erk = bytes.fromhex("".join(spec.split()))
            label = "PCK1 from the command line"
        if len(erk) != ERK_SIZE:
            out.append("%s: %d bytes, not 48 - skipped" % (label, len(erk)))
            continue
        ok, lines = check_candidate(args.device, erk, label, samples)
        any_ok = any_ok or bool(ok)
        inconclusive = inconclusive or ok is None
        out.extend(lines)

    if any_ok:
        out.append("result heuristic or model-block match; disk identity is unverified")
    elif inconclusive:
        out.append("result inconclusive: no nonzero raw sector in samples")
    else:
        out.append("result no heuristic match; key and disk compatibility are inconclusive")
    text = "\n".join(out)
    print(text)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    return 0 if any_ok else (4 if inconclusive else 3)


if __name__ == "__main__":
    sys.exit(main())
