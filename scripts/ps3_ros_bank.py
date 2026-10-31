#!/usr/bin/env python3
"""
Read and write the ros recovery banks of a PS3 flash image.

A NOR image keeps two 0x700000-byte recovery banks (`ros0` at 0xC0000 and
`ros1` at 0x7C0000, or the `ros` region the flash table names).  Each bank is
the console's copy of the firmware the update installer writes:

    +0x00  the bank's own header (0x10 in a NOR carve, 0x20 for a NAND `ros`
           region; ros0 also carries the region's 0x20-byte header in front)
    +...   the CORE_OS package's `content` image, verbatim
           +0x00  u32 version, u32 entry count, u32 0, u32 size
           +0x10  count * 0x30 entries { u64 offset, u64 size, char name[32] }
           +...   the files

So the content header is at 0x10 in a NOR carve, at 0x20 for ros1 of a NAND
region and at 0x30 for ros0 (region header + bank header).  `fs_base` finds it
by the entry count, and `install` writes the new content back at the same
offset, so the bank keeps the shape the console's flash has.

One difference between the two: a bank record for a SELF carries a record
header in front of the container (0x10 in a NOR carve, 0x30 in a NAND `ros`
bank; the carves a flash tool writes out have it stripped, which is why a
dump's `emer_init.self` begins "SCE\\0" and a bank's begins earlier), and the
entry's offset points at that header.  The package's `content` has no such
headers.  `install` therefore takes the prefix each file's record already had
in the bank and puts it in front of the new payload, so a replaced file keeps
the record form the console's own bank used.

Usage:
    ps3_ros_bank.py list FLASH
    ps3_ros_bank.py get FLASH NAME -o OUT [--bank 0|1]
    ps3_ros_bank.py install FLASH --content CONTENT [-o OUT] [--banks both]
    ps3_ros_bank.py compare FLASH-A FLASH-B
"""

from __future__ import annotations

import argparse
import struct
import sys

BANK_SIZE = 0x700000
NOR_BANKS = (0x0C0000, 0x7C0000)
SELF_MAGIC = (b"SCE\x00", b"\x7fELF")


def be32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def be64(b, o):
    return struct.unpack_from(">Q", b, o)[0]


def put32(b, o, v):
    struct.pack_into(">I", b, o, v)


def put64(b, o, v):
    struct.pack_into(">Q", b, o, v)


def banks(flash):
    """The (offset, length, name) of each recovery bank in the image."""
    if len(flash) >= 0x210 and be32(flash, 0x200) == 1:
        count = be32(flash, 0x204)
        if 0 < count <= 64:
            for i in range(count):
                e = 0x210 + i * 0x30
                if e + 0x30 > len(flash):
                    break
                name = flash[e + 0x10:e + 0x30].split(b"\x00")[0]
                if name != b"ros":
                    continue
                at = 0x200 + be64(flash, e)
                size = be64(flash, e + 8)
                if at >= len(flash):
                    return []
                size = min(size, len(flash) - at)
                out = []
                while size >= BANK_SIZE and len(out) < 2:
                    out.append((at, BANK_SIZE, "ros"))
                    at += BANK_SIZE
                    size -= BANK_SIZE
                if size and len(out) < 2:
                    out.append((at, size, "ros"))
                return out
    return [(off, BANK_SIZE, "ros%d" % i) for i, off in enumerate(NOR_BANKS)
            if off + BANK_SIZE <= len(flash)]


def fs_base(bank):
    """Where the CORE_OS content header starts inside a bank.

    The header is `u32 version, u32 count, u32 0, u32 size`, then the entries.
    What sits in front of it differs: a NOR carve has the bank's 0x10-byte
    record header (so content at 0x10); a NAND/eMMC `ros` region puts a
    0x20-byte region header in front of ros0 *and* the bank's record header
    after it (ros0 content at 0x30), while ros1 has no second region header
    (content at 0x20).  The entry count is what tells them apart.
    """
    for base in (0x30, 0x20, 0x10, 0):
        if base + 0x14 > len(bank):
            continue
        count = be32(bank, base + 0x04)
        if 0 < count <= 0x100:
            return base
    raise SystemExit("no CORE_OS header in the bank (entry count is not sane)")


def entries(bank):
    """[(name, offset, size, prefix)] for a bank's files.

    `prefix` is the record header in front of the payload (0x10 in a NOR carve,
    0x30 in a NAND `ros` bank), or b"" when the record starts with the
    container itself (a carve that has no header).
    """
    base = fs_base(bank)
    count = be32(bank, base + 0x04)
    out = []
    for i in range(count):
        e = base + 0x10 + i * 0x30
        off = be64(bank, e)
        size = be64(bank, e + 8)
        name = bank[e + 0x10:e + 0x30].split(b"\x00")[0].decode("latin-1")
        rec = bank[off:off + size]
        if rec[:4] in SELF_MAGIC:
            prefix = b""
        elif rec[0x30:0x34] in SELF_MAGIC:
            prefix = bytes(rec[:0x30])
        elif rec[0x10:0x14] in SELF_MAGIC:
            prefix = bytes(rec[:0x10])
        else:
            prefix = None            # not a container: stored as it is
        out.append((name, off, size, prefix))
    return out


def payload(bank, name):
    for entry in entries(bank):
        if entry[0] != name:
            continue
        rec = bank[entry[1]:entry[1] + entry[2]]
        if entry[3] is None:
            return bytes(rec)
        return bytes(rec[len(entry[3]):])
    raise SystemExit("no %s in the bank" % name)


def read_content(blob):
    """[(name, payload)] from a CORE_OS `content` image."""
    if len(blob) < 0x20:
        raise SystemExit("content image is too short")
    count = be32(blob, 0x04)
    if not 0 < count <= 0x100:
        raise SystemExit("content image has no sane entry count")
    out = []
    for i in range(count):
        e = 0x10 + i * 0x30
        off = be64(blob, e)
        size = be64(blob, e + 8)
        name = blob[e + 0x10:e + 0x30].split(b"\x00")[0].decode("latin-1")
        if off + size > len(blob):
            raise SystemExit("%s runs past the content image" % name)
        out.append((name, blob[off:off + size]))
    return out


def build_bank(old_bank, content):
    """A bank image carrying `content`, keeping each record's own header.

    The order is the bank's own, not the package's: the first record starts
    0x10 before the end of the table, inside the last entry's name field, which
    is why the console's table ends with a short name (`pkg.srvk`) and the
    package's alphabetical order (ending in `sv_iso_spu_module.self`) would be
    cut by that header.
    """
    payloads = dict(content)
    prefix = {}
    order = []
    for name, _off, _size, pre in entries(old_bank):
        prefix[name] = pre
        order.append(name)
    order += [n for n in payloads if n not in prefix]

    base = max(fs_base(old_bank), 0x10)
    count = len(order)
    data_start = base + 0x10 + count * 0x30
    records = []
    at = data_start
    for name in order:
        before = prefix.get(name)
        head = b"" if before is None else before
        rec = head + payloads[name]
        records.append((name, at, len(rec)))
        at += len(rec)
    if at > BANK_SIZE:
        raise SystemExit("the files need 0x%X bytes; the bank is 0x%X"
                         % (at, BANK_SIZE))

    bank = bytearray(b"\xff" * BANK_SIZE)
    # Whatever sits in front of the content (a region header) is kept as the
    # console wrote it; the bank's record header is rewritten below.
    bank[0:base - 0x10] = old_bank[0:base - 0x10]
    # The bank's own record header, then the CORE_OS image header.
    put64(bank, base - 0x10, 0)
    put64(bank, base - 0x08, at - base)
    put32(bank, base + 0x00, be32(old_bank, base))
    put32(bank, base + 0x04, count)
    put32(bank, base + 0x08, 0)
    put32(bank, base + 0x0C, at - base)

    for i, (name, off, size) in enumerate(records):
        e = base + 0x10 + i * 0x30
        put64(bank, e, off)
        put64(bank, e + 8, size)
        raw = name.encode("latin-1")[:31]
        bank[e + 0x10:e + 0x30] = b"\x00" * 0x20
        bank[e + 0x10:e + 0x10 + len(raw)] = raw

    for name, off, size in records:
        head = prefix.get(name)
        rec = (b"" if head is None else head) + payloads[name]
        bank[off:off + len(rec)] = rec

    return bytes(bank)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list", help="list a bank's files")
    p.add_argument("flash")
    p.add_argument("--bank", type=int, default=0, choices=(0, 1))

    p = sub.add_parser("get", help="write one file out of a bank")
    p.add_argument("flash")
    p.add_argument("name")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--bank", type=int, default=0, choices=(0, 1))

    p = sub.add_parser("install", help="put a CORE_OS content image in the banks")
    p.add_argument("flash")
    p.add_argument("--content", required=True)
    p.add_argument("-o", "--out")
    p.add_argument("--banks", default="both", choices=("both", "0", "1"))
    p.add_argument("--in-place", action="store_true")

    p = sub.add_parser("compare", help="say which files differ between two images")
    p.add_argument("flash_a")
    p.add_argument("flash_b")

    args = ap.parse_args(argv)

    if args.cmd == "compare":
        a = open(args.flash_a, "rb").read()
        b = open(args.flash_b, "rb").read()
        if not banks(a) or not banks(b):
            raise SystemExit("no recovery bank in one of the images")
        for bank, (off, size, name) in enumerate(banks(a)):
            print("%s:" % name)
            for fname, _o, _s, _p in entries(a[off:off + size]):
                pa = payload(a[off:off + size], fname)
                pb = payload(b[off:off + size], fname)
                print("  %-34s %s" % (fname, "same" if pa == pb else
                                      "DIFFERS (%d -> %d bytes)"
                                      % (len(pa), len(pb))))
        return 0

    flash = open(args.flash, "rb").read()

    if args.cmd == "list":
        found = banks(flash)
        if not found:
            raise SystemExit("no recovery bank in %s" % args.flash)
        off, size, name = found[args.bank]
        bank = flash[off:off + size]
        print("%s: %s at 0x%X, 0x%X bytes" % (args.flash, name, off, size))
        for fname, foff, fsize, pre in entries(bank):
            form = "raw" if pre is None else ("record" if pre else "bare")
            print("  %-34s 0x%08X 0x%08X %s" % (fname, foff, fsize, form))
        return 0

    if args.cmd == "get":
        found = banks(flash)
        off, size, _name = found[args.bank]
        data = payload(flash[off:off + size], args.name)
        open(args.out, "wb").write(data)
        print("%s: %d bytes from %s bank %d -> %s"
              % (args.name, len(data), args.flash, args.bank, args.out))
        return 0

    if args.cmd == "install":
        found = banks(flash)
        if not found:
            raise SystemExit("no recovery bank in %s" % args.flash)
        content = read_content(open(args.content, "rb").read())
        image = bytearray(flash)
        wanted = range(len(found)) if args.banks == "both" else [int(args.banks)]
        for i in wanted:
            off, size, name = found[i]
            bank = build_bank(flash[off:off + size], content)
            image[off:off + size] = bank
            print("%s bank %s at 0x%X: %d files installed"
                  % (args.flash, name, off, len(content)))
        out = args.out or (args.flash if args.in_place else None)
        if not out:
            raise SystemExit("give -o OUT (or --in-place)")
        open(out, "wb").write(image)
        print("wrote %s (%d bytes)" % (out, len(image)))
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
