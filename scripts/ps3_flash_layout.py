#!/usr/bin/env python3
"""
PS3 flash image helper for the rs6000-ps3 model.

The NOR/NAND maps in FLASH_LAYOUT.md (ps3tools) are what the model boots from:
the mask ROM reads `bootldr` and the asecure_loader entry table at fixed
offsets, and none of that is described by the flash's own table of contents.
This script owns those offsets in one place so a flash image can be inspected,
carved and rebuilt without hand-copying them:

    ps3_flash_layout.py list nor
    ps3_flash_layout.py dump .tmp/bootchain_flash.bin
    ps3_flash_layout.py get bootldr=.tmp/lv0ldr2.bin .tmp/bootchain_flash.bin
    ps3_flash_layout.py build nor --base .tmp/4301c_flash493.bin \\
        --put bootldr=.tmp/lv0ldr2.bin -o .tmp/rebuild.bin

A `--put` file is placed verbatim at the region's documented offset; sealing a
stage into its container is the caller's job (the model's norbuild path, or the
loader itself), because the container's key comes from the console, not from
this tree.  Everything here is offsets and bounds checks - no keys, no Sony
code.
"""
import argparse
import hashlib
import os
import struct
import sys

MiB = 1024 * 1024

SELE_MAGIC = b"SCE\0"
FLASH_TOC_OFFSETS = (0x400, 0x200, 0x40200)

# Region name, NOR offset, NAND offset, size.  None means "not in this map".
# Offsets are flash offsets, i.e. what the mask ROM and lv0 address.
REGIONS = [
    ("asecure_loader", 0x000800, 0x040800, 0x2E800),
    ("trvk_prg0", 0x040000, 0x091820, 0x2C0),
    ("trvk_prg1", 0x060000, 0x092810, 0x2E0),
    ("trvk_prg_hdr", None, 0x091800, 0x20),
    ("extnor", 0xF20000, None, 0x20000),
    ("crl1", 0xF40000, None, 0x40),
    ("drl1", 0xF60000, None, 0x40),
    ("crl2", 0xF80000, None, 0x40),
    ("drl2", 0xFA0000, None, 0x40),
    ("ocrl", 0xF69400, None, 0x130),
    ("bootldr", 0xFC0000, 0x000000, 0x40000),
]

MAPS = {
    "nor": {"size": 16 * MiB,
            "toc": 0x400,
            "note": "16 MiB NOR dump; bootldr sits at the top"},
    "nand": {"size": 0x10000000,
             "toc": 0x200,
             "note": "256 MiB NAND image; a software dump made from GameOS "
                     "starts at flash 0x40000 and has no bootldr"},
}


def be32(data, off):
    return struct.unpack_from(">I", data, off)[0]


def be64(data, off):
    return struct.unpack_from(">Q", data, off)[0]


def region_offset(name, which):
    for rname, nor, nand, size in REGIONS:
        if rname == name:
            off = nor if which == "nor" else nand
            if off is None:
                raise SystemExit("%s is not part of the %s map" % (name, which))
            return off, size
    raise SystemExit("no such region: %s (try --list)" % name)


def detect_map(data):
    size = len(data)
    if size == 16 * MiB:
        return "nor"
    # A NAND dump is either the full map or a GameOS dump that starts at
    # flash 0x40000; both have the boot header after the TOC.
    if size > 0x8000000:
        return "nand"
    return "nor"


def find_toc(data):
    for off in FLASH_TOC_OFFSETS:
        if off + 0x10 > len(data):
            continue
        n = be32(data, off + 0x04)
        if 1 <= n <= 64 and off + 0x10 + n * 0x30 <= len(data):
            return off
    return None


def toc_entries(data, base):
    n = be32(data, base + 0x04)
    out = []
    for i in range(n):
        at = base + 0x10 + i * 0x30
        name = data[at:at + 0x20].split(b"\0")[0].decode("latin-1")
        rel = be64(data, at + 0x20)
        size = be64(data, at + 0x28)
        out.append((name, base + rel, size))
    return out


def block_header(data, off):
    """The container header both metldr and bootldr carry."""
    if off + 0x40 > len(data):
        return None
    blocks = be32(data, off)
    total = be32(data, off + 0x08)
    counter = data[off + 0x10:off + 0x1C].hex().upper()
    if not blocks or blocks > 0x100000 or total > 0x100000:
        return None
    return blocks, total, counter, blocks * 0x10 + 0x40


def show_region(name, off, size, data):
    if off + size > len(data):
        print("  %-16s 0x%08X  %8X  (outside the image)" % (name, off, size))
        return
    part = data[off:off + size]
    if part.count(0) == size:
        state = "zeroed"
    elif part.count(0xFF) == size:
        state = "FF (erased)"
    elif part[:4] == SELE_MAGIC or (len(part) > 0x10 and
                                    part[0x10:0x14] == SELE_MAGIC):
        state = "SELF"
    else:
        state = "data"
    extra = ""
    hdr = block_header(data, off)
    if hdr:
        blocks, total, counter, span = hdr
        extra = ", container %d blocks + 0x40 = 0x%X" % (blocks, span)
    print("  %-16s 0x%08X  %8X  %-10s%s" % (name, off, size, state, extra))


def cmd_list(args):
    for which in ([args.map] if args.map else ["nor", "nand"]):
        print("%s: %s, TOC at 0x%X" % (which, MAPS[which]["note"],
                                       MAPS[which]["toc"]))
        for name, nor, nand, size in REGIONS:
            off = nor if which == "nor" else nand
            if off is None:
                continue
            print("  %-16s 0x%08X  %8X" % (name, off, size))
        print()


def cmd_dump(args):
    data = open(args.image, "rb").read()
    which = args.map or detect_map(data)
    print("%s: %d bytes (%s)" % (args.image, len(data), which))

    base = find_toc(data)
    if base is None:
        print("  no flash TOC found")
    else:
        print("  TOC at 0x%X" % base)
        for name, off, size in toc_entries(data, base):
            if off + size > len(data):
                print("    %-16s 0x%08X  %8X  (outside the image)" %
                      (name, off, size))
                continue
            magic = data[off + 0x10:off + 0x14] if size > 0x14 else b""
            kind = "SELF" if magic == SELE_MAGIC else ""
            print("    %-16s 0x%08X  %8X  %s" % (name, off, size, kind))

    print("  documented regions:")
    for name, nor, nand, size in REGIONS:
        off = nor if which == "nor" else nand
        if off is None:
            continue
        show_region(name, off, size, data)
    print("  sha256 %s" % hashlib.sha256(data).hexdigest())


def cmd_get(args):
    data = open(args.image, "rb").read()
    which = args.map or detect_map(data)
    for item in args.region:
        name, _, path = item.partition("=")
        if not path:
            raise SystemExit("--get wants region=FILE")
        off, size = region_offset(name, which)
        if off + size > len(data):
            raise SystemExit("%s is outside the image" % name)
        with open(path, "wb") as f:
            f.write(data[off:off + size])
        print("%s: %s, 0x%X bytes from 0x%X" % (path, name, size, off))


def cmd_build(args):
    which = args.map
    if which not in MAPS:
        raise SystemExit("--build wants nor or nand")
    if args.base:
        data = bytearray(open(args.base, "rb").read())
        if len(data) < MAPS[which]["size"]:
            print("note: base is 0x%X bytes, extending to the %s map size" %
                  (len(data), which))
            data.extend(b"\xFF" * (MAPS[which]["size"] - len(data)))
    else:
        data = bytearray(b"\xFF" * MAPS[which]["size"])

    for item in args.put or []:
        name, _, path = item.partition("=")
        if not path:
            raise SystemExit("--put wants region=FILE")
        off, size = region_offset(name, which)
        blob = open(path, "rb").read()
        if len(blob) > size:
            raise SystemExit("%s is 0x%X bytes, region %s holds 0x%X" %
                             (path, len(blob), name, size))
        data[off:off + len(blob)] = blob
        print("  %-16s 0x%08X  %8X  <- %s" % (name, off, len(blob), path))

    for name in args.erase or []:
        off, size = region_offset(name, which)
        data[off:off + size] = b"\xFF" * size
        print("  %-16s 0x%08X  %8X  erased" % (name, off, size))

    with open(args.output, "wb") as f:
        f.write(data)
    print("%s: %d bytes, sha256 %s" %
          (args.output, len(data), hashlib.sha256(data).hexdigest()))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list", help="print the documented region map")
    p.add_argument("--map", choices=sorted(MAPS))
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("dump", help="TOC entries and documented regions")
    p.add_argument("image")
    p.add_argument("--map", choices=sorted(MAPS))
    p.set_defaults(func=cmd_dump)

    p = sub.add_parser("get", help="carve regions out of an image")
    p.add_argument("image")
    p.add_argument("region", nargs="+", metavar="NAME=FILE")
    p.add_argument("--map", choices=sorted(MAPS))
    p.set_defaults(func=cmd_get)

    p = sub.add_parser("build", help="place files at the documented offsets")
    p.add_argument("map", choices=sorted(MAPS))
    p.add_argument("--base", help="image to start from (default: erased)")
    p.add_argument("--put", action="append", metavar="NAME=FILE")
    p.add_argument("--erase", action="append", metavar="NAME")
    p.add_argument("-o", "--output", required=True)
    p.set_defaults(func=cmd_build)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
