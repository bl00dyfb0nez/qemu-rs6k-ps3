#!/usr/bin/env python3
"""
PS3 flash image helper for the rs6000-ps3 model.

A console's NOR/NAND is described in two independent ways, and the model needs
both: the flash's own table of contents (which is what a dump carries and what
the flash writer patches), and the fixed offsets the mask boot ROM uses before
it has parsed anything (metldr at 0x840, and the container the ROM opens at
0xFC0000, whose own name string is `lv0ldr.2`).  This script owns those layouts
in one place so an image can be inspected, carved and rebuilt without
hand-copying offsets:

    ps3_flash_layout.py list nor
    ps3_flash_layout.py dump  .tmp/bootchain_flash.bin
    ps3_flash_layout.py get   .tmp/bootchain_flash.bin --all .tmp/carve
    ps3_flash_layout.py get   .tmp/bootchain_flash.bin metldr=.tmp/metldr.bin
    ps3_flash_layout.py build nor --from .tmp/carve --toc -o .tmp/flash.bin
    ps3_flash_layout.py build nor --base .tmp/dump.bin \\
        --put bootldr=.tmp/lv0ldr2.bin --toc -o .tmp/rebuild.bin

`get --all` writes every documented region of an image into a directory;
`build --from` places those files back at their documented offsets, and
`--toc` regenerates the flash table of contents from the same table so the
result is self-describing again.  A region that is not in the map (e.g. a
carved `metldr`) has to be placed with `--put` at its documented slot.  A NAND
dump made from GameOS starts at flash 0x40000, so `get` detects that base on
its own and `build nand --flash-base 0x40000` writes at the same one.

Layouts (all big-endian, from the flash section of the ps3tools notes):

  flash TOC, at 0x400 on NOR (0x200 in a NAND dump that starts at flash
  0x40000): u32 magic, u32 entry count, u32 zero, u32 end offset relative to
  the TOC base; then 0x30-byte entries of u64 offset (relative to the base),
  u64 size, char name[0x20].

  asecure_loader, at 0x800: u32 magic, u32 count, u64 region length; then
  0x20-byte entries of u64 offset (relative to the header), u64 length, name.
  The first entry is `metldr`, whose own container follows at header+0x40.

  a container (metldr.2, lv0ldr.2): u32 encrypted blocks at 0x00, 12-byte
  counter suffix at 0x04, u32 total blocks at 0x10, 12-byte nonce at 0x14,
  16-byte key-derivation input at 0x20, 16-byte masked tag at 0x30, body at
  0x40; the container's span is total * 16 + 0x40.

Nothing here carries a key or decrypts anything: sealing a stage back into its
container is the loader's (or spu_rom/norbuild.py's) job, because the key is
the console's, not this tree's.  Everything below is offsets and bounds checks.

The channel-66 key is not part of any of this.  It belongs to the *mask boot
ROM* (the 0x400 bytes the SPUs execute first): the ROM reads those 32 bytes on
its own channel 66, expands them into the key ladder and opens the flash
container with them.  It is not stored in metldr, not in bootldr, and not
anywhere in the flash regions this script maps - a dump carries no copy of it,
which is why the model takes it as `readout`/`readout-file`.  The name this
script (and the older flash-writer patches) use for the 0xFC0000 slot is kept
only so existing commands keep working: what sits there is the container the
ROM opens, and its own name string says `lv0ldr.2`.

ch66 is public (it is the container key), but the per-console key is one level
in: **PCK1** (the EID root key, `per_console_root_key_1`) is derived from the
channel-66 readout (PCK0) by `metldr` and carried in `metldr`; `lv0ldr.2` is
metldr's next stage and may carry a copy.  PCK1 is what the loaders run the ATA
and flash ladders on, and what `ps3_hdd_create.py` wraps the key sector under.
So this script maps the container's slots; `ps3_emmc_create.py --identify` reads
the loader carrier (`ros`, `lv0`, `lv0.2`) out of the flash it maps.
"""
import argparse
import hashlib
import os
import struct
import sys

MiB = 1024 * 1024
SECTOR = 512

SELE_MAGIC = b"SCE\0"
TOC_MAGICS = {0x400, 0x200, 0x40200}

# name, NOR offset, NAND offset, size.  None means "not part of that map".
# NOR offsets are the ones a dump carries; NAND offsets are flash offsets, so
# a software dump that starts at flash 0x40000 has them 0x40000 lower.
REGIONS = [
    ("asecure_loader", 0x000800, 0x040800, 0x2E800),
    ("eEID",           0x02F000, None,     0x10000),
    ("cISD",           0x03F000, None,     0x800),
    ("cCSD",           0x03F800, None,     0x800),
    ("trvk_prg0",      0x040000, 0x091820, 0x2C0),
    ("trvk_prg1",      0x060000, 0x092810, 0x2E0),
    ("trvk_prg_hdr",   None,     0x091800, 0x20),
    ("trvk_pkg0",      0x080000, None,     0x20000),
    ("trvk_pkg1",      0x0A0000, None,     0x20000),
    ("ros0",           0x0C0000, None,     0x700000),
    ("ros1",           0x7C0000, None,     0x700000),
    ("cvtrm",          0xEC0000, None,     0x40000),
    ("extnor",         0xF20000, None,     0x20000),
    ("crl1",           0xF40000, None,     0x40),
    ("drl1",           0xF60000, None,     0x40),
    ("crl2",           0xF80000, None,     0x40),
    ("drl2",           0xFA0000, None,     0x40),
    ("ocrl",           0xF69400, None,     0x130),
    # The container the mask boot ROM opens (0xFC0000 on NOR).  The model's
    # chain check finds it by its own name string, `lv0ldr.2`; the key that
    # opens it is the ROM's channel-66 readout, not anything in this slot.
    ("bootldr",        0xFC0000, 0x000000, 0x40000),
]

# The entries a NOR table of contents lists, in the order a dump lists them,
# with the slot size each entry carries.  A slot is not the region's data
# length: trvk_prg0 holds a 0x2C0 revocation record in a 0x20000 slot, and the
# flash writer patches these slots in place.  The container slot at 0xFC0000
# is deliberately absent: the ROM finds it by fixed offset and the table never
# mentions it.  `ros` is
# one 0xE00000 NAND entry instead of the two NOR banks, which is why NAND
# tables are copied from a dump rather than built.
TOC_LAYOUT = [
    ("asecure_loader", 0x000800, 0x2E800),
    ("eEID",           0x02F000, 0x10000),
    ("cISD",           0x03F000, 0x800),
    ("cCSD",           0x03F800, 0x800),
    ("trvk_prg0",      0x040000, 0x20000),
    ("trvk_prg1",      0x060000, 0x20000),
    ("trvk_pkg0",      0x080000, 0x20000),
    ("trvk_pkg1",      0x0A0000, 0x20000),
    ("ros0",           0x0C0000, 0x700000),
    ("ros1",           0x7C0000, 0x700000),
    ("cvtrm",          0xEC0000, 0x40000),
]

MAPS = {
    "nor": {"size": 16 * MiB,
            "toc": 0x400,
            "note": "16 MiB NOR dump; the container the ROM opens "
                    "(lv0ldr.2) sits at the top"},
    "nand": {"size": 0x10000000,
             "toc": 0x200,
             "note": "256 MiB NAND image or a GameOS dump that starts at "
                     "flash 0x40000 (then every offset is 0x40000 lower)"},
}

ALIASES = {"OCRL0200": "ocrl", "extnor_area": "extnor",
           "CELL_EXTNOR_AREA": "extnor", "trvk_prg": "trvk_prg_hdr",
           # A dump that names the slot by its container says lv0ldr.2.
           "lv0ldr.2": "bootldr", "lv0ldr": "bootldr"}


def read_blob(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        raise SystemExit("cannot read %s: %s" % (path, e.strerror or e))


def be32(data, off):
    return struct.unpack_from(">I", data, off)[0]


def be64(data, off):
    return struct.unpack_from(">Q", data, off)[0]


def region_entry(name):
    name = ALIASES.get(name, name)
    for rname, nor, nand, size in REGIONS:
        if rname == name:
            return rname, nor, nand, size
    raise SystemExit("no such region: %s (try `list`)" % name)


def region_offset(name, which):
    rname, nor, nand, size = region_entry(name)
    off = nor if which == "nor" else nand
    if off is None:
        raise SystemExit("%s is not part of the %s map" % (rname, which))
    return off, size


def region_slot(name, which):
    """Where a file for `name` goes and how much room it has."""
    rname = ALIASES.get(name, name)
    if which == "nor":
        for sname, off, size in TOC_LAYOUT:
            if sname == rname:
                return off, size
    return region_offset(rname, which)


def detect_map(data):
    if len(data) == 16 * MiB:
        return "nor"
    return "nand"


def dump_base(data):
    """A NAND dump made from GameOS starts at flash 0x40000."""
    if len(data) == 16 * MiB:
        return 0
    if data[:4] in (b"\xFA\xCE\x0F\xFF", b"\xFA\xCE\x0F\xFE"):
        return 0x40000
    return 0


def find_toc(data):
    for off in sorted(TOC_MAGICS):
        if off + 0x10 > len(data):
            continue
        magic = be32(data, off)
        n = be32(data, off + 4)
        if magic == 1 and 1 <= n <= 64 and off + 0x10 + n * 0x30 <= len(data):
            return off
    return None


def toc_entries(data, base):
    n = be32(data, base + 4)
    out = []
    for i in range(n):
        at = base + 0x10 + i * 0x30
        name = data[at + 0x10:at + 0x30].split(b"\0")[0].decode("latin-1")
        out.append((name, base + be64(data, at), be64(data, at + 0x08)))
    return out


def asecure_entries(data, base=0x800):
    """The asecure_loader header's own file table (metldr lives behind it)."""
    if base + 0x10 > len(data):
        return None, []
    magic = be32(data, base)
    count = be32(data, base + 4)
    length = be64(data, base + 8)
    if magic != 1 or not (1 <= count <= 32):
        return None, []
    if base + 0x10 + count * 0x20 > len(data):
        return None, []
    out = []
    for i in range(count):
        at = base + 0x10 + i * 0x20
        name = data[at + 0x10:at + 0x30].split(b"\0")[0].decode("latin-1")
        out.append((name, base + be64(data, at), be64(data, at + 0x08)))
    return length, out


def container_header(data, off):
    """
    The block header metldr, bootldr and every stage share.  Returns
    (encrypted blocks, total blocks, suffix hex, span) or None if the bytes
    there cannot be one.
    """
    if off + 0x40 > len(data):
        return None
    encrypted = be32(data, off)
    total = be32(data, off + 0x10)
    # A stage container is fully encrypted and agrees with itself; a ros bank
    # header (size at +0x08, version 1 at +0x10) fails the first test, and a
    # partly-encrypted blob (eEID, cISD) fails it too.
    if not total or total > 0x100000 or encrypted != total:
        return None
    return (encrypted, total, data[off + 4:off + 0x10].hex().upper(),
            total * 0x10 + 0x40)


def ros_bank(off, size, data, at):
    if at + 0x20 > len(data):
        return None
    bank_size = be64(data, at + 0x08)
    version = be32(data, at + 0x10)
    count = be32(data, at + 0x14)
    if version == 1 and 1 <= count <= 64 and 0 < bank_size <= size:
        return bank_size, count
    return None


def show_region(name, off, size, data, base):
    at = off - base if base else off
    if at < 0 or at + size > len(data):
        print("  %-16s 0x%08X  %8X  (outside the image)" % (name, off, size))
        return
    part = data[at:at + size]
    container = container_header(data, at)
    bank = ros_bank(off, size, data, at)
    if name == "asecure_loader" and part[:4] == b"\0\0\0\1":
        state = "asec header"
        extra = " %d entr%s, region 0x%X" % (
            be32(data, at + 4), "y" if be32(data, at + 4) == 1 else "ies",
            be64(data, at + 8))
    elif container:
        enc, total, suffix, span = container
        state = "container"
        extra = (" %u/%u blocks + 0x40 = 0x%X, suffix %s"
                 % (enc, total, span, suffix))
    elif part.count(0) == size:
        state, extra = "zeroed", ""
    elif part.count(0xFF) == size:
        state, extra = "FF (erased)", ""
    elif part[:4] == SELE_MAGIC or part[0x10:0x14] == SELE_MAGIC:
        state, extra = "SELF", ""
    elif bank:
        state = "ros bank"
        extra = " 0x%X bytes, %d entr%s" % (bank[0], bank[1],
                                            "y" if bank[1] == 1 else "ies")
    else:
        state, extra = "data", ""
    print("  %-16s 0x%08X  %8X  %-11s%s" % (name, off, size, state, extra))


def cmd_list(args):
    which_one = args.map or args.map_opt
    for which in ([which_one] if which_one else ["nor", "nand"]):
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
    base = dump_base(data)
    print("%s: %d bytes (%s%s)" % (args.image, len(data), which,
                                   ", dump base 0x%X" % base if base else ""))

    toc = find_toc(data)
    if toc is None:
        print("  no flash TOC found")
    else:
        print("  TOC at 0x%X: %d entries, ends at 0x%X" %
              (toc, be32(data, toc + 4), toc + be32(data, toc + 0x0C)))
        for name, off, size in toc_entries(data, toc):
            if off + size > len(data):
                print("    %-16s 0x%08X  %8X  (outside the image)" %
                      (name, off, size))
                continue
            kind = ""
            if data[off:off + 4] == SELE_MAGIC or \
                    data[off + 0x10:off + 0x14] == SELE_MAGIC:
                kind = "SELF"
            elif container_header(data, off):
                kind = "container"
            elif ros_bank(off, size, data, off):
                kind = "ros bank"
            print("    %-16s 0x%08X  %8X  %s" % (name, off, size, kind))

    length, entries = asecure_entries(data, 0x800 - base if base else 0x800)
    if entries:
        print("  asecure_loader at 0x%X: region 0x%X bytes, %d entr%s" %
              (0x800, length or 0, len(entries),
               "y" if len(entries) == 1 else "ies"))
        for name, off, size in entries:
            span = container_header(data, off - base if base else off)
            detail = ""
            if span:
                detail = (", container %u blocks + 0x40 = 0x%X"
                          % (span[1], span[3]))
            print("    %-16s 0x%08X  %8X%s" % (name, off, size, detail))

    print("  documented regions:")
    for name, nor, nand, size in REGIONS:
        off = nor if which == "nor" else nand
        if off is None:
            continue
        show_region(name, off, size, data, base)
    print("  sha256 %s" % hashlib.sha256(data).hexdigest())


def carve(data, base, which, name, path):
    if name == "metldr":
        length, entries = asecure_entries(data, 0x800 - base)
        for ename, off, size in entries:
            # The asecure table names the loader after its own revision, so a
            # 3.60+ dump says metldr.2 where an older one says metldr.
            if not ename.startswith("metldr"):
                continue
            at = off - base
            hdr = container_header(data, at)
            span = hdr[3] if hdr else size
            if at < 0 or at + span > len(data):
                raise SystemExit("metldr is outside the image")
            with open(path, "wb") as f:
                f.write(data[at:at + span])
            print("%s: %s, 0x%X bytes from 0x%X" % (path, ename, span, at))
            return
        raise SystemExit("no metldr entry in the asecure_loader table")

    off, size = region_slot(name, which)
    at = off - base
    if at < 0 or at + size > len(data):
        raise SystemExit("%s at 0x%X is outside the image" % (name, off))
    with open(path, "wb") as f:
        f.write(data[at:at + size])
    print("%s: %s, 0x%X bytes from 0x%X" % (path, name, size, off))


def cmd_get(args):
    data = open(args.image, "rb").read()
    which = args.map or detect_map(data)
    base = dump_base(data)
    if args.all:
        os.makedirs(args.all, exist_ok=True)
        names = [name for name, nor, nand, size in REGIONS
                 if (nor if which == "nor" else nand) is not None]
        if args.slots:
            # Every TOC slot and the bootldr slot, so `build --from' restores
            # the whole image, padding included, instead of only the regions
            # whose data length happens to equal their slot.
            toc_names = [name for name, off, size in TOC_LAYOUT]
            names = toc_names + [n for n in names if n not in toc_names]
        for name in names:
            off, size = region_slot(name, which)
            if off - base + size > len(data):
                continue
            carve(data, base, which, name,
                  os.path.join(args.all, name + ".bin"))
        carve(data, base, which, "metldr",
              os.path.join(args.all, "metldr.bin"))
        return
    if not args.region:
        raise SystemExit("get wants NAME=FILE... or --all DIR")
    for item in args.region:
        name, _, path = item.partition("=")
        if not path:
            raise SystemExit("get wants NAME=FILE")
        carve(data, base, which, name, path)


def build_toc(data, which, base):
    """Write a fresh table of contents from the documented NOR layout."""
    if which != "nor":
        raise SystemExit("the documented NAND table lists one `ros` entry of "
                         "0xE00000 bytes at an offset the notes do not pin "
                         "down; copy the base image's TOC instead of building "
                         "one (build --base ... without --toc)")
    toc = MAPS["nor"]["toc"]
    order = TOC_LAYOUT
    last_end = max(off + size for name, off, size in order)
    n = len(order)
    if toc + 0x10 + n * 0x30 > len(data):
        raise SystemExit("image is too small for the TOC")
    struct.pack_into(">IIII", data, toc, 1, n, 0, last_end - toc)
    for i, (name, off, size) in enumerate(order):
        at = toc + 0x10 + i * 0x30
        struct.pack_into(">QQ", data, at, off - toc, size)
        raw = name.encode("latin-1")[:0x1F]
        data[at + 0x10:at + 0x30] = raw + b"\0" * (0x20 - len(raw))
        print("  %-16s 0x%08X  %8X  TOC entry %d" % (name, off, size, i))


def cmd_build(args):
    which = args.map
    size = MAPS[which]["size"]
    fbase = int(args.flash_base, 0) if args.flash_base else 0
    if args.base:
        data = bytearray(open(args.base, "rb").read())
        if len(data) < size:
            print("note: base is 0x%X bytes, extending to the %s map size" %
                  (len(data), which))
            data.extend(b"\xFF" * (size - len(data)))
    else:
        data = bytearray(b"\xFF" * size)

    if args.from_dir:
        for name in sorted(os.listdir(args.from_dir)):
            path = os.path.join(args.from_dir, name)
            if not os.path.isfile(path):
                continue
            stem = os.path.splitext(name)[0]
            if stem == "metldr":
                print("note: %s is not a mapped region; place it with "
                      "--put asecure_loader if the table changed" % path)
                continue
            try:
                region_slot(stem, which)
            except SystemExit:
                print("note: %s is not a mapped region, skipped" % path)
                continue
            args.put = (args.put or []) + ["%s=%s" % (stem, path)]

    for item in args.put or []:
        name, _, path = item.partition("=")
        if not path:
            raise SystemExit("--put wants NAME=FILE")
        rname = ALIASES.get(name, name)
        off, size_ = region_slot(rname, which)
        at = off - fbase
        if at < 0:
            raise SystemExit("%s is at flash 0x%X, below the dump base 0x%X" %
                             (rname, off, fbase))
        blob = read_blob(path)
        if len(blob) > size_:
            raise SystemExit("%s is 0x%X bytes, region %s holds 0x%X" %
                             (path, len(blob), rname, size_))
        data[at:at + len(blob)] = blob
        print("  %-16s 0x%08X  %8X  <- %s" % (rname, at, len(blob), path))

    for name in args.erase or []:
        rname = ALIASES.get(name, name)
        off, size_ = region_slot(rname, which)
        at = off - fbase
        if at < 0:
            raise SystemExit("%s is at flash 0x%X, below the dump base 0x%X" %
                             (rname, off, fbase))
        data[at:at + size_] = b"\xFF" * size_
        print("  %-16s 0x%08X  %8X  erased" % (rname, at, size_))

    if args.toc:
        print("  table of contents:")
        build_toc(data, which, args.base)

    with open(args.output, "wb") as f:
        f.write(data)
    print("%s: %d bytes, sha256 %s" %
          (args.output, len(data), hashlib.sha256(data).hexdigest()))

    # Read the result back the way the model does, so a wrong offset shows up
    # here rather than as a boot that stops early.
    toc = find_toc(data)
    if toc is None:
        print("  warning: the image carries no parseable TOC")
    else:
        bad = [n for n, o, s in toc_entries(data, toc)
               if data[o:o + 4] == b"\xFF\xFF\xFF\xFF"]
        print("  read back: TOC at 0x%X, %d entries%s" %
              (toc, be32(data, toc + 4),
               ", %d still erased: %s" % (len(bad), ", ".join(bad)) if bad
               else ", every entry has content"))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list", help="print the documented region map")
    p.add_argument("map", nargs="?", choices=sorted(MAPS))
    p.add_argument("--map", dest="map_opt", choices=sorted(MAPS))
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("dump", help="TOC, asecure table and regions")
    p.add_argument("image")
    p.add_argument("--map", choices=sorted(MAPS))
    p.set_defaults(func=cmd_dump)

    p = sub.add_parser("get", help="carve regions out of an image")
    p.add_argument("image")
    p.add_argument("region", nargs="*", metavar="NAME=FILE")
    p.add_argument("--all", metavar="DIR",
                   help="carve every documented region plus metldr")
    p.add_argument("--slots", action="store_true",
                   help="with --all, carve the TOC slots rather than only the "
                        "regions' data length")
    p.add_argument("--map", choices=sorted(MAPS))
    p.set_defaults(func=cmd_get)

    p = sub.add_parser("build", help="place files at the documented offsets")
    p.add_argument("map", choices=sorted(MAPS))
    p.add_argument("--base", help="image to start from (default: erased)")
    p.add_argument("--from", dest="from_dir",
                   help="directory of region files, one per region name")
    p.add_argument("--put", action="append", metavar="NAME=FILE")
    p.add_argument("--erase", action="append", metavar="NAME")
    p.add_argument("--flash-base", metavar="BYTES",
                   help="flash offset the image's first byte carries (a "
                        "GameOS NAND dump is 0x40000; default 0)")
    p.add_argument("--toc", action="store_true",
                   help="regenerate the flash table of contents")
    p.add_argument("-o", "--output", required=True)
    p.set_defaults(func=cmd_build)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
