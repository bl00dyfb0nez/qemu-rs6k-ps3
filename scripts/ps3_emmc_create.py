#!/usr/bin/env python3
"""Build the 12 GB eMMC image of a CECH-40xxA SuperSlim from a NAND dump.

The 12 GB console has no HDD: its storage *is* the eMMC, and the flash half of
that eMMC is mapped exactly like NAND.  Sony's layout, as the flash section of
the ps3tools notes describes it and as this tool writes it:

    absolute offset  contents
    0x00000..         the NAND-mapped flash area, 256 MiB from offset 0: the
                      Flash Region Table at 0x200, asecure_loader at 0x800 and
                      metldr.2's container at 0x840 - the same offsets NOR
                      flash uses
    0x10000000..      the storage area, which is where the console keeps its
                      dev_flash / dev_flash2 / dev_flash3 / dev_hdd0 / dev_hdd1 files

Nothing sits in front of the flash area: a raw chip dump begins with the very
bytes the chip answers for offset 0, and they are copied in at 0.  A dump whose
reader kept a 256 KiB preamble in front of the region has its table at 0x40200
instead of 0x200; that preamble is dropped, so the region lands at 0x0 and
metldr.2 stays at 0x840 either way.  Where the table is tells the two apart.

Identification comes first, because the layout it writes depends on what the
image is:

  * flash type  - eMMC when the dump is NAND-mapped and the SKU is a 40xx/42xx
  * SKU         - named with --model, otherwise read from the dump's idps in
                  the check log next to it when one exists
  * firmware    - the ROS0/ROS1 version words, the same values PyPS3checker
                  prints as "ROS0 : 491.000"
  * ldr revision- lv0ldr.2 (with lv0.2) when the recovery bank carries lv0.2,
                  otherwise lv0ldr.1.  Every 4xxx console is revision 2.

Nothing here decrypts anything: the containers are copied byte for byte into
their NAND slots, and the tool never asks for a key.  What it does build is the
storage area's file tree (the PS3HDFS1 tree the model mounts dev_flash from), so
one eMMC image is all the console needs to boot.

Examples
--------
  # what is this dump?
  scripts/ps3_emmc_create.py CECH4201A.NAND.BIN --identify

  # the full 12 GB image, firmware tree included
  scripts/ps3_emmc_create.py CECH4201A.NAND.BIN -o emmc_12g.img \\
      --tree-root /path/to/rs3

  # a console with no files on it yet: flash only, storage left empty
  scripts/ps3_emmc_create.py CECH4201A.NAND.BIN -o emmc_12g.img

Then the model boots from it without a flash image or an HDD:

  qemu-system-ppc64 -M rs6000-ps3 -display sdl \\
      -global ps3-boot-rom.emmc-file=emmc_12g.img \\
      -global ps3-boot-rom.boot-medium=emmc \\
      -global ps3-boot-rom.vsh-run=on
"""

import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ps3_hdd_tree                       # noqa: E402  (the tree writer)

MiB = 1024 * 1024
GiB = 1024 * MiB

# Sony's flash layout for the eMMC consoles.  The NAND-mapped area - region
# table, asecure_loader and the containers - starts at offset 0 of the chip and
# is 256 MiB long; the console's storage follows it.
FLASH_AREA = 0x10000000         # the whole NAND-mapped area: 256 MiB from 0
PREAMBLE = 0x40000              # a reader's preamble, when it kept one
FRT_OFF = 0x200                 # Flash Region Table, inside the flash region
TREE_OFF = FLASH_AREA           # storage area, straight after the flash area
BLOCK = 4096

# "12GB" as Sony sells it, decimal, not 12 GiB.
SONY_12GB = 12 * 1000 ** 3

NAND_MAGIC = (b"\xfa\xce\x0f\xff", b"\xfa\xce\x0f\xfe")


def be32(data, off):
    return struct.unpack_from(">I", data, off)[0]


def be64(data, off):
    return struct.unpack_from(">Q", data, off)[0]


def sony_size(text):
    """`12GB` is decimal (Sony's own number); `12G` is 12 GiB."""
    text = text.strip()
    if text.upper().endswith("GB"):
        return int(text[:-2], 0) * 1000 ** 3
    mult = {"K": 1024, "M": MiB, "G": GiB, "T": 1024 * GiB}
    if text[-1:].upper() in mult:
        return int(text[:-1], 0) * mult[text[-1].upper()]
    return int(text, 0)


def flash_base(data):
    """The dump's offset of the flash region's byte 0.

    A raw chip dump starts at the region, so its table is at 0x200 and the
    region is at 0.  A reader that kept the preamble in front shifts both by
    0x40000, and the table is then at 0x40200.  The first word of the table is
    1 and its second is a small entry count.
    """
    for base in (0, PREAMBLE):
        at = base + FRT_OFF
        if len(data) >= at + 0x10 and be32(data, at) == 1 and \
                1 <= be32(data, at + 4) <= 64:
            return base
    if data[:4] in NAND_MAGIC:
        return 0
    # Nothing recognisable: a console dump that starts at the region.
    return 0


def region_table(data, base):
    """The Flash Region Table: name, offset (absolute in flash), length.

    Its entries are 0x30 bytes - u64 offset, u64 length, char name[32] - and
    the offsets are relative to the table itself, which is why the first entry
    (asecure_loader) reads 0x600 and lands at 0x800.
    """
    at = base + FRT_OFF
    if at + 0x10 > len(data) or be32(data, at) != 1:
        raise SystemExit("no Flash Region Table at 0x%X: not a NAND/eMMC dump"
                         % at)
    count = be32(data, at + 4)
    if not 1 <= count <= 64:
        raise SystemExit("the Flash Region Table claims %u entries" % count)
    out = []
    for i in range(count):
        e = at + 0x10 + i * 0x30
        if e + 0x30 > len(data):
            raise SystemExit("the Flash Region Table runs past the dump")
        name = data[e + 0x10:e + 0x30].split(b"\0")[0].decode("latin-1")
        out.append((name, at + be64(data, e), be64(data, e + 8)))
    return out


def ros_base(region):
    """Where a bank's filesystem begins.

    In the eMMC/NAND `ros` region the banks sit 0x20 bytes into it (the region
    header carries the length at 0x08), while a carved NOR bank starts with the
    filesystem itself.  The entry count tells them apart: it is word 5 of the
    filesystem (0x14) and reads 0x19 on a console.
    """
    for base in (0, 0x20):
        if base + 0x18 <= len(region):
            count = be32(region, base + 0x14)
            if 1 <= count <= 0x100:
                return base
    return None


def ros_files(region):
    """The recovery bank's own filesystem: name -> (offset, size)."""
    out = {}
    base = ros_base(region)
    if base is None:
        return out
    count = be32(region, base + 0x14)
    for i in range(count):
        at = base + 0x20 + i * 0x30
        if at + 0x30 > len(region):
            break
        name = region[at + 0x10:at + 0x30].split(b"\0")[0].decode("latin-1")
        out[name] = (base + be64(region, at), be64(region, at + 8))
    return out


def ros_version(region, files):
    """What the bank says about itself, for the identification line.

    The bank header carries no printable firmware version (PyPS3checker reaches
    its "ROS0 : 491.000" through the images inside the bank), so this reports
    what a bank *does* carry: its loader set and file count.
    """
    have = [n for n in ("lv0", "lv0.2", "lv1.self", "lv2_kernel.self",
                        "emer_init.self") if n in files]
    if not have:
        return "empty"
    return "%d file(s): %s" % (len(files), ", ".join(have))


def identify(data, model_hint):
    base = flash_base(data)
    regs = region_table(data, base)
    names = {name: (off, size) for name, off, size in regs}
    ros = None
    for name, off, size in regs:
        if name in ("ros", "ros0"):
            ros = data[off:off + min(size, 0xE00000)]
            break

    info = {
        "base": base,
        "regions": regs,
        "model": model_hint,
        "ros0": "?",
        "ros1": "?",
        "ldr": "?",
        "lv0.2": False,
    }

    if ros:
        files = ros_files(ros)
        info["ldr"] = ("lv0ldr.2 (the ROS carries lv0.2)" if "lv0.2" in files
                       else "lv0ldr.1 (no lv0.2 in the ROS)")
        info["lv0.2"] = "lv0.2" in files
        info["ros0"] = ros_version(ros, files)
        info["files"] = sorted(files)
        # A NAND/eMMC dump holds one `ros` region of two banks: 0x700000 each,
        # 0x20 bytes past the region header.
        head = ros_base(ros) or 0
        bank = 0x700000
        for start in (bank, head + bank, bank + head):
            if len(ros) < start + 0x40:
                continue
            second = ros[start:]
            files = ros_files(second)
            if files:
                info["ros1"] = ros_version(second, files)
                break

    if not info["model"] and os.path.exists(data_path + ".checklog.txt"):
        with open(data_path + ".checklog.txt", "rb") as f:
            for line in f.read().decode("latin-1").splitlines():
                if "SKU" in line and "CECH" in line:
                    info["model"] = " ".join(line.split()[1:])

    return info


def print_identification(info):
    print("flash type : eMMC (NAND-mapped, 256 MiB flash region)")
    print("dump base  : 0x%X%s" % (info["base"],
          " (a preamble in front of the region)" if info["base"]
          else " (the region itself, table at 0x200)"))
    print("model      : %s" % (info["model"] or "unknown (pass --model)"))
    print("ros0       : %s" % info["ros0"])
    print("ros1       : %s" % info["ros1"])
    print("ldr        : %s" % info["ldr"])
    print("regions    :")
    for name, off, size in info["regions"]:
        print("              %-16s 0x%08X 0x%X" % (name, off, size))


class EmmcImage:
    """A sparse image whose tree writer sits at the storage area."""

    def __init__(self, path, size=None):
        if not os.path.exists(path):
            if size is None:
                raise SystemExit("%s does not exist; pass --total" % path)
            with open(path, "wb") as f:
                f.truncate(size)
        self.path = path
        self.size = os.path.getsize(path)
        self.f = open(path, "r+b")

    def write_at(self, off, blob):
        self.f.seek(off)
        self.f.write(blob)

    def close(self):
        self.f.close()


class StorageTree:
    """ps3_hdd_tree's builder, writing blocks at the eMMC's storage area."""

    def __init__(self, image, tree_off=TREE_OFF):
        self.image = image
        self.tree_off = tree_off
        self.next_block = 1
        self.blocks = (self.image.size - tree_off) // BLOCK
        if self.blocks < 8:
            raise SystemExit("the image has no room for a file tree")

    def read_block(self, block):
        self.image.f.seek(self.tree_off + block * BLOCK)
        return self.image.f.read(BLOCK)

    def write_block(self, block, data):
        assert len(data) <= BLOCK, len(data)
        self.image.f.seek(self.tree_off + block * BLOCK)
        self.image.f.write(data + b"\x00" * (BLOCK - len(data)))

    def alloc(self, count=1):
        first = self.next_block
        self.next_block += count
        if self.next_block + 1 >= self.blocks:
            raise SystemExit("the image is too small for the tree")
        return first

    def write_dir(self, path):
        entries = []
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            raw = name.encode()
            if len(raw) >= ps3_hdd_tree.NAME_MAX:
                print("skipping %s: name too long" % full, file=sys.stderr)
                continue
            if os.path.isdir(full):
                child = self.write_dir(full)
                entries.append((name, ps3_hdd_tree.TYPE_DIR, 0, child))
            elif os.path.isfile(full):
                size = os.path.getsize(full)
                first = self.alloc(max(1, (size + BLOCK - 1) // BLOCK))
                with open(full, "rb") as f:
                    written = 0
                    while True:
                        chunk = f.read(BLOCK)
                        if not chunk:
                            break
                        self.write_block(first + written // BLOCK, chunk)
                        written += BLOCK
                entries.append((name, ps3_hdd_tree.TYPE_FILE, size, first))
        per_block = (BLOCK - ps3_hdd_tree.DIR_HEAD) // ps3_hdd_tree.ENTRY
        chunks = [entries[i:i + per_block]
                  for i in range(0, len(entries), per_block)] or [[]]
        blocks = [self.alloc() for _ in chunks]
        for index, (block, chunk) in enumerate(zip(blocks, chunks)):
            data = bytearray()
            nxt = blocks[index + 1] if index + 1 < len(blocks) else 0
            data += struct.pack(">II", nxt, 0)
            for name, kind, size, first in chunk:
                raw = name.encode()
                data += bytes([len(raw), kind]) + b"\x00\x00"
                data += struct.pack(">IQ", size, first)
                data += raw + b"\x00" * (ps3_hdd_tree.NAME_MAX - len(raw))
            self.write_block(block, bytes(data))
        return blocks[0]

    def write_super(self, root, generation):
        data = bytearray(BLOCK)
        data[0:8] = ps3_hdd_tree.MAGIC
        struct.pack_into(">II", data, 8, root, generation)
        self.write_block(0, bytes(data))


def build(args, data, info):
    total = sony_size(args.total)
    if total <= TREE_OFF + 8 * MiB:
        raise SystemExit("--total must leave room for the flash and the "
                         "storage area")

    out = EmmcImage(args.output, total)
    base = info["base"]

    # The flash area begins at offset 0 of the chip, so the region goes in at 0.
    # A dump that kept a preamble in front of it is shifted forward by it, and
    # dropping that shift is what puts metldr.2 at 0x840 as the chip maps it.
    if base:
        print("preamble    : dropping the dump's 0x%X bytes in front of the "
              "region" % base)

    flash = data[base:base + FLASH_AREA]
    if len(flash) < FLASH_AREA:
        flash = flash + b"\x00" * (FLASH_AREA - len(flash))
    out.write_at(0, flash)
    print("flash       : 0x%X bytes at 0x0 (FRT at 0x%X, asecure_loader at "
          "0x800, metldr.2 at 0x840)" % (len(flash), FRT_OFF))

    if args.tree_root:
        if not os.path.isdir(args.tree_root):
            raise SystemExit("%s is not a directory" % args.tree_root)
        tree = StorageTree(out)
        root = tree.write_dir(args.tree_root)
        tree.write_super(root, 1)
        print("storage     : PS3HDFS1 tree at 0x%X from %s (%d blocks)"
              % (TREE_OFF, args.tree_root, tree.next_block))
    else:
        print("storage     : empty (no --tree-root)")

    out.close()
    print("image       : %s, %d bytes (%.2f GB)" %
          (args.output, total, total / 1e9))


def main(argv=None):
    global data_path
    ap = argparse.ArgumentParser(
        description="Build the 12 GB eMMC image of a CECH-40xxA from a NAND "
                    "dump.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("source", nargs="?", help="the NAND/eMMC dump to read")
    ap.add_argument("-o", "--output", help="the eMMC image to create")
    ap.add_argument("--total", default="12GB",
                    help="size as sold: 12GB is decimal, 12G is 12 GiB")
    ap.add_argument("--model", help="the SKU, when the dump does not say")
    ap.add_argument("--tree-root",
                    help="a directory holding dev_flash, dev_flash2, "
                         "dev_flash3, dev_hdd0 and dev_hdd1 to store in the image")
    ap.add_argument("--identify", action="store_true",
                    help="only say what the dump is")
    args = ap.parse_args(argv)

    if not args.source:
        ap.error("the dump to read is required")
    data_path = args.source
    try:
        with open(args.source, "rb") as f:
            data = f.read()
    except OSError as e:
        raise SystemExit("cannot read %s: %s" % (args.source, e.strerror or e))

    info = identify(data, args.model)
    print_identification(info)

    if args.identify:
        return 0

    if not args.output:
        ap.error("-o/--output is required to build an image")
    build(args, data, info)
    return 0


if __name__ == "__main__":
    sys.exit(main())
