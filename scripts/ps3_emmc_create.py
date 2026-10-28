#!/usr/bin/env python3
"""Build the 12 GB eMMC image of a CECH-40xxA SuperSlim from a NAND dump.

The 12 GB console has no HDD: its storage *is* the eMMC, and the flash half of
that eMMC is mapped exactly like NAND.  Sony's layout, as the flash section of
the ps3tools notes describes it and as this tool writes it:

    absolute offset  contents
    0x00000..0x3FFFF  bootldr, the block the HV masks from the guest's flash
    0x40000..         the flash area the region table describes: its 0FACE0FF
                      DEADBEEF block, the Flash Region Table at 0x40200,
                      asecure_loader at 0x40800 and metldr.2's container at
                      0x40840 - the NAND-mapped positions docs/lv1rev.txt and
                      docs/flash.txt list
    0x10000000..      the storage area, which is where the console keeps its
                      dev_flash / dev_flash2 / dev_flash3 / dev_hdd0 / dev_hdd1 files

The table's own entries are relative to the table, so a reader that starts at
the table's block (0FACE0FF at its 0x14, the table at 0x200) begins at NAND
0x40000 - the shape most dumps come in, bootldr masked away.  Its bytes go in at
0x40000 and every entry then lands on the position the docs give: asecure_loader
0x40800, eEID 0x80800, ros 0xC0000 with its two banks, cvtrm 0xEC0000.  A dump
that already starts at NAND 0 (its table at 0x40200) goes in as it stands.

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

  # the full 12 GB image, firmware tree included and sealed with the
  # console's own EID root key (PCK1), as the encdec block writes it
  scripts/ps3_emmc_create.py CECH4201A.NAND.BIN -o emmc_12g.img \\
      --tree-root /path/to/rs3 --erk-file erk48.bin

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
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import ps3_hdd_tree                       # noqa: E402  (the tree writer)

MiB = 1024 * 1024
GiB = 1024 * MiB
SECTOR = 512

# The model's own AES/XTS sources, and where the seal tool is built from them.
ROOT = os.path.dirname(HERE)
AES_DIR = os.path.join(ROOT, "hw", "ppc", "ps3_aes")
TOOL_DIR = os.path.join(ROOT, ".tmp", "ps3-encdec")

# Sony's flash layout for the eMMC consoles.  The NAND-mapped area is 256 MiB
# from offset 0 of the chip, bootldr first; the console's storage follows it.
FLASH_AREA = 0x10000000         # the whole NAND-mapped area: 256 MiB from 0
BOOTLDR_OFF = 0x40000           # where the region table's block sits in it
FRT_OFF = 0x200                 # Flash Region Table, inside that block
TREE_OFF = FLASH_AREA           # storage area, straight after the flash area
BLOCK = 4096

# Past the last byte the dump covers, flash reads as erased - 0xFF - and the
# chip returns that from every block it has not written.  The builder writes
# the padding out to the end of the NAND-mapped area instead of leaving the tail
# of the file a sparse hole, so an image is the same bytes whether it is read
# straight, copied without sparse support, or compared against the dump.
PAD_FROM = 0x0F000000           # where the erased tail of the area is reported
ERASED = 0xFF

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


def encdec_tool():
    """Build (once) the seal tool from the model's own AES/XTS sources.

    hw/ppc/ps3_aes is what qemu-system-ppc64 links, so the image this writes is
    the image ps3_xts_crypt_sector reads back - including the tweak the model
    folds the sector number into.  A C compiler is the only thing it needs, and
    the binary is rebuilt whenever one of those sources changes.
    """
    exe = os.path.join(TOOL_DIR, "ps3_encdec" + (".exe" if os.name == "nt"
                                                 else ""))
    srcs = [os.path.join(AES_DIR, "ps3_encdec.c"),
            os.path.join(AES_DIR, "ps3_aes.c"),
            os.path.join(AES_DIR, "aes.c")]
    shim = os.path.join(TOOL_DIR, "shim", "qemu", "osdep.h")

    for src in srcs:
        if not os.path.exists(src):
            raise SystemExit("missing %s: the storage area is sealed with the "
                             "model's own XTS" % src)

    if not os.path.exists(shim):
        os.makedirs(os.path.dirname(shim), exist_ok=True)
        with open(shim, "w") as f:
            f.write("/* Stand-in for qemu/osdep.h: ps3_aes.c needs nothing "
                    "from it. */\n"
                    "#ifndef QEMU_OSDEP_H\n#define QEMU_OSDEP_H\n"
                    "#include <stdbool.h>\n#include <stddef.h>\n"
                    "#include <stdint.h>\n#include <stdio.h>\n"
                    "#include <stdlib.h>\n#include <string.h>\n#endif\n")

    os.makedirs(TOOL_DIR, exist_ok=True)

    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        raise SystemExit("no C compiler (cc/gcc/clang) to build the seal tool "
                         "from hw/ppc/ps3_aes; drop --erk to leave the storage "
                         "area as it stands")

    # 64-bit offsets: the storage area starts past 2 GiB, so a 32-bit off_t
    # would seek into the wrong place on a 12 GB image.  The tool also seeks
    # through the platform's 64-bit call and checks where it landed, so this
    # define is belt and braces - and it is part of the stamp below, so a tool
    # built with a different line is rebuilt rather than reused.
    cmd = [cc, "-O2", "-std=gnu11", "-D_FILE_OFFSET_BITS=64",
           "-I", AES_DIR, "-I", os.path.join(TOOL_DIR, "shim"),
           "-o", exe] + srcs
    line = subprocess.list2cmdline(cmd)
    stamp = os.path.join(TOOL_DIR, "ps3_encdec.build")
    newest = max(os.path.getmtime(src) for src in srcs)

    if os.path.exists(exe) and os.path.getmtime(exe) >= newest and \
            os.path.exists(stamp):
        with open(stamp, "r", encoding="utf-8") as f:
            if f.read().strip() == line:
                return exe

    print("seal tool  : %s" % line)
    done = subprocess.run(cmd, capture_output=True, text=True)
    if done.returncode:
        raise SystemExit("cannot build the seal tool:\n  %s\n%s"
                         % (line, done.stderr.strip() or done.stdout.strip()))

    with open(stamp, "w", encoding="utf-8") as f:
        f.write(line + "\n")
    return exe


def seal_storage(path, total, erk):
    """Seal the storage area with the console's ERK, XTS-AES-128 per sector.

    The flash area stays as it stands - it is NAND - and the model only applies
    the encdec keys past it, so this is the same boundary.  The key goes in over
    stdin rather than through a file or the command line.
    """
    length = ((total - TREE_OFF) // SECTOR) * SECTOR
    if length <= 0:
        raise SystemExit("no storage area to seal at 0x%X" % TREE_OFF)

    done = subprocess.run([encdec_tool(), path, hex(TREE_OFF), hex(length), "-"],
                          input=erk, capture_output=True)
    if done.returncode:
        raise SystemExit("cannot seal %s:\n%s"
                         % (path, done.stderr.decode("utf-8", "replace").strip()))
    return done.stdout.decode("utf-8", "replace").strip(), length


def flash_base(data):
    """Where the dump's first byte belongs in the chip's own offsets.

    Most dumps begin where the HV lets the guest see flash - the 0FACE0FF block
    with the region table at 0x200 - and that is NAND 0x40000, past the bootldr
    block.  A dump taken from NAND 0 has the table at 0x40200 and goes in at 0.
    The first word of the table is 1 and its second is a small entry count.
    """
    if len(data) >= FRT_OFF + 0x10 and be32(data, FRT_OFF) == 1 and \
            1 <= be32(data, FRT_OFF + 4) <= 64:
        return BOOTLDR_OFF
    if len(data) >= BOOTLDR_OFF + FRT_OFF + 0x10 and \
            be32(data, BOOTLDR_OFF + FRT_OFF) == 1 and \
            1 <= be32(data, BOOTLDR_OFF + FRT_OFF + 4) <= 64:
        return 0
    if data[:4] in NAND_MAGIC:
        return BOOTLDR_OFF
    # Nothing recognisable: treat it as a guest-view dump.
    return BOOTLDR_OFF


def region_table(data, base):
    """The Flash Region Table: name, offset (absolute in flash), length.

    Its entries are 0x30 bytes - u64 offset, u64 length, char name[32] - and
    the offsets are relative to the table itself, so the first entry
    (asecure_loader) reads 0x600 and lands at NAND 0x40800, the position
    docs/flash.txt gives it.
    """
    at = FRT_OFF                      # the table inside the dump
    nand = base + FRT_OFF             # ... and where the chip puts it
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
        out.append((name, nand + be64(data, e), be64(data, e + 8)))
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
    """What the dump is: its shape, its regions and its loader bank."""
    base = flash_base(data)
    regs = region_table(data, base)
    ros = None
    for name, off, size in regs:
        if name in ("ros", "ros0"):
            # `off` is a NAND position; the dump starts `base` bytes into NAND.
            at = off - base
            ros = data[at:at + min(size, 0xE00000)]
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
    print("dump base  : NAND 0x%X%s" % (info["base"],
          " (the guest-view dump, bootldr masked)" if info["base"]
          else " (from NAND 0, table at 0x40200)"))
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

    def write_pad(self, off, end, byte):
        """Write one byte across a range, so the padding is in the file."""
        chunk = bytes([byte]) * MiB
        self.f.seek(off)
        while off < end:
            n = min(len(chunk), end - off)
            self.f.write(chunk[:n])
            off += n

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

    # The dump goes in at its NAND-mapped position, so the table's entries land
    # where the docs list them: asecure_loader 0x40800 and metldr.2 0x40840 for
    # a guest-view dump, the same minus 0x40000 for one taken from NAND 0.
    flash = data[:FLASH_AREA - base]
    if base + len(data) > FLASH_AREA:
        print("warning     : the dump runs 0x%X bytes past the NAND-mapped "
              "area; that tail is not stored"
              % (base + len(data) - FLASH_AREA))
    out.write_at(base, flash)
    print("flash       : 0x%X byte(s) at 0x%X (FRT at 0x%X, asecure_loader at "
          "0x%X, metldr.2 at 0x%X)"
          % (len(flash), base, base + FRT_OFF, base + 0x800, base + 0x840))

    # Erased flash reads as 0xFF, and a dump stops where its data does, so the
    # rest of the NAND-mapped area is written out the way the chip returns it.
    # The storage area then begins exactly at FLASH_AREA, whatever the dump's
    # length was.
    flash_end = base + len(flash)
    if flash_end < FLASH_AREA:
        out.write_pad(flash_end, FLASH_AREA, ERASED)
        print("pad         : 0x%X..0x%X, 0x%02X (erased flash)"
              % (flash_end, FLASH_AREA, ERASED))
        if flash_end < PAD_FROM:
            print("              0x%X..0x%X is the area's erased tail"
                  % (PAD_FROM, FLASH_AREA))

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

    if args.erk:
        line, length = seal_storage(args.output, total, args.erk)
        print("sealed      : %s - 0x%X bytes from 0x%X with the console's ERK "
              "(encdec ladder, XTS-AES-128)" % (line, length, TREE_OFF))
    else:
        print("sealed      : no --erk-file/--erk; the storage area stays in the "
              "clear and the model reads it unkeyed")

    print("image       : %s, %d bytes (%.2f GB)" %
          (args.output, total, total / 1e9))


def read_erk(args):
    """The 48-byte ERK from --erk-file or --erk, or None when neither is given."""
    if args.erk_file:
        try:
            with open(args.erk_file, "rb") as f:
                key = f.read(49)
        except OSError as e:
            raise SystemExit("cannot read %s: %s"
                             % (args.erk_file, e.strerror or e))
    elif args.erk:
        try:
            key = bytes.fromhex(args.erk.strip())
        except ValueError:
            raise SystemExit("--erk is not hex")
    else:
        return None

    if len(key) != 48:
        raise SystemExit("the ERK is 48 bytes (32 key + 16 IV), not %d"
                         % len(key))
    return key


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
    ap.add_argument("--erk",
                    help="the console's 48-byte EID root key (PCK1) as 96 hex "
                         "digits; seals the storage area the way the encdec "
                         "block writes it")
    ap.add_argument("--erk-file",
                    help="the same 48 bytes in a file")
    ap.add_argument("--identify", action="store_true",
                    help="only say what the dump is")
    args = ap.parse_args(argv)

    args.erk = read_erk(args)

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
