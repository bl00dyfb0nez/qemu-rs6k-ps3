#!/usr/bin/env python3
"""Store the console's dev_* file tree inside a PS3 HDD image.

A console keeps its firmware and its /dev_hdd0 files inside the disk, so the
model's HDD image can carry them too.  This tool writes the tree the model
reads (see `ps3_hdd_tree_setup()' in hw/ppc/rs6000_ps3.c): a superblock, then
one 4 KiB block per directory or file.

Two media carry such a tree, and the superblock sits where each one puts it:

  HDD / raw disk   32 MiB in (0x02000000), past the disk's 16 MiB flash copy
  NAND / eMMC      past the 256 MiB flash region, at 0x10040000 - the chip's
                   own first 256 KiB are the CFI preamble, so the flash region
                   starts at 0x40000 and the tree after it

The layout is otherwise identical.  The tool works out which one an existing
image is from the magic's position, and a new image is a disk unless --emmc,
--nand or --base says otherwise.

Layout, all integers big-endian:

  block 0, offset 32 MiB   "PS3HDFS1" (8 bytes)
                           u32 root block (1)
                           u32 generation (bumped on every write, so the
                               model unpacks a new tree only once)

  directory block          u32 next block (0 ends the chain)
                           u32 unused
                           entries of 64 bytes from offset 8 until a name
                           length of 0:
                             u8  name length
                             u8  type (1 directory, 2 file)
                             u16 unused
                             u32 size in bytes
                             u64 first block
                             char name[48]

  file block               consecutive 4 KiB blocks, `size' bytes used

Blocks are read and written by the model through its HDD block layer, so an
image keyed with the console's ATA keys is served the same way: this tool
writes a plain image, which is what an unkeyed image is.  Pass --erk,
--data-key or --tweak-key and the tool refuses instead of writing blocks the
model would read as ciphertext.

Examples
--------
  # a fresh 20 GiB image with the firmware trees inside it
  scripts/ps3_hdd_tree.py -o ps3-hdd.img --size 20G \\
      --root /path/to/rs3            # holds dev_flash, dev_flash2, ...

  # update the tree in an image that already exists
  scripts/ps3_hdd_tree.py ps3-hdd.img --root /path/to/rs3

  # what is in the image?
  scripts/ps3_hdd_tree.py ps3-hdd.img --list

  # a 12 GiB eMMC image (the SuperSlim's single chip) instead of a disk
  scripts/ps3_hdd_tree.py -o ps3-emmc.img --size 12G --emmc \\
      --root /path/to/rs3

Then the model boots from the disk's own firmware:

  qemu-system-ppc64 -M rs6000-ps3 -drive if=pflash,...,file=CECH4301C.bin \\
      -global ps3-boot-rom.hdd-file=ps3-hdd.img \\
      -global ps3-boot-rom.boot-medium=hdd -global ps3-boot-rom.vsh-run=on
"""

import argparse
import os
import struct
import sys

MAGIC = b"PS3HDFS1"
SUPER_OFF = 0x02000000            # a disk: past its 16 MiB flash copy
EMMC_FLASH_OFF = 0x00040000       # the chip's CFI preamble ends here
EMMC_FLASH_SIZE = 0x10000000      # 256 MiB of flash, as on NAND
def emmc_tree_off():
    return EMMC_FLASH_OFF + EMMC_FLASH_SIZE
BLOCK = 4096
NAME_MAX = 48
ENTRY = 64
DIR_HEAD = 8
TYPE_DIR = 1
TYPE_FILE = 2
SECTOR = 512

# The devices a console's storage carries, in the order the model looks for
# them.  dev_hdd1 is the FAT32 cache partition, and it is on both media: a
# console with a disk keeps it on the disk, the 12 GB SuperSlim keeps it on its
# eMMC beside dev_hdd0, so the same tree root serves either one.
DEVICES = ("dev_flash", "dev_flash2", "dev_flash3", "dev_hdd0", "dev_hdd1")


def parse_size(text):
    mult = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}
    text = text.strip()
    if text[-1:].upper() in mult:
        return int(text[:-1], 0) * mult[text[-1].upper()]
    return int(text, 0)


def probe_magic(path, off):
    """Is the tree's superblock where this medium puts it?"""
    try:
        with open(path, "rb") as f:
            f.seek(off)
            return f.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


class Image:
    def __init__(self, path, size=None, base=None, medium=None):
        self.path = path
        if not os.path.exists(path):
            if size is None:
                raise SystemExit("%s does not exist; pass --size to create it"
                                 % path)
            with open(path, "wb") as f:
                f.truncate(size)
        self.size = os.path.getsize(path)

        if base is not None:
            self.base, self.medium = base, "custom"
        elif medium == "emmc":
            self.base, self.medium = emmc_tree_off(), "emmc"
        elif medium == "hdd":
            self.base, self.medium = SUPER_OFF, "hdd"
        elif probe_magic(path, SUPER_OFF):
            self.base, self.medium = SUPER_OFF, "hdd"
        elif probe_magic(path, emmc_tree_off()):
            self.base, self.medium = emmc_tree_off(), "emmc"
        else:
            # Nothing there yet: a new image is a disk unless told otherwise.
            self.base, self.medium = SUPER_OFF, "hdd"

        if self.base + BLOCK > self.size:
            raise SystemExit("%s is smaller than its tree offset 0x%X"
                             % (path, self.base))
        self.f = open(path, "r+b")

    def read_block(self, block):
        self.f.seek(self.base + block * BLOCK)
        return self.f.read(BLOCK)

    def write_block(self, block, data):
        assert len(data) <= BLOCK, len(data)
        self.f.seek(self.base + block * BLOCK)
        self.f.write(data + b"\x00" * (BLOCK - len(data)))

    def close(self):
        self.f.close()


class Builder:
    def __init__(self, image):
        self.image = image
        self.next_block = 1          # block 0 is the superblock
        self.blocks = self.image.size // BLOCK

    def alloc(self, count=1):
        first = self.next_block
        self.next_block += count
        if self.next_block + 1 >= self.blocks:
            raise SystemExit("the image is too small for the tree; it needs "
                             "more than %d blocks" % (self.next_block + 1))
        return first

    def write_dir(self, path):
        """Write one host directory and return (block, entries)."""
        entries = []

        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            if len(name.encode()) >= NAME_MAX:
                print("skipping %s: the name is longer than %d bytes"
                      % (full, NAME_MAX - 1), file=sys.stderr)
                continue
            if os.path.isdir(full):
                child, _ = self.write_dir(full)
                entries.append((name, TYPE_DIR, 0, child))
            elif os.path.isfile(full):
                size = os.path.getsize(full)
                first = self.alloc(max(1, (size + BLOCK - 1) // BLOCK))
                with open(full, "rb") as f:
                    written = 0
                    while True:
                        chunk = f.read(BLOCK)
                        if not chunk:
                            break
                        self.image.write_block(first + written // BLOCK, chunk)
                        written += BLOCK
                entries.append((name, TYPE_FILE, size, first))
            else:
                print("skipping %s: not a file or directory" % full,
                      file=sys.stderr)

        # As many blocks as the entries need, chained from the first one.
        per_block = (BLOCK - DIR_HEAD) // ENTRY
        chunks = [entries[i:i + per_block]
                  for i in range(0, len(entries), per_block)] or [[]]
        blocks = [self.alloc() for _ in chunks]

        for index, (block, chunk) in enumerate(zip(blocks, chunks)):
            data = bytearray()
            next_block = blocks[index + 1] if index + 1 < len(blocks) else 0
            data += struct.pack(">II", next_block, 0)
            for name, kind, size, first in chunk:
                raw = name.encode()
                data += bytes([len(raw), kind]) + b"\x00\x00"
                data += struct.pack(">IQ", size, first)
                data += raw + b"\x00" * (NAME_MAX - len(raw))
            self.image.write_block(block, bytes(data))

        return blocks[0], entries

    def write_super(self, root, generation):
        data = bytearray(BLOCK)
        data[0:8] = MAGIC
        struct.pack_into(">II", data, 8, root, generation)
        self.image.write_block(0, bytes(data))


def read_super(image):
    data = image.read_block(0)
    if data[:8] != MAGIC:
        return None
    root, generation = struct.unpack_from(">II", data, 8)
    return root, generation


def list_dir(image, block, prefix="", depth=0):
    out = []
    while block:
        data = image.read_block(block)
        for off in range(DIR_HEAD, BLOCK, ENTRY):
            if data[off] == 0:
                break
            name_len = data[off]
            kind = data[off + 1]
            size, first = struct.unpack_from(">IQ", data, off + 4)
            name = data[off + 16:off + 16 + name_len].decode(errors="replace")
            out.append((prefix + name, kind, size, first))
            if kind == TYPE_DIR and depth < 12:
                out += list_dir(image, first, prefix + name + "/", depth + 1)
        block = struct.unpack_from(">I", data, 0)[0]
    return out


def main(argv=None):
    # A console's tree holds names in the firmware's own languages, and a
    # Windows console codepage cannot represent all of them: without this a
    # listing stops at the first such name instead of printing the tree.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image", help="the HDD image to write or inspect")
    ap.add_argument("-o", "--output", help="image to create (same as image)")
    ap.add_argument("--size", help="size when creating an image, e.g. 20G")
    ap.add_argument("--root", help="directory holding dev_flash, dev_flash2, "
                                   "dev_flash3, dev_hdd0 and dev_hdd1")
    ap.add_argument("--dev", action="append", metavar="NAME=DIR",
                    help="override one device directory (repeatable)")
    ap.add_argument("--list", action="store_true",
                    help="print the tree stored in the image")
    layout = ap.add_mutually_exclusive_group()
    layout.add_argument("--emmc", "--nand", dest="medium",
                        action="store_const", const="emmc",
                        help="the image is a NAND/eMMC chip: tree at 0x%X"
                             % emmc_tree_off())
    layout.add_argument("--hdd", "--disk", dest="medium",
                        action="store_const", const="hdd",
                        help="the image is a disk: tree at 32 MiB")
    layout.add_argument("--base", type=lambda s: int(s, 0),
                        help="the tree's superblock offset, in bytes")
    layout.add_argument("--auto", dest="medium", action="store_const",
                        const=None,
                        help="use whichever offset holds the magic (default)")
    ap.add_argument("--erk-file", help="refused: this tool writes plain images")
    ap.add_argument("--erk", help="refused: this tool writes plain images")
    args = ap.parse_args(argv)

    if args.erk or args.erk_file:
        raise SystemExit("this tool writes an unkeyed image; a keyed one has "
                         "to be encrypted with the console's ATA keys after "
                         "the tree is written (see ps3_hdd_create.py)")

    image_path = args.output or args.image
    image = Image(image_path, parse_size(args.size) if args.size else None,
                  base=args.base, medium=args.medium)

    try:
        if args.list:
            sup = read_super(image)
            if not sup:
                raise SystemExit("%s carries no tree" % image_path)
            root, generation = sup
            print("%s: %s layout, tree at 0x%X, generation %d"
                  % (image_path, image.medium, image.base, generation))
            for name, kind, size, first in list_dir(image, root):
                if kind == TYPE_DIR:
                    print("  %s/" % name)
                else:
                    print("  %-60s %10d bytes at block %d"
                          % (name, size, first))
            return 0

        if not args.root and not args.dev:
            raise SystemExit("pass --root or --dev to say what to store")

        devices = {}
        if args.root:
            for name in DEVICES:
                path = os.path.join(args.root, name)
                if os.path.isdir(path):
                    devices[name] = path
        for spec in args.dev or []:
            name, _, path = spec.partition("=")
            if not name or not path:
                raise SystemExit("--dev wants NAME=DIR, not %r" % spec)
            devices[name] = path

        if not devices:
            raise SystemExit("no dev_* directory found")

        builder = Builder(image)
        entries = []
        for name in DEVICES:
            if name not in devices:
                continue
            print("%s <- %s" % (name, devices[name]))
            block, _ = builder.write_dir(devices[name])
            entries.append((name, TYPE_DIR, 0, block))

        # The root block lists the devices as if they sat in /dev.
        root = builder.alloc()
        data = bytearray()
        data += struct.pack(">II", 0, 0)
        for name, kind, size, block in entries:
            raw = name.encode()
            data += bytes([len(raw), kind]) + b"\x00\x00"
            data += struct.pack(">IQ", size, block)
            data += raw + b"\x00" * (NAME_MAX - len(raw))
        image.write_block(root, bytes(data))

        sup = read_super(image)
        generation = (sup[1] + 1) if sup else 1
        builder.write_super(root, generation)
        used = builder.next_block * BLOCK

        print("%s: %s layout, tree at 0x%X, generation %d, %d KiB of tree "
              "in a %d MiB image"
              % (image_path, image.medium, image.base, generation,
                 used // 1024, image.size // (1024 * 1024)))
        return 0
    finally:
        image.close()


if __name__ == "__main__":
    sys.exit(main())
