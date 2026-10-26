#!/usr/bin/env python3
"""Store the console's dev_* file tree inside a PS3 HDD image.

A console keeps its firmware and its /dev_hdd0 files inside the disk, so the
model's HDD image can carry them too.  This tool writes the tree the model
reads (see `ps3_hdd_tree_setup()' in hw/ppc/rs6000_ps3.c): a superblock at
32 MiB, then one 4 KiB block per directory or file.

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
SUPER_OFF = 0x02000000
BLOCK = 4096
NAME_MAX = 48
ENTRY = 64
DIR_HEAD = 8
TYPE_DIR = 1
TYPE_FILE = 2
SECTOR = 512

# The devices a console's disk carries, in the order the model looks for them.
DEVICES = ("dev_flash", "dev_flash2", "dev_flash3", "dev_hdd0")


def parse_size(text):
    mult = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}
    text = text.strip()
    if text[-1:].upper() in mult:
        return int(text[:-1], 0) * mult[text[-1].upper()]
    return int(text, 0)


class Image:
    def __init__(self, path, size=None):
        self.path = path
        if not os.path.exists(path):
            if size is None:
                raise SystemExit("%s does not exist; pass --size to create it"
                                 % path)
            with open(path, "wb") as f:
                f.truncate(size)
        self.size = os.path.getsize(path)
        self.f = open(path, "r+b")

    def read_block(self, block):
        self.f.seek(SUPER_OFF + block * BLOCK)
        return self.f.read(BLOCK)

    def write_block(self, block, data):
        assert len(data) <= BLOCK, len(data)
        self.f.seek(SUPER_OFF + block * BLOCK)
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
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image", help="the HDD image to write or inspect")
    ap.add_argument("-o", "--output", help="image to create (same as image)")
    ap.add_argument("--size", help="size when creating an image, e.g. 20G")
    ap.add_argument("--root", help="directory holding dev_flash, dev_flash2, "
                                   "dev_flash3 and dev_hdd0")
    ap.add_argument("--dev", action="append", metavar="NAME=DIR",
                    help="override one device directory (repeatable)")
    ap.add_argument("--list", action="store_true",
                    help="print the tree stored in the image")
    ap.add_argument("--erk-file", help="refused: this tool writes plain images")
    ap.add_argument("--erk", help="refused: this tool writes plain images")
    args = ap.parse_args(argv)

    if args.erk or args.erk_file:
        raise SystemExit("this tool writes an unkeyed image; a keyed one has "
                         "to be encrypted with the console's ATA keys after "
                         "the tree is written (see ps3_hdd_create.py)")

    image_path = args.output or args.image
    image = Image(image_path, parse_size(args.size) if args.size else None)

    try:
        if args.list:
            sup = read_super(image)
            if not sup:
                raise SystemExit("%s carries no tree" % image_path)
            root, generation = sup
            print("%s: generation %d" % (image_path, generation))
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

        print("%s: generation %d, %d KiB of tree in a %d MiB image"
              % (image_path, generation, used // 1024,
                 image.size // (1024 * 1024)))
        return 0
    finally:
        image.close()


if __name__ == "__main__":
    sys.exit(main())
