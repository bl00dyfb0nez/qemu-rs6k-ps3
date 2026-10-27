#!/usr/bin/env python3
"""Build a disc image that carries a system update, for dev_bdvd.

The rs6000-ps3 model mounts the image it is given as the console's Blu-ray
drive: the guest's own ATA driver and lv2's storage layer read its raw 2048
byte sectors, and the model's path mapper mounts the image's ISO 9660 tree as
/dev_bdvd, so the update flow reads

    /dev_bdvd/PS3_UPDATE/PS3UPDAT.PUP

This tool writes such an image.  It is the same layout a pressed disc's
directory structure has - primary volume descriptor, path tables, root and
PS3_UPDATE directories, then the file - enough for x3's mount and for the
model's own reader.  Give it a real update file with --pup, or ask for a
placeholder with --size when the point is to exercise the read path:

    python scripts/ps3_pup_disc.py --size 1M --out .tmp/pup_disc.iso
    python scripts/ps3_pup_disc.py --pup PS3UPDAT.PUP --out .tmp/update.iso

Then attach it the way the console's drive is attached:

    qemu-system-ppc64 -M rs6000-ps3 -display sdl \\
      -drive if=ide,media=cdrom,file=.tmp/pup_disc.iso,format=raw

The model answers with what it found on the disc:

    ps3-bdvd: ... ISO 9660, 1 directory and 1 file(s), 1 MiB; mounted as dev_bdvd
    ps3-bdvd: /PS3_UPDATE/PS3UPDAT.PUP is on the disc, 1048576 bytes; ...
"""

from __future__ import annotations

import argparse
import os
import struct
import sys

SECTOR = 2048
PUP_DIR = "PS3_UPDATE"
PUP_NAME = "PS3UPDAT.PUP"

# The magic a real update package starts with; a placeholder gets it too, so a
# guest that checks it sees the same bytes as it would on the console.
PUP_MAGIC = b"SCEUF\x00\x00\x00"

# Where each structure goes.  The system area is the first 16 sectors, the
# descriptor set follows it, then the path tables, then the directories - the
# order every optical image uses.
SYSTEM_AREA = 0
PVD_LBA = 16
TERMINATOR_LBA = 17
PATH_L_BA = 18
PATH_M_LBA = 19
ROOT_DIR_LBA = 20
PUP_DIR_LBA = 21
FILE_LBA = 22


def both16(value: int) -> bytes:
    """A 16-bit number in ISO 9660's both-endian form."""
    return struct.pack("<H", value) + struct.pack(">H", value)


def both32(value: int) -> bytes:
    """A 32-bit number in ISO 9660's both-endian form."""
    return struct.pack("<I", value) + struct.pack(">I", value)


def recording_time(year: int = 2026, month: int = 1, day: int = 1) -> bytes:
    """The 7-byte directory record timestamp."""
    return bytes([year - 1900, month, day, 0, 0, 0, 0])


def dir_record(
    name: bytes,
    extent: int,
    size: int,
    is_dir: bool,
    identifier: bytes | None = None,
) -> bytes:
    """One ISO 9660 directory record.

    The name is padded to an even length so the record length stays even, and
    a name of 0x00 or 0x01 is the `.` and `..` entries, as the format has it.
    """
    ident = identifier if identifier is not None else name.encode("ascii")
    length = 33 + len(ident)
    if length % 2:
        length += 1

    rec = bytearray(length)
    rec[0] = length
    rec[1] = 0  # no extended attributes
    rec[2:10] = both32(extent)
    rec[10:18] = both32(size)
    rec[18:25] = recording_time()
    rec[25] = 2 if is_dir else 0
    rec[26] = 0  # file unit size
    rec[27] = 0  # interleave gap
    rec[28:32] = both16(1)  # volume sequence number
    rec[32] = len(ident)
    rec[33 : 33 + len(ident)] = ident
    return bytes(rec)


def directory(records: bytes) -> bytes:
    """A directory's one sector: its records, then zero padding."""
    if len(records) > SECTOR:
        raise SystemExit("the directory does not fit in one sector")
    return records + bytes(SECTOR - len(records))


def path_table(big_endian: bool) -> bytes:
    """The root-only path table: one entry, its parent, and the root's LBA.

    The parent index of the root is 1 (itself) and its name is a single zero
    byte, which is why the entry is 10 bytes long.
    """
    entry = bytearray(10)
    entry[0] = 1  # name length: one byte, the root's zero name
    entry[1] = 0  # extended attribute length
    entry[2:6] = struct.pack(">I" if big_endian else "<I", ROOT_DIR_LBA)
    entry[6:8] = struct.pack(">H" if big_endian else "<H", 1)  # parent
    entry[8:10] = b"\x00\x00"
    return bytes(entry) + bytes(SECTOR - len(entry))


def primary_volume_descriptor(
    volume_lbas: int, path_table_size: int, volume_id: str
) -> bytes:
    """The primary volume descriptor: where the tree and the file start."""
    vd = bytearray(SECTOR)
    vd[0] = 1  # primary volume descriptor
    vd[1:6] = b"CD001"
    vd[6] = 1  # version
    vd[8:40] = b"PLAYSTATION 3".ljust(32)
    vd[40:72] = volume_id.encode("ascii")[:32].ljust(32)
    vd[80:88] = both32(volume_lbas)  # volume space size
    vd[120:124] = both16(1)  # volume set size
    vd[124:128] = both16(1)  # volume sequence number
    vd[128:132] = both16(SECTOR)  # logical block size
    vd[132:140] = both32(path_table_size)
    vd[140:144] = struct.pack("<I", PATH_L_BA)
    vd[148:152] = struct.pack(">I", PATH_M_LBA)
    vd[156:190] = dir_record(
        b"", ROOT_DIR_LBA, SECTOR, True, identifier=b"\x00"
    )  # the root directory record
    vd[190:318] = volume_id.encode("ascii")[:64].ljust(128)  # volume set id
    vd[318:446] = b" ".ljust(128)  # publisher
    vd[446:574] = b" ".ljust(128)  # data preparer
    vd[574:702] = b"PS3 PUP DISC".ljust(128)
    vd[702:739] = b" ".ljust(37)  # copyright file
    vd[739:776] = b" ".ljust(37)  # abstract file
    vd[776:813] = b" ".ljust(37)  # bibliographic file

    # The four 17-byte timestamps: YYYYMMDDHHMMSScc then the offset.
    stamp = b"2026010100000000" + b"0" + b"+"
    for off in (813, 830, 847, 864):
        vd[off : off + 17] = stamp

    vd[881] = 1  # file structure version

    return bytes(vd)


def read_payload(args: argparse.Namespace) -> bytes:
    """The update file's bytes: a real one, or the placeholder asked for."""
    if args.pup:
        with open(args.pup, "rb") as f:
            payload = f.read()
        print(f"payload: {args.pup}, {len(payload)} bytes")
        return payload

    size = parse_size(args.size)
    if size < len(PUP_MAGIC):
        raise SystemExit("--size must be at least 8 bytes")

    # A placeholder with the package magic, then a byte pattern so a reader
    # can tell where a block came from: offset modulo 251 never repeats over a
    # sector, which makes a misread visible in a hex dump.
    body = bytearray(size)
    body[: len(PUP_MAGIC)] = PUP_MAGIC
    for i in range(len(PUP_MAGIC), size):
        body[i] = i % 251
    print(f"payload: placeholder, {size} bytes")
    return bytes(body)


def parse_size(text: str) -> int:
    """A size with an optional K/M/G suffix, the way the other tools take it."""
    units = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}
    t = text.strip().lower().rstrip("b")
    suffix = t[-1] if t and t[-1] in units and t[-1] else ""

    if suffix:
        t = t[:-1]
    try:
        value = int(t)
    except ValueError:
        raise SystemExit(f"size {text!r} is not a number")

    if value <= 0:
        raise SystemExit("size must be positive")
    if value * units[suffix] > 1024**4:
        raise SystemExit("a disc image larger than 1 TiB is not supported")

    return value * units[suffix]


def build(payload: bytes, volume_id: str) -> bytes:
    """The whole image, structure by structure."""
    file_lbas = (len(payload) + SECTOR - 1) // SECTOR
    volume_lbas = FILE_LBA + file_lbas
    path_table_size = 10

    root = directory(
        dir_record(b"", ROOT_DIR_LBA, SECTOR, True, identifier=b"\x00")
        + dir_record(b"", ROOT_DIR_LBA, SECTOR, True, identifier=b"\x01")
        + dir_record(PUP_DIR, PUP_DIR_LBA, SECTOR, True)
    )
    pup = directory(
        dir_record(b"", PUP_DIR_LBA, SECTOR, True, identifier=b"\x00")
        + dir_record(b"", ROOT_DIR_LBA, SECTOR, True, identifier=b"\x01")
        + dir_record(f"{PUP_NAME};1", FILE_LBA, len(payload), False)
    )

    image = bytearray(SECTOR * volume_lbas)
    image[PVD_LBA * SECTOR : PVD_LBA * SECTOR + SECTOR] = (
        primary_volume_descriptor(volume_lbas, path_table_size, volume_id)
    )

    terminator = bytearray(SECTOR)
    terminator[0] = 255
    terminator[1:6] = b"CD001"
    terminator[6] = 1
    image[TERMINATOR_LBA * SECTOR : TERMINATOR_LBA * SECTOR + SECTOR] = (
        terminator
    )

    image[PATH_L_BA * SECTOR : PATH_L_BA * SECTOR + SECTOR] = path_table(False)
    image[PATH_M_LBA * SECTOR : PATH_M_LBA * SECTOR + SECTOR] = path_table(True)
    image[ROOT_DIR_LBA * SECTOR : ROOT_DIR_LBA * SECTOR + SECTOR] = root
    image[PUP_DIR_LBA * SECTOR : PUP_DIR_LBA * SECTOR + SECTOR] = pup
    image[FILE_LBA * SECTOR : FILE_LBA * SECTOR + len(payload)] = payload

    return bytes(image)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Build an ISO 9660 disc image carrying "
        "/PS3_UPDATE/PS3UPDAT.PUP for dev_bdvd."
    )
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--pup", help="a real update file to put on the disc")
    src.add_argument(
        "--size",
        default="1M",
        help="size of the placeholder package (default 1M; K/M/G accepted)",
    )
    ap.add_argument("--out", required=True, help="the image to write")
    ap.add_argument(
        "--volume-id", default="PS3PUP", help="the disc's volume identifier"
    )
    ap.add_argument(
        "--force", action="store_true", help="overwrite an existing image"
    )
    args = ap.parse_args()

    if os.path.exists(args.out) and not args.force:
        raise SystemExit(f"{args.out} exists; pass --force to overwrite it")

    payload = read_payload(args)
    image = build(payload, args.volume_id)

    with open(args.out, "wb") as f:
        f.write(image)

    print(
        f"wrote {args.out}: {len(image)} bytes, "
        f"{len(image) // SECTOR} sector(s) of {SECTOR}; "
        f"/{PUP_DIR}/{PUP_NAME} is {len(payload)} bytes"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
