#!/usr/bin/env python3
"""ps3_encdec.py - the console's ENCDEC keys from PCK1, and the storage seal.

The console's 48-byte EID root key (PCK1, per-console key 1: 32 bytes of key,
16 of IV) is the only input.  lv1ldr runs it through the four published
seeds -

    encdec data   AES-256-CBC(PCK1, seeds[0x00:0x20])   -> the storage data key
    encdec tweak  AES-256-CBC(PCK1, seeds[0x40:0x60])   -> the storage tweak key
    ATA data      AES-256-CBC(PCK1, seeds[0x20:0x40])   -> the disk's data key
    ATA tweak     AES-256-CBC(PCK1, seeds[0x60:0x80])   -> the disk's tweak key

and the encdec pair then encrypts every 512-byte sector of the storage area
with XTS-AES, the sector number (absolute offset / 512) as the tweak.  This is
the same ladder hw/ppc/ps3_aes/ps3_aes.c implements, and `selftest` checks it
against the known answers built into that file, so a seal made here is the seal
the model reads back - and the seal a console expects.

Where PCK1 comes from matters: it is *not* in a NOR/NAND dump.  Per
`docs/PCK.txt` it is per_console_root_key_1, derived from PCK0 (the channel-66
readout) by metldr and carried in metldr, which copies it into its own local
store (0x30 bytes at 0x00) before it does anything else; `isoldr` clears it
later.  `chain_keys.py --scan-lv0` opens the dump's containers with PCK0 and
scans the decrypted metldr first, then lv0ldr.2, for a raw 48-byte copy accepted
by EID0 - a model convenience for a copy, not the hardware derivation.
`find_erk.py --erk <48-byte candidate> --eid0 <the dump's eEID>` is the check
that a candidate belongs to a console: it must reproduce EID0 section 0's
AES-CMAC, which a wrong key cannot.

The tool never prints key material.  `keys` writes the ladder to a file (128
bytes: encdec data, encdec tweak, ATA data, ATA tweak, in that order) and prints
a short id per key so two runs can be compared without the bytes ending up in a
log; `seal`/`open` use the keys in memory only.

Usage
  py scripts/ps3_encdec.py selftest
  py scripts/ps3_encdec.py loaders --dump nor.bin --readout ch66.bin
  py scripts/ps3_encdec.py loaders --dump nor.bin --readout ch66.bin --bank 1
  py scripts/ps3_encdec.py verify --pck1 <48 bytes> --dump nor.bin
  py scripts/ps3_encdec.py keys  --pck1 erk48.bin --out .tmp/encdec-keys.bin
  py scripts/ps3_encdec.py seal  --pck1 erk48.bin --image emmc.img --storage
  py scripts/ps3_encdec.py open  --pck1 erk48.bin --image emmc.img --storage
  py scripts/ps3_encdec.py seal  --pck1 - --image hdd.raw --ata
  py scripts/ps3_encdec.py open  --pck1 erk48.bin --image drive.img --ata
                                 # a FAT console's disk: --fat instead

The default seal is the eMMC storage area's (the encdec pair, AES-256 XTS).
A console's *disk* is a different scheme: `--ata` uses the ATA pair with
AES-128 XTS and the 16-bit sector swap, `--fat` the ATA pair with AES-192 CBC
and the same swap, exactly as ps3encdec's decrypt_all_sectors() does.

`--pck1 -` reads the 48 bytes from stdin, so a key given to the shell does not
have to appear in the process list.  `--seeds` takes the 128-byte block (or a
loader image that carries the four published blocks, in either interleave);
without it the published block is used, which is the one lv1ldr 4.93 carries.

Needs pycryptodome (`pip install pycryptodome`); `ps3_emmc_create.py` builds and
uses the C tool from hw/ppc/ps3_aes for the same job when a compiler is around.
"""
import argparse
import hashlib
import os
import struct
import sys

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import CMAC
except ImportError:
    sys.stderr.write("ps3_encdec.py needs pycryptodome (pip install pycryptodome)\n")
    raise SystemExit(4)

SECTOR = 512
CHUNK = 1024 * 1024
STORAGE_OFF = 0x10000000        # where an eMMC image's storage area starts
ERK_SIZE = 48

# The four seeds, in the order the ladder uses them.  This is the model's copy
# (hw/ppc/ps3_aes/ps3_aes.c, ps3_ladder_default) and the block lv1ldr carries.
SEEDS_DEFAULT = bytes.fromhex(
    "E2D05D4071945B01C36D5151E88CB8334AAA298081D8C44F185DC660ED575686"
    "D92D65DB057D49E1A66F2274B8BAC50883844ED756CA79516362EA8ADAC60326"
    "02083292C305D538BC50E699710C0A3E55F51CBAA535A38030B67F79C905BDA3"
    "C3B3B5AACC74CD6A48EFABF44DCDF16E379F55F5777D09FBEEDE07058E94BE08")
ENCDEC_DATA = slice(0x00, 0x20)
ENCDEC_TWEAK = slice(0x40, 0x60)
ATA_DATA = slice(0x20, 0x40)
ATA_TWEAK = slice(0x60, 0x80)

# EID0: the section-0 record that proves a key belongs to a console.  The
# per-console INDIV is the ERK through this seed, the section key is one AES
# block under INDIV[0x20:0x40], and section 0's plaintext ends with its CMAC.
INDIV_SEED = bytes.fromhex(
    "abcaad1771efabfc2b921276fac2130c37a6be3fef82c79f3ba5733fc35a690b"
    "08b358f970fa16a3d2ffe2299e841ee4d3db0e0c9baeb51bc7dff10467472f85")
SECTION_SEED_0 = bytes.fromhex("2ed7ce8d1d55454585bf6a3281cd03af")
EID0_SIZE, EID0_HEADER, EID0_SECTION, EID0_CMAC = 0x860, 0x20, 0xC0, 0xA8
EID_OFF = 0x2F000               # where a NOR/NAND dump carries the eEID

# The known answers from hw/ppc/ps3_aes/ps3_aes.c, ps3_aes_selftest().
KAT_CBC_KEY = bytes(range(32))
KAT_CBC_PT = bytes(range(32))
KAT_CBC_CT = bytes.fromhex(
    "5A6E045708FB7196F02E553D02C3A692C77147EBD5121DE8D0FAE7762423B6BF")
KAT_XTS_CT = bytes.fromhex(
    "3A8C89CAB036012A4EE848E9819C281A79BF4DA7D64C9155D0DBBF7A225238AA"
    "B4A216E205A1D63A075A0130F44F93B4B19BD20B620698719B8F9E4401983BAF")


# --------------------------------------------------------------------------
# AES-256, CBC (the ladder) and XTS (the sectors).  ECB comes from pycryptodome;
# the modes are built on it so both match aes.c / ps3_aes.c exactly.

def ecb_encrypt(key, block):
    return AES.new(key, AES.MODE_ECB).encrypt(block)


def ecb_decrypt(key, block):
    return AES.new(key, AES.MODE_ECB).decrypt(block)


def cbc_encrypt(key, iv, data):
    """AES-256-CBC encrypt; `data` must be a whole number of blocks."""
    if len(data) % 16:
        raise ValueError("CBC input must be 16-byte aligned")
    out = bytearray()
    chain = iv
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i:i + 16], chain))
        chain = ecb_encrypt(key, block)
        out += chain
    return bytes(out)


def cbc_decrypt(key, iv, data):
    if len(data) % 16:
        raise ValueError("CBC input must be 16-byte aligned")
    out = bytearray()
    chain = iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(ecb_decrypt(key, block), chain))
        chain = block
    return bytes(out)


def xts_crypt(data_key, tweak_key, sector, buf, encrypt, keybits=256):
    """XTS-AES over one 512-byte sector, tweak = sector number (little-endian).

    Port of aes_xts_crypt() from naehrwert's ps3encdec: encrypt the tweak with
    the tweak key, then per 16-byte block xor / crypt / xor and advance the
    tweak by x in GF(2^128) with the same byte order (bit 7 of byte i is the
    carry out of byte i).

    `keybits` is the AES key size the ENCDEC device is given: the hardware path
    is 128, so only the first 16 bytes of each 32-byte derived key are used,
    while the model uses all 32.  The tweak and the GF step are the same either
    way.
    """
    if not buf or len(buf) % 16:
        return bytes(buf)
    data_key = data_key[:keybits // 8]
    tweak_key = tweak_key[:keybits // 8]
    tw = bytearray(16)
    struct.pack_into("<Q", tw, 0, sector & 0xFFFFFFFFFFFFFFFF)
    tw = bytearray(ecb_encrypt(tweak_key, bytes(tw)))

    out = bytearray(buf)
    for off in range(0, len(out), 16):
        block = bytes(a ^ b for a, b in zip(out[off:off + 16], tw))
        block = ecb_encrypt(data_key, block) if encrypt else ecb_decrypt(data_key, block)
        out[off:off + 16] = bytes(a ^ b for a, b in zip(block, tw))

        carry_in = 0
        carry_out = 0
        for i in range(16):
            carry_out = (tw[i] >> 7) & 1
            tw[i] = ((tw[i] << 1) + carry_in) & 0xFF
            carry_in = carry_out
        if carry_out:
            tw[0] ^= 0x87
    return bytes(out)


def swap16(data):
    """Swap the two bytes of every 16-bit word.

    The ATA path runs `_es16_buffer()` over each sector before it decrypts and
    after it encrypts; the storage/VFLASH path does not.  The swap is its own
    inverse, so one call on the input is the whole of it.
    """
    out = bytearray(data)
    for i in range(0, len(out) - 1, 2):
        out[i], out[i + 1] = out[i + 1], out[i]
    return bytes(out)


def ata_crypt(data_key, tweak_key, sector, buf, encrypt, fat=False):
    """One ATA sector, the way the ENCDEC device's disk side does it.

    From ps3encdec's `decrypt_all_sectors()`: the sector is 16-bit byte-swapped
    first, then a slim console runs XTS-AES with the *first 16 bytes* of each
    derived key, while a FAT console runs AES-192-CBC with a zero IV and no
    tweak (the sector-number XOR in that function belongs to the VFLASH branch,
    not to ATA).  Encryption is the same two steps in the other order.
    """
    if not buf:
        return bytes(buf)
    if fat:
        k = data_key[:24]
        if encrypt:
            return swap16(cbc_encrypt(k, bytes(16), buf))
        return cbc_decrypt(k, bytes(16), swap16(buf))
    if encrypt:
        return swap16(xts_crypt(data_key, tweak_key, sector, buf, True, 128))
    return xts_crypt(data_key, tweak_key, sector, swap16(buf), False, 128)


# --------------------------------------------------------------------------
# Inputs: PCK1 and the seed block.

def read_key(spec):
    """48 bytes from a file, `-` for stdin, or 96 hex digits."""
    if spec == "-":
        raw = sys.stdin.buffer.read(ERK_SIZE + 1)
        where = "stdin"
    elif os.path.isfile(spec):
        with open(spec, "rb") as f:
            raw = f.read(ERK_SIZE + 1)
        where = os.path.basename(spec)
    else:
        try:
            raw = bytes.fromhex("".join(spec.split()))
        except ValueError:
            raise SystemExit("--pck1 is neither a file, - , nor hex")
        where = "the command line"
    if len(raw) != ERK_SIZE:
        raise SystemExit("PCK1 must be %d bytes; %s holds %d"
                         % (ERK_SIZE, where, len(raw)))
    return raw, where


def ladder_seeds(spec):
    """The 128-byte seed block, from a 128-byte file or a loader that carries it.

    A loader holds the same four 0x20-byte blocks, sometimes with the ATA pair
    and the encdec pair swapped (ps3_ladder_views() in ps3_aes.c).  They are
    found by content, so no offset into the loader is assumed.
    """
    if spec is None:
        return SEEDS_DEFAULT, "the published block"
    with open(spec, "rb") as f:
        raw = f.read()
    if len(raw) == 128:
        return raw, os.path.basename(spec)
    blocks = [SEEDS_DEFAULT[i:i + 0x20] for i in range(0, 128, 0x20)]
    found = [raw.find(b) for b in blocks]
    if all(at >= 0 for at in found):
        return b"".join(blocks), os.path.basename(spec)
    raise SystemExit("%s carries none of the four published seed blocks"
                     % os.path.basename(spec))


def derive(erk, seeds):
    """The four keys the ladder yields, in the order the output file uses.

    All four are AES-256-CBC over their seed block, keyed by PCK1 with its own
    RIV as the IV - ps3_encdec_keys_seeds() and ps3_ata_keys_seeds().
    """
    key, riv = erk[:32], erk[32:48]
    return (cbc_encrypt(key, riv, seeds[ENCDEC_DATA]),
            cbc_encrypt(key, riv, seeds[ENCDEC_TWEAK]),
            cbc_encrypt(key, riv, seeds[ATA_DATA]),
            cbc_encrypt(key, riv, seeds[ATA_TWEAK]))


def key_id(key):
    return hashlib.sha256(key).hexdigest()[:16]


# --------------------------------------------------------------------------
# EID0: the only proof that a key belongs to a console.

def read_eid0(spec, dump_off):
    """Read a bounded EID0 record, eEID, or eEID region of a dump."""
    name = os.path.basename(spec)
    if dump_off is not None and dump_off < 0:
        raise SystemExit("eEID dump offset must not be negative")
    try:
        with open(spec, "rb") as f:
            if dump_off is None:
                raw = f.read(0x10001)
            else:
                f.seek(dump_off)
                raw = f.read(0x10000)
    except OSError as e:
        raise SystemExit("%s: %s" % (name, e))
    if dump_off is None and len(raw) == EID0_SIZE:
        return raw, "the bare record"
    if len(raw) != 0x10000:
        raise SystemExit("%s: expected a 0x10000-byte eEID%s"
                         % (name, " at 0x%X" % dump_off if dump_off is not None
                            else " or a 0x%X-byte bare EID0" % EID0_SIZE))

    count = int.from_bytes(raw[0:4], "big")
    total = int.from_bytes(raw[4:8], "big")
    table_end = 0x10 + count * 0x10
    if not 1 <= count <= 16 or not table_end <= total <= len(raw):
        raise SystemExit("%s: invalid eEID table header" % name)
    offsets = set()
    for pos in range(0x10, table_end, 0x10):
        entry = raw[pos:pos + 0x10]
        # Retail: offset/length/ID. Older project fixtures: ID/offset/length.
        layouts = ((int.from_bytes(entry[0:4], "big"),
                    int.from_bytes(entry[4:8], "big"),
                    int.from_bytes(entry[8:16], "big")),
                   (int.from_bytes(entry[8:12], "big"),
                    int.from_bytes(entry[12:16], "big"),
                    int.from_bytes(entry[0:8], "big")))
        for off, size, eid_number in layouts:
            if eid_number == 0 and size == EID0_SIZE and table_end <= off and off + size <= total:
                offsets.add(off)
    if len(offsets) != 1:
        raise SystemExit("%s: invalid or ambiguous EID0 table entry" % name)
    off = offsets.pop()
    return raw[off:off + EID0_SIZE], "EID0 at 0x%X" % (off + (dump_off or 0))


def eid0_authenticate(erk, record):
    """(derivation, INDIV) if this key opens the EID0, else (None, None).

    Section 0's plaintext ends with its AES-CMAC, so a wrong key cannot land on
    it - this is the check a readout has to pass before its keys are the
    console's.  Both CBC directions are tried, as the chain does.
    """
    if len(erk) != ERK_SIZE or len(record) < EID0_HEADER + EID0_SECTION:
        return None, None
    ct = record[EID0_HEADER:EID0_HEADER + EID0_SECTION]
    for name, indiv in (
            ("AES-256-CBC encrypt", cbc_encrypt(erk[:32], erk[32:48], INDIV_SEED)),
            ("AES-256-CBC decrypt", cbc_decrypt(erk[:32], erk[32:48], INDIV_SEED))):
        key = ecb_encrypt(indiv[0x20:0x40], SECTION_SEED_0)
        pt = cbc_decrypt(key, indiv[0x10:0x20], ct)
        mac = CMAC.new(key, ciphermod=AES)
        mac.update(pt[:EID0_CMAC])
        if mac.digest() == pt[EID0_CMAC:EID0_CMAC + 16]:
            return name, indiv
    return None, None


# --------------------------------------------------------------------------
# Loader containers: the opener the mask ROM carries.
#
# `ps3_rom_open()` in hw/ppc/rs6000_ps3.c is the model's copy of what the ROM
# runs at 0x15C-0x39C, and the replayed ROM agrees with it: hdr[0x10] is the
# block count, hdr[0x00] is how many *trailing* blocks are encrypted and is
# clamped to the count, the blocks before that gate are copied through as they
# stand, and the tag is the CBC-MAC over the three header blocks and the
# reconstructed plaintext, masked by S0.  The two counts are not compared: a
# container with size1 != size2 opens on a console, so a reader that insists
# they agree refuses something real (measured in .tmp/probes/counts_vs_rom.py,
# which boots both the built-in opener and the mask ROM on such a header).
#
# This is what decrypts metldr and lv0ldr; the ENCDEC ladder starts from the
# PCK1 that metldr carries, and lv1ldr is a SELF inside lv0, which `loaders`
# reports but does not open - lv0 is sealed to the same PCK1, not to these keys.

LOADER_SLOTS = (("metldr", 0x840), ("lv0ldr", 0xFC0000))
MAX_LOADER_BLOCKS = 0x3DC0       # PS3_ROM_MAX_BLOCKS in rs6000_ps3.c
LOADER_STOP = {0: "opened", 1: "invalid payload length", 2: "MAC mismatch"}


def rom_open_container(blob, off, readout):
    """Open one loader container the way the ROM does.

    `readout` is the 32 bytes channel 66 yields, K_lo then K_hi.  Returns a
    record with the stop code (0 opened, 1 bad length, 2 bad MAC), the block
    count, how many trailing blocks were encrypted, the working key, and - only
    when it opened - the plaintext.  The key is returned so a caller can use
    it; nothing here prints it.
    """
    res = {"stop": 1, "blocks": 0, "encrypted": 0, "key": None, "plain": None}
    if len(readout) != 32 or off < 0 or off + 0x40 > len(blob):
        return res
    hdr = blob[off:off + 0x40]
    total = struct.unpack(">I", hdr[0x10:0x14])[0]
    res["blocks"] = total
    if not total or total > MAX_LOADER_BLOCKS or \
            off + 0x40 + total * 16 > len(blob):
        return res

    encrypted = min(struct.unpack(">I", hdr[0:4])[0], total)
    res["encrypted"] = encrypted
    k_lo, k_hi = readout[:16], readout[16:]
    kp = ecb_encrypt(k_hi, xor_bytes(hdr[0x20:0x30], k_lo))
    res["key"] = kp

    chain = bytes(16)
    for i in range(3):
        chain = ecb_encrypt(kp, xor_bytes(hdr[i * 16:(i + 1) * 16], chain))

    plain = bytearray(total * 16)
    body = blob[off + 0x40:]
    for i in range(total):
        ct = body[i * 16:(i + 1) * 16]
        if i < total - encrypted:
            pt = ct
        else:
            stream = ecb_encrypt(kp, struct.pack(">I", total - i) + hdr[4:0x10])
            pt = xor_bytes(ct, stream)
        plain[i * 16:(i + 1) * 16] = pt
        chain = ecb_encrypt(kp, xor_bytes(pt, chain))

    s0 = ecb_encrypt(kp, struct.pack(">I", 0) + hdr[4:0x10])
    if xor_bytes(chain, s0) == hdr[0x30:0x40]:
        res["stop"] = 0
        res["plain"] = bytes(plain)
    else:
        res["stop"] = 2
    return res


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _rom_seal(kp, hdr, plain, encrypted=None):
    """The inverse of `rom_open_container`, for the selftest.

    `encrypted` is what goes in hdr[0x00]: the number of trailing blocks to
    encrypt.  Anything above the block count is written as given (the ROM
    clamps it), anything below leaves the earlier blocks in the clear.
    """
    n = len(plain) // 16
    enc = n if encrypted is None else min(encrypted, n)
    h = bytearray(hdr[:0x40])
    h[0x00:0x04] = struct.pack(">I", n if encrypted is None else encrypted)
    h[0x10:0x14] = struct.pack(">I", n)
    body = bytearray(plain)
    for i in range(n - enc, n):
        stream = ecb_encrypt(kp, struct.pack(">I", n - i) + bytes(h[4:0x10]))
        body[i * 16:(i + 1) * 16] = xor_bytes(body[i * 16:(i + 1) * 16], stream)
    chain = bytes(16)
    for i in range(3):
        chain = ecb_encrypt(kp, xor_bytes(bytes(h[i * 16:(i + 1) * 16]), chain))
    for i in range(n):
        chain = ecb_encrypt(kp, xor_bytes(plain[i * 16:(i + 1) * 16], chain))
    s0 = ecb_encrypt(kp, struct.pack(">I", 0) + bytes(h[4:0x10]))
    h[0x30:0x40] = xor_bytes(chain, s0)
    return bytes(h) + bytes(body)


def find_pck1(plain, record, align=16):
    """The PCK1 metldr carries: a 48-byte copy EID0's CMAC accepts.

    The search is over aligned copies; a candidate is only reported when it
    authenticates the console's own EID0, so a hit is proof and a miss is not a
    guess.  Returns (key, offset) or (None, None).
    """
    if not plain or record is None:
        return None, None
    for at in range(0, len(plain) - ERK_SIZE + 1, align):
        cand = plain[at:at + ERK_SIZE]
        if eid0_authenticate(cand, record)[0] is not None:
            return cand, at
    return None, None


# --------------------------------------------------------------------------
# Commands.

def print_ladder(erk, seeds, out):
    encdec_data, encdec_tweak, ata_data, ata_tweak = derive(erk, seeds)
    for name, key in (("encdec data ", encdec_data), ("encdec tweak", encdec_tweak),
                      ("ATA data    ", ata_data), ("ATA tweak   ", ata_tweak)):
        print("%s id %s" % (name, key_id(key)))
    if out:
        with open(out, "wb") as f:
            f.write(encdec_data + encdec_tweak + ata_data + ata_tweak)
        print("wrote     %s (128 bytes: encdec data, encdec tweak, ATA data, "
              "ATA tweak)" % out)


def cmd_verify(args):
    erk, where = read_key(args.pck1)
    spec = args.dump or args.eid0
    record, what = read_eid0(spec, args.eid0_offset if args.dump else None)
    derivation, _ = eid0_authenticate(erk, record)

    print("PCK1      id %s from %s" % (key_id(erk), where))
    print("EID0      %s of %s, section 0 CMAC %s"
          % (what, os.path.basename(spec),
             "OK" if derivation else "does not match"))
    if not derivation:
        print("verdict   candidate did not authenticate the selected EID0 record")
        return 3
    print("verdict   candidate authenticated the selected EID0 record (%s)" % derivation)
    if args.out:
        seeds, _ = ladder_seeds(args.seeds)
        print_ladder(erk, seeds, args.out)
    return 0


# A SELF's header is not encrypted: the certificate, the program id header and
# the segment table can be read straight out of a bank record, which is what
# lets the reader report lv0 and the loaders it carries without any key.
LV0_APPIDS = {8: "lv1ldr", 9: "lv2ldr", 10: "isoldr", 11: "(11)", 12: "appldr"}


def self_header(blob, base=0):
    """The public part of a SELF at `base`: sizes, app id, segments."""
    if base + 0x70 > len(blob) or blob[base:base + 4] != b"SCE\0":
        return None
    h = {"file_off": struct.unpack(">Q", blob[base + 0x10:base + 0x18])[0],
         "file_size": struct.unpack(">Q", blob[base + 0x18:base + 0x20])[0],
         "app": struct.unpack(">Q", blob[base + 0x28:base + 0x30])[0],
         "segments": []}
    app = h["app"]
    h["authid"] = blob[base + app:base + app + 8].hex() if app else None
    # authid 1ff0 0000 <app> 0000 01: the app id is the fifth byte.
    h["appid"] = int(h["authid"][8:10], 16) if h["authid"] else None
    h["name"] = LV0_APPIDS.get(h["appid"], "?")

    phoff = struct.unpack(">Q", blob[base + 0x38:base + 0x40])[0]
    elf = struct.unpack(">Q", blob[base + 0x30:base + 0x38])[0]
    if phoff and elf and base + elf + 0x3A <= len(blob):
        phnum = struct.unpack(">H", blob[base + elf + 0x38:base + elf + 0x3A])[0]
        entsize = struct.unpack(">H", blob[base + elf + 0x36:base + elf + 0x38])[0]
        for i in range(min(phnum, 8)):
            p = base + phoff + i * (entsize or 0x38)
            if p + 0x38 > len(blob):
                break
            ptype, _flags = struct.unpack(">II", blob[p:p + 8])
            p_off, _vaddr, _paddr, filesz, memsz = struct.unpack(
                ">QQQQQ", blob[p + 8:p + 0x30])
            if ptype == 1:
                h["segments"].append((p_off, filesz, memsz))
    return h


def lv0_report(dump, blob, where, bank_index=0, encrypted=False):
    """Read lv0's SELF header from the bank and list the SELFs inside it.

    lv0 is the file the console loads after PCK1 opens it.  Its own SELF header
    sits before the encryption root and is therefore readable from the bank
    with no key, which is what this prints.  The payload it carries is not: the
    embedded loader SELFs are inside encrypted segments, so they only appear
    when a decrypted lv0 payload is supplied (`encrypted=False`).
    """
    if blob is None:
        try:
            import ps3_ros_bank as rb
        except ImportError:
            print("lv0       ps3_ros_bank.py not importable; cannot read the bank")
            return
        found = rb.banks(dump)
        if not found:
            print("lv0       no recovery bank in this dump")
            return
        off, length, _name = found[min(bank_index, len(found) - 1)]
        bank = dump[off:off + length]
        try:
            blob = rb.payload(bank, "lv0")
        except SystemExit as e:
            print("lv0       %s" % e)
            return
        where = "bank %d at 0x%X" % (bank_index, off)

    h = self_header(blob)
    if not h:
        if encrypted:
            print("lv0       %s does not begin with a SELF header" % where)
            return
        print("lv0       %s: decrypted payload, %d bytes, no SELF header (the "
              "image begins %s)" % (where, len(blob), blob[:4].hex()))
    else:
        print("lv0       %s: SELF %d bytes (payload 0x%X at 0x%X), authid %s"
              % (where, len(blob), h["file_size"], h["file_off"],
                 h["authid"]))
        for i, (off, filesz, memsz) in enumerate(h["segments"]):
            print("          segment %d at 0x%X, 0x%X bytes (0x%X in memory)"
                  % (i, off, filesz, memsz))

    if encrypted:
        print("          its segments are encrypted, so the loaders it carries "
              "are not readable here; give --lv0-decrypted for the table")
        return

    # Every SELF header inside the payload, by magic, skipping the container's
    # own header at 0.  The same header can appear twice: once before its body,
    # and once in the table at the end.
    seen = {}
    at = blob.find(b"SCE\0", 1)
    while at >= 0:
        sub = self_header(blob, at)
        if sub and sub["file_size"]:
            end = at + sub["file_off"] + sub["file_size"]
            body = "body" if end <= len(blob) else "header only"
            seen.setdefault(sub["authid"], []).append((at, sub, body))
        at = blob.find(b"SCE\0", at + 1)

    for authid, hits in sorted(seen.items(), key=lambda kv: kv[1][0][0]):
        for at, sub, body in hits:
            print("          %-7s app %2s at +0x%06X, %d bytes (%s)"
                  % (sub["name"], sub["appid"], at, sub["file_size"], body))

    lv1 = seen.get("1ff0000008000001")
    if lv1:
        print("lv1ldr.2  inside lv0 at +0x%X (%d bytes)" % (lv1[0][0],
                                                        lv1[0][1]["file_size"]))
    else:
        print("lv1ldr.2  not inside this lv0: no SELF with app id 8 in its "
              "extent.  It is its own record (CORE_OS `lv1ldr.self`, authid "
              "1ff0000008000001), so it is opened from there, not from lv0")


def cmd_loaders(args):
    """Open metldr and lv0ldr from a dump with a channel-66 readout.

    This is the first step of the chain lv1ldr needs, done the way the console
    does it rather than off a captured copy: the readout goes through the ROM's
    ladder, the header's block count and Size1 gate decide what is decrypted,
    and the tag has to verify.  When metldr opens, the plaintext is scanned for
    the PCK1 that EID0 accepts; that key is what the ENCDEC ladder is derived
    from, and what lv0 (and through it lv1ldr) is sealed to.
    """
    with open(args.readout, "rb") as f:
        readout = f.read(33)
    if len(readout) != 32:
        raise SystemExit("--readout must be the 32-byte channel-66 capture "
                         "(PCK0: K_lo then K_hi); %s holds %d bytes"
                         % (os.path.basename(args.readout), len(readout)))

    with open(args.dump, "rb") as f:
        blob = f.read()
    print("dump      %s (%d bytes)" % (os.path.basename(args.dump), len(blob)))
    print("PCK0      32-byte channel-66 readout from %s"
          % os.path.basename(args.readout))

    opened = {}
    for name, off in LOADER_SLOTS:
        rec = rom_open_container(blob, off, readout)
        line = "%-8s @0x%06X  %-23s blocks %5d, encrypted %5d" % (
            name, off, LOADER_STOP[rec["stop"]], rec["blocks"],
            rec["encrypted"])
        print(line)
        if rec["stop"]:
            continue
        opened[name] = rec
        print("          plaintext %d bytes, sha256 %s, starts %s" % (
            len(rec["plain"]), hashlib.sha256(rec["plain"]).hexdigest()[:16],
            rec["plain"][:4].hex()))

    pck1 = None
    if "metldr" in opened:
        try:
            record, what = read_eid0(args.eid0 or args.dump,
                                     None if args.eid0 else args.eid0_offset)
        except SystemExit as e:
            print("EID0      %s" % e)
            record, what = None, None
        if record is not None:
            pck1, at = find_pck1(opened["metldr"]["plain"], record)
            if pck1:
                print("PCK1      metldr carries a copy at +0x%X, EID0 %s: %s"
                      % (at, what, "accepts it" if eid0_authenticate(
                          pck1, record)[0] else "says no"))
                seeds, seeds_where = ladder_seeds(args.seeds)
                print("seeds     %s" % seeds_where)
                print_ladder(pck1, seeds, args.out)
            else:
                print("PCK1      metldr opened, but no aligned 48-byte copy in "
                      "its plaintext authenticates %s" % what)
    elif "lv0ldr" not in opened:
        print("PCK1      neither container opened, so there is nothing to "
              "carry it")

    if "lv0ldr" in opened:
        print("lv0ldr    plaintext holds the stage lv0 is loaded from; lv0 is "
              "sealed to PCK1, not to this container key")

    if args.lv0_decrypted:
        with open(args.lv0_decrypted, "rb") as f:
            lv0_report(None, f.read(), os.path.basename(args.lv0_decrypted))
    elif args.lv0:
        with open(args.lv0, "rb") as f:
            lv0_report(None, f.read(), os.path.basename(args.lv0), encrypted=True)
    else:
        lv0_report(blob, None, None, args.bank, encrypted=True)

    print("next      lv0's payload needs its own key; lv1ldr.2 is a separate "
          "record (authid 1ff0000008000001) opened from the CORE_OS side"
          "%s" % (" - PCK1 above is the first input it needs" if pck1 else ""))
    return 0 if ("metldr" in opened or "lv0ldr" in opened) else 3


def cmd_keys(args):
    erk, where = read_key(args.pck1)
    seeds, seeds_where = ladder_seeds(args.seeds)

    print("PCK1      48 bytes from %s, id %s" % (where, key_id(erk)))
    print("seeds     %s, id %s" % (seeds_where, key_id(seeds)))
    print_ladder(erk, seeds, args.out)
    if not args.out:
        print("no --out: nothing written (this tool does not print key bytes)")
    return 0


def crypt_image(args, encrypt):
    off, length = args.offset, args.length
    if args.storage:
        off = args.offset if args.offset is not None else STORAGE_OFF
    elif off is None:
        off = 0
    if length is None:
        length = os.path.getsize(args.image) - off
    if off % SECTOR or length % SECTOR:
        raise SystemExit("offset 0x%X and length 0x%X must be 512-byte aligned"
                         % (off, length))
    if length <= 0:
        raise SystemExit("nothing to %s at 0x%X"
                         % ("seal" if encrypt else "open", off))

    erk, where = read_key(args.pck1)
    seeds, _ = ladder_seeds(args.seeds)
    encdec_data, encdec_tweak, ata_data, ata_tweak = derive(erk, seeds)
    ata = args.ata or args.fat

    with open(args.image, "r+b") as f:
        f.seek(off)
        if f.tell() != off:
            raise SystemExit("cannot seek to 0x%X in %s" % (off, args.image))
        done = 0
        while done < length:
            n = min(CHUNK, length - done)
            f.seek(off + done)
            buf = f.read(n)
            if len(buf) != n:
                raise SystemExit("short read at 0x%X" % (off + done))
            out = bytearray()
            for i in range(0, n, SECTOR):
                sector = (off + done + i) // SECTOR
                if ata:
                    out += ata_crypt(ata_data, ata_tweak, sector,
                                     buf[i:i + SECTOR], encrypt,
                                     fat=args.fat)
                else:
                    out += xts_crypt(encdec_data, encdec_tweak, sector,
                                     buf[i:i + SECTOR], encrypt)
            f.seek(off + done)
            f.write(bytes(out))
            done += n

    print("%s 0x%X byte(s) at 0x%X (sector 0x%X), %s, key id %s"
          % ("sealed" if encrypt else "opened", length, off, off // SECTOR,
             "FAT ATA (AES-192 CBC, swapped)" if args.fat else
             "ATA (AES-128 XTS, swapped)" if ata else "storage",
             key_id(erk)))
    return 0


def cmd_selftest(_args):
    good = cbc_encrypt(KAT_CBC_KEY, bytes(16), KAT_CBC_PT) == KAT_CBC_CT
    print("AES-256-CBC  %s" % ("known answer" if good else "FAILED"))

    erk = bytes(range(48))
    _, _, ata_data, ata_tweak = derive(erk, SEEDS_DEFAULT)
    pt = bytes(((i * 7 + 3) & 0xFF) for i in range(64))
    ct = xts_crypt(ata_data, ata_tweak, 0, pt, True)
    xts_ok = ct == KAT_XTS_CT
    back_ok = xts_crypt(ata_data, ata_tweak, 0, ct, False) == pt
    print("XTS-AES      %s, round trip %s"
          % ("known answer" if xts_ok else "FAILED",
             "OK" if back_ok else "FAILED"))

    # The disk side: the ATA pair, AES-128 and the 16-bit swap.  A sector must
    # survive the round trip, and the result must differ from the storage seal
    # - same keys, different scheme, so agreement between them would mean the
    # ATA branch is not being taken.
    pt = bytes(((i * 11 + 7) & 0xFF) for i in range(SECTOR))
    ata_ct = ata_crypt(ata_data, ata_tweak, 0x1234, pt, True)
    ata_ok = ata_ct != pt and \
        ata_crypt(ata_data, ata_tweak, 0x1234, ata_ct, False) == pt and \
        swap16(ata_ct) != ata_ct
    fat_ct = ata_crypt(ata_data, ata_tweak, 0x1234, pt, True, fat=True)
    fat_ok = ata_crypt(ata_data, ata_tweak, 0x1234, fat_ct, False, fat=True) == pt
    print("ATA-AES      slim XTS-128 round trip %s, FAT CBC-192 round trip %s"
          % ("OK" if ata_ok else "FAILED", "OK" if fat_ok else "FAILED"))

    # A synthetic EID0 record made exactly the way a console makes one: the
    # record must accept its own key and refuse a different one.
    indiv = cbc_encrypt(erk[:32], erk[32:48], INDIV_SEED)
    sec = ecb_encrypt(indiv[0x20:0x40], SECTION_SEED_0)
    pt = bytearray(((i * 5 + 1) & 0xFF) for i in range(EID0_SECTION))
    mac = CMAC.new(sec, ciphermod=AES)
    mac.update(bytes(pt[:EID0_CMAC]))
    pt[EID0_CMAC:EID0_CMAC + 16] = mac.digest()
    record = bytes(EID0_HEADER) + cbc_encrypt(sec, indiv[0x10:0x20], bytes(pt))
    eid_ok = eid0_authenticate(erk, record)[0] is not None and \
        eid0_authenticate(bytes(range(1, 49)), record)[0] is None
    print("EID0 CMAC    accepts its own record, refuses another key: %s"
          % ("OK" if eid_ok else "FAILED"))

    # The loader opener: the ROM's rules, on a synthetic metldr.  The tag is
    # valid for the header it is stored in in every case, so each verdict is
    # about the rule being tested and not about a broken seal.
    kp = bytes(range(0x10, 0x20))
    hdr = bytearray(0x40)
    hdr[4:0x10] = bytes.fromhex("43b6ef4ae20f7400c8809e53")
    blocks = 64
    body = bytearray((i * 3 + 5) & 0xFF for i in range(blocks * 16))
    body[0x100:0x100 + ERK_SIZE] = erk       # the key `record' was made for
    body = bytes(body)
    k_hi = bytes.fromhex("a1a2a3a4a5a6a7a8a9aaabacadaeafb0")
    sealed = _rom_seal(kp, hdr, body)
    readout = xor_bytes(sealed[0x20:0x30], ecb_decrypt(k_hi, kp)) + k_hi
    open_ok = rom_open_container(sealed, 0, readout)["stop"] == 0
    clamp_ok = rom_open_container(
        _rom_seal(kp, hdr, body, encrypted=blocks + 1), 0, readout)["plain"] == body
    gate_ok = rom_open_container(
        _rom_seal(kp, hdr, body, encrypted=blocks - 1), 0, readout)["plain"] == body
    flip = bytearray(sealed)
    flip[0x30] ^= 1
    tag_ok = rom_open_container(bytes(flip), 0, readout)["stop"] == 2
    found, at = find_pck1(body, record)
    pck1_ok = found == erk and at == 0x100
    print("loader open  equal counts %s, size1 clamped %s, Size1 gate %s, "
          "bad tag refused %s, PCK1 found %s"
          % tuple("OK" if x else "FAILED"
                  for x in (open_ok, clamp_ok, gate_ok, tag_ok, pck1_ok)))

    print("PCK1 ladder  encdec data key id %s" % key_id(derive(erk, SEEDS_DEFAULT)[0]))
    all_ok = good and xts_ok and back_ok and eid_ok and open_ok and clamp_ok \
        and gate_ok and tag_ok and pck1_ok
    print("result       %s" % ("OK" if all_ok else "FAILED"))
    return 0 if all_ok else 1


def cmd_chain(args):
    """PCK0/ERK -> metldr/lv0ldr -> PCK1 -> ladder, in one pass.

    The chain is walked in order and the first value that is missing is the
    only thing reported, so a run ends with the input it needs rather than
    with a verdict about the keys it was given.  `--pck1` starts at the second
    arrow and is held to the EID0 CMAC; `--readout` starts at the first and
    lets metldr supply PCK1 itself.
    """
    with open(args.dump, "rb") as f:
        dump = f.read()
    print("dump      %s (%d bytes)" % (os.path.basename(args.dump), len(dump)))
    record, what = read_eid0(args.eid0 or args.dump,
                             None if args.eid0 else args.eid0_offset)

    pck1 = None
    if args.pck1:
        pck1, where = read_key(args.pck1)
        ok = eid0_authenticate(pck1, record)[0] is not None
        print("PCK1      id %s from %s" % (key_id(pck1), where))
        print("EID0      %s: %s" % (what, "accepts it" if ok else "does not match"))
        if not ok:
            print("blocked   that key is not this console's; nothing was derived")
            return 3
    else:
        with open(args.readout, "rb") as f:
            readout = f.read(33)
        if len(readout) != 32:
            raise SystemExit("--readout must be 32 bytes (K_lo then K_hi)")
        opened = {}
        for name, off in LOADER_SLOTS:
            rec = rom_open_container(dump, off, readout)
            print("%-8s @0x%06X  %s" % (name, off, LOADER_STOP[rec["stop"]]))
            if not rec["stop"]:
                opened[name] = rec
        if not opened:
            print("blocked   PCK0 does not open metldr or lv0ldr, so there is "
                  "no PCK1 to carry")
            return 3
        source = opened.get("metldr") or opened["lv0ldr"]
        pck1, at = find_pck1(source["plain"], record)
        if not pck1:
            print("blocked   the opened loader carries no 48-byte copy that "
                  "authenticates %s" % what)
            return 3
        print("PCK1      carried at +0x%X, %s accepts it" % (at, what))

    seeds, seeds_where = ladder_seeds(args.seeds)
    print("seeds     %s" % seeds_where)
    print_ladder(pck1, seeds, args.out)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Derive the console's ENCDEC keys from PCK1 and seal or "
                    "open an image's 512-byte sectors with them.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, image=False):
        p.add_argument("--pck1", required=True,
                       help="48-byte EID root key (PCK1, per-console key 1): "
                            "file, - for stdin, or hex")
        p.add_argument("--seeds", help="128-byte seed block or a loader that "
                                       "carries it (default: the published one)")

    v = sub.add_parser("verify", help="does this key belong to that console?")
    common(v)
    src = v.add_mutually_exclusive_group(required=True)
    src.add_argument("--dump", help="a NOR/NAND dump that carries the eEID")
    src.add_argument("--eid0", help="a bare EID0 record, or a 0x10000-byte eEID")
    v.add_argument("--eid0-offset", type=lambda s: int(s, 0), default=EID_OFF,
                   help="where the eEID starts in --dump (default 0x%X)" % EID_OFF)
    v.add_argument("--out", help="write the 128-byte ladder if the key passes")
    v.set_defaults(func=cmd_verify)

    c = sub.add_parser("chain", help="PCK0/ERK -> metldr/lv0ldr -> PCK1 -> "
                                      "ladder, stopping at the first missing input")
    c.add_argument("--dump", required=True, help="the console's NOR/NAND dump")
    src = c.add_mutually_exclusive_group(required=True)
    src.add_argument("--readout", help="32-byte channel-66 capture (PCK0)")
    src.add_argument("--pck1", help="48-byte ERK for this console (PCK1, "
                                      "per-console key 1; skips metldr)")
    c.add_argument("--eid0", help="a bare EID0 record (default: the dump's eEID)")
    c.add_argument("--eid0-offset", type=lambda s: int(s, 0), default=EID_OFF,
                   help="where the eEID starts in --dump (default 0x%X)" % EID_OFF)
    c.add_argument("--seeds", help="128-byte seed block or a loader that "
                                    "carries it (default: the published one)")
    c.add_argument("--out", help="write the 128-byte ladder if it is reached")
    c.set_defaults(func=cmd_chain)

    k = sub.add_parser("keys", help="derive the four keys and write them out")
    common(k)
    k.add_argument("--out", help="write the 128-byte ladder here")
    k.set_defaults(func=cmd_keys)

    for name, encrypt in (("seal", True), ("open", False)):
        p = sub.add_parser(name, help="%s the sectors of an image"
                                      % ("encrypt" if encrypt else "decrypt"))
        common(p)
        p.add_argument("--image", required=True)
        p.add_argument("--offset", type=lambda s: int(s, 0),
                       help="first byte (default 0, or 0x10000000 for --storage)")
        p.add_argument("--length", type=lambda s: int(s, 0),
                       help="bytes (default: to the end of the image)")
        p.add_argument("--storage", action="store_true",
                       help="the eMMC storage area: start at 0x10000000")
        media = p.add_mutually_exclusive_group()
        media.add_argument("--ata", action="store_true",
                           help="a console's disk: the ATA pair, AES-128 XTS "
                                "with the 16-bit swap")
        media.add_argument("--fat", action="store_true",
                           help="a FAT console's disk: the ATA pair, "
                                "AES-192 CBC with the 16-bit swap")
        p.set_defaults(func=lambda a, e=encrypt: crypt_image(a, e))

    L = sub.add_parser("loaders", help="open metldr/lv0ldr from a dump with a "
                                       "channel-66 readout, the way the ROM does")
    L.add_argument("--dump", required=True, help="a NOR/NAND dump holding them")
    L.add_argument("--readout", required=True,
                   help="32-byte channel-66 capture (PCK0: K_lo then K_hi)")
    L.add_argument("--eid0", help="a bare EID0 record (default: the dump's eEID)")
    L.add_argument("--eid0-offset", type=lambda s: int(s, 0), default=EID_OFF,
                   help="where the eEID starts in --dump (default 0x%X)" % EID_OFF)
    L.add_argument("--seeds", help="128-byte seed block or a loader that "
                                    "carries it (default: the published one)")
    L.add_argument("--out", help="write the 128-byte ladder if a PCK1 is found")
    L.add_argument("--bank", type=int, default=0, choices=(0, 1),
                   help="which recovery bank to read lv0 from (default 0)")
    L.add_argument("--lv0", help="a carved lv0 SELF to read instead of the bank")
    L.add_argument("--lv0-decrypted",
                   help="the decrypted lv0 payload (the scetool -d ELF), whose "
                        "loader SELFs are then listed")
    L.set_defaults(func=cmd_loaders)

    s = sub.add_parser("selftest", help="check both paths against the model's "
                                        "known answers")
    s.set_defaults(func=cmd_selftest)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
