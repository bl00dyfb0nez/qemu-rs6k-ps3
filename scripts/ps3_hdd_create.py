#!/usr/bin/env python3
"""
Create a raw HDD image for the rs6000-ps3 model.

The model stores a console's disk the way the console does: sector 0 is the
ATA key block, AES-256-CBC under the EID root key (PCK1: 32 bytes of key, then
the 16-byte IV), and every other sector is XTS-AES under the two keys it
holds.  With the disk's own copy of the keys present, the model unwraps them on
startup and checks them against the pair PCK1 derives, which is what makes a
disk portable between runs:

    ps3_hdd_create.py --erk-file .tmp/erk.bin -o .tmp/hdd.raw
    ps3_hdd_create.py --erk-file .tmp/erk.bin --size 1G -o .tmp/test.raw

The data area is left zeroed (an unformatted disk): the console - and the
model's guest - formats it on first boot.  No key is printed; only a
fingerprint, because a PCK1 in a log is a console in a log.

    -o/--output      image to create
    --size           bytes ("20G", "512M", or a number); default 20 GiB
    --erk-file       48-byte EID root key (PCK1) dump
    --erk            the same 48 bytes as hex
    --data-key / --tweak-key   use these ATA keys instead of deriving them
    --no-key         plain zero image; the model then runs unkeyed
    --verify         reopen sector 0 and check it matches the keys used

The AES here is a small, dependency-free AES-256 (one 512-byte sector is all
it encrypts), so the script runs anywhere Python does.
"""
import argparse
import hashlib
import os
import sys

SECTOR = 512
MAGIC = b"PS3ATA01"
DEFAULT_SIZE = 20 * 1024 ** 3

# The two static "SB indiv" seeds from ps3_decrypt_tools' kgen.c, the same
# constants the model's ps3_ata_keys() runs through AES-256-CBC.
SEED_DATA = bytes.fromhex(
    "d92d65db057d49e1a66f2274b8bac508"
    "83844ed756ca79516362ea8adac60326")
SEED_TWEAK = bytes.fromhex(
    "c3b3b5aacc74cd6a48efabf44dcdf16e"
    "379f55f5777d09fbeede07058e94be08")


# ---- AES-256, encryption only -------------------------------------------

def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sbox():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4)
        sbox[p] = x ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


SBOX = _build_sbox()


def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)


def _mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _expand_key(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= rcon
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    return w, nr


def _add_round_key(state, w, rnd):
    for c in range(4):
        for r in range(4):
            state[r][c] ^= w[rnd * 4 + c][r]


def encrypt_block(w, nr, block):
    state = [[block[4 * c + r] for c in range(4)] for r in range(4)]
    _add_round_key(state, w, 0)
    for rnd in range(1, nr + 1):
        for r in range(4):
            for c in range(4):
                state[r][c] = SBOX[state[r][c]]
        for r in range(1, 4):
            state[r] = state[r][r:] + state[r][:r]
        if rnd != nr:
            for c in range(4):
                a0, a1, a2, a3 = (state[0][c], state[1][c],
                                  state[2][c], state[3][c])
                state[0][c] = _mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3
                state[1][c] = a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3
                state[2][c] = a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3)
                state[3][c] = _mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2)
        _add_round_key(state, w, rnd)
    return bytes(state[r][c] for c in range(4) for r in range(4))


def cbc_encrypt(key, iv, data):
    if len(data) % 16:
        raise ValueError("length must be a multiple of 16")
    w, nr = _expand_key(key)
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[off:off + 16], prev))
        prev = encrypt_block(w, nr, blk)
        out += prev
    return bytes(out)


def aes256_cbc_self_test():
    """NIST FIPS-197 / SP 800-38A AES-256 ECB and CBC vectors."""
    key = bytes(range(32))
    want = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    w, nr = _expand_key(key)
    got = encrypt_block(w, nr, bytes.fromhex("00112233445566778899aabbccddeeff"))
    if got != want:
        raise SystemExit("AES-256 self-test failed: %s" % got.hex())

    # SP 800-38A F.2.5, CBC-AES256.
    cbc_key = bytes.fromhex("603deb1015ca71be2b73aef0857d7781"
                            "1f352c073b6108d72d9810a30914dff4")
    cbc_iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                          "ae2d8a571e03ac9c9eb76fac45af8e51")
    cbc_want = bytes.fromhex("f58c4c04d6e5f1ba779eabfb5f7bfbd6"
                             "9cfc4e967edb808d679f777bc6702c7d")
    if cbc_encrypt(cbc_key, cbc_iv, plain) != cbc_want:
        raise SystemExit("AES-256-CBC self-test failed")


# ---- keys and the image -------------------------------------------------

def derive_ata_keys(erk):
    data_key = cbc_encrypt(erk[:32], erk[32:48], SEED_DATA)
    tweak_key = cbc_encrypt(erk[:32], erk[32:48], SEED_TWEAK)
    return data_key, tweak_key


def key_sector(erk, data_key, tweak_key):
    plain = bytearray(SECTOR)
    plain[0:8] = MAGIC
    plain[8:40] = data_key
    plain[40:72] = tweak_key
    return cbc_encrypt(erk[:32], erk[32:48], bytes(plain))


def parse_size(text):
    text = text.strip().upper()
    mult = 1
    for suffix, m in (("KIB", 1024), ("MIB", 1024 ** 2), ("GIB", 1024 ** 3),
                      ("K", 1000), ("M", 1000 ** 2), ("G", 1000 ** 3),
                      ("B", 1)):
        if text.endswith(suffix):
            mult = m
            text = text[:-len(suffix)]
            break
    try:
        value = int(text, 0)
    except ValueError:
        raise SystemExit("bad size: %s" % text)
    return value * mult


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--size", default=str(DEFAULT_SIZE),
                    help="image size (default 20G)")
    ap.add_argument("--erk-file")
    ap.add_argument("--erk", help="48-byte EID root key as hex")
    ap.add_argument("--data-key", help="32-byte ATA data key as hex")
    ap.add_argument("--tweak-key", help="32-byte ATA tweak key as hex")
    ap.add_argument("--no-key", action="store_true",
                    help="plain zero image, no key sector")
    ap.add_argument("--verify", action="store_true")
    args = ap.parse_args(argv)

    aes256_cbc_self_test()

    size = parse_size(args.size)
    if size < SECTOR or size % SECTOR:
        raise SystemExit("size must be a multiple of 512 bytes")

    if os.path.exists(args.output):
        raise SystemExit("%s exists; remove it first" % args.output)

    if args.no_key:
        with open(args.output, "wb") as f:
            f.truncate(size)
        print("%s: %d bytes, no key sector (the model runs it unkeyed)" %
              (args.output, size))
        return 0

    erk = None
    if args.erk_file:
        erk = open(args.erk_file, "rb").read()
        if len(erk) != 48:
            raise SystemExit("%s is %d bytes, an EID root key is 48" %
                             (args.erk_file, len(erk)))
    elif args.erk:
        erk = bytes.fromhex(args.erk.replace(" ", ""))
        if len(erk) != 48:
            raise SystemExit("--erk must be 96 hex digits")
    elif not (args.data_key and args.tweak_key):
        raise SystemExit("pass --erk-file/--erk, --data-key and --tweak-key, "
                         "or --no-key")

    data_key = bytes.fromhex(args.data_key.replace(" ", "")) \
        if args.data_key else None
    tweak_key = bytes.fromhex(args.tweak_key.replace(" ", "")) \
        if args.tweak_key else None
    if data_key is None or tweak_key is None:
        if erk is None:
            raise SystemExit("ATA keys need the EID root key to be derived")
        data_key, tweak_key = derive_ata_keys(erk)
    if len(data_key) != 32 or len(tweak_key) != 32:
        raise SystemExit("ATA keys are 32 bytes each")

    if erk is None:
        raise SystemExit("the key sector is wrapped under the EID root key; "
                         "pass --erk-file or --erk")

    sector0 = key_sector(erk, data_key, tweak_key)

    with open(args.output, "wb") as f:
        f.write(sector0)
        f.truncate(size)

    print("%s: %d bytes, key sector written (ATA data key sha256 %s, "
          "tweak key sha256 %s)" %
          (args.output, size,
           hashlib.sha256(data_key).hexdigest()[:16],
           hashlib.sha256(tweak_key).hexdigest()[:16]))

    if args.verify:
        raw = open(args.output, "rb").read(SECTOR)
        if raw != key_sector(erk, data_key, tweak_key):
            raise SystemExit("verify: sector 0 does not match the keys")
        print("verify: sector 0 opens under the EID root key and carries "
              "both ATA keys")

    return 0


if __name__ == "__main__":
    sys.exit(main())
