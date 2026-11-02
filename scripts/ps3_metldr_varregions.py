#!/usr/bin/env python3
"""ps3_metldr_varregions.py - do metldr's two variable regions carry a key?

The two plaintexts of the same metldr build differ in exactly two spans:

    file 0xC476..0xC57B   (LS 0xC876..0xC97B)
    file 0xD2C8..0xD300   (LS 0xD6C8..0xD700)

Both are data (chance-level decodability), and their sizes differ by 8 bytes
between consoles.  If they hold a per-console key or certificate, it should be
readable with a key from the container ladder; this tool tries that.

Key sources, in the order they are used:

  --pck0 HEX32   the 32-byte channel-66 readout (PCK0).  Kp is derived the way
                 the mask ROM does it, in both half orders:
                     Kp = AES-128-ECB(K_hi, hdr[0x20] XOR K_lo)
  --kp HEX32     the container key directly (16 bytes), when the readout is not
                 known - the sample consoles ship this.
  --pck1 HEX96   the 48-byte EID root key (PCK1, per-console key 1), if held.

For each key the tool builds a short list of ladder-stage candidates (the key
itself, AES under the container's 0x20/0x14 fields, XOR masks, SHA-256 halves,
the four ENCDEC seed derivations) and decrypts both regions with AES-ECB and
AES-CBC (zero IV), scoring each result for structure: SCE magic, a plausible
length field, printable text, or zero runs.

Exit status: 0 if any candidate produced structure, 3 if none did, 2 on bad
input.  No key bytes are ever printed; only labels, lengths and scores.

    py scripts/ps3_metldr_varregions.py --plain metldr.2.dec \
        --container metldr.2 --kp <hex> 
    py scripts/ps3_metldr_varregions.py --plain ... --container ... --pck0 <hex>
    py scripts/ps3_metldr_varregions.py --selftest
"""
import argparse
import hashlib
import os
import re
import sys

from Crypto.Cipher import AES

REGIONS = [(0xC476, 0xC57C), (0xD2C8, 0xD301)]


def be32(b, o):
    return int.from_bytes(b[o:o + 4], "big")


def derive_kp(pck0, hdr):
    """Both half orders of the ROM's container-key ladder."""
    if len(pck0) != 32:
        raise SystemExit("PCK0 must be 32 bytes")
    out = []
    for label, k_lo, k_hi in (("K_lo|K_hi", pck0[:16], pck0[16:]),
                              ("K_hi|K_lo", pck0[16:], pck0[:16])):
        try:
            kp = AES.new(k_hi, AES.MODE_ECB).encrypt(
                bytes(x ^ y for x, y in zip(hdr[0x20:0x30], k_lo)))
        except ValueError:
            continue
        out.append((label, kp))
    return out


def candidates(kp, hdr, pck1=None):
    """[(label, key)] - short, explicit, and cheap to try."""
    h20 = hdr[0x20:0x30]
    h14 = hdr[0x14:0x20].ljust(16, b"\x00")
    ecb = AES.new(kp, AES.MODE_ECB)
    out = [("Kp", kp),
           ("AES(Kp,0)", ecb.encrypt(bytes(16))),
           ("AES(Kp,h20)", ecb.encrypt(h20)),
           ("AES(Kp,h14)", ecb.encrypt(h14)),
           ("AES(Kp,Kp)", ecb.encrypt(kp)),
           ("Kp^h20", bytes(x ^ y for x, y in zip(kp, h20))),
           ("Kp^h14", bytes(x ^ y for x, y in zip(kp, h14)))]
    for label, digest in (("sha256(Kp)", hashlib.sha256(kp).digest()),
                          ("sha1(Kp)", hashlib.sha1(kp).digest())):
        out.append((label + "[0:16]", digest[:16]))
        if len(digest) >= 32:
            out.append((label + "[16:32]", digest[16:32]))
    # the ENCDEC ladder shape: AES-CBC(key, seed) over the published seeds
    seeds = _seeds()
    for i in (0, 1, 2, 3):
        blk = seeds[0x20 * i:0x20 * i + 0x20]
        out.append(("cbc(Kp,seed%d)" % i,
                    AES.new(kp, AES.MODE_CBC, bytes(16)).encrypt(blk)[:16]))
    if pck1:
        # PCK1 is 48 bytes: a 32-byte AES-256 key then its 16-byte IV.
        pck1_key = pck1[:32]
        for i in (0, 1, 2, 3):
            blk = seeds[0x20 * i:0x20 * i + 0x20]
            out.append(("cbc(PCK1,seed%d)" % i,
                        AES.new(pck1_key, AES.MODE_CBC,
                                bytes(16)).encrypt(blk)[:16]))
    return out


def _seeds():
    """The published 128-byte seed block, when the tree carries it."""
    here = os.path.dirname(os.path.abspath(__file__))
    for rel in ("../data/seeds.bin", "../data/keys/seeds.bin", "seeds.bin"):
        p = os.path.normpath(os.path.join(here, rel))
        if os.path.exists(p):
            data = open(p, "rb").read()
            if len(data) >= 128:
                return data[:128]
    return bytes(128)


def score(out):
    """(structured?, why) - structure means something a key store would show."""
    if not out:
        return False, "empty"
    if b"SCE\x00" in out[:0x40]:
        return True, "SCE header"
    n = be32(out, 0)
    if 0x10 <= n <= len(out) and out[4:8] in (bytes(4), b"\x00\x00\x00\x02"):
        return True, "length %#x" % n
    zeros = max((len(m) for m in re.findall(b"\x00+", out)), default=0)
    if zeros >= 16:
        return True, "zero run %d" % zeros
    printable = sum(1 for b in out if 32 <= b < 127) / len(out)
    if printable >= 0.70:
        return True, "printable %.0f%%" % (100 * printable)
    return False, "entropy %.2f" % entropy(out)


def entropy(b):
    import math
    n = len(b)
    if not n:
        return 0.0
    counts = [b.count(bytes([i])) for i in range(256)]
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def try_regions(regions, keys):
    """regions: [(name, bytes)]; keys: [(label, key)] -> scored attempts."""
    hits = []
    for label, key in keys:
        if len(key) not in (16, 24, 32):
            continue
        for name, data in regions:
            seg = data[:len(data) // 16 * 16]
            if not seg:
                continue
            for mode in ("ECB", "CBC"):
                try:
                    if mode == "ECB":
                        out = AES.new(key, AES.MODE_ECB).decrypt(seg)
                    else:
                        out = AES.new(key, AES.MODE_CBC, bytes(16)).decrypt(seg)
                except ValueError:
                    continue
                ok, why = score(out)
                hits.append((ok, label, mode, name, why))
    return hits


def cmd_selftest():
    """Two properties, no external data: the PCK0 ladder and the detector."""
    ok = True
    k_lo, k_hi = bytes(range(16)), bytes(range(16, 32))
    want = bytes.fromhex("00112233445566778899aabbccddeeff")
    in20 = bytes(x ^ y for x, y in zip(
        AES.new(k_hi, AES.MODE_ECB).decrypt(want), k_lo))
    hdr = bytes(0x40)
    hdr = hdr[:0x20] + in20
    got = dict(derive_kp(k_lo + k_hi, hdr))
    print("PCK0 ladder  K_lo|K_hi -> %s" %
          ("OK" if got.get("K_lo|K_hi") == want else "FAIL"))
    ok &= got.get("K_lo|K_hi") == want
    got2 = dict(derive_kp(k_hi + k_lo, hdr))
    print("PCK0 ladder  K_hi|K_lo -> %s" %
          ("OK" if got2.get("K_hi|K_lo") == want else "FAIL"))
    ok &= got2.get("K_hi|K_lo") == want

    plain = b"SCE\x00" + bytes(12) + b"marker" + bytes(26)
    key = want
    region = AES.new(key, AES.MODE_ECB).encrypt(plain)
    hits = try_regions([("selftest", region)], [("Kp", want)])
    good = [h for h in hits if h[0]]
    print("detector     SCE marker under Kp -> %s" %
          ("OK" if good else "FAIL"))
    ok &= bool(good)
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--plain", help="the decrypted metldr image")
    ap.add_argument("--container", help="its sealed container (header source)")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--pck0", help="32-byte channel-66 readout (PCK0), hex")
    src.add_argument("--kp", help="16-byte container key, hex")
    ap.add_argument("--pck1", help="48-byte EID root key (PCK1), hex")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return cmd_selftest()
    if not (args.plain and args.container and (args.pck0 or args.kp)):
        ap.error("need --plain, --container and --pck0 or --kp")

    plain = open(args.plain, "rb").read()
    hdr = open(args.container, "rb").read(0x40)
    regions = [("%s(%#x)" % (name, s), plain[s:e]) for name, (s, e) in
               zip(("region1", "region2"), REGIONS)]
    for name, (s, e) in zip(("region1", "region2"), REGIONS):
        if len(plain) < e:
            ap.error("%s does not reach %#x" % (args.plain, e))

    if args.pck0:
        keys = derive_kp(bytes.fromhex(args.pck0), hdr)
        if not keys:
            ap.error("--pck0 did not derive a key")
    else:
        keys = [("Kp", bytes.fromhex(args.kp))]
    cand = []
    for label, kp in keys:
        for clabel, ckey in candidates(kp, hdr,
                                       bytes.fromhex(args.pck1) if args.pck1
                                       else None):
            cand.append(("%s/%s" % (label, clabel), ckey))

    print("key source   %s" % ("PCK0 readout" if args.pck0 else "container key"))
    print("candidates   %d" % len(cand))
    for name, data in regions:
        print("  %-14s %3d B  entropy %.2f  unique %d" %
              (name, len(data), entropy(data), len(set(data))))
    hits = try_regions(regions, cand)
    for ok, label, mode, name, why in sorted(hits, key=lambda h: (not h[0], h[1])):
        if ok:
            print("  HIT  %-28s %-3s %-14s %s" % (label, mode, name, why))
    found = [h for h in hits if h[0]]
    def _entropy(hit):
        part = hit[4].split()[-1]
        try:
            return float(part)
        except ValueError:
            return 99.0

    best = min((h for h in hits if not h[0]), key=_entropy, default=None)
    if found:
        print("\n%d candidate(s) produced structure; inspect the ones above" %
              len(found))
        return 0
    if best:
        print("best neutral result: %s/%s %s (%s)" %
              (best[1], best[2], best[3], best[4]))
    print("\nno candidate produced structure in either region")
    return 3


if __name__ == "__main__":
    sys.exit(main())
