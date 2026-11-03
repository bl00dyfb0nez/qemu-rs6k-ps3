#!/usr/bin/env python3
"""ps3_ch66_chain.py - channel-66 capture -> PCK1 -> EID0 -> ENCDEC keys.

Two things are being separated here, because conflating them is what made the
4301C look closer than it is:

  * the **capture** is real.  The mask ROM is executed by the model's SPU
    interpreter (`-bios rom.bin`, selftest=on) and the eight `rdch $35,$ch66`
    reads it performs are written to a file by the device (`ch66-capture`).
    Nothing is copied from the command line: the file is what the ROM read.

  * the **console** is synthetic.  No 4301C readout, PCK1 or loader plaintext
    exists in this tree, so this mode builds its own: a chosen 48-byte PCK1,
    an eEID whose EID0 section 0 is sealed and CMAC'd under it (the same
    construction `mk_eid_test.py` uses), and a synthetic "metldr" container
    sealed under the captured PCK0.  The container format, the ladder, the
    CTR/CBC-MAC, the EID0 CMAC and the ENCDEC derivation are the real ones.

What the run proves, in order:

  1. the ROM's channel-66 read loop completes 8 reads and the capture is 32
     bytes in read order;
  2. `Kp = AES-128(K_hi, hdr[0x20] XOR K_lo)` opens the synthetic metldr
     (its own CBC-MAC, no key assumed);
  3. the metldr payload carries PCK1, and the 48 bytes read back out of the
     local store are byte-identical to the sealed copy;
  4. that PCK1 authenticates EID0 section 0's AES-CMAC - the one check a wrong
     key cannot satisfy;
  5. PCK1 runs through the four published seeds to the ENCDEC and ATA pairs,
     and a sector round-trips under them.

Synthetic mode:

    py scripts/ps3_ch66_chain.py --synthetic

Capture-only (verify a real 32-byte capture against this dump, then stop):

    py scripts/ps3_ch66_chain.py --capture ch66.bin --flash CECH4301C.NOR.BIN \
        --eid0 eEID_4301C.bin

A real capture that does not open the dump's containers is reported as such:
no PCK1 is invented, and nothing is written.  That is the current 4301C state.

Exit codes: 0 chain confirmed, 3 capture did not open the container / PCK1 did
not authenticate, 4 usage or material unreadable, 5 the QEMU capture failed.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.stderr.write("ps3_ch66_chain.py needs pycryptodome\n")
    raise SystemExit(4)

HERE = os.path.dirname(os.path.abspath(__file__))
QEMU_ROOT = os.path.dirname(HERE)
HOME = os.path.dirname(QEMU_ROOT)
TOOLS = os.path.join(HOME, "Documents", "ps3tools-main")
sys.path.insert(0, TOOLS)
sys.path.insert(0, HERE)

import bootldrdec as B            # noqa: E402  (container format)
import mk_eid_test as EID         # noqa: E402  (synthetic eEID, same ladder)
import ps3_encdec as ENC          # noqa: E402  (EID0 check, key ladder)



def first_existing(*paths):
    for path in paths:
        if os.path.exists(path):
            return path
    return paths[0]


QEMU = first_existing(os.path.join(QEMU_ROOT, "build-ps3", "qemu-system-ppc64"),
                      os.path.join(QEMU_ROOT, "build-ps3",
                                   "qemu-system-ppc64.exe"))
ROM = first_existing(os.path.join(TOOLS, ".tmp", "rom", "rom.bin"),
                     os.path.join(HOME, "Downloads", "rom.bin"))
WORK = os.path.join(QEMU_ROOT, ".tmp", "ch66_chain")
NOR = os.path.join(HOME, "Downloads", "CECH4301C.NOR.BIN")
METLDR_OFF = 0x840
HEADER = 0x40
# metldr's own plaintext carries the 48-byte PCK1 hand-off (32-byte key and
# 16-byte IV) at 0xD2D0, with the loader build tag at 0xD300.  Its code copies
# the 32/16/8 pieces to LS 0x00/0x20/0x30 (lv0pen's metldr2 main.cpp; the 3.6.5
# sample exposes the same block in METLDR_4301C_COMPARISON.md).  The model puts
# a stage's plaintext at LS 0x400, so the block sits at LS 0xD6D0 there.
PCK1_SLOT = 0xD2D0
PCK1_TAG = 0xD300
PCK1_TAG_VALUE = 0x0003006500000000
LS_BASE = 0x400


def qemu_env():
    env = os.environ.copy()
    for d in (r"C:\msys64\ucrt64\bin", r"C:\msys64\usr\bin"):
        if os.path.isdir(d) and d not in env.get("PATH", ""):
            env["PATH"] = d + os.pathsep + env.get("PATH", "")
    env["MSYSTEM"] = "UCRT64"
    return env


def run_qemu(args, log, timeout=25):
    """Run the model headless; a timeout is the normal end of a boot."""
    with open(log, "wb") as out:
        try:
            proc = subprocess.run([QEMU] + args, stdout=out,
                                  stderr=subprocess.STDOUT, env=qemu_env(),
                                  timeout=timeout)
            return proc.returncode
        except subprocess.TimeoutExpired:
            return 124
        except OSError as e:
            sys.stderr.write("cannot run %s: %s\n" % (QEMU, e))
            return -1


def capture_from_rom(path):
    """Execute the mask ROM and let the device write its ch66 reads."""
    os.makedirs(WORK, exist_ok=True)
    log = os.path.join(WORK, "capture.log")
    # `-bios' only names the ROM: the model keeps its built-in opener unless
    # own-rom=off says to execute the supplied one, and only then does the
    # device record the eight rdch $35,$ch66 reads.
    args = ["-M", "rs6000-ps3", "-bios", ROM, "-nographic",
            "-global", "ps3-boot-rom.own-rom=off",
            "-global", "ps3-boot-rom.ch66-capture=" + path,
            "-global", "ps3-boot-rom.boot-logo=off"]
    run_qemu(args, log)
    if not os.path.exists(path) or os.path.getsize(path) != 32:
        return None, log
    return open(path, "rb").read(), log


def boot_container(image, container, readout, ls_dump, capture, tag):
    log = os.path.join(WORK, "boot_%s.log" % tag)
    args = ["-M", "rs6000-ps3", "-bios", ROM, "-nographic",
            # rom-exec runs the supplied ROM, and the model only does that
            # when own-rom=off says the built-in opener is not the one wanted.
            "-global", "ps3-boot-rom.own-rom=off",
            "-drive", "if=pflash,format=raw,file=%s,readonly=on" % image,
            "-global", "ps3-boot-rom.container=" + container,
            "-global", "ps3-boot-rom.readout=" + readout.hex(),
            "-global", "ps3-boot-rom.selftest=off",
            "-global", "ps3-boot-rom.rom-exec=on",
            "-global", "ps3-boot-rom.boot-logo=off",
            "-global", "ps3-boot-rom.ch66-capture=" + capture,
            "-global", "ps3-boot-rom.ls-dump=" + ls_dump]
    run_qemu(args, log)
    return log


def seal_synthetic_metldr(pck0, pck1, path):
    """A container under `pck0` laid out like metldr's own plaintext.

    The first word is `stop`, so the SPU stage ends immediately and the local
    store keeps the plaintext the ROM wrote.  The 48-byte PCK1 hand-off sits at
    0xD2D0 and the build tag at 0xD300, which is where lv0pen's metldr2 reads
    them from before copying the 32/16/8 pieces to LS 0x00/0x20/0x30.  The
    property under test is the key chain and its slot, not the stage's code.
    """
    kd = hashlib.sha256(b"ps3 ch66 synthetic key-derivation field").digest()[:16]
    iv = hashlib.sha256(b"ps3 ch66 synthetic ctr suffix").digest()[:12]
    nonce = hashlib.sha256(b"ps3 ch66 synthetic machine label").digest()[:12]
    hdr = bytearray(HEADER)
    hdr[0x04:0x10] = iv
    hdr[0x14:0x20] = nonce
    hdr[0x20:0x30] = kd

    kp = AES.new(pck0[16:32], AES.MODE_ECB).encrypt(B.xor(kd, pck0[0:16]))
    plain = bytearray(PCK1_TAG + 16)        # tag is 8 bytes, padded to a block
    plain[0:4] = bytes(4)                  # stop: the stage ends here
    plain[PCK1_SLOT:PCK1_SLOT + 48] = pck1
    plain[PCK1_TAG:PCK1_TAG + 8] = PCK1_TAG_VALUE.to_bytes(8, "big")
    plain = bytes(plain)
    blob = B.seal(kp, bytes(hdr), plain)
    with open(path, "wb") as f:
        f.write(blob)
    return blob, kp, plain


def build_image(blob, path):
    img = bytearray(16 * 1024 * 1024)
    img[METLDR_OFF:METLDR_OFF + len(blob)] = blob
    with open(path, "wb") as f:
        f.write(img)
    return path


def sector_roundtrip(keys):
    """Seal and reopen a sector-0-shaped block and one XTS sector."""
    encdec_data, encdec_tweak, ata_data, ata_tweak = keys
    block = bytearray(512)
    block[0:8] = b"PS3HDFS1"
    block[8:24] = hashlib.sha256(b"synthetic ata data").digest()[:16]
    block[24:40] = hashlib.sha256(b"synthetic ata tweak").digest()[:16]
    sealed = ENC.cbc_encrypt(ata_data, bytes(16), bytes(block))
    opened = ENC.cbc_decrypt(ata_data, bytes(16), sealed)
    ata_ok = opened == bytes(block)

    data = bytes((i * 3 + 7) & 0xFF for i in range(512))
    ct = ENC.xts_crypt(encdec_data, encdec_tweak, 7, data, True)
    pt = ENC.xts_crypt(encdec_data, encdec_tweak, 7, ct, False)
    enc_ok = pt == data and ct != data
    return ata_ok, enc_ok


def synthetic(args):
    os.makedirs(WORK, exist_ok=True)
    if not os.path.exists(QEMU):
        sys.stderr.write("no QEMU build at %s\n" % QEMU)
        return 4
    if not os.path.exists(ROM):
        sys.stderr.write("no mask ROM at %s\n" % ROM)
        return 4

    cap_path = os.path.join(WORK, "rom_ch66.bin")
    for p in (cap_path,):
        if os.path.exists(p):
            os.remove(p)
    pck0, log = capture_from_rom(cap_path)
    if pck0 is None:
        sys.stderr.write("the ROM ran but wrote no capture; see %s\n" % log)
        return 5

    pck1 = hashlib.sha384(b"PS3 CECH-4301C synthetic PCK1").digest()
    nor = open(args.nor, "rb").read()
    idps = nor[0x2F070:0x2F080]
    tail4 = nor[0x2F080:0x2F084]
    nonce12 = nor[0x2F084:0x2F090]
    eid, _k0, _k6, _ka, _indiv = EID.build(pck1, idps, nonce12, tail4)
    eid0 = eid[EID.EID0_OFF:EID.EID0_OFF + EID.EID0_SIZE]
    eid_path = os.path.join(WORK, "synthetic_eEID.bin")
    open(eid_path, "wb").write(eid)

    print("PCK0 capture (channel-66, mask ROM, 8 reads): %s" % cap_path)
    print("  read order K_lo||K_hi, %d bytes" % len(pck0))
    print("synthetic PCK1: %d bytes, fingerprint %s"
          % (len(pck1), hashlib.sha256(pck1).hexdigest()[:16]))

    blob, kp, plain = seal_synthetic_metldr(
        pck0, pck1, os.path.join(WORK, "metldr_synthetic.bin"))
    print("synthetic metldr: %d blocks, tag %s, Kp fingerprint %s"
          % (int.from_bytes(blob[0:4], "big"), blob[0x30:0x40].hex(),
             hashlib.sha256(kp).hexdigest()[:16]))

    image = build_image(blob, os.path.join(WORK, "synthetic_nor.bin"))
    ls_path = os.path.join(WORK, "ls.bin")
    bootcap = os.path.join(WORK, "boot_ch66.bin")
    for p in (ls_path, bootcap):
        if os.path.exists(p):
            os.remove(p)
    log = boot_container(image, "metldr.2", pck0, ls_path, bootcap, "synthetic")

    ok = True
    if not os.path.exists(ls_path):
        print("FAIL  no local-store dump; see %s" % log)
        return 5
    ls = open(ls_path, "rb").read()

    captured = open(bootcap, "rb").read() if os.path.exists(bootcap) else b""
    same = captured == pck0
    print("%s  boot path capture equals the ROM capture"
          % ("PASS" if same else "FAIL"))
    ok &= same

    # The container's plaintext lands at LS 0x400, so metldr's hand-off block
    # is at LS 0xD6D0 (0x400 + 0xD2D0) and its build tag at LS 0xD700.
    carried = ls[LS_BASE + PCK1_SLOT:LS_BASE + PCK1_SLOT + 48]
    tag = ls[LS_BASE + PCK1_TAG:LS_BASE + PCK1_TAG + 8]
    matches = carried == pck1
    tag_ok = tag == PCK1_TAG_VALUE.to_bytes(8, "big")
    print("%s  PCK1 at the metldr hand-off slot (LS 0x%X) matches the sealed copy"
          % ("PASS" if matches else "FAIL", LS_BASE + PCK1_SLOT))
    print("%s  the hand-off build tag at LS 0x%X is 0x%X"
          % ("PASS" if tag_ok else "FAIL", LS_BASE + PCK1_TAG,
             int.from_bytes(tag, "big")))
    ok &= matches and tag_ok

    record = eid0
    derivation, _indiv = ENC.eid0_authenticate(carried, record)
    confirmed = derivation is not None
    print("%s  PCK1 authenticates EID0 section 0's CMAC (%s)"
          % ("PASS" if confirmed else "FAIL", derivation or "no derivation"))
    ok &= confirmed

    if confirmed:
        seeds = ENC.SEEDS_DEFAULT
        keys = ENC.derive(carried, seeds)
        ata_ok, enc_ok = sector_roundtrip(keys)
        print("%s  sector 0 round-trips under the derived ATA pair"
              % ("PASS" if ata_ok else "FAIL"))
        print("%s  an XTS sector round-trips under the derived ENCDEC pair"
              % ("PASS" if enc_ok else "FAIL"))
        ok &= ata_ok and enc_ok

        out = os.path.join(WORK, "synthetic_encdec.bin")
        open(out, "wb").write(b"".join(keys))
        print("wrote %s (128 bytes, synthetic: encdec data/tweak, ATA data/tweak)"
              % out)
        for name, key in zip(("encdec data", "encdec tweak",
                              "ATA data", "ATA tweak"), keys):
            print("  %-13s id %s" % (name, ENC.key_id(key)))

    report = {
        "mode": "synthetic",
        "capture": os.path.basename(cap_path),
        "capture_matches_boot": same,
        "pck1_matches": matches,
        "eid0": derivation,
        "confirmed": bool(ok),
    }
    open(os.path.join(WORK, "chain.json"), "w").write(
        json.dumps(report, indent=2) + "\n")
    return 0 if ok else 3


def confirm_pck1(name, at, key, record, desc):
    """Report and save one PCK1 candidate when it authenticates EID0."""
    derivation, _ = ENC.eid0_authenticate(key, record)
    if not derivation:
        return False
    print("PASS  PCK1 at %s plaintext +0x%X authenticates %s (%s)"
          % (name, at, desc, derivation))
    keys = ENC.derive(key, ENC.SEEDS_DEFAULT)
    out = os.path.join(WORK, "encdec_real.bin")
    os.makedirs(WORK, exist_ok=True)
    open(out, "wb").write(b"".join(keys))
    for label, k in zip(("encdec data", "encdec tweak", "ATA data",
                         "ATA tweak"), keys):
        print("  %-13s id %s" % (label, ENC.key_id(k)))
    print("wrote %s" % out)
    return True


def verify_real(args):
    """Check a real 32-byte capture against a dump; never invent a PCK1."""
    cap = open(args.capture, "rb").read()
    if len(cap) != 32:
        sys.stderr.write("capture is %d bytes, expected 32\n" % len(cap))
        return 4
    flash = open(args.flash, "rb").read()
    if len(flash) < 16 * 1024 * 1024:
        sys.stderr.write("flash is shorter than a 16 MiB NOR image\n")
        return 4

    opened = []
    for name, off in (("metldr.2", METLDR_OFF), ("lv0ldr.2", 0xFC0000)):
        hdr = flash[off:off + HEADER]
        n = int.from_bytes(hdr[0x10:0x14], "big")
        body = flash[off + HEADER:off + HEADER + n * 16]
        if not n or len(body) != n * 16:
            continue
        kd = hdr[0x20:0x30]
        for order, ro in (("K_lo|K_hi", cap), ("K_hi|K_lo", cap[16:] + cap[:16])):
            kp = AES.new(ro[16:32], AES.MODE_ECB).encrypt(B.xor(kd, ro[0:16]))
            tag, plain = B.compute(kp, hdr, body, n, want_plain=True)
            if tag == hdr[0x30:0x40]:
                opened.append((name, off, order, plain))
                print("PASS  %s at 0x%X opens (%s)" % (name, off, order))

    if not opened:
        print("FAIL  the capture opens neither container; no PCK1 to confirm")
        return 3

    if not args.eid0:
        print("no --eid0: the container opened, but PCK1 cannot be confirmed")
        return 3

    record, desc = ENC.read_eid0(args.eid0, None)
    for name, off, order, plain in opened:
        # metldr's fixed hand-off slot first; a container that is not metldr, or
        # a different build, can still carry the copy elsewhere, so the scan
        # stays as the fallback.
        if PCK1_SLOT + 48 <= len(plain):
            if confirm_pck1("%s hand-off slot" % name, PCK1_SLOT,
                            plain[PCK1_SLOT:PCK1_SLOT + 48], record, desc):
                return 0
            print("note  %s has no authenticating hand-off block at +0x%X"
                  % (name, PCK1_SLOT))
        for at in range(0, max(0, len(plain) - 48), 16):
            if confirm_pck1(name, at, plain[at:at + 48], record, desc):
                return 0
    print("FAIL  no 48-byte window in the opened container authenticates EID0 "
          "(the metldr hand-off slot +0x%X was checked first)" % PCK1_SLOT)
    return 3


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--synthetic", action="store_true",
                    help="capture from the ROM and run the synthetic console")
    ap.add_argument("--capture", help="a 32-byte channel-66 capture (PCK0) "
                                       "to check")
    ap.add_argument("--flash", help="the NOR dump the capture should open")
    ap.add_argument("--eid0", help="the console's eEID, to confirm PCK1 "
                                    "(per-console key 1)")
    ap.add_argument("--nor", default=NOR,
                    help="the dump the synthetic eEID takes its public header "
                         "from (default: the 4301C NOR)")
    args = ap.parse_args()

    if args.synthetic:
        return synthetic(args)
    if args.capture and args.flash:
        return verify_real(args)
    ap.print_help()
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
