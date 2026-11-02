#!/usr/bin/env python3
"""ps3_rom_handoff_test.py - the ROM must not leave a container key behind.

The contract this pins, for both loader containers the ROM opens: at the
hand-off (`0x400`) the key schedule is gone from local store and from the
registers.  The ROM builds the schedule at LS `0x00` from the eight channel-66
reads, uses it, and clears it in the tail loop at `0x3C0`..`0x3FC`; `$7`, which
carries `rk[10]`, is zeroed at the same point.  A ROM that stops clearing, or
one whose wipe no longer covers `0x00` or the register, would hand the
per-console container key - or its last round key, which inverts to the same
key - to the loader.  This test fails on exactly that.

It runs the real ROM in the model, so no console secret is needed: the test
seals its own container under a random `Kp`, derives the matching readout the
way the ROM does, and replays the ROM with `stop-pc`.  Both containers are in
the one image, at the slots the ROM opens them from:

    metldr.2  at 0x000840  (3991 blocks)
    lv0ldr.2  at 0xFC0000  (12315 blocks)

and each is run through the same six snapshots:

    stop 0x368  the readout must be live  (all eight channel-66 words found in
                $15 and at LS 0x00..0x0F), so the hand-off check below is not
                vacuous: the same probe sees a readout that is there.  $7 must
                not yet hold rk[10]: the r7 window is closed in the body pass
    stop 0x388  $7 must hold rk[10] of the schedule  (the r7 capture window:
                a glitch here plus a read of r7 is the documented key route)
    stop 0x3A0  $7 must still hold it  (mid-window, so the window is not two
                isolated points that happen to coincide with the edges)
    stop 0x3BC  $7 must still hold it, and 0x368 must not  (the edges: the
                window opens at the tag compare and closes with the wipe.
                0x3BC is the loop's last address and the model stops on its
                first pass, so a cleanup that clears $7 one store earlier
                fails here, while 0x3C0 - reached only on exit - witnesses
                the completed wipe)
    stop 0x3C0  the schedule must be at LS 0x00 and $7 must be zero  (the wipe
                has to clear the register, not only local store)
    stop 0x400  neither Kp nor the 11-round schedule may appear anywhere in the
                first KiB of LS, no readout word and no round key may appear in
                LS or in any of the 128 registers, and the decrypted body must
                be at 0x400

Word granularity is deliberate: the ROM never holds the 32-byte readout whole,
so searching for a 16-byte half would pass even on a ROM that leaks every word
of it.

Each run passes `exit-on-stop=on`, so the model ends the run itself the moment
the snapshot is written; a run that has to be killed is reported as a failure.

Prerequisites: the Cell SDK ROM (`Downloads/rom.bin`), a built
`build-ps3/qemu-system-ppc64.exe`, and pycryptodome.  Missing any of them is a
skip, not a pass.

    py scripts/ps3_rom_handoff_test.py [--rom ...] [--qemu ...] [--keep]
"""
import argparse
import os
import struct
import subprocess
import sys
import tempfile

from Crypto.Cipher import AES

HERE = os.path.dirname(os.path.abspath(__file__))
QEMU_ROOT = os.path.dirname(HERE)
HOME = os.path.dirname(QEMU_ROOT)
WORK = os.path.join(QEMU_ROOT, ".tmp", "rom_handoff_test")

HEADER = 0x40
FLASH = 16 * 1024 * 1024

# Block counts are the 4301C dumps' own, so each container has its real shape
# and the lv0ldr run stops where the console's does.
CONTAINERS = (
    {"name": "metldr", "label": "metldr.2", "offset": 0x000840, "blocks": 0xF97},
    {"name": "lv0ldr", "label": "lv0ldr.2", "offset": 0xFC0000, "blocks": 0x301B},
)

# The older single-container probes under .tmp/probes seal a metldr-shaped
# container and call run() without naming a slot, so the metldr entry stays
# reachable under its own names.  The suite itself always walks CONTAINERS.
SLOT = CONTAINERS[0]["offset"]
BLOCKS = CONTAINERS[0]["blocks"]

ROM_CANDIDATES = [
    os.path.join(HOME, "Downloads", "rom.bin"),
    os.path.join(QEMU_ROOT, ".tmp", "rom", "rom.bin"),
]
QEMU_CANDIDATES = [
    os.path.join(QEMU_ROOT, "build-ps3", "qemu-system-ppc64.exe"),
    os.path.join(QEMU_ROOT, "build-ps3", "qemu-system-ppc64"),
    os.path.join(QEMU_ROOT, "build-ps3-gui", "qemu-system-ppc64.exe"),
]

SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")


def expand(key):
    """FIPS-197 AES-128 key expansion: 11 round keys, 176 bytes."""
    rk = [key]
    rc = 1
    for _ in range(1, 11):
        prev = rk[-1]
        w = prev[12:16]
        t = bytes(SBOX[b] for b in (w[1], w[2], w[3], w[0]))
        t = bytes([t[0] ^ rc]) + t[1:]
        nxt = bytes(a ^ b for a, b in zip(prev[:4], t))
        out = bytearray(nxt)
        for i in range(1, 4):
            out += bytes(a ^ b for a, b in zip(prev[i * 4:i * 4 + 4], out[-4:]))
        rk.append(bytes(out))
        rc = ((rc << 1) ^ 0x1B) & 0xFF if rc & 0x80 else (rc << 1) & 0xFF
    return rk


def seal(kp, hdr, plain):
    """Seal a container from the spec: CTR counting down, CBC-MAC tag."""
    n = len(plain) // 16
    body = bytearray()
    for i in range(n):
        ctr = struct.pack(">I", n - i) + hdr[4:16]
        ks = AES.new(kp, AES.MODE_ECB).encrypt(ctr)
        body += bytes(a ^ b for a, b in zip(plain[i * 16:(i + 1) * 16], ks))
    chain = bytes(16)
    for blk in (hdr[0:16], hdr[16:32], hdr[32:48]):
        chain = AES.new(kp, AES.MODE_ECB).encrypt(
            bytes(a ^ b for a, b in zip(blk, chain)))
    for i in range(n):
        chain = AES.new(kp, AES.MODE_ECB).encrypt(
            bytes(a ^ b for a, b in zip(plain[i * 16:(i + 1) * 16], chain)))
    s0 = AES.new(kp, AES.MODE_ECB).encrypt(struct.pack(">I", 0) + hdr[4:16])
    out = bytearray(hdr)
    out[0x30:0x40] = bytes(a ^ b for a, b in zip(chain, s0))
    return bytes(out), bytes(body)


def schedule_at(ls, rks):
    return [off for off in range(0, len(ls) - 176, 16)
            if all(ls[off + 16 * i:off + 16 * (i + 1)] == rks[i]
                   for i in range(11))]


def find_all(hay, needle):
    out, i = [], hay.find(needle)
    while i >= 0:
        out.append(i)
        i = hay.find(needle, i + 1)
    return out


def readout_hits(ls, regs, readout):
    """Every place a readout word, or either half, still sits.

    Words, not halves: the ROM consumes the readout four words at a time.  At
    0x2BC and 0x368 the low half's words are in $15 and the high half's at LS
    0x00..0x0F, so a 16-byte search would find nothing even while every word is
    present - it would pass on a ROM that leaks the whole readout.
    """
    needles = [("w%d" % i, readout[i * 4:(i + 1) * 4]) for i in range(8)]
    needles += [("lo half", readout[:16]), ("hi half", readout[16:])]
    ls_hits, reg_hits = [], []
    for name, needle in needles:
        ls_hits += [(name, off) for off in find_all(ls, needle)]
        reg_hits += [(name, r) for r in range(128)
                     if needle in regs[r * 16:(r + 1) * 16]]
    return ls_hits, reg_hits


def run(qemu, rom, image, readout, cap, stop, container=None, offset=None):
    """Replay the ROM to `stop`; the metldr slot unless a container is named."""
    if container is None:
        container = CONTAINERS[0]["name"]
    if offset is None:
        offset = SLOT
    args = [qemu, "-M", "rs6000-ps3", "-nographic",
            "-bios", rom,
            "-global", "ps3-boot-rom.own-rom=off",
            "-global", "ps3-boot-rom.rom-exec=on",
            "-global", "ps3-boot-rom.stop-pc=0x%X" % stop,
            "-global", "ps3-boot-rom.exit-on-stop=on",
            "-global", "ps3-boot-rom.no-chain-fallback=on",
            "-global", "ps3-boot-rom.selftest=off",
            "-global", "ps3-boot-rom.boot-logo=off",
            "-drive", "if=pflash,format=raw,file=%s,readonly=on" % image,
            "-global", "ps3-boot-rom.container=" + container,
            "-global", "ps3-boot-rom.container-offset=0x%X" % offset,
            "-global", "ps3-boot-rom.ch66-capture=" + cap,
            "-global", "ps3-boot-rom.readout-file=" + readout]
    for stale in (cap, cap + ".ls400", cap + ".pc", cap + ".regs"):
        try:
            os.remove(stale)
        except OSError:
            pass
    env = dict(os.environ)
    ucrt = r"C:\msys64\ucrt64\bin"
    if os.path.isdir(ucrt):
        env["PATH"] = ucrt + ";" + env.get("PATH", "")

    # The model ends the run itself once the stop snapshot is written
    # (exit-on-stop), so a normal probe returns in well under a second.  The
    # timeout only covers a model that never reaches the stop, and killing it
    # is recorded: a killed run means the model did not end on its own.
    proc = subprocess.Popen(args, cwd=QEMU_ROOT, env=env,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    pc_path = cap + ".pc"
    killed = False
    try:
        proc.wait(timeout=120)
    except subprocess.TimeoutExpired:
        killed = True
        proc.kill()
        proc.wait()

    path = cap + ".ls400"
    state = {"killed": killed, "rc": proc.returncode, "ls": None,
             "regs": None, "pc": None}
    if not os.path.exists(path):
        return state
    state["ls"] = open(path, "rb").read()
    if os.path.exists(cap + ".regs"):
        state["regs"] = open(cap + ".regs", "rb").read()
    if os.path.exists(pc_path):
        state["pc"] = int.from_bytes(open(pc_path, "rb").read(), "big")
    return state


def verify(label, kp, readout, rks, live, opened, window, last, before, after,
           check):
    """The whole contract for one container, as checks prefixed with `label`."""
    def reg(st, r):
        return st["regs"][r * 16:(r + 1) * 16]

    # The model must end the run itself at each stop; a probe that has to kill
    # QEMU is one whose exit contract has regressed.
    killed = [name for name, st in (("0x368", live), ("0x388", opened),
                                    ("0x3A0", window), ("0x3BC", last),
                                    ("0x3C0", before), ("0x400", after))
              if st["killed"]]
    check("%s: the model exited at the stop without being killed" % label,
          not killed, "killed at %s" % ", ".join(killed))

    # Reaching 0x3C0 means the tag check at 0x388 already passed; a rejected
    # container would have branched to stop 2 (0x1E4) and never got here.
    check("%s: the ROM reached the 0x3A0 window" % label,
          window["pc"] == 0x3A0)

    # The r7 route: the ROM leaves rk[10] in $7 through the cleanup window, and
    # the wipe must clear it.  A ROM that stops clearing $7 would hand the
    # round key - and through the invertible schedule, Kp - to the loader.
    check("%s: $7 carries rk[10] at 0x3A0 (r7 capture window is open)" % label,
          reg(window, 7) == rks[10], reg(window, 7).hex())

    # The window's edges, sampled on both sides: open at the tag compare
    # (0x388), still open at the last stop before the wipe (0x3BC), closed
    # during the body pass (0x368) and closed once the wipe has run (0x3C0).
    # A change that moves either edge earlier or later flips one of these, so
    # the window cannot drift while the mid-window sample still passes.
    check("%s: the window is closed at 0x368 (body pass, before the compare)"
          % label,
          live["pc"] == 0x368 and reg(live, 7) != rks[10],
          "pc=0x%X $7=%s" % (live["pc"] or 0, reg(live, 7).hex()))
    check("%s: the window is open at 0x388 (the tag compare)" % label,
          opened["pc"] == 0x388 and reg(opened, 7) == rks[10],
          "pc=0x%X $7=%s" % (opened["pc"] or 0, reg(opened, 7).hex()))
    check("%s: the window is still open at 0x3BC (loop's last address, first "
          "pass)" % label,
          last["pc"] == 0x3BC and reg(last, 7) == rks[10],
          "pc=0x%X $7=%s" % (last["pc"] or 0, reg(last, 7).hex()))
    check("%s: $7 is zero at 0x3C0 (the wipe clears the register)" % label,
          reg(before, 7) == bytes(16), reg(before, 7).hex())

    check("%s: the ROM reached 0x3C0 with the container accepted" % label,
          before["pc"] == 0x3C0)
    check("%s: the schedule is present at 0x3C0 (test is sensitive)" % label,
          before["ls"][:16] == kp and 0 in schedule_at(before["ls"], rks),
          "Kp@0=%s schedule=%s" % (before["ls"][:16] == kp,
                                   schedule_at(before["ls"], rks)))
    # Negative control: the same predicate the hand-off uses is false on the
    # un-wiped state, so a ROM that stopped clearing would be caught.
    check("%s: the hand-off predicate rejects the un-wiped 0x3C0 state" % label,
          kp in before["ls"] and bool(schedule_at(before["ls"], rks)))
    check("%s: the ROM reached the hand-off 0x400" % label,
          after["pc"] == 0x400)
    check("%s: Kp is not in LS at the hand-off" % label,
          kp not in after["ls"])
    check("%s: no 11-round schedule in LS at the hand-off" % label,
          not schedule_at(after["ls"], rks))

    # The readout half of the contract.  Its sensitivity stop is 0x368, inside
    # the body pass, where the ROM is still holding both halves; the hand-off
    # must show it gone from both places the loader can read.
    live_ls, live_reg = readout_hits(live["ls"], live["regs"], readout)
    found = {name for name, _ in live_ls + live_reg}
    check("%s: all eight readout words are live at 0x368 (test is sensitive)"
          % label,
          live["pc"] == 0x368 and found >= {"w%d" % i for i in range(8)},
          "pc=0x%X found=%s" % (live["pc"] or 0, sorted(found)))
    after_ls, after_reg = readout_hits(after["ls"], after["regs"], readout)
    check("%s: no readout word is in LS at the hand-off" % label, not after_ls,
          "%s" % after_ls[:4])
    check("%s: no readout word is in any register at the hand-off" % label,
          not after_reg, "%s" % after_reg[:4])
    leaked = [(r, i) for r in range(128) for i, rk in enumerate(rks)
              if reg(after, r) == rk]
    check("%s: no round key is in any register at the hand-off" % label,
          not leaked, "%s" % leaked[:4])


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rom", default=None)
    ap.add_argument("--qemu", default=None)
    ap.add_argument("--keep", action="store_true",
                    help="keep the sealed image and snapshots")
    args = ap.parse_args()

    rom = args.rom or next((p for p in ROM_CANDIDATES if os.path.exists(p)),
                           None)
    qemu = args.qemu or next((p for p in QEMU_CANDIDATES if os.path.exists(p)),
                             None)
    if not rom or not os.path.exists(rom):
        print("SKIP: no mask ROM (looked in %s)" % ", ".join(
            [args.rom] if args.rom else ROM_CANDIDATES))
        return 0
    if not qemu or not os.path.exists(qemu):
        print("SKIP: no built qemu-system-ppc64")
        return 0

    os.makedirs(WORK, exist_ok=True)
    run_dir = tempfile.mkdtemp(prefix="handoff-", dir=WORK)

    # Both containers go into the one image, each sealed under its own key, so
    # the two runs differ only in which slot the ROM is asked to open.
    image = bytearray(FLASH)
    prepared = []
    for spec in CONTAINERS:
        kp, k_hi, h20 = os.urandom(16), os.urandom(16), os.urandom(16)
        n = spec["blocks"]
        hdr = bytearray(HEADER)
        struct.pack_into(">I", hdr, 0x00, n)
        struct.pack_into(">I", hdr, 0x10, n)
        hdr[0x04:0x10] = os.urandom(12)
        hdr[0x20:0x30] = h20
        k_lo = bytes(a ^ b for a, b in zip(
            h20, AES.new(k_hi, AES.MODE_ECB).decrypt(kp)))
        readout = k_lo + k_hi
        plain = os.urandom(n * 16)
        hdr, body = seal(kp, bytes(hdr), plain)
        off = spec["offset"]
        image[off:off + HEADER + len(body)] = hdr + body
        prepared.append(dict(spec, kp=kp, readout=readout, rks=expand(kp)))

    image_path = os.path.join(run_dir, "nor.bin")
    open(image_path, "wb").write(image)

    checks = []

    def check(name, ok, detail=""):
        checks.append((name, ok, detail))

    for spec in prepared:
        label = spec["label"]
        path = os.path.join(run_dir, "readout_%s.bin" % spec["name"])
        open(path, "wb").write(spec["readout"])
        states = {}
        for pc in (0x368, 0x388, 0x3A0, 0x3BC, 0x3C0, 0x400):
            states[pc] = run(qemu, rom, image_path, path,
                             os.path.join(run_dir, "%s_%03X.bin"
                                          % (spec["name"], pc)),
                             pc, spec["name"], spec["offset"])
        if any(st["ls"] is None for st in states.values()):
            print("FAIL: %s wrote no local-store snapshot" % label)
            return 1
        verify(label, spec["kp"], spec["readout"], spec["rks"],
               states[0x368], states[0x388], states[0x3A0], states[0x3BC],
               states[0x3C0], states[0x400], check)

    failed = [c for c in checks if not c[1]]
    for name, ok, detail in checks:
        print("%s  %s%s" % ("PASS" if ok else "FAIL", name,
                            "  [%s]" % detail if detail and not ok else ""))
    if not args.keep:
        for name in ("nor.bin",):
            try:
                os.remove(os.path.join(run_dir, name))
            except OSError:
                pass
    print("\n%d check(s), %d failed" % (len(checks), len(failed)))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
