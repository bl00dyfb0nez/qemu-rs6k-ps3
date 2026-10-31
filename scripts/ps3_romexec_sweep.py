#!/usr/bin/env python3
"""ps3_romexec_sweep.py - run the mask ROM over every loader container in a dump.

A NOR dump holds more than one channel-66 container, and they are not all at
the same place or even the same console's sealing:

    metldr.2   the asecure_loader's first entry, at the header that follows the
               name in its 0x20-byte table (0x840 on the 4301C dumps)
    lv0ldr.2   the container the ROM opens at the boot slot (0xFC0000 on NOR);
               it carries no name string, so only the fixed slot finds it

The model can be pointed at either one exactly (`container-offset`).  The
verdict is the model's built-in opener by default - the same open, decrypt and
tag-check the mask ROM performs, run as the model's own code with no `-bios`
and no Sony image.  `--rom-exec` opts into the developer check instead: the
supplied mask ROM is replayed and its own execution is the verdict.  Either way
the stop is the interesting part, because the two stops mean different things:

    0x1E4  stop 2 - the header was accepted and the tag check failed
    else   an earlier gate (block count, size) refused the container

Each run also writes the eight channel-66 reads the opener performed
(`ch66-capture`), so the capture is reported next to the verdict: a run that
stops before 0x148 has fewer than eight reads, which is how a header rejected
before the key read is told apart from one rejected after it.

The model now accounts for all 128 channels, so every run also reports the map
it executed: how many channels it touched (`channels.touched`) and any access
the map does not define - a reserved number, or a direction the channel does
not have.  That verdict is recorded per row (`channels.clean`, and the flag
`"0x2E reserved x3"`) and flagged in the report, because a container that reads
or writes an undefined channel is running code the model cannot account for, so
the run is not a clean pass: it is flagged in the console output, the JSON and
the report, and the sweep exits 3.

No key is printed.  A readout is named by the file it came from and its
SHA-256 prefix; a capture by its length and prefix.  With no `--readout` the
opener is handed 32 zero bytes, which is the console-less control.

Two sample consoles are also run, because the dump rows are all rejections and
the acceptance branch needs firmware that opens.  They also say where a key
comes from: the 4th sample ships `Kp` per container (a result), the 2nd ships
`rk10`, which is inverted through the AES key schedule to `Kp` (a method).  A
key match matrix then answers, for every key in the run, which container it
opens and which it does not: `Kp` is per image and matches only its own, while
a channel-66 readout is per console and opens every image of that console.
The tree holds one real readout, so exactly one row opens two containers.

    py scripts/ps3_romexec_sweep.py
    py scripts/ps3_romexec_sweep.py --readout .tmp/dlt/readout.bin
    py scripts/ps3_romexec_sweep.py --dump CECH4301C.NOR.BIN --readout cap.bin
    py scripts/ps3_romexec_sweep.py --control      # also run a misaligned point

Exit codes: 0 swept clean, 3 a run failed verification (a sample container
did not open, a run touched a channel the model does not define, or a key in
the match matrix failed its own container), 4 usage/material unreadable, 5
QEMU would not run.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import time

try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None

HERE = os.path.dirname(os.path.abspath(__file__))
QEMU_ROOT = os.path.dirname(HERE)
HOME = os.path.dirname(QEMU_ROOT)
TOOLS = os.path.join(HOME, "Documents", "ps3tools-main")

QEMU = os.path.join(QEMU_ROOT, "build-ps3", "qemu-system-ppc64.exe")
ROM = os.path.join(TOOLS, ".tmp", "rom", "rom.bin")
WORK = os.path.join(QEMU_ROOT, ".tmp", "romexec_sweep")
DOWNLOADS = os.path.join(HOME, "Downloads")

DUMPS = ("CECH4301C.NOR.BIN", "CECH4301C-verylate.NOR.BIN")

HEADER = 0x40
MAX_BLOCKS = 0x3DC0          # PS3_ROM_MAX_BLOCKS in rs6000_ps3.c
FLASH_SIZE = 16 * 1024 * 1024

# The two slots the boot chain fixes before it has parsed anything.
FIXED_SLOTS = ((0x000840, "metldr.2"), (0xFC0000, "lv0ldr.2"))

#
# A sample console's containers, with the key each is sealed under.  They are
# real firmware and they do open, which is the only way the sweep's pass path
# gets exercised on something other than the synthetic image: the dump rows are
# all rejections, so without these a regression in the acceptance branch would
# show up only on a console nobody has.
#
# Each is placed at the slot its container belongs to, and its readout is
# derived from the key (`Kp` fixes `K_lo` for a chosen `K_hi`), so no capture is
# invented and nothing is copied from the dump.
#
SAMPLE_SET = os.path.join(HOME, "Downloads", "4th sample")
SAMPLE2_SET = os.path.join(HOME, "Downloads", "pc tool second sample dot 2",
                           "pc tool second sample")

#
# Two sample consoles, and two ways of recovering a container key.  They are
# both real firmware and both open, which is the only way the pass path is
# exercised on something other than the synthetic image: the dump rows are all
# rejections.
#
# The 4th sample ships the container key itself (`Kp`, 16 bytes per image), so
# its rows are the published-key route.  The 2nd sample ships no key file: its
# tool publishes the *last round key* (`rk10`), which is what a console's local
# store keeps at LS 0xa0, and `Kp` is recovered by inverting the AES key
# schedule.  Reading rk10 from that tool rather than copying it here keeps one
# source of truth, and makes the row prove the inversion rather than a
# hand-entered constant.
#
SAMPLES = (
    {"name": "4th sample metldr.2", "tag": "s4_metldr", "route": "kp",
     "file": os.path.join(SAMPLE_SET, "metldr.2"),
     "key": os.path.join(SAMPLE_SET, "metldr_key.txt"), "slot": 0x000840},
    {"name": "4th sample lv0ldr.2", "tag": "s4_lv0ldr", "route": "kp",
     "file": os.path.join(SAMPLE_SET, "lv0ldr.2"),
     "key": os.path.join(SAMPLE_SET, "lv0ldr_key.txt"), "slot": 0xFC0000},
    {"name": "2nd sample metldr.2", "tag": "s2_metldr", "route": "rk10",
     "file": os.path.join(SAMPLE2_SET, "metldr.2"),
     "rk10_from": os.path.join(SAMPLE2_SET, "decrypt_loader.py"),
     "container": "metldr.2", "slot": 0x000840},
    {"name": "2nd sample lv0ldr.2", "tag": "s2_lv0ldr", "route": "rk10",
     "file": os.path.join(SAMPLE2_SET, "lv0ldr.2"),
     "rk10_from": os.path.join(SAMPLE2_SET, "decrypt_loader.py"),
     "container": "lv0ldr.2", "slot": 0xFC0000},
)

#
# AES-128's key schedule, both ways.  The console's ladder never leaves `Kp`
# (rk0) for a loader key, but a capture of local store keeps the schedule the
# ROM built, and rk10 alone is enough: the schedule inverts with no other
# input.  The S-box is the standard one; Rcon is the AES-128 sequence.
#
AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16")
AES_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def aes_expand(kp):
    """The 11 round keys of AES-128: rk0 is `Kp`, rk10 the last one."""
    w = [kp[i * 4:(i + 1) * 4] for i in range(4)]
    for i in range(4, 44):
        t = w[i - 1]
        if i % 4 == 0:
            t = xor_bytes(bytes(AES_SBOX[b] for b in t[1:] + t[:1]),
                          bytes([AES_RCON[i // 4 - 1], 0, 0, 0]))
        w.append(xor_bytes(w[i - 4], t))
    return [b"".join(w[i * 4:(i + 1) * 4]) for i in range(11)]


def aes_invert(rk10):
    """Recover `Kp` (rk0) from the last round key.

    `w[i] = w[i-4] ^ f(w[i-1])`, so `w[i-4] = w[i] ^ f(w[i-1])`: walking the
    schedule backwards needs only the words already recovered.
    """
    if len(rk10) != 16:
        return None
    w = [None] * 44
    for i in range(4):
        w[40 + i] = rk10[i * 4:(i + 1) * 4]
    for i in range(39, -1, -1):
        t = w[i + 3]
        if (i + 4) % 4 == 0:
            t = xor_bytes(bytes(AES_SBOX[b] for b in t[1:] + t[:1]),
                          bytes([AES_RCON[(i + 4) // 4 - 1], 0, 0, 0]))
        w[i] = xor_bytes(w[i + 4], t)
    return b"".join(w[0:4])


def rk10_from_tool(path, container):
    """The `rk10` a sample tool publishes for one of its containers, or None.

    The tool lists each container as its name, the `Kp` and `N`, then the round
    key in parentheses on the next line.  Parsing stops at the next container
    heading so a missing entry cannot pick up its neighbour's key.
    """
    try:
        lines = open(path, errors="ignore").read().splitlines()
    except OSError:
        return None
    for i, line in enumerate(lines):
        if not line.strip().startswith(container + " "):
            continue
        for nxt in lines[i:i + 4]:
            m = re.search(r"rk10\s+([0-9A-Fa-f]{32})", nxt)
            if m:
                return bytes.fromhex(m.group(1))
            if nxt is not lines[i] and re.match(r"\s*\S+\.\S*\s+[0-9A-Fa-f]{32}",
                                                nxt):
                break
    return None


def container_crypt_kp(hdr, body, kp):
    """The CTR body and the tag check in Python, for a known `Kp`.

    `Kp` is per image, so this is the only way to say what a key *matches*
    without booting the model for every pair: decrypt the body (counter
    counting down from N) and compute the CBC-MAC tag.  The sample rows prove
    the same result through the model, which keeps this implementation honest.
    """
    if AES is None or len(kp) != 16 or len(hdr) != HEADER:
        return False
    n = len(body) // 16
    if not n or len(body) != n * 16:
        return False

    plain = bytearray()
    for i in range(n):
        ctr = struct.pack(">I", n - i) + hdr[0x04:0x10]
        plain += xor_bytes(body[i * 16:(i + 1) * 16],
                           AES.new(kp, AES.MODE_ECB).encrypt(ctr))

    chain = bytes(16)
    for blk in (hdr[0x00:0x10], hdr[0x10:0x20], hdr[0x20:0x30]):
        chain = AES.new(kp, AES.MODE_ECB).encrypt(xor_bytes(blk, chain))
    for i in range(n):
        chain = AES.new(kp, AES.MODE_ECB).encrypt(
            xor_bytes(bytes(plain[i * 16:(i + 1) * 16]), chain))
    s0 = AES.new(kp, AES.MODE_ECB).encrypt(struct.pack(">I", 0) +
                                           hdr[0x04:0x10])
    return xor_bytes(chain, s0) == hdr[0x30:0x40]


def container_crypt(hdr, body, readout):
    """The ladder and the tag check: what a 32-byte readout opens."""
    if AES is None or len(readout) != 32:
        return False
    kp = AES.new(readout[16:32], AES.MODE_ECB).encrypt(
        xor_bytes(hdr[0x20:0x30], readout[0:16]))
    return container_crypt_kp(hdr, body, kp)


def _tool_sample_containers():
    """The 9BF07E57 console's two images, which no sample key opens."""
    base = os.path.join(DOWNLOADS, "pc tool channel 66")
    out = []
    for name in ("metldr", "lv0ldr"):
        path = os.path.join(base, name)
        if not os.path.exists(path):
            continue
        blob = open(path, "rb").read()
        ok, blocks, _ = header_ok(blob, 0)
        if not ok:
            continue
        out.append({"name": "tool sample " + name,
                    "hdr": blob[:HEADER],
                    "body": blob[HEADER:HEADER + blocks * 16],
                    "console": "9BF07E57"})
    return out


def match_matrix():
    """What matches what: per-image keys, and the one real readout.

    Two levels, and they are not interchangeable:

      * `Kp` is per image.  A sample ships one per container (the 4th directly,
        the 2nd as `rk10` that has to be inverted), and each has to match its
        own container and no other.  A `Kp` cannot be turned back into a
        console readout without the console's `K_hi`.
      * A channel-66 readout is per console.  It becomes a different `Kp` for
        every header, so one readout opens every image of its own console.
        The tree holds exactly one real one, `.tmp/dlt/readout.bin`, for the
        tool's sample console - which is why that row opens two images.
    """
    kp_rows = []
    for sample in SAMPLES:
        if not os.path.exists(sample["file"]):
            continue
        kp, route, source = sample_key(sample)
        if kp is None:
            continue
        kp_rows.append({"name": sample["name"], "kp": kp,
                        "route": route, "source": source})

    readout_rows = []
    capture = os.path.join(WORK, "..", "dlt", "readout.bin")
    capture = os.path.normpath(capture)
    if os.path.exists(capture):
        raw = open(capture, "rb").read()
        if len(raw) == 32:
            readout_rows.append({"name": "9BF07E57 capture",
                                 "source": "readout.bin", "bytes": raw})
    readout_rows.append({"name": "no capture", "source": "32 zero bytes",
                         "bytes": bytes(32)})

    containers = []
    for sample in SAMPLES:
        if not os.path.exists(sample["file"]):
            continue
        blob = open(sample["file"], "rb").read()
        ok, blocks, _ = header_ok(blob, 0)
        if not ok:
            continue
        containers.append({"name": sample["name"],
                           "hdr": blob[:HEADER],
                           "body": blob[HEADER:HEADER + blocks * 16],
                           "sample": sample["name"]})
    containers += _tool_sample_containers()
    for dump in DUMPS:
        path = os.path.join(DOWNLOADS, dump)
        if not os.path.exists(path):
            continue
        flash = open(path, "rb").read()
        for slot, label in FIXED_SLOTS:
            ok, blocks, _ = header_ok(flash, slot)
            if not ok:
                continue
            containers.append({"name": "%s %s" % (dump.split(".")[0], label),
                               "hdr": flash[slot:slot + HEADER],
                               "body": flash[slot + HEADER:
                                             slot + HEADER + blocks * 16],
                               "sample": None})

    self_check = []
    kp_matrix = []
    for key in kp_rows:
        row = []
        for c in containers:
            ok = container_crypt_kp(c["hdr"], c["body"], key["kp"])
            row.append(ok)
            if c["name"] == key["name"] and not ok:
                self_check.append({"key": key["name"],
                                   "container": c["name"], "ok": False})
        kp_matrix.append(row)

    ro_matrix = []
    for ro in readout_rows:
        row = []
        for c in containers:
            ok = container_crypt(c["hdr"], c["body"], ro["bytes"])
            row.append(ok)
            # The capture's own console is the two "tool sample" images; a
            # capture row that does not open them is not a capture.
            if ro["name"] == "9BF07E57 capture" and c.get("console") and not ok:
                self_check.append({"key": ro["name"],
                                   "container": c["name"], "ok": False})
        ro_matrix.append(row)

    names = [c["name"] for c in containers]
    return {"kp": {"keys": [{"name": k["name"], "route": k["route"],
                             "source": k["source"]} for k in kp_rows],
                    "containers": names, "matrix": kp_matrix},
            "readouts": {"keys": [{"name": r["name"], "source": r["source"]}
                                   for r in readout_rows],
                         "containers": names, "matrix": ro_matrix},
            "self_check": self_check}


def sample_key(sample):
    """(Kp, route, source) for a sample container, or (None, None, why).

    `kp`: the sample ships the container key as a 16-byte hex value.
    `rk10`: it ships the last round key; invert the schedule to get `Kp`, then
    check the forward schedule returns the round key that was given - so a row
    that opens cannot be opening because of a wrong inversion.
    """
    if sample.get("route") == "rk10":
        rk10 = rk10_from_tool(sample["rk10_from"], sample["container"])
        if rk10 is None:
            return None, None, "no rk10 for %s in %s" % (
                sample["container"], os.path.basename(sample["rk10_from"]))
        kp = aes_invert(rk10)
        if aes_expand(kp)[10] != rk10:
            return None, None, "the schedule does not invert to that rk10"
        return kp, "rk10 -> Kp", os.path.basename(sample["rk10_from"])

    token = None
    try:
        text = open(sample["key"], errors="ignore").read()
    except OSError:
        return None, None, "missing key file"
    for found in re.findall(r"\b[0-9A-Fa-f]{32}\b", text):
        token = found
        break
    if token is None:
        return None, None, "the key file has no 32-hex value"
    return bytes.fromhex(token), "Kp", os.path.basename(sample["key"])

# Names a dump may carry in front of a container header (at name - 0x20).
LOADER_NAMES = ("metldr", "metldr.2", "lv0ldr", "lv0ldr.2", "bootldr",
                "bootldr.2", "lv1ldr", "lv1ldr.2", "lv2ldr", "lv2ldr.2",
                "appldr", "appldr.2", "isoldr", "isoldr.2")


def be32(d, off):
    return struct.unpack(">I", d[off:off + 4])[0]


def be64(d, off):
    return struct.unpack(">Q", d[off:off + 8])[0]


def qemu_env():
    env = os.environ.copy()
    for d in (r"C:\msys64\ucrt64\bin", r"C:\msys64\usr\bin"):
        if os.path.isdir(d) and d not in env.get("PATH", ""):
            env["PATH"] = d + os.pathsep + env.get("PATH", "")
    env["MSYSTEM"] = "UCRT64"
    return env


def header_ok(flash, off):
    """The same two fields the model checks, plus the span."""
    if off + 0x40 > len(flash):
        return False, 0, 0
    blocks = be32(flash, off)
    total = be32(flash, off + 0x10)
    if blocks != total or not blocks or blocks > MAX_BLOCKS:
        return False, blocks, total
    if off + HEADER + blocks * 16 > len(flash):
        return False, blocks, total
    return True, blocks, total


def asecure_entries(flash):
    """The asecure_loader table at 0x800: (name, container offset)."""
    out = []
    if be32(flash, 0x800) != 1:
        return out
    count = be32(flash, 0x804)
    for i in range(min(count, 8)):
        ent = 0x810 + i * 0x20
        off = be64(flash, ent)
        name = flash[ent + 16:ent + 32].split(b"\0")[0].decode("ascii",
                                                               "replace")
        out.append((name, 0x800 + off))
    return out


def find_containers(flash):
    """Every validated loader container, with the name it is known by."""
    found = {}

    for name, off in asecure_entries(flash):
        ok, blocks, _ = header_ok(flash, off)
        if ok:
            found[off] = {"name": name, "source": "asecure_loader table"}

    for slot, label in FIXED_SLOTS:
        ok, blocks, _ = header_ok(flash, slot)
        if ok:
            found.setdefault(slot, {"name": label, "source": "fixed slot"})

    for name in LOADER_NAMES:
        at = flash.find(name.encode())
        while at >= 0:
            off = at + 0x20
            ok, _, _ = header_ok(flash, off)
            if ok:
                found.setdefault(off, {"name": name,
                                       "source": "name string at 0x%X" % at})
            at = flash.find(name.encode(), at + 1)

    out = []
    for off in sorted(found):
        rec = dict(found[off], offset=off)
        ok, blocks, total = header_ok(flash, off)
        rec.update(blocks=blocks, total=total, ok=ok,
                   size=HEADER + blocks * 16,
                   tag=flash[off + 0x30:off + 0x40].hex(),
                   kdf=hashlib.sha256(flash[off + 0x20:off + 0x30])
                       .hexdigest()[:8],
                   body_sha=hashlib.sha256(
                       flash[off + HEADER:off + HEADER + blocks * 16])
                       .hexdigest()[:16])
        out.append(rec)
    return out


# Both spellings matter: a rejection is "did not open the container (stop N at
# 0x..)", an acceptance is "opened the container in the SPU interpreter
# (reached 0x400 ...)".  Matching only the first is how a passing run gets
# reported as having no verdict at all.
VERDICT = re.compile(r"the mask ROM (opened the container(?: in the SPU "
                     r"interpreter)?|did not open the container) \(.*")

# The built-in opener's verdict, which is the default path now that the model
# boots without a mask ROM: ps3_rom_set_status() prints one of these.
BUILTIN_VERDICT = re.compile(r"ps3-boot-rom: (?:container verified, \d+ "
                             r"bytes|stop \d+, )")


# Only a stage's own ending counts, not any `ps3-spu:` line: the channel map is
# now printed before the payload runs, and matching it would cut the payload off.
PAYLOAD_DONE = re.compile(r"ps3-spu: (?:stop |instruction limit|"
                          r"blocked on a channel|fault )|"
                          r"container verified, \d+ bytes of payload")

# The model's channel accounting, as ps3_rom_report_channel_map() prints it:
#
#   ps3-spu: channels: 34 of 128 modelled, 14 touched (0x03,...,0x42)
#   ps3-spu: channels: 1 channel(s) with an access the model does not define:
#                       0x2E reserved x3
#
CHANNEL_MAP = re.compile(r"ps3-spu: channels: (\d+) of (\d+) modelled, "
                         r"(\d+) touched(?: \(([^)]*)\))?")
CHANNEL_UNDEF = re.compile(r"ps3-spu: channels: (\d+) channel\(s\) with an "
                           r"access the model does not define: (.*)")
CHANNEL_UNDEF_ITEM = re.compile(r"\s*(0x[0-9A-Fa-f]{2})\s+(.*?)\s+x(\d+)\s*$")


def channel_map(text):
    """The 128-entry channel map a run reported, or None.

    The model prints the touched set after the ROM and again after a payload,
    so the last map wins: it is the one that covers everything the run did.
    """
    maps = CHANNEL_MAP.findall(text)
    undef = CHANNEL_UNDEF.findall(text)
    if not maps and not undef:
        return None

    rec = {"modelled": 0, "total": 0, "touched": [], "touched_count": 0,
           "undefined": [], "clean": True}
    if maps:
        modelled, total, count, touched = maps[-1]
        rec["modelled"] = int(modelled)
        rec["total"] = int(total)
        rec["touched_count"] = int(count)
        rec["touched"] = ["0x" + t.strip()[2:].upper()
                          for t in (touched or "").split(",") if t.strip()]
    if undef:
        for item in undef[-1][1].split(";"):
            m = CHANNEL_UNDEF_ITEM.match(item)
            if m:
                rec["undefined"].append({"channel": "0x" + m.group(1)[2:].upper(),
                                         "name": m.group(2),
                                         "hits": int(m.group(3))})
    rec["clean"] = not rec["undefined"]
    return rec


def channel_flag(rec):
    """The row's undefined-channel accesses as one line, or None."""
    if not rec or rec["clean"]:
        return None
    return "; ".join("%s %s x%d" % (u["channel"], u["name"], u["hits"])
                     for u in rec["undefined"])


def run_qemu(args, log, timeout=30, until=VERDICT):
    """Run until the chain reports, then stop it.

    The machine keeps running after the chain result (a console idles at its
    boot screen), so waiting for the process to exit would spend the whole
    timeout every time.  The log line is the result; once it is there the
    model has nothing left to say for this run.
    """
    with open(log, "wb") as out:
        try:
            proc = subprocess.Popen([QEMU] + args, stdout=out,
                                    stderr=subprocess.STDOUT, env=qemu_env())
        except OSError as e:
            sys.stderr.write("cannot run %s: %s\n" % (QEMU, e))
            return -1
        deadline = time.time() + timeout
        try:
            while time.time() < deadline:
                time.sleep(0.2)
                if proc.poll() is not None:
                    return proc.returncode
                try:
                    text = open(log, "r", errors="replace").read()
                except OSError:
                    continue
                if until.search(text):
                    # Stop here.  On a pass the device runs the container's SPU
                    # payload before it prints its final status, and that
                    # payload is not what this sweep measures: the ROM's own
                    # line is the verdict.  On a rejection the status line is
                    # already written.
                    return 0
            return 124
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()


def boot_args(dump, offset, label, readout, cap, ls, rom_exec):
    """The model's argv for one run.

    The built-in opener passes no `-bios` at all and says so with
    `own-rom=on`; `--rom-exec` is the only path that supplies a mask ROM, and
    it has to turn `own-rom` off because the model refuses a run that claims
    both.  Kept separate from `boot()` so the contract can be checked without
    a QEMU binary.
    """
    args = ["-M", "rs6000-ps3", "-nographic"]
    if rom_exec:
        args += ["-bios", ROM, "-global", "ps3-boot-rom.own-rom=off",
                 "-global", "ps3-boot-rom.rom-exec=on"]
    else:
        args += ["-global", "ps3-boot-rom.own-rom=on"]
    args += ["-drive", "if=pflash,format=raw,file=%s,readonly=on" % dump,
             "-global", "ps3-boot-rom.container=" + label,
             "-global", "ps3-boot-rom.container-offset=0x%X" % offset,
             "-global", "ps3-boot-rom.selftest=off",
             "-global", "ps3-boot-rom.boot-logo=off",
             "-global", "ps3-boot-rom.ch66-capture=" + cap,
             "-global", "ps3-boot-rom.ls-dump=" + ls]
    if readout:
        args += ["-global", "ps3-boot-rom.readout-file=" + readout]
    return args


def boot(dump, offset, label, readout, tag, payload=False, rom_exec=False):
    """One run.  Returns the parsed verdict and the capture.

    Without `rom_exec` the model boots on its built-in opener: no mask ROM is
    loaded at all (`own-rom=on`), and the verdict is the model's own open,
    decrypt and tag check.  With `rom_exec` the developer check is reproduced:
    a mask ROM is supplied and replayed, and its execution is the verdict.
    """
    os.makedirs(WORK, exist_ok=True)
    log = os.path.join(WORK, "%s.log" % tag)
    cap = os.path.join(WORK, "%s_cap.bin" % tag)
    ls = os.path.join(WORK, "%s_ls.bin" % tag)
    for p in (cap, ls):
        if os.path.exists(p):
            os.remove(p)

    args = boot_args(dump, offset, label, readout, cap, ls, rom_exec)

    if rom_exec:
        until = PAYLOAD_DONE if payload else VERDICT
    else:
        # The built-in opener writes its status the moment it has one; a
        # sample run continues to its payload, a dump run is done there.
        until = PAYLOAD_DONE if payload else BUILTIN_VERDICT
    rc = run_qemu(args, log, timeout=40 if payload else 30, until=until)
    text = open(log, "r", errors="replace").read()

    rec = {"log": log, "qemu_rc": rc, "capture": None,
           "opener": "mask rom (--rom-exec)" if rom_exec else "built-in"}
    # The stage's result shares the `ps3-spu:` prefix with the peer's post, the
    # local-store dump and the loader-channel summary, so pick by shape: the
    # result is the line that says how the run ended.
    spu_lines = [m.group(1).strip() for m in re.finditer(r"ps3-spu: (.*)", text)
                 if re.match(r"(stop |instruction limit|blocked on a channel|"
                             r"fault )", m.group(1))]
    rec["payload"] = spu_lines[-1] if spu_lines else None
    if rom_exec:
        verdict = re.search(r"the mask ROM (opened the container(?: in the SPU "
                            r"interpreter)?|did not open the container) "
                            r"\((.*)\)", text)
        if verdict:
            rec["rom"] = verdict.group(1)
            rec["rom_why"] = verdict.group(2)
            stop = re.search(r"stop (\d+) at 0x([0-9A-Fa-f]+)",
                             verdict.group(2))
            if stop:
                rec["stop"] = int(stop.group(1))
                rec["stop_pc"] = int(stop.group(2), 16)
            else:
                rec["stop"] = 0
                rec["stop_pc"] = (0x400 if "reached 0x400" in verdict.group(2)
                                  else 0)
        else:
            rec["rom"] = "no verdict in the log"
            rec["stop"] = None
            rec["stop_pc"] = None
    else:
        # The built-in opener reports through ps3_rom_set_status(): the same
        # three outcomes, one `ps3-boot-rom:` line each.
        line = re.search(r"ps3-boot-rom: (container verified, \d+ bytes.*|"
                         r"stop \d+, .*)", text)
        if line:
            rec["rom_why"] = line.group(1).strip()
            if line.group(1).startswith("container verified"):
                rec["rom"] = "opened the container (built-in opener)"
                rec["stop"], rec["stop_pc"] = 0, 0x400
            else:
                rec["rom"] = "did not open the container (built-in opener)"
                rec["stop"] = int(re.match(r"stop (\d+)", line.group(1))
                                  .group(1))
                rec["stop_pc"] = None
        else:
            rec["rom"] = "no verdict in the log"
            rec["stop"] = None
            rec["stop_pc"] = None

    status = re.findall(r"ps3-boot-rom: (stop \d, [^(]+|container verified,"
                        r" \d+ bytes)", text)
    if status:
        rec["status"] = status[-1].strip()
    elif rec.get("rom", "").startswith("opened"):
        rec["status"] = ("container verified (mask ROM)" if rom_exec else
                         "container verified (built-in opener)")
    elif rec.get("stop") is not None:
        rec["status"] = "stop %d" % rec["stop"]
    else:
        rec["status"] = ""

    if os.path.exists(cap):
        raw = open(cap, "rb").read()
        rec["capture"] = {"bytes": len(raw),
                          "sha": hashlib.sha256(raw).hexdigest()[:16],
                          "all_zero": raw == bytes(len(raw))}

    rec["channels"] = channel_map(text)
    rec["channel_flag"] = channel_flag(rec["channels"])
    return rec


def channel_note(rec):
    """The per-row console suffix: touched count, or the undefined access."""
    ch = rec.get("channels")
    if not ch:
        return ""
    if rec.get("channel_flag"):
        return "  ! ch %d, undefined %s" % (ch["touched_count"],
                                           rec["channel_flag"])
    return "  ch %d" % ch["touched_count"]


def exit_status(rows, failed_samples, matrix_bad=None):
    """3 when a run failed verification, else 0.

    Three things make a sweep a failure: a sample container that should open
    did not, a run that accessed a channel outside the 128-entry map, and a
    matrix row whose own container the Python key check refused - the last is
    an inconsistency between the model's verdict and the arithmetic, not a key
    problem, so it must not pass quietly.
    """
    if failed_samples or matrix_bad:
        return 3
    return 3 if any(r.get("channel_flag") for r in rows) else 0


def sample_rows(rom_exec=False):
    """Run a sample console's own containers, which must open.

    The readout is derived from the key the container is sealed under: with
    `Kp` known, `K_lo = hdr[0x20] XOR AES-DEC(K_hi, Kp)` for any chosen `K_hi`,
    which is the ladder the ROM runs.  Nothing here is a console capture.

    Two routes get to `Kp`, and both are exercised because they are different
    halves of the same story: a sample that publishes `Kp` (a result), and a
    sample that publishes `rk10` (the round key a console's local store keeps,
    which has to be inverted back to `Kp` before the ladder can use it).
    """
    rows = []
    for sample in SAMPLES:
        material = (sample["rk10_from"] if sample["route"] == "rk10"
                    else sample["key"])
        if not (os.path.exists(sample["file"]) and os.path.exists(material)):
            print("  %-22s missing (file or key material)" % sample["name"])
            rows.append({"dump": "sample", "name": sample["name"],
                         "offset": sample["slot"], "blocks": 0, "size": 0,
                         "tag": "", "kdf": "", "body_sha": "",
                         "route": sample["route"],
                         "source": "sample file", "rom": "missing",
                         "status": "missing material", "stop": None,
                         "stop_pc": None, "capture": None, "payload": None,
                         "channels": None, "channel_flag": None})
            continue

        blob = open(sample["file"], "rb").read()
        ok, blocks, _ = header_ok(blob, 0)
        if not ok:
            print("  %-22s no valid container header" % sample["name"])
            continue
        span = HEADER + blocks * 16

        kp, route, source = sample_key(sample)
        if kp is None:
            print("  %-22s %s" % (sample["name"], source))
            rows.append({"dump": "sample", "name": sample["name"],
                         "offset": sample["slot"], "blocks": blocks,
                         "size": span, "tag": blob[0x30:0x40].hex(),
                         "kdf": "", "body_sha": "", "route": sample["route"],
                         "source": "sample file", "rom": "missing",
                         "status": "key not recovered", "stop": None,
                         "stop_pc": None, "capture": None, "payload": None,
                         "channels": None, "channel_flag": None})
            continue

        image = bytearray(FLASH_SIZE)
        image[sample["slot"]:sample["slot"] + span] = blob[:span]
        tag = "sample_%s" % sample["tag"]
        image_path = os.path.join(WORK, tag + "_nor.bin")
        open(image_path, "wb").write(image)

        k_hi = hashlib.sha256(b"ps3 romexec sweep K_hi").digest()[:16]
        k_lo = bytes(a ^ b for a, b in zip(
            blob[0x20:0x30], AES.new(k_hi, AES.MODE_ECB).decrypt(kp)))
        readout_path = os.path.join(WORK, tag + "_readout.bin")
        open(readout_path, "wb").write(k_lo + k_hi)

        rec = boot(image_path, sample["slot"], sample["name"], readout_path,
                   tag, payload=True, rom_exec=rom_exec)
        rows.append(dict(dump="sample (real firmware)", name=sample["name"],
                         offset=sample["slot"], blocks=blocks,
                         readout="%s (%s, derived)" % (source, route),
                         route=route,
                         size=span, tag=blob[0x30:0x40].hex(),
                         kdf=hashlib.sha256(blob[0x20:0x30]).hexdigest()[:8],
                         body_sha=hashlib.sha256(blob[HEADER:span])
                         .hexdigest()[:16],
                         source="its own key material (readout derived)",
                         **rec))
        print("  0x%06X %-22s %6d B  %s%s%s  [%s]"
              % (sample["slot"], sample["name"], span,
                 rec.get("status") or "-",
                 "  [stop %d%s]" % (rec["stop"],
                                     " @0x%X" % rec["stop_pc"]
                                     if rec.get("stop_pc") is not None else "")
                 if rec.get("stop") is not None else "",
                 channel_note(rec), route))
        if rec.get("payload"):
            print("           payload: %s" % rec["payload"])
    return rows


def readout_label(path):
    if not path:
        return "none (32 zero bytes)"
    raw = open(path, "rb").read()
    if len(raw) != 32:
        raise SystemExit("%s is %d bytes, a readout is 32" % (path, len(raw)))
    return "%s (%s)" % (os.path.basename(path),
                        hashlib.sha256(raw).hexdigest()[:16])


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dump", action="append", default=None,
                    help="a NOR dump (default: both 4301C dumps)")
    ap.add_argument("--readout", default=None,
                    help="a 32-byte channel-66 readout; omit for the "
                         "zero-key control")
    ap.add_argument("--control", action="store_true",
                    help="also point at 0xFC0040, a misaligned address, to "
                         "show that the offset is not cosmetic")
    ap.add_argument("--no-samples", action="store_true",
                    help="skip the real-firmware sample containers, whose "
                         "runs are what exercise the acceptance path")
    ap.add_argument("--rom-exec", action="store_true",
                    help="developer check only: replay the supplied mask ROM "
                         "instead of the model's built-in opener (default, "
                         "and what a checkout without a ROM image runs)")
    ap.add_argument("--json", default=os.path.join(WORK, "sweep.json"))
    ap.add_argument("--report", default=os.path.join(WORK, "REPORT.md"))
    args = ap.parse_args()

    dumps = [os.path.join(DOWNLOADS, d) for d in (args.dump or DUMPS)]
    for p in dumps:
        if not os.path.exists(p):
            sys.stderr.write("no dump at %s\n" % p)
            return 4
    if not os.path.exists(QEMU):
        sys.stderr.write("no QEMU build at %s\n" % QEMU)
        return 4
    if args.readout and not os.path.exists(args.readout):
        sys.stderr.write("no readout at %s\n" % args.readout)
        return 4

    label = readout_label(args.readout)
    rows = []
    for dump in dumps:
        flash = open(dump, "rb").read()
        name = os.path.basename(dump)
        if len(flash) != FLASH_SIZE:
            sys.stderr.write("%s is not a 16 MiB NOR image\n" % name)
            return 4
        containers = find_containers(flash)
        print("%s: %d container%s" % (name, len(containers),
                                      "" if len(containers) == 1 else "s"))
        for c in containers:
            tag = "%s_%06X_%s" % (name.split(".")[0].replace("-", "_"),
                                  c["offset"],
                                  "key" if args.readout else "zero")
            rec = boot(dump, c["offset"], c["name"], args.readout, tag,
                       rom_exec=args.rom_exec)
            row = dict(dump=name, readout=label, **{k: c[k] for k in
                       ("name", "offset", "blocks", "size", "tag", "kdf",
                        "body_sha", "source")}, **rec)
            rows.append(row)
            stop = ("  [stop %d%s]" % (rec["stop"],
                    " @0x%X" % rec["stop_pc"]
                    if rec.get("stop_pc") is not None else "")
                    if rec.get("stop") is not None else "")
            print("  0x%06X %-9s %6d B  %s%s%s"
                  % (c["offset"], c["name"], c["size"], rec["status"] or "-",
                     stop, channel_note(rec)))

        if args.control:
            off = 0xFC0040
            rec = boot(dump, off, "misaligned-control", args.readout,
                       "%s_%06X_ctrl" % (name.split(".")[0].replace("-", "_"),
                                         off), rom_exec=args.rom_exec)
            # The field the model validates is the header's total at +0x10;
            # for a real container it equals the encrypted count at +0x00.
            rows.append(dict(dump=name, readout=label, name="misaligned "
                             "control", offset=off,
                             blocks=be32(flash, off + 0x10),
                             size=0, tag="", kdf="", body_sha="",
                             source="--control", **rec))
            print("  0x%06X control    %s%s"
                  % (off, rec["status"] or "-", channel_note(rec)))

    matrix = None
    if not args.no_samples:
        print("\nsample containers (real firmware, readout derived from the "
              "key each is sealed under)")
        rows += sample_rows(rom_exec=args.rom_exec)
        matrix = match_matrix()
        print("\nkey match matrix: what each key opens")
        for title, table in (("per-image keys (Kp)", matrix["kp"]),
                             ("console readouts", matrix["readouts"])):
            print("  %s" % title)
            for row, cells in zip(table["keys"], table["matrix"]):
                opened = [c for c, ok in zip(table["containers"], cells) if ok]
                print("    %-24s %-30s %d of %d: %s"
                      % (row["name"], row["source"], len(opened),
                         len(table["containers"]),
                         ", ".join(opened) or "none"))
        for bad in matrix["self_check"]:
            print("  ! %s does not open its own %s in Python"
                  % (bad["key"], bad["container"]))

    # A run that touched a channel the 128-entry map does not define is not a
    # clean run: the model cannot account for what that access did, so it is
    # called out in the summary, the JSON and the report.
    mapped = [r for r in rows if r.get("channels")]
    flagged = [r for r in rows if r.get("channel_flag")]
    # The verdict string is "opened the container in the SPU interpreter" on a
    # pass, so this is a prefix test and not an equality one.
    opened = [r for r in rows if r.get("rom", "").startswith("opened")]
    failed_samples = [r for r in rows if r.get("dump", "").startswith("sample")
                      and not r.get("rom", "").startswith("opened")]
    status = exit_status(rows, failed_samples,
                         matrix["self_check"] if matrix else None)
    summary = {"runs": len(rows), "reported": len(mapped),
               "clean": len(mapped) - len(flagged),
               "failed": status != 0,
               "exit": status,
               "flagged": [{"dump": r["dump"], "container": r["name"],
                            "offset": r["offset"],
                            "undefined": r["channels"]["undefined"]}
                           for r in flagged]}

    os.makedirs(WORK, exist_ok=True)
    with open(args.json, "w") as f:
        json.dump({"readout": label,
                   "opener": ("mask rom" if args.rom_exec else "built-in"),
                   "channel_summary": summary,
                   "key_match": matrix,
                   "rows": rows}, f, indent=2)

    print("\n%d run%s, %d opened, %d rejected  [opener: %s]"
          % (len(rows), "" if len(rows) == 1 else "s", len(opened),
             len(rows) - len(opened),
             "mask rom" if args.rom_exec else "built-in"))
    print("channels: %d run(s) reported the map, %d clean, %d with an access "
          "the model does not define"
          % (len(mapped), summary["clean"], len(flagged)))
    for r in flagged:
        print("  ! %s %s: %s" % (r["dump"], r["name"], r["channel_flag"]))
    if flagged:
        print("FAILED: %d run(s) touched a channel the model does not define"
              % len(flagged))
    if failed_samples:
        print("sample control failed: %s"
              % ", ".join(r["name"] for r in failed_samples))

    with open(args.report, "w") as f:
        f.write("# Sweep over the loader containers\n\n")
        f.write("Opener: %s.  " % (
            "the supplied mask ROM, replayed (`--rom-exec`)" if args.rom_exec
            else "the model's built-in opener - no mask ROM is loaded, and "
                 "the open, decrypt and tag check are the model's own code"))
        f.write("Readout: %s for the dump rows.  Sample rows are separate: "
                "each derives a readout from the key it is sealed under.  "
                "The verdict is %s: it either reached 0x400 or "
                "stopped first.\n\n" % (label, "the ROM's own" if args.rom_exec
                                        else "the built-in opener's"))
        reasons = []
        if failed_samples:
            reasons.append("%d sample container(s) did not open"
                           % len(failed_samples))
        if flagged:
            reasons.append("%d run(s) touched a channel the model does not "
                           "define" % len(flagged))
        if reasons:
            f.write("**Sweep failed (exit %d): %s.**\n\n"
                    % (status, "; ".join(reasons)))
        f.write("| dump | container | offset | size | blocks | ROM verdict "
                "| stop | capture | channels |\n")
        f.write("|---|---|---|---|---|---|---|---|---|\n")
        for r in rows:
            cap = r["capture"]
            ch = r.get("channels")
            f.write("| %s | %s | 0x%06X | %d | %d | %s | %s | %s | %s |\n"
                    % (r["dump"], r["name"], r["offset"], r.get("size", 0),
                       r.get("blocks", 0),
                       r.get("status", "-") or "-",
                       ("%d%s" % (r["stop"],
                                   " @0x%X" % r["stop_pc"]
                                   if r.get("stop_pc") is not None else "")
                        if r.get("stop") is not None
                        else ("0x400" if r.get("rom", "").startswith("opened")
                              else "not run")),
                       "%dB %s%s" % (cap["bytes"], cap["sha"],
                                     " zero" if cap["all_zero"] else "")
                       if cap else "none",
                       ("**FLAG** " + r["channel_flag"]) if r.get("channel_flag")
                       else ("%d touched" % ch["touched_count"] if ch else "-")))
        samples = [r for r in rows if r.get("dump", "").startswith("sample")]
        if samples:
            f.write("\n## Sample containers (real firmware)\n\n")
            f.write("The readout is derived from the key each container is "
                    "sealed under (`K_lo = hdr[0x20] XOR AES-DEC(K_hi, Kp)`), "
                    "so the acceptance branch runs on firmware rather than on "
                    "the synthetic image.  Two key routes are exercised, "
                    "because they are different halves of the same story: the "
                    "4th sample ships `Kp` itself (a result), and the 2nd "
                    "sample ships `rk10` - the round key a console's local "
                    "store keeps at LS 0xa0 - which the sweep inverts through "
                    "the AES key schedule to recover `Kp` (a method).  The "
                    "inversion is checked forward before it is used: the "
                    "schedule rebuilt from the recovered `Kp` has to return "
                    "the round key it was given.  The payload is the "
                    "container's own SPU stage, run by the model after the "
                    "hand-off.  Where it ends is the stage's own business: "
                    "`metldr.2` finishes its teardown once its channel-0x1D "
                    "poll is answered (the mailbox peer does that), and "
                    "`lv0ldr.2` never polls a mailbox at all - it spends the "
                    "whole budget in a per-element byte loop fed by its own "
                    "data.\n\n")
            for r in samples:
                f.write("* `%s` @0x%06X [%s]: %s%s\n"
                        % (r["name"], r["offset"], r.get("route", "-"),
                           r.get("status") or "-",
                           ", payload `%s`" % r["payload"]
                           if r.get("payload") else ""))
        if matrix and matrix["kp"]["containers"]:
            f.write("\n## Key match matrix\n\n")
            f.write("Two levels, and they are not interchangeable.  `Kp` is "
                    "**per image**: a sample ships one per container (the 4th "
                    "directly, the 2nd as the round key `rk10`, inverted back "
                    "through the schedule), and each has to match its own "
                    "container and no other.  A channel-66 readout is **per "
                    "console**: it becomes a different `Kp` for every header, "
                    "so one readout opens every image of the console it was "
                    "read from.  The tree holds one real readout "
                    "(`.tmp/dlt/readout.bin`, the tool's sample console), "
                    "which is why that row opens two images and every other "
                    "row opens one or none.  The checks are the CTR body and "
                    "the CBC-MAC tag in Python; the sample runs above prove "
                    "the same pairs through the model, so a key that fails to "
                    "match its own container here is an inconsistency and "
                    "fails the sweep.\n\n")
            for title, table in (("Per-image keys (`Kp`)", matrix["kp"]),
                                 ("Console readouts", matrix["readouts"])):
                f.write("### %s\n\n" % title)
                f.write("| key | source | %s | matches |\n"
                        % " | ".join(table["containers"]))
                f.write("|---" * (len(table["containers"]) + 3) + "|\n")
                for row, cells in zip(table["keys"], table["matrix"]):
                    f.write("| %s | %s | %s | %d |\n"
                            % (row["name"], row["source"],
                               " | ".join("opens" if ok else "-"
                                          for ok in cells), sum(cells)))
                f.write("\n")
            f.write("\n")

        f.write("\n## Channel map per run\n\n")
        f.write("Every run is judged against the model's 128-entry channel map.  "
                "`touched` is what the image actually executed, not what a "
                "listing suggests; an access the map does not define - a "
                "reserved number, or a direction the channel does not have - "
                "is flagged, because the model cannot account for it.\n\n")
        f.write("| dump | container | modelled | touched | undefined access |\n")
        f.write("|---|---|---|---|---|\n")
        for r in rows:
            ch = r.get("channels")
            if not ch:
                f.write("| %s | %s | - | no map reported | - |\n"
                        % (r["dump"], r["name"]))
                continue
            f.write("| %s | %s | %d of %d | %d: %s | %s |\n"
                    % (r["dump"], r["name"], ch["modelled"], ch["total"],
                       ch["touched_count"],
                       ", ".join(ch["touched"]) or "none",
                       ("**" + r["channel_flag"] + "**")
                       if r.get("channel_flag") else "none"))
        f.write("\n")
        if flagged:
            f.write("**FAILED: %d run(s) touched a channel the map does not "
                    "define**, so the sweep exits 3.\n\n" % len(flagged))
            for r in flagged:
                f.write("* `%s` %s @0x%06X: %s\n"
                        % (r["dump"], r["name"], r["offset"],
                           r["channel_flag"]))
        else:
            f.write("No run touched a channel outside the map, so every "
                    "verdict above stands on code the model fully accounts "
                    "for.\n")

        f.write("\nContainers, as found:\n\n")
        for r in rows:
            if r["name"] == "misaligned control":
                continue
            f.write("* `%s` at 0x%06X in %s (%s): %d blocks, tag %s, body "
                    "sha256 %s\n" % (r["name"], r["offset"], r["dump"],
                                     r["source"], r["blocks"], r["tag"],
                                     r["body_sha"]))
    print("wrote %s and %s" % (args.json, args.report))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
