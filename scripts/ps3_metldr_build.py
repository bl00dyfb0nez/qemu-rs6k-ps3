#!/usr/bin/env python3
"""Identify a decrypted metldr.2 by its build stamps, in one step.

Two sample builds differ by 3,411 bytes on a raw diff, but almost all of that
is one function being recompiled and everything after it moving.  What actually
distinguishes them is two `stop` words the binary carries in its 0x30000 band -
`0x30066/0x30065` in the 4th sample, `0x30065/0x30064` in the dot-2 sample -
each one lower in the newer build, which is the shape of a revision bump.
Reading those two words is enough to name a build; the byte diff is only needed
once a *new* pair appears.

This reads them, names the build when the pair is known, and refuses to pretend
about anything else:

  * a stamp pair that matches the registry and a matching SHA-1 is `known`;
  * a pair that matches but bytes that do not is reported as `same stamp,
    different bytes` - the stamp names a revision, not a file, so two builds can
    share one;
  * no stamp at all is `unrecognised`, which also covers a sealed body and a
    wrong-key decryption (both are high-entropy and carry no such word).  A
    63,536-byte build in this tree has no stamp at all: it predates the pair, so
    it is named by size and SHA-1 instead.

    py scripts/ps3_metldr_build.py metldr.dec [more.dec ...]
    py scripts/ps3_metldr_build.py --list
    py scripts/ps3_metldr_build.py --selftest

Exit codes: 0 a build was named, 3 it was not (no stamp, or an unknown pair),
2 usage or an unreadable file.
"""
import argparse
import hashlib
import json
import math
import os
import sys

# Stamp pair (in file order) -> build.  These are the two samples' words; the
# fingerprint is the decrypted plaintext's, which is not key material.
KNOWN = {
    (0x30066, 0x30065): {
        "build": "0x30066", "sha1": "20530d2d0979",
        "bytes": 63712, "blocks": 3982, "note": "4th sample",
    },
    (0x30065, 0x30064): {
        "build": "0x30065", "sha1": "d93173456847",
        "bytes": 63712, "blocks": 3982, "note": "pc tool second sample dot 2",
    },
}

# Builds that predate the stamp pair, named by size and fingerprint.
UNSTAMPED = {
    ("7f074689ea58", 59536): {
        "build": "pre-stamp", "note": "pc tool channel 66 sample",
    },
}

STAMP_LO, STAMP_HI = 0x00030000, 0x0003FFFF


def entropy(data):
    if not data:
        return 0.0
    seen = [0] * 256
    for b in data:
        seen[b] += 1
    n = float(len(data))
    return -sum((c / n) * math.log2(c / n) for c in seen if c)


def stamps(data):
    """Every word in the 0x0003xxxx band, with its offset."""
    out = []
    for off in range(0, len(data) - 3, 4):
        w = int.from_bytes(data[off:off + 4], "big")
        if STAMP_LO <= w <= STAMP_HI:
            out.append((off, w))
    return out


def identify(path):
    data = open(path, "rb").read()
    rec = {"file": os.path.basename(path), "path": path, "bytes": len(data),
           "words": len(data) // 4, "blocks": len(data) // 16,
           "sha1": hashlib.sha1(data).hexdigest()[:12],
           "zeros": round(100.0 * data.count(0) / len(data), 1)
           if data else 0.0,
           "entropy": round(entropy(data), 2)}
    found = stamps(data)
    rec["stamps"] = [{"offset": off, "value": w} for off, w in found]
    pair = tuple(w for _o, w in found[:2]) if len(found) >= 2 else None
    rec["pair"] = pair

    if pair in KNOWN:
        known = KNOWN[pair]
        rec["build"] = known["build"]
        rec["note"] = known["note"]
        rec["known"] = (rec["sha1"] == known["sha1"]
                        and rec["bytes"] == known["bytes"])
        rec["status"] = "known" if rec["known"] else "same stamp, different bytes"
    elif ("%s" % rec["sha1"], rec["bytes"]) in UNSTAMPED:
        entry = UNSTAMPED[("%s" % rec["sha1"], rec["bytes"])]
        rec["build"] = entry["build"]
        rec["note"] = entry["note"]
        rec["known"] = True
        rec["status"] = "known (no stamp in this build)"
    else:
        rec["build"] = None
        rec["note"] = None
        rec["known"] = False
        # A sealed body or a wrong-key decryption looks like this: no 0x300xx
        # word, almost no zero bytes, nearly full entropy.
        sealed = rec["zeros"] < 1.0 and rec["entropy"] > 7.8
        rec["status"] = ("no stamp - looks sealed or wrongly decrypted"
                         if sealed else "no stamp - unrecognised build")
    return rec


def show(rec):
    print("%-28s %6d bytes  %5d blocks  sha1 %s"
          % (rec["file"], rec["bytes"], rec["blocks"], rec["sha1"]))
    if rec["stamps"]:
        print("  stamps   %s" % ", ".join("0x%X at 0x%X"
                                          % (s["value"], s["offset"])
                                          for s in rec["stamps"]))
    else:
        print("  stamps   none in 0x%05X-0x%05X" % (STAMP_LO, STAMP_HI))
    print("  zeros %.1f%%, entropy %.2f" % (rec["zeros"], rec["entropy"]))
    if rec["build"]:
        print("  build    %s  %s%s"
              % (rec["build"], rec["note"],
                 "" if rec["known"] else "  (stamp only, bytes differ)"))
    print("  verdict  %s" % rec["status"])


def selftest():
    checks = 0
    failures = 0

    def check(name, ok):
        nonlocal checks, failures
        checks += 1
        print("%-54s %s" % (name, "ok" if ok else "FAIL"))
        if not ok:
            failures += 1

    code = bytearray(b"\x00\x00\x00\x00" * 16)
    code[0x40:0x44] = (0x30066).to_bytes(4, "big")
    code[0x50:0x54] = (0x30065).to_bytes(4, "big")
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "a.dec")
        open(p, "wb").write(bytes(code))
        rec = identify(p)
        check("a synthetic 0x30066/0x30065 pair is found",
              rec["pair"] == (0x30066, 0x30065))
        check("the synthetic pair names build 0x30066",
              rec["build"] == "0x30066")
        check("its bytes are not the registered file",
              rec["status"] == "same stamp, different bytes")

        junk = os.urandom(4096)
        p = os.path.join(d, "junk.dec")
        open(p, "wb").write(junk)
        rec = identify(p)
        check("random bytes carry no stamp", rec["pair"] is None)
        check("random bytes are called sealed or wrongly decrypted",
              rec["status"].startswith("no stamp - looks sealed"))

        p = os.path.join(d, "none.dec")
        open(p, "wb").write(b"\x42\x00\x00\x00" * 64)
        rec = identify(p)
        check("low-entropy bytes with no stamp are unrecognised",
              rec["status"] == "no stamp - unrecognised build")

    print("\n%d check(s), %d failed" % (checks, failures))
    return 0 if failures == 0 else 3


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Name a decrypted metldr.2 build from its 0x300xx stop "
                    "stamps.")
    ap.add_argument("files", nargs="*", help="decrypted metldr images")
    ap.add_argument("--list", action="store_true", help="show the registry")
    ap.add_argument("--json", action="store_true", help="machine-readable")
    ap.add_argument("--selftest", action="store_true",
                    help="prove detection and each refusal with no sample files")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if args.list:
        for pair, entry in KNOWN.items():
            print("0x%05X/0x%05X  %-8s %s  %d blocks  sha1 %s"
                  % (pair[0], pair[1], entry["build"], entry["note"],
                     entry["blocks"], entry["sha1"]))
        for (_sha, size), entry in UNSTAMPED.items():
            print("%-16s  %-8s %s  %d bytes"
                  % ("(no stamp)", entry["build"], entry["note"], size))
        return 0
    if not args.files:
        ap.error("name at least one decrypted metldr, or pass --list")

    records = []
    for path in args.files:
        if not os.path.exists(path):
            sys.stderr.write("cannot read %s\n" % path)
            return 2
        records.append(identify(path))
    if args.json:
        print(json.dumps(records))
    else:
        for n, rec in enumerate(records):
            if n:
                print()
            show(rec)
    return 0 if all(r["build"] for r in records) else 3


if __name__ == "__main__":
    raise SystemExit(main())
