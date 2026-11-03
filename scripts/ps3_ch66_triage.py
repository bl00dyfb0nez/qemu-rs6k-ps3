#!/usr/bin/env python3
"""ps3_ch66_triage.py - is this 32-byte channel-66 readout this dump's?

One question, one command: take a readout (PCK0) and a dump, and say whether it
opens `metldr.2` or `lv0ldr.2` at their real offsets.  Nothing is derived past
that point - a readout that opens neither cannot yield PCK1, and a readout that
opens one is confirmed against the other before it is reported.

The check is the container's own: the ROM derives

    Kp = AES-128-ECB(K_hi, header[0x20] XOR K_lo)

and the CCM-style tag over header and plaintext must verify.  No key is
assumed, and the verdict is a MAC comparison, not a heuristic.

Two searches, because a capture can be right and still not byte-ordered the way
this tool would guess:

  * the two half orders - `K_lo||K_hi`, the layout `ch66-capture` writes, and
    its reverse;
  * if neither opens anything, the 1,152 four-word compositions of each half
    with the halves in both positions.  The ROM assembles the readout from
    eight 32-bit channel reads, so a dump from another tool can be the same
    eight words in a different order.  This pass is what makes a `no` mean
    "not this console" rather than "not in the byte order I tried".

`--quick` skips the second pass.  A `no` after it is weaker: it rules out the
two whole-half orders only.

`--rom-exec` adds the mask ROM's own answer beside the Python one: the readout is
handed to the model, the published ROM is replayed over the same dump, and the
stop code it reaches is reported.  That is the check with no Python in the
arithmetic - the ROM either computes the same tag or it does not - so it is
opt-in: it needs a QEMU build and the ROM image, and a readout given as hex has
to be a file first.  When the two disagree the tool says so and exits 7: that
would mean the model and the ROM have drifted apart, not that a capture is bad.

    py scripts/ps3_ch66_triage.py --nor CECH4301C.NOR.BIN --readout ch66.bin

The readout is never printed, hashed or written; only its file name, length and
verdict appear.  `--readout` also takes the 64 hex digits directly.  Medium and
offsets follow `ps3_capture_verify.py`: a 16 MiB file is NOR, a larger one is
NAND/eMMC flash, and `--metldr-offset`/`--bootldr-offset` override either.

Exit codes: 0 opens at least one container, 3 opens neither, 2 usage or material
unreadable, 5 the dump carries no container at the expected offsets, 7 the
mask ROM and the model disagree (`--rom-exec` only).
"""
import argparse
import hashlib
import itertools
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
QEMU_ROOT = os.path.dirname(HERE)
HOME = os.path.dirname(QEMU_ROOT)
TOOLS = os.path.join(HOME, "Documents", "ps3tools-main")
sys.path.insert(0, TOOLS)
sys.path.insert(0, HERE)
import ps3_capture_verify as cap  # noqa: E402  (container crypto, dump reads)


def readout_bytes(spec):
    """The 32 bytes named by `spec`: a file, or 64 hex digits."""
    if len(spec) == 64 and not os.path.exists(spec):
        try:
            return bytes.fromhex(spec)
        except ValueError:
            pass
    return cap.read_file(spec)


def half_orders(raw):
    """The two whole-half readings, in the order the ROM and the model use."""
    yield {"lo": raw[:16], "hi": raw[16:], "note": "K_lo||K_hi (read order)"}
    yield {"lo": raw[16:], "hi": raw[:16], "note": "K_hi||K_lo (reversed)"}


def word_orders(raw):
    """Every four-word composition of each half, halves either way round."""
    w = [raw[4 * i:4 * i + 4] for i in range(8)]
    perms = list(itertools.permutations(range(4)))
    for a in perms:
        lo = b"".join(w[i] for i in a)
        for b in perms:
            hi = b"".join(w[4 + i] for i in b)
            tag = "%s/%s" % ("".join(map(str, a)), "".join(map(str, b)))
            yield {"lo": lo, "hi": hi, "note": "words %s as K_lo/K_hi" % tag}
            yield {"lo": hi, "hi": lo, "note": "words %s as K_lo/K_hi (swapped)" % tag}


def opens(cont, candidates):
    """The first candidate that opens `cont`, or None."""
    for cand in candidates:
        kp = cap.kp_from_readout(cand["lo"], cand["hi"],
                                 cont["hdr"][0x20:0x30])
        if cap.container_opens(kp, cont):
            return cand
    return None


def triage(raw, records, deep=True):
    """[{name, offset, blocks, opened_with, pass}] for each container.

    `pass` says which search produced the answer, so a `no` from the quick pass
    is never reported with the authority of the full one.

    The word pass runs on the cheapest container only, and its hit composition
    is then tried once against the others.  A capture's layout is one fact, not
    one per container, so re-searching 1,152 orders against a 12,315-block
    container would only re-derive an answer the first hit already implies.
    """
    out = []
    quick = list(half_orders(raw))
    for rec in records:
        cont = rec["container"]
        if cont is None:
            out.append({"name": rec["name"], "offset": rec["offset"],
                        "blocks": None, "opened_with": None, "pass": None})
            continue
        hit = opens(cont, quick)
        out.append({"name": rec["name"], "offset": rec["offset"],
                    "blocks": cont["blocks"],
                    "opened_with": hit["note"] if hit else None,
                    "pass": "half orders"})

    if deep and not any(r["opened_with"] for r in out):
        searched = next((r for r in out if r["blocks"] is not None), None)
        if searched is not None:
            idx = out.index(searched)
            cont = next(r["container"] for r in records
                        if r["offset"] == searched["offset"])
            hit = opens(cont, word_orders(raw))
            searched["pass"] = "half orders + 1152 word compositions"
            if hit:
                searched["opened_with"] = hit["note"]
                for r in out:
                    if r is searched or r["blocks"] is None:
                        continue
                    other = next(c for c in records
                                 if c["offset"] == r["offset"])["container"]
                    if opens(other, [hit]):
                        r["opened_with"] = hit["note"]
                        r["pass"] = ("half orders + the composition %s opened "
                                     "with" % searched["name"])
                    else:
                        r["pass"] = ("half orders + the composition %s opened "
                                     "with (refused)" % searched["name"])
            else:
                for r in out:
                    if r["blocks"] is not None:
                        r["pass"] = ("half orders (word pass found no opening "
                                     "on %s)" % searched["name"])
    return out


def rom_exec(results, args):
    """One mask-ROM replay per container, through the sweep's boot path.

    `ps3_romexec_sweep.boot()` is the single place the model's argv and its
    verdict parsing live, so this mode calls it rather than re-deriving either:
    a second copy of the flag names is how `--rom-exec` and the sweep drift.
    """
    import ps3_romexec_sweep as sweep

    qemu = args.qemu or sweep.QEMU
    rom = args.rom or sweep.ROM
    for path, what in ((qemu, "a QEMU build"), (rom, "the mask ROM image")):
        if not os.path.exists(path):
            sys.stderr.write("--rom-exec needs %s, and %s does not exist\n"
                             % (what, path))
            raise SystemExit(2)
    if not os.path.exists(args.readout):
        sys.stderr.write("--rom-exec needs the readout as a file: hex on the "
                         "command line has nothing to hand the model\n")
        raise SystemExit(2)
    out = []
    for r in results:
        if r["blocks"] is None:
            out.append(None)
            continue
        tag = "triage_%s" % r["name"].replace(".", "_")
        out.append(sweep.boot(args.nor, r["offset"], r["name"],
                              args.readout, tag, rom_exec=True))
    return out


def rom_line(rec):
    """(opened, text) for one mask-ROM record."""
    if rec is None:
        return None, "no container"
    opened = (rec.get("stop") == 0
              and (rec.get("rom") or "").startswith("opened"))
    why = rec.get("rom_why") or rec.get("status") or "no verdict in the log"
    stop, pc = rec.get("stop"), rec.get("stop_pc")
    # The model's own line already carries "stop N at 0x..."; prefixing an
    # unconditional "stop N" only says it twice.
    if stop is not None and "stop %d at 0x" % stop not in why:
        why = "stop %d at 0x%X (%s)" % (stop, pc or 0, why)
    return opened, why


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Report whether a 32-byte channel-66 readout opens either "
                    "loader container in a PS3 dump.")
    ap.add_argument("--nor", required=False,
                    help="16 MiB NOR dump, or a larger NAND/eMMC flash dump")
    ap.add_argument("--readout", required=False,
                    help="32-byte readout: a file, or 64 hex digits")
    ap.add_argument("--medium", choices=("auto", "nor", "nand"), default="auto")
    ap.add_argument("--metldr-offset", type=lambda s: int(s, 0), default=None,
                    help="metldr.2 offset (default 0x840 NOR, 0x840/0x40840 NAND)")
    ap.add_argument("--bootldr-offset", type=lambda s: int(s, 0), default=None,
                    help="lv0ldr.2 offset (default 0xFC0000 on NOR)")
    ap.add_argument("--quick", action="store_true",
                    help="only the two half orders; skips the word search")
    ap.add_argument("--rom-exec", action="store_true",
                    help="also replay the published mask ROM over this dump "
                         "and report its stop code (needs QEMU and the ROM; "
                         "the readout must be a file)")
    ap.add_argument("--qemu", help="qemu-system-ppc64 (default: build-ps3/)")
    ap.add_argument("--rom", help="the mask ROM image (default: .tmp/rom/rom.bin)")
    ap.add_argument("--json", action="store_true", help="machine-readable result")
    ap.add_argument("--selftest", action="store_true",
                    help="seal a container in memory and prove both answers")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.nor or not args.readout:
        raise SystemExit("pass --nor and --readout")

    raw = readout_bytes(args.readout)
    # A readout typed as hex is still a readout: name the form, never echo it.
    label = (os.path.basename(args.readout) if os.path.exists(args.readout)
             else "hex given on the command line")
    if len(raw) != 32:
        sys.stderr.write("%s: %d bytes is not a 32-byte channel-66 readout\n"
                         % (label, len(raw)))
        return 2

    try:
        dump, medium, base = cap.load_dump(args.nor, args.medium)
    except SystemExit as e:
        sys.stderr.write("%s\n" % e)
        return 2
    metldr_off, bootldr_off, _eid = cap.record_offsets(medium, base)
    if args.metldr_offset is not None:
        metldr_off = args.metldr_offset
    if args.bootldr_offset is not None:
        bootldr_off = args.bootldr_offset
    records = cap.dump_records(dump, metldr_off, bootldr_off)

    if all(r["container"] is None for r in records):
        print("dump      %s (%d bytes, %s, sha256 %s)"
              % (os.path.basename(args.nor), len(dump), medium,
                 hashlib.sha256(dump).hexdigest()[:16]))
        print("verdict   NO CONTAINER at 0x%X / %s - wrong dump, or override "
              "the offsets" % (metldr_off,
                               "none" if bootldr_off is None
                               else "0x%X" % bootldr_off))
        return 5

    results = triage(raw, records, deep=not args.quick)
    roms = rom_exec(results, args) if args.rom_exec else None
    disagree = []
    for r, rec in zip(results, roms or []):
        if rec is not None and rom_line(rec)[0] != bool(r["opened_with"]):
            disagree.append(r["name"])
    report = {
        "dump": {"name": os.path.basename(args.nor), "size": len(dump),
                 "medium": medium, "sha256": hashlib.sha256(dump).hexdigest()},
        "readout": {"name": label, "size": len(raw)},
        "containers": results,
        "opened": [r["name"] for r in results if r["opened_with"]],
        "rom_exec": None if roms is None else [
            None if rec is None else
            {"name": results[i]["name"], "stop": rec.get("stop"),
             "stop_pc": rec.get("stop_pc"),
             "verdict": rec.get("rom_why") or rec.get("status"),
             "opened": rom_line(rec)[0], "log": rec.get("log")}
            for i, rec in enumerate(roms)],
        "model_rom_agree": None if roms is None else not disagree,
    }
    hit = bool(report["opened"])

    if args.json:
        print(json.dumps(report))
    else:
        print("dump      %s (%d bytes, %s, sha256 %s)"
              % (report["dump"]["name"], len(dump), medium,
                 report["dump"]["sha256"][:16]))
        print("readout   %s (32 bytes)" % report["readout"]["name"])
        for idx, r in enumerate(results):
            if r["blocks"] is None:
                print("%-9s 0x%06X  MISSING" % (r["name"], r["offset"]))
                continue
            print("%-9s 0x%06X  %5d blocks  %s"
                  % (r["name"], r["offset"], r["blocks"],
                     "OPEN" if r["opened_with"] else "no"))
            if r["opened_with"]:
                print("          opens as %s" % r["opened_with"])
            if not args.quick:
                print("          searched %s" % r["pass"])
            if roms is not None and roms[idx] is not None:
                opened, text = rom_line(roms[idx])
                print("          mask rom  %s %s"
                      % ("OPEN," if opened else "refused,", text))
        if hit:
            print("verdict   OPENS %s - this is a readout for this dump"
                  % ", ".join(report["opened"]))
            notes = [r["opened_with"] for r in results if r["opened_with"]]
            if any("reversed" in n for n in notes):
                print("note      the readout verifies only with its halves "
                      "reversed; reverse it before feeding the model")
        else:
            print("verdict   NEITHER CONTAINER OPENS - not this dump's readout")
            if args.quick:
                print("note      --quick searched the two half orders only; "
                      "rerun without it to rule out word composition")
    if disagree:
        print("note      model and mask ROM disagree on %s - the opener and "
              "the ROM have drifted apart" % ", ".join(disagree))
        return 7
    return 0 if hit else 3


# --------------------------------------------------------------------------
# Selftest: no dump, no console, no ROM.  Seal a container under a readout,
# then prove it is found in both byte orders and refused otherwise.

def selftest():
    plain = bytes(((i * 11 + 5) & 0xFF) for i in range(0x800))
    readout = bytes(range(32))
    hdr = bytearray(cap.HEADER)
    hdr[4:0x10] = bytes(range(0x20, 0x2C))
    hdr[0x14:0x20] = bytes(range(0x30, 0x3C))
    hdr[0x20:0x30] = bytes(range(0x40, 0x50))
    kp = cap.kp_from_readout(readout[:16], readout[16:], bytes(hdr[0x20:0x30]))
    sealed = cap.seal_container(kp, bytes(hdr), plain)

    records = [
        {"name": "metldr.2", "offset": 0x840,
         "container": {"offset": 0x840, "hdr": sealed[:cap.HEADER],
                       "body": sealed[cap.HEADER:],
                       "blocks": len(plain) // 16}},
        {"name": "lv0ldr.2", "offset": 0xFC0000, "container": None},
    ]
    good = triage(readout, records, deep=False)
    rev = triage(readout[16:] + readout[:16], records, deep=False)
    zero = triage(bytes(32), records, deep=True)
    flip = triage(bytes([readout[0] ^ 1]) + readout[1:], records, deep=False)
    # A readout whose words are shuffled per half must still be found by the
    # word pass, and must not be found by the half orders alone.
    words = [readout[4 * i:4 * i + 4] for i in range(8)]
    shuffled = (words[1] + words[0] + words[3] + words[2] +
                words[5] + words[4] + words[7] + words[6])
    shuffled_quick = triage(shuffled, records, deep=False)
    shuffled_deep = triage(shuffled, records, deep=True)

    checks = [
        ("readout opens its container", good[0]["opened_with"] is not None),
        ("verdict names the read order",
         (good[0]["opened_with"] or "").startswith("K_lo||K_hi")),
        ("reversed readout is found and named reversed",
         (rev[0]["opened_with"] or "").startswith("K_hi||K_lo")),
        ("missing container is not invented",
         good[1]["opened_with"] is None and good[1]["blocks"] is None),
        ("zeros are refused by both passes",
         all(r["opened_with"] is None for r in zero)),
        ("a flipped bit is refused", flip[0]["opened_with"] is None),
        ("word shuffle is invisible to the half orders",
         shuffled_quick[0]["opened_with"] is None),
        ("word shuffle is found by the word pass",
         (shuffled_deep[0]["opened_with"] or "").startswith("words ")),
        ("the word pass is 1152 compositions",
         sum(1 for _ in word_orders(readout)) == 1152),
    ]
    for name, ok in checks:
        print("%-46s %s" % (name, "OK" if ok else "FAILED"))
    good_all = all(ok for _n, ok in checks)
    print("selftest: %s" % ("PASS" if good_all else "FAIL"))
    return 0 if good_all else 6


if __name__ == "__main__":
    raise SystemExit(main())
