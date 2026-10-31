#!/usr/bin/env python3
"""The sweep's channel-map parsing and exit contract, with no QEMU.

`ps3_romexec_sweep.py` is mostly a runner, but the part that decides whether a
sweep passed can be checked without a machine: the two `ps3-spu: channels:`
lines the model prints, the flag built from them, and `exit_status()`.  Those
are the pieces a model change can break silently, and they are also where the
sweep's one real bug lived - `PAYLOAD_DONE` used to be `ps3-spu: `, so the map
line printed before a payload matched it and the sample payloads were killed at
the ROM verdict.  That regex is pinned here too.

This file imports the tool and feeds it log text; it never starts QEMU, never
touches a dump and needs no key material.

    py scripts/ps3_romexec_sweep_test.py

Exit codes: 0 every check held, 3 a check failed.
"""
import os
import struct
import sys

try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ps3_romexec_sweep as sweep   # noqa: E402

INFO = "qemu-system-ppc64.exe: info: "

MAP13 = INFO + ("ps3-spu: channels: 34 of 128 modelled, 13 touched "
                "(0x03,0x04,0x0D,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,"
                "0x18,0x42)")
MAP15 = INFO + ("ps3-spu: channels: 34 of 128 modelled, 15 touched "
                "(0x03,0x04,0x0D,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,"
                "0x18,0x1D,0x40,0x42)")
FLAG = INFO + ("ps3-spu: channels: 2 channel(s) with an access the model does "
               "not define: 0x2E reserved x3; 0x40 loader command out x1")
STAGE = INFO + ("ps3-spu-stage: stage.elf entry=0x400 segments=1 bytes=64 "
                "steps=9 result=stop stop=0 :: stop 0 at 0x420")

failures = 0
checks = 0


def seal_container(kp, hdr, plain):
    """Seal a container the way the format says, for the matrix checks.

    Independent of `sweep.container_crypt` on purpose: the tag is computed
    here from the spec (CTR counting down from N, CBC-MAC over the three
    header blocks and the plaintext, whitened by S0) so a round trip is a
    check on the reader and not a restatement of it.
    """
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


def check(name, got, want):
    global failures, checks

    checks += 1
    ok = got == want
    print("%-58s %s" % (name, "ok" if ok else "FAIL"))
    if not ok:
        failures += 1
        print("    got  %r" % (got,))
        print("    want %r" % (want,))


def main():
    # A clean map: every field, and the touched set in the order printed.
    ch = sweep.channel_map(MAP13)
    check("clean map parses",
          (ch["modelled"], ch["total"], ch["touched_count"]),
          (34, 128, 13))
    check("touched set keeps its order",
          ch["touched"], ["0x03", "0x04", "0x0D", "0x10", "0x11", "0x12",
                          "0x13", "0x14", "0x15", "0x16", "0x17", "0x18",
                          "0x42"])
    check("clean map has no undefined access",
          (ch["undefined"], ch["clean"], sweep.channel_flag(ch)),
          ([], True, None))
    check("clean row note is the count",
          sweep.channel_note({"channels": ch, "channel_flag": None}),
          "  ch 13")

    # The undefined line on its own: two entries, one with spaces in its name.
    ch = sweep.channel_map(FLAG)
    check("undefined line is not mistaken for a map",
          (ch["modelled"], ch["touched"], ch["touched_count"]), (0, [], 0))
    check("undefined entries parse",
          ch["undefined"],
          [{"channel": "0x2E", "name": "reserved", "hits": 3},
           {"channel": "0x40", "name": "loader command out", "hits": 1}])
    check("undefined line is not clean",
          (ch["clean"], sweep.channel_flag(ch)),
          (False, "0x2E reserved x3; 0x40 loader command out x1"))
    check("flagged row note carries the flag",
          sweep.channel_note({"channels": ch, "channel_flag":
                              sweep.channel_flag(ch)}),
          "  ! ch 0, undefined 0x2E reserved x3; 0x40 loader command out x1")

    # The model prints the map twice on a payload run; the last one wins.
    ch = sweep.channel_map(MAP13 + "\n" + MAP15 + "\n" + FLAG)
    check("the last map a run printed is the one used",
          (ch["touched_count"], ch["touched"][-1]), (15, "0x42"))
    check("a later undefined line still flags the row",
          sweep.channel_flag(ch),
          "0x2E reserved x3; 0x40 loader command out x1")

    # Shapes the model can print: zero touched (no parentheses), lowercase hex,
    # spaces after the commas.
    ch = sweep.channel_map(INFO + "ps3-spu: channels: 34 of 128 modelled, "
                                  "0 touched")
    check("zero touched parses", (ch["touched"], ch["touched_count"],
                                  ch["clean"]), ([], 0, True))
    ch = sweep.channel_map(INFO + "ps3-spu: channels: 34 of 128 modelled, "
                                  "2 touched (0x0a, 0x2e)")
    check("lowercase and spaces normalise", ch["touched"], ["0x0A", "0x2E"])
    check("no map line gives no record", sweep.channel_map(STAGE), None)
    check("a row with no map has an empty note",
          sweep.channel_note({"channels": None, "channel_flag": None}), "")

    # The exit contract: 3 on either kind of failure, 0 otherwise.
    clean = {"channels": {"clean": True}, "channel_flag": None}
    flagged = {"channels": {"clean": False},
               "channel_flag": "0x2E reserved x3"}
    control = {"channels": None, "channel_flag": None}
    sample_fail = {"name": "4th sample metldr.2"}
    check("clean rows exit 0", sweep.exit_status([clean, control], []), 0)
    check("no rows exit 0", sweep.exit_status([], []), 0)
    check("a flagged row exits 3", sweep.exit_status([clean, flagged], []), 3)
    check("a failed sample exits 3", sweep.exit_status([clean], [sample_fail]),
          3)
    check("both failures still exit 3",
          sweep.exit_status([flagged], [sample_fail]), 3)

    # The default run must not use a mask ROM at all - that is what lets the
    # sweep run on a checkout with no Sony image.  --rom-exec is the only path
    # that supplies one, and it has to turn own-rom off because the model
    # refuses a run that claims both.
    plain = sweep.boot_args("dump.bin", 0x840, "metldr.2", None,
                            "cap.bin", "ls.bin", False)
    check("the default run passes no mask ROM", "-bios" in plain, False)
    check("the default run says the opener is built in",
          "ps3-boot-rom.own-rom=on" in plain, True)
    check("the default run does not ask for rom-exec",
          "ps3-boot-rom.rom-exec=on" in plain, False)

    dev = sweep.boot_args("dump.bin", 0x840, "metldr.2", None,
                          "cap.bin", "ls.bin", True)
    check("--rom-exec supplies the mask ROM",
          dev[dev.index("-bios") + 1], sweep.ROM)
    check("--rom-exec turns own-rom off",
          "ps3-boot-rom.own-rom=off" in dev, True)
    check("--rom-exec replays the ROM",
          "ps3-boot-rom.rom-exec=on" in dev, True)

    # A built-in run has to end on the model's own status line, and a
    # mask-ROM verdict must not be mistaken for it.
    check("the built-in verdict ends a verified built-in run",
          bool(sweep.BUILTIN_VERDICT.search(
              INFO + "ps3-boot-rom: container verified, 63712 bytes of "
                     "payload")), True)
    check("the built-in verdict also matches a stop",
          bool(sweep.BUILTIN_VERDICT.search(
              INFO + "ps3-boot-rom: stop 2, MAC mismatch (metldr.2 at flash "
                     "0x840)")), True)
    check("a mask-ROM verdict does not end a built-in run",
          bool(sweep.BUILTIN_VERDICT.search(
              INFO + "the mask ROM did not open the container (stop 2)")),
          False)

    # The round-key route: rk10 is what a console's local store keeps, and the
    # sweep has to recover Kp from it with nothing else.  FIPS-197's AES-128
    # vector pins the schedule in both directions (key -> rk10 -> key).
    fips_key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    fips_rk10 = bytes.fromhex("d014f9a8c9ee2589e13f0cc8b6630ca6")
    check("the schedule builds FIPS-197 rk10",
          sweep.aes_expand(fips_key)[10].hex(), fips_rk10.hex())
    check("rk10 inverts to the FIPS-197 key",
          sweep.aes_invert(fips_rk10).hex(), fips_key.hex())
    check("a round key round-trips",
          sweep.aes_expand(
              sweep.aes_invert(bytes(range(16))))[10], bytes(range(16)))
    check("a short value is not a round key", sweep.aes_invert(b"\0" * 15),
          None)

    # The sample tool publishes each container as name, Kp, N, then the round
    # key in parentheses.  The parser must pick that entry's key and no other.
    import tempfile
    tmp = tempfile.mkdtemp(prefix="ps3sweep")
    tool = os.path.join(tmp, "decrypt_loader.py")
    with open(tool, "w") as f:
        f.write("    KEYS\n"
                "        machine AAAA\n"
                "            metldr.2   11111111111111111111111111111111  "
                "N=0x0001\n"
                "                       (rk10 %s)\n"
                "            lv0ldr.2   22222222222222222222222222222222  "
                "N=0x0002\n"
                "                       (rk10 %s)\n"
                % ("33" * 16, "44" * 16))
    check("the tool's rk10 is read for metldr",
          sweep.rk10_from_tool(tool, "metldr.2").hex(), "33" * 16)
    check("the tool's rk10 is read for lv0ldr",
          sweep.rk10_from_tool(tool, "lv0ldr.2").hex(), "44" * 16)
    check("a container with no entry has no rk10",
          sweep.rk10_from_tool(tool, "appldr.2"), None)

    keyfile = os.path.join(tmp, "metldr_key.txt")
    with open(keyfile, "w") as f:
        f.write("5a" * 16 + "\n")
    kp, route, source = sweep.sample_key({"route": "kp", "key": keyfile})
    check("the Kp route reads the key file",
          (kp.hex(), route), ("5a" * 16, "Kp"))
    kp, route, why = sweep.sample_key({"route": "rk10", "rk10_from": tool,
                                       "container": "metldr.2"})
    check("the rk10 route recovers a Kp",
          (route, kp == sweep.aes_invert(bytes.fromhex("33" * 16))),
          ("rk10 -> Kp", True))
    kp, route, why = sweep.sample_key({"route": "rk10", "rk10_from": tool,
                                       "container": "appldr.2"})
    check("a missing round key is reported, not guessed",
          (kp, "rk10" in (why or "")), (None, True))

    # The match matrix's primitive: a readout goes through the ladder to Kp,
    # decrypts the body and has to reproduce the tag.  A container sealed here
    # from the spec must open from its own readout and from nothing else.
    if AES is None:
        check("the key-match check has pycryptodome", False, True)
    else:
        kp = bytes(range(16, 32))
        k_hi = bytes(range(0x40, 0x50))
        hdr = bytearray(0x40)
        hdr[0x00:0x04] = (3).to_bytes(4, "big")
        hdr[0x04:0x10] = bytes(range(0x10, 0x1C))
        hdr[0x10:0x14] = (3).to_bytes(4, "big")
        hdr[0x20:0x30] = bytes(range(0x20, 0x30))
        plain = bytes((i * 7 + 3) & 0xFF for i in range(48))
        sealed, body = seal_container(kp, bytes(hdr), plain)
        k_lo = bytes(a ^ b for a, b in zip(
            sealed[0x20:0x30], AES.new(k_hi, AES.MODE_ECB).decrypt(kp)))
        ro = k_lo + k_hi
        check("a sealed container opens from its readout",
              sweep.container_crypt(sealed, body, ro), True)
        check("... and refuses a bit-flipped readout",
              sweep.container_crypt(sealed, body,
                                    ro[:31] + bytes([ro[31] ^ 1])), False)
        check("... and refuses the console-less zeros",
              sweep.container_crypt(sealed, body, bytes(32)), False)
        check("... and refuses a short readout",
              sweep.container_crypt(sealed, body, ro[:16]), False)

    # The wait must not end on the map line: that is what cut the sample
    # payloads off at the ROM verdict before the fix.
    check("channel map does not end the payload wait",
          bool(sweep.PAYLOAD_DONE.search(MAP13)),
          False)
    check("undefined-channel line does not end the payload wait",
          bool(sweep.PAYLOAD_DONE.search(FLAG)),
          False)
    check("a payload stop ends the payload wait",
          bool(sweep.PAYLOAD_DONE.search(INFO + "ps3-spu: stop 21 at 0x490")),
          True)
    check("a payload limit ends the payload wait",
          bool(sweep.PAYLOAD_DONE.search(
              INFO + "ps3-spu: instruction limit (67108864) at 0x20058")),
          True)
    check("the stage line is not what the sweep waits for",
          bool(sweep.PAYLOAD_DONE.search(STAGE)), False)
    check("a verified container ends the payload wait",
          bool(sweep.PAYLOAD_DONE.search("container verified, 63712 bytes "
                                         "of payload")), True)
    check("a blocking stage ends the payload wait",
          bool(sweep.PAYLOAD_DONE.search(
              INFO + "ps3-spu: blocked on a channel at 0x424")), True)

    # The whole contract from log text: parse, flag, exit.
    log = MAP13 + "\n" + FLAG + "\n" + STAGE
    ch = sweep.channel_map(log)
    rec = {"channels": ch, "channel_flag": sweep.channel_flag(ch)}
    check("a flagged run's log exits 3", sweep.exit_status([rec], []), 3)
    check("its touched set is still the ROM's",
          (rec["channels"]["touched_count"], rec["channels"]["clean"]),
          (13, False))

    print("\n%d check(s), %d failed" % (checks, failures))
    return 0 if failures == 0 else 3


if __name__ == "__main__":
    raise SystemExit(main())
