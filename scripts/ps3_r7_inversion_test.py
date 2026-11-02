#!/usr/bin/env python3
"""The r7 -> Kp inversion and the readout rebuild, pinned on fixed vectors.

The r7 route is measured in QEMU by `ps3_rom_handoff_test.py`, and it was
confirmed on real sample containers by the probe the samples shipped with.
Neither can run in CI: one needs a built model and the ROM image, the other
needs third-party sample files.  What both rest on is arithmetic, and that is
what this file pins, with no QEMU, no dump and no ROM:

  * `rk[10] -> Kp`, through the schedule walked backwards, against the
    FIPS-197 known-answer vector (key `000102..0f`, round key 10
    `13111d7f..30c5`) - an outside answer, not this repo's own output - and a
    second key checked as a round trip at every index;
  * `Kp -> rk[10]` forward, and the two shipped schedules agreeing
    (`ps3_capture_verify.expand` and `ps3_rom_handoff_test.expand`), because a
    divergence between them would move the r7 window without failing anything
    that runs today;
  * the readout rebuild: `K_hi` chosen, `K_lo = hdr[0x20] ^ AES_dec(K_hi, Kp)`,
    which must satisfy `kp_from_readout(K_lo, K_hi, hdr[0x20]) == Kp`;
  * a container sealed under that `Kp` opens with the rebuilt readout in both
    half orders, and `ps3_ch66_triage.triage()` - the shipping search - names
    the order it found rather than answering "no";
  * the negatives that matter: `rk[10]` of another key, a single flipped bit in
    `r7`, and a round key offered as if it were `Kp` all have to fail.

The only key in this file is the published FIPS-197 example key; the rest is
derived in the test.  Run it:

    py scripts/ps3_r7_inversion_test.py

Exit codes: 0 every check held, 3 a check failed.
"""
import os
import sys

from Crypto.Cipher import AES

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ps3_capture_verify as cap        # noqa: E402
import ps3_ch66_triage as triage        # noqa: E402
import ps3_rom_handoff_test as handoff  # noqa: E402

# FIPS-197 Appendix A: AES-128, key 000102..0f.  Round key 10 is published, so
# it is an independent answer rather than something this repo computed.
FIPS_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
FIPS_RK10 = bytes.fromhex("13111d7fe3944a17f307a78b4d2b30c5")

# Two more keys, checked as round trips: reversal catches a schedule that is
# "almost" right in a way one vector would not, and the byte-reversed key is the
# one shape a hand-typed vector tends to get wrong.
SECOND_KEY = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
THIRD_KEY = bytes(range(0x10, 0x20))

# The header field the ladder xors the readout into, and a fixed high half.
H20 = bytes(range(0x40, 0x50))
K_HI = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")

failures = 0
checks = 0


def check(name, got, want=True):
    global failures, checks

    checks += 1
    ok = got == want
    print("%-58s %s" % (name, "ok" if ok else "FAIL"))
    if not ok:
        failures += 1
        print("    got  %s" % (got.hex() if isinstance(got, bytes) else got))
        print("    want %s" % (want.hex() if isinstance(want, bytes) else want))


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def ecb_dec(key, block):
    return AES.new(key, AES.MODE_ECB).decrypt(block)


def rebuild_readout(kp, h20, k_hi):
    """The readout whose ladder lands on `kp` for this header field."""
    return xor(h20, ecb_dec(k_hi, kp)) + k_hi


def sealed_dump(kp, blocks=0x10):
    """A buffer with one container at the metldr slot, and its plaintext.

    `blocks` stays at the format's minimum (`container_at` rejects anything
    smaller as not a container), so the fixture is one real header and body.
    """
    hdr = bytearray(cap.HEADER)
    hdr[4:0x10] = bytes(range(0x20, 0x2C))
    hdr[0x14:0x20] = bytes(range(0x30, 0x3C))
    hdr[0x20:0x30] = H20
    plain = bytes(((i * 7 + 3) & 0xFF) for i in range(blocks * 16))
    sealed = cap.seal_container(kp, bytes(hdr), plain)
    dump = bytearray(cap.METLDR_OFF + len(sealed))
    dump[cap.METLDR_OFF:cap.METLDR_OFF + len(sealed)] = sealed
    return bytes(dump), plain


def main():
    # 1. Forward schedules: the published round key, and both implementations.
    check("expand() reaches the FIPS-197 round key 10",
          cap.expand(FIPS_KEY)[10], FIPS_RK10)
    check("ps3_rom_handoff_test.expand reaches it too",
          handoff.expand(FIPS_KEY)[10], FIPS_RK10)
    agree = all(handoff.expand(k) == cap.expand(k)
                for k in (FIPS_KEY, SECOND_KEY, THIRD_KEY, bytes(16)))
    check("the two shipped schedules agree on four keys", agree)

    # 2. The inversion the r7 route uses.
    check("rk[10] inverts to the FIPS-197 key",
          cap.recover_master_key(FIPS_RK10, 10), FIPS_KEY)
    for name, key in (("second", SECOND_KEY), ("third", THIRD_KEY)):
        rks = cap.expand(key)
        check("%s key: rk[10] inverts back to it" % name,
              cap.recover_master_key(rks[10], 10), key)
        check("%s key: every index inverts back to it" % name,
              all(cap.recover_master_key(rks[i], i) == key
                  for i in range(1, 11)))
    check("index 0 is the key itself, not a schedule walk",
          cap.recover_master_key(FIPS_KEY, 0), FIPS_KEY)

    # 3. Negatives: the inversion must not answer for the wrong input.
    check("another key's rk[10] does not invert to the FIPS key",
          cap.recover_master_key(cap.expand(SECOND_KEY)[10], 10) != FIPS_KEY)
    check("a flipped bit in rk[10] does not invert to it",
          cap.recover_master_key(bytes([FIPS_RK10[0] ^ 1]) + FIPS_RK10[1:],
                                 10) != FIPS_KEY)
    check("rk[10] read as Kp is not the key",
          cap.recover_master_key(FIPS_RK10, 0) != FIPS_KEY)

    # 4. The readout rebuild, and the ladder run forwards over it.
    readout = rebuild_readout(FIPS_KEY, H20, K_HI)
    check("rebuilt readout reproduces Kp through kp_from_readout",
          cap.kp_from_readout(readout[:16], readout[16:], H20), FIPS_KEY)
    check("a different K_hi rebuilds a different readout",
          rebuild_readout(FIPS_KEY, H20, bytes(16)) != readout)
    check("rebuilding for the wrong header field misses Kp",
          cap.kp_from_readout(readout[:16], readout[16:], bytes(16))
          != FIPS_KEY)

    # 5. A container sealed under that Kp opens with the rebuilt readout, and
    #    the shipping triage search names the order it found.
    dump, plain = sealed_dump(FIPS_KEY)
    records = cap.dump_records(dump, cap.METLDR_OFF, None)
    found = triage.triage(readout, records, deep=False)
    check("triage opens the container in read order",
          (found[0]["opened_with"] or "").startswith("K_lo||K_hi"))
    rev = triage.triage(readout[16:] + readout[:16], records, deep=False)
    check("triage names a reversed readout as reversed",
          (rev[0]["opened_with"] or "").startswith("K_hi||K_lo"))
    flipped = triage.triage(bytes([readout[0] ^ 1]) + readout[1:], records,
                            deep=False)
    check("triage refuses a one-bit change", flipped[0]["opened_with"] is None)
    check("the sealed body is the plaintext's length",
          len(plain) == records[0]["container"]["blocks"] * 16)

    # 6. The route end to end, arithmetically: ladder -> Kp, r7 -> Kp, equal.
    kp = cap.kp_from_readout(readout[:16], readout[16:], H20)
    rk10 = cap.expand(kp)[10]
    check("readout -> Kp -> rk[10] -> Kp is the same key",
          cap.recover_master_key(rk10, 10), FIPS_KEY)
    check("the r7 of a wrong readout is a different round key",
          cap.expand(cap.kp_from_readout(bytes(16), bytes(16), H20))[10]
          != rk10)

    print("\n%d check(s), %d failed" % (checks, failures))
    return 0 if failures == 0 else 3


if __name__ == "__main__":
    raise SystemExit(main())
