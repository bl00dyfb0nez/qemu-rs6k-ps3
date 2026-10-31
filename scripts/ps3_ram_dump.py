#!/usr/bin/env python3
"""
Dump (or peek at) the guest's RAM while rs6000-ps3 is running.

The model keeps the whole console in one 256 MiB RAM region, and what a run is
doing is usually only visible in that memory: a module's relocated text, the
OPD a call went through, the descriptor a `lvlx` read.  QEMU's own monitor can
write it out (`pmemsave`), so this script drives the monitor over QMP and does
not need a debugger or a patched binary.

Two ways to use it:

    # start the machine, wait, dump RAM, stop
    ps3_ram_dump.py --launch --after 20 -o .tmp/ram.bin

    # or against a machine already started with
    #   -qmp tcp:127.0.0.1:4444,server=on,wait=off
    ps3_ram_dump.py --connect 127.0.0.1:4444 -o .tmp/ram.bin

    # read words straight out of a dump afterwards
    ps3_ram_dump.py --read .tmp/ram.bin --at 0x1FF4634 --count 8

    # disassemble from a dump (needs capstone)
    ps3_ram_dump.py --read .tmp/ram.bin --at 0x1FF4600 --count 40 --disasm

`--launch` starts the machine with the same options the guest boot uses
(dev-flash roots if they are given, vsh-run on), so a dump of a VSH run is one
command.  The dump is the guest's addresses: RAM starts at 0, so the file's
offset is the guest address.
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import time

EXE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "build-ps3", "qemu-system-ppc64.exe")
VERIFY = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "ps3_capture_verify.py")
RAM_SIZE = 0x10000000            # 256 MiB of XDR


class Qmp:
    def __init__(self, host, port, timeout=30):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.buf = b""
        self._read_message()     # greeting
        self.command("qmp_capabilities")

    def _read_message(self):
        while True:
            while b"\n" not in self.buf:
                chunk = self.sock.recv(65536)
                if not chunk:
                    raise SystemExit("QMP closed the connection")
                self.buf += chunk
            line, self.buf = self.buf.split(b"\n", 1)
            if line.strip():
                return json.loads(line)

    def command(self, name, arguments=None):
        self.sock.sendall(json.dumps({"execute": name,
                                      "arguments": arguments or {}}).encode()
                          + b"\n")
        while True:
            msg = self._read_message()
            if "return" in msg:
                return msg["return"]
            if "error" in msg:
                raise SystemExit("QMP %s failed: %s" % (name, msg["error"]))

    def hmp(self, line):
        return self.command("human-monitor-command", {"command-line": line})

    def close(self):
        self.sock.close()


def find_free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def verify_capture(args, refuse=True):
    """Run the capture verifier and return its JSON result, or abort.

    This is the gate: a launch that opens a loader must show a capture that
    authenticates the dump's own records.  The verifier prints no key material;
    this function prints only its PASS/FAIL report.
    """
    if not args.nor or not args.capture:
        raise SystemExit("--nor and --capture are required together")
    cmd = [sys.executable, VERIFY, "--nor", args.nor,
           "--capture", args.capture, "--json"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    info = None
    if res.stdout:
        try:
            info = json.loads(res.stdout)
        except ValueError:
            sys.stderr.write(res.stdout)
    if info is None:
        if res.stderr:
            sys.stderr.write(res.stderr)
        raise SystemExit(res.returncode if res.returncode in (2, 3, 4, 5, 6) else 1)
    dump = info["dump"]
    capture = info["capture"]
    print("dump      %s (%d bytes, %s, sha256 %s)"
          % (dump["name"], dump["size"], dump["medium"], dump["sha256"][:16]))
    print("capture   %s (%d bytes, %s)"
          % (capture["name"], capture["size"], capture["kind"]))
    for rec in info["records"]:
        print("%-9s 0x%06X  %s" % (rec["name"], rec["offset"], rec["status"]))
    if info["eid0"]:
        print("EID0      %s" % info["eid0"]["status"])
    print("verdict   %s" % ("VERIFIED" if info["verified"] else "NOT VERIFIED"))
    if res.returncode:
        if refuse:
            sys.stderr.write("capture did not verify against %s; refusing to start qemu\n"
                             % os.path.basename(args.nor))
        raise SystemExit(res.returncode if res.returncode in (2, 3, 4, 5, 6) else 1)
    return info


def launch(args, port, verified):
    cmd = [EXE, "-M", "rs6000-ps3", "-display", args.display,
           "-qmp", "tcp:127.0.0.1:%d,server=on,wait=off" % port]
    for opt, value in (("dev-flash", args.dev_flash),
                       ("dev-flash2", args.dev_flash2),
                       ("dev-flash3", args.dev_flash3),
                       ("hdd-file", args.hdd_file)):
        if value:
            cmd += ["-global", "ps3-boot-rom.%s=%s" % (opt, value)]
    if verified:
        kind = verified["capture"]["kind"]
        if kind == "readout":
            if verified.get("readout_order") != "K_lo||K_hi":
                print("note: the capture verifies only with its halves reversed; "
                      "not passing it to the model as a readout")
            else:
                prop = ("nand-readout-file"
                        if verified["dump"]["medium"] == "nand"
                        else "readout-file")
                cmd += ["-global", "ps3-boot-rom.%s=%s"
                        % (prop, os.path.abspath(args.capture))]
        elif kind == "erk":
            cmd += ["-global", "ps3-boot-rom.erk-file=%s"
                    % os.path.abspath(args.capture)]
        else:
            print("note: a round key verified, but the model needs a readout "
                  "or ERK to open a container; not passing it to the model")
    if args.vsh_run:
        cmd += ["-global", "ps3-boot-rom.vsh-run=on",
                "-global", "ps3-boot-rom.threads=on"]
    if args.serial:
        cmd += ["-serial", args.serial]
    cmd += args.extra
    print("+ " + " ".join(cmd))
    return subprocess.Popen(cmd, stdout=args.log and open(args.log, "wb")
                            or subprocess.DEVNULL, stderr=subprocess.STDOUT)


def wait_for_qmp(port, deadline):
    while time.time() < deadline:
        try:
            return Qmp("127.0.0.1", port)
        except OSError:
            time.sleep(0.2)
    raise SystemExit("qemu never opened its QMP port")


def dump_ram(qmp, path, base, size):
    if os.path.exists(path):
        raise SystemExit("%s exists; remove it first" % path)
    # pmemsave is in the QMP schema itself (memsave/pmemsave), so this does not
    # need the human monitor, which this build does not expose over QMP.
    qmp.command("pmemsave", {"val": base, "size": size, "filename": path})
    print("%s: %d bytes of guest RAM from 0x%x" %
          (path, os.path.getsize(path), base))


def read_words(path, at, count, disasm):
    data = open(path, "rb").read()
    if at + 4 * count > len(data):
        raise SystemExit("0x%x+0x%x is past the end of the dump (0x%x)" %
                         (at, 4 * count, len(data)))
    if disasm:
        try:
            from capstone import Cs, CS_ARCH_PPC, CS_MODE_64, CS_MODE_BIG_ENDIAN
        except ImportError:
            raise SystemExit("--disasm needs capstone (pip install capstone)")
        md = Cs(CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN)
        for ins in md.disasm(data[at:at + 4 * count], at):
            print("0x%08X %-10s %s" % (ins.address, ins.mnemonic, ins.op_str))
        return
    for i in range(count):
        off = at + 4 * i
        print("0x%08X %08X" % (off, int.from_bytes(data[off:off + 4], "big")))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--output", help="where to write the RAM image")
    ap.add_argument("--read", help="read an existing dump instead of running")
    ap.add_argument("--at", type=lambda s: int(s, 0), default=0,
                    help="guest address to read from (with --read)")
    ap.add_argument("--count", type=lambda s: int(s, 0), default=16,
                    help="words to print, or instructions with --disasm")
    ap.add_argument("--disasm", action="store_true", help="disassemble instead")
    ap.add_argument("--launch", action="store_true",
                    help="start qemu, dump, then stop it")
    ap.add_argument("--connect", help="HOST:PORT of a running -qmp socket")
    ap.add_argument("--after", type=float, default=20.0,
                    help="seconds to let the guest run (--launch)")
    ap.add_argument("--size", type=lambda s: int(s, 0), default=RAM_SIZE,
                    help="bytes to dump, default the whole 256 MiB")
    ap.add_argument("--base", type=lambda s: int(s, 0), default=0,
                    help="guest address to start the dump at")
    ap.add_argument("--display", default="none")
    ap.add_argument("--serial", help="chardev for the guest console, "
                                     "e.g. file:.tmp/uart.txt")
    ap.add_argument("--log", help="capture qemu's own log here (--launch)")
    ap.add_argument("--dev-flash")
    ap.add_argument("--dev-flash2")
    ap.add_argument("--dev-flash3")
    ap.add_argument("--hdd-file")
    ap.add_argument("--nor", help="NOR or NAND/eMMC dump with the loader records")
    ap.add_argument("--capture", help="16/32/48-byte key capture to verify")
    ap.add_argument("--verify-only", action="store_true",
                    help="verify --nor/--capture and exit without starting qemu")
    ap.add_argument("--allow-unverified", action="store_true",
                    help="launch without requiring a verified --nor/--capture; "
                         "only for runs that do not open a loader")
    ap.add_argument("--vsh-run", action="store_true", default=True)
    ap.add_argument("--no-vsh-run", dest="vsh_run", action="store_false")
    ap.add_argument("extra", nargs=argparse.REMAINDER,
                    help="further qemu arguments (after --)")
    args = ap.parse_args(argv)

    if args.read:
        read_words(args.read, args.at, args.count, args.disasm)
        return 0

    if args.verify_only:
        if not args.nor or not args.capture:
            raise SystemExit("--verify-only needs --nor and --capture")
        verify_capture(args, refuse=False)
        return 0

    if not args.output:
        raise SystemExit("pass -o/--output (or --read for an existing dump)")

    if args.connect:
        host, _, port = args.connect.partition(":")
        qmp = Qmp(host or "127.0.0.1", int(port))
        dump_ram(qmp, args.output, args.base, args.size)
        qmp.close()
        return 0

    if not args.launch:
        raise SystemExit("pass --launch or --connect")

    if args.launch and not args.allow_unverified:
        if not args.nor or not args.capture:
            raise SystemExit(
                "--launch requires --nor and --capture: the model must open a "
                "loader with a capture that authenticates that dump.  Use "
                "--allow-unverified only for a run that does not open one.")
        verified = verify_capture(args)
    elif args.nor or args.capture:
        if not (args.nor and args.capture):
            raise SystemExit("pass both --nor and --capture, or neither")
        verified = verify_capture(args)
    else:
        verified = None

    port = find_free_port()
    proc = launch(args, port, verified)
    try:
        qmp = wait_for_qmp(port, time.time() + 30)
        print("guest running; dumping after %.1f s" % args.after)
        time.sleep(args.after)
        dump_ram(qmp, args.output, args.base, args.size)
        qmp.command("quit")
        qmp.close()
    finally:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
