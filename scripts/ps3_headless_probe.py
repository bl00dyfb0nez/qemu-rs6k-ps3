#!/usr/bin/env python3
"""Probe the console's applications on the rs6000-ps3 model, headless.

The three programs the firmware runs outside a game are `vsh.self`,
`emer_init.self` and `hdd_copy.self`.  Each is an application SELF, each is
started with arguments of its own, and each ends somewhere different: the VSH
parks in its own loop, the emergency program asks the system manager for a
restart, and the exchange utility either asks for the restart that begins its
copy or reports that it found no replacement disk.

The machine's `app=`, `app-args=` and `probe=on` properties exist for exactly
this: the run names the guest path the firmware names, hands the program the
arguments its launcher would, and stops at the first verdict instead of
following a warm reset into the recovery program again.  This tool wraps those
properties, runs the probes one at a time with `-display none`, and prints what
each program is and how its run ended.

    python3 scripts/ps3_headless_probe.py
    python3 scripts/ps3_headless_probe.py --app hdd_copy --keep
    python3 scripts/ps3_headless_probe.py --qemu build-ps3/qemu-system-ppc64

Exit status: 0 every selected probe loaded the application and printed a
verdict, 3 one did not, 2 usage or missing media.  A verdict is not a pass: the
text is the program's own answer, and this tool does not turn "no replacement
hard disk" into a failure of the model.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# The applications, the arguments their launchers pass, and the tick budget.
# vsh.self is started with no arguments; emer_init looks for "-mode=safe"; the
# exchange utility takes "-mode=1" (copy) or "-mode=2" (the other direction).
APPS = {
    # 600 ticks stops inside the VSH's own start-up, before it touches a
    # resource.  The XMB's resource stage - the .rco loader and its zlib
    # streams, then qglbase/raf - begins after that, so the budget is the
    # one ../PS3_MODEL.md uses for the resource runs.  A main thread that
    # takes the 0x700 vector ends the probe early, with that stop named.
    "vsh": ("", 4000),
    "emer_init": ("-mode=safe", 300),
    "hdd_copy": ("-mode=1", 300),
}

SELF_RE = re.compile(
    r"SELF (?P<kind>[a-z0-9 ]+) \(type (?P<type>\d+)\), "
    r"authid (?P<authid>0x[0-9A-Fa-f]+), "
    r"vendor (?P<vendor>0x[0-9A-Fa-f]+), "
    r"version (?P<version>0x[0-9A-Fa-f]+), "
    r"key revision (?P<key>0x[0-9A-Fa-f]+)")
ENTRY_RE = re.compile(
    r"entry (?P<entry>0x[0-9A-Fa-f]+), (?P<segs>\d+) segment\(s\), "
    r"(?P<bytes>0x[0-9A-Fa-f]+) byte")
ARGC_RE = re.compile(r"argc=(?P<argc>\d+), arguments \"(?P<args>[^\"]*)\"")
VERDICT_RE = re.compile(r"verdict (?P<path>[^:]+): (?P<what>.+)$")


def default_flash() -> str:
    """The console's own dump when it is there, the fixture otherwise."""
    real = os.path.expanduser("~/Downloads/CECHL.hex")
    return real if os.path.isfile(real) else ".tmp/bootchain_flash.bin"


def find_qemu(explicit: str | None) -> str | None:
    """The model binary: the caller's, the environment's, a build tree, PATH."""
    candidates = []
    if explicit:
        candidates.append(explicit)
    if os.environ.get("QEMU_PS3"):
        candidates.append(os.environ["QEMU_PS3"])
    for build in ("build-ps3", "build-ps3-gui", "build"):
        for name in ("qemu-system-ppc64", "qemu-system-ppc64.exe"):
            candidates.append(str(Path(build) / name))
    for path in candidates:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            # subprocess in this Python cannot launch a relative .exe path,
            # and the default candidates are relative to the build trees.
            return os.path.abspath(path)
    return shutil.which("qemu-system-ppc64")


def probe(qemu: str, app: str, args: str, ticks: int, flash: str, hdd: str,
          timeout: int, out_dir: Path) -> dict:
    """Run one application under the model and read its verdict back."""
    log = out_dir / f"probe_{app}.log"
    cmd = [
        qemu, "-M", "rs6000-ps3", "-display", "none",
        "-icount", "shift=6,sleep=off",
        "-drive", f"if=pflash,format=raw,file={flash},readonly=on",
        "-global", "ps3-boot-rom.own-rom=on",
        "-global", f"ps3-boot-rom.hdd-file={hdd}",
        "-global", "ps3-boot-rom.probe=on",
        "-global", f"ps3-boot-rom.app={app}",
        "-global", f"ps3-boot-rom.ppu-ticks={ticks}",
    ]
    if args:
        cmd += ["-global", f"ps3-boot-rom.app-args={args}"]

    result = {
        "app": app,
        "log": str(log),
        "cmd": cmd,
        "exit": None,
        "timed_out": False,
        "self": None,
        "entry": None,
        "segments": None,
        "bytes": None,
        "argc": None,
        "arguments": None,
        "verdict": None,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        with open(log, "wb") as fh:
            proc = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT,
                                  timeout=timeout)
        result["exit"] = proc.returncode
    except subprocess.TimeoutExpired:
        result["timed_out"] = True
        result["exit"] = None
    except OSError as exc:
        print(f"{app}: cannot run {qemu}: {exc}", file=sys.stderr)
        return result

    text = log.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        if "ps3-probe" not in line:
            continue
        m = SELF_RE.search(line)
        if m:
            result["self"] = m.groupdict()
            continue
        m = ENTRY_RE.search(line)
        if m:
            result["entry"] = m.group("entry")
            result["segments"] = int(m.group("segs"))
            result["bytes"] = m.group("bytes")
            continue
        m = ARGC_RE.search(line)
        if m:
            result["argc"] = int(m.group("argc"))
            result["arguments"] = m.group("args")
            continue
        m = VERDICT_RE.search(line)
        if m:
            result["verdict"] = m.group("what").strip()
            continue
        if "is not on dev_flash" in line or "could not be read" in line:
            result["verdict"] = line.split("ps3-probe:")[-1].strip()

    return result


def report(results: list[dict]) -> int:
    """One line per application, then the answer: did every probe report?"""
    missing = 0
    print(f"{'app':10} {'self':24} {'entry':10} {'segs':>4} {'bytes':>10} "
          f"{'argc':>4}  verdict")
    for r in results:
        self_desc = "-"
        if r["self"]:
            s = r["self"]
            self_desc = f"{s['kind']}/{s['version']}"
        entry = r["entry"] or "-"
        segs = "" if r["segments"] is None else r["segments"]
        nbytes = r["bytes"] or "-"
        argc = "" if r["argc"] is None else r["argc"]
        verdict = r["verdict"] or "NO VERDICT"
        if not r["verdict"]:
            missing += 1
        print(f"{r['app']:10} {self_desc:24} {entry:10} {segs:>4} {nbytes:>10} "
              f"{argc:>4}  {verdict}")
        if r["timed_out"]:
            print(f"{'':10} timed out after the probe timeout; log {r['log']}",
                  file=sys.stderr)
        elif r["exit"] not in (0, None):
            print(f"{'':10} qemu exited {r['exit']}; log {r['log']}",
                  file=sys.stderr)

    print()
    print(f"{len(results) - missing} of {len(results)} probe(s) reached a "
          f"verdict.")
    return 0 if missing == 0 else 3


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--app", action="append", choices=sorted(APPS),
                    help="probe only this application (repeatable)")
    ap.add_argument("--qemu", help="the model binary (default: a build tree, "
                                   "then PATH)")
    ap.add_argument("--flash", default=default_flash(),
                    help="NOR image the chain and the recovery banks come "
                         "from (default: ~/Downloads/CECHL.hex when present, "
                         "else .tmp/bootchain_flash.bin)")
    ap.add_argument("--hdd", default=".tmp/hdd_fs.img",
                    help="HDD image carrying dev_flash")
    ap.add_argument("--timeout", type=int, default=420,
                    help="seconds per application (default 420)")
    ap.add_argument("--out-dir", default=".tmp",
                    help="where the per-application logs go (default .tmp)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print each command before it runs")
    args = ap.parse_args()

    qemu = find_qemu(args.qemu)
    if not qemu:
        print("ps3_headless_probe: no qemu-system-ppc64 found; pass --qemu or "
              "build one", file=sys.stderr)
        return 2
    for path, what in ((args.flash, "flash"), (args.hdd, "HDD")):
        if not os.path.isfile(path):
            print(f"ps3_headless_probe: {what} image {path} is missing",
                  file=sys.stderr)
            return 2

    out_dir = Path(args.out_dir)
    selected = args.app or list(APPS)
    results = []
    for app in selected:
        app_args, ticks = APPS[app]
        if args.verbose:
            print(f"# {app}: {qemu} ... app={app} app-args={app_args!r} "
                  f"ticks={ticks}", file=sys.stderr)
        results.append(probe(qemu, app, app_args, ticks, args.flash, args.hdd,
                             args.timeout, out_dir))

    return report(results)


if __name__ == "__main__":
    raise SystemExit(main())
