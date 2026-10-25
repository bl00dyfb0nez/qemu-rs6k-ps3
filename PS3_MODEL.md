# PS3 / Cell model in this tree

This checkout carries a local research model of the PS3 boot path: the Cell
memory interface controller, the SPU mask ROM and its container opener, the
SPU interpreter the decrypted loader runs on, and a SELF opener for the later
loader stages. It is an experiment, not an upstream contribution - see
`AGENTS.md` and `docs/devel/code-provenance.rst`.

Nothing here is needed to build or use the rest of QEMU.

# Credits

> I do not take any credit it will be stated in the PS3_MODEL.md.
>
> - bl00dyb0nes

- RPCS3 Team
- zecoxao
- wildcard
- ZeroTolerance
- jestero
- MikeM64
- DJ
- flat_z
- Mina Ralwasser
- sagemono
- Kafuu
- esc0rtd3w
- naehrwert
- mysis
- skgleba
- xorloser
- Myria
- bguerville
- Proxima
- golden
- bguerville
- and last but not least... Anonymous

## Files

| Path | Contents |
| --- | --- |
| `hw/ppc/rs6000_ps3.c` | machine `rs6000-ps3`, `ps3-mic` (MIC MMIO), `ps3-boot-rom` (mask ROM, 256 KiB local store, container opener, register window) |
| `hw/ppc/ps3_spu.c`, `ps3_spu.h` | SPU interpreter, channels, MFC transfers |
| `hw/ppc/ps3_spu_isa.h` | instruction tables used by the interpreter |
| `hw/ppc/ps3_self.c`, `ps3_self.h` | SELF opener used by stage runs (ERK/RIV key ladder, CTR sections) |
| `hw/ppc/Kconfig`, `hw/ppc/meson.build` | wiring; gated on `CONFIG_PS3` |

## Build

### Windows (MSYS2, UCRT64)

Packages, once:

```sh
pacman -S --needed mingw-w64-ucrt-x86_64-{gcc,ninja,pkgconf,glib2,pixman,python}
```

Configure and build from a UCRT64 shell:

```sh
cd ~/qemu
mkdir -p build-ps3 && cd build-ps3
../configure --target-list=ppc64-softmmu \
    --without-default-features --enable-tcg --disable-werror --disable-docs
ninja
```

The first `configure` creates a Python venv under `build-ps3/pyvenv` and
installs meson into it, so it needs network access once. The result is
`build-ps3/qemu-system-ppc64.exe`.

Incremental rebuild after editing sources:

```sh
ninja -C build-ps3
```

`ninja` re-runs `configure` itself when `configure`/`meson_options.txt`
change. After editing a `Kconfig` file, or if a build option changed, re-run
the `../configure` command above inside `build-ps3`.

### Linux / other hosts

Same commands with the distribution's packages (`gcc`, `ninja-build`,
`pkg-config`, `glib2-devel`, `pixman-devel`, `python3-venv`):

```sh
mkdir -p build-ps3 && cd build-ps3
../configure --target-list=ppc64-softmmu \
    --without-default-features --enable-tcg --disable-werror --disable-docs
ninja
```

Only `ppc64-softmmu` is built; the PS3 machine is registered there.
`build*/` is ignored by git.

## Run

The Windows binary links the MSYS2 DLLs, so from outside an MSYS2 shell put
`ucrt64\bin` on `PATH` first:

```sh
PATH="/c/msys64/ucrt64/bin:$PATH" ./build-ps3/qemu-system-ppc64.exe ...
```

Open a boot container with the console's channel-66 readout:

```sh
./build-ps3/qemu-system-ppc64.exe -M rs6000-ps3 \
    -bios rom.bin \
    -drive if=pflash,format=raw,file=CECH4301C.bin,readonly=on \
    -global ps3-boot-rom.readout-file=ch66.bin \
    -nographic
```

There is no guest firmware after the ROM returns: the PPU reset vector is a
`b .`, and all boot work happens in `ps3-boot-rom` during reset. Pass
`-display none -qtest stdio` for scripted inspection, or stop the run with
Ctrl-A x.

### `ps3-boot-rom` properties

| Property | Default | Meaning |
| --- | --- | --- |
| `rom-file` | - | 1 KiB SPU mask ROM (set by `-bios`) |
| `drive` | - | flash image (set by `-drive if=pflash,...`) |
| `container` | `lv0ldr.2` | container to look for; falls back to the NOR slots at flash `0xFC0000` and `0x840` |
| `readout` | - | 32-byte channel-66 key as 64 hex digits |
| `readout-file` | - | same key, raw 32 bytes in ROM read order (K_lo, then K_hi) |
| `selftest` | on | device selftest at reset |
| `spu` | on | execute the decrypted payload on the SPU interpreter |
| `spu-trace` | off | one log line per SPU instruction |
| `ls-dump` | - | write the local store after the run (256 KiB + `0x4000` trailer) |
| `stage-elf` | - | load this SELF/ELF into local storage, run it, exit |
| `stage-entry` | 0 | override the entry address for `stage-elf` |
| `stage-limit` | `1<<22` | instruction budget for `stage-elf` |
| `ppu-elf` | - | 64-bit PPU SELF/ELF (lv0 and above), loaded into RAM before reset |
| `ppu-entry` | 0 | entry override for `ppu-elf` (lv0's loader entry is `0xC40`) |
| `ppu-dump` | - | open `ppu-elf` and write the decrypted container out, then exit |
| `ppu-ticks` | 0 | stop after this many `ppu-tick-ns` periods (0 keeps running) |
| `ppu-tick-ns` | `10000000` | period between PPU progress reports |
| `ppu-trace` | off | log PC/LR/MSR each period and the first console reads |
| `pad-count` | 1 | gamepad ports the console has, 1..7 |
| `pad-types` | `standard` | product in each port, comma separated (`standard`, `guitar`, `guitar-rb`, `drums`, `drums-rb`, `drums-rb3`, `drums-rr`, `dj`, `dancemat`, `navigation`, `skateboard`); one name applies to every port |
| `flash-base` | `0x20000000` | window the flash image is mapped at |

Without a readout the device feeds channel 66 32 zero bytes, which is what the
channel returns once metldr is loaded, and the container fails its tag check.

### Where to look

| Address | Window |
| --- | --- |
| `0xF050A000` | `ps3-mic` registers |
| `0xF1000000` | 256 KiB local store; a decrypted payload lands at `0xF1000400` |
| `0xF1040000` | `ps3-boot-rom` registers |
| `0xFFF00000` | PPU reset vector window |
| `0x20000000` | flash image |

Boot ROM registers: `0x00` status (0 idle, 1 verified, 2 bad header,
3 bad MAC, 4 no container, 5 bad ROM), `0x04` blocks from the header,
`0x08` payload bytes, `0x0C` selftest result (0 not run, 1 passed, 2 failed),
`0x10` container offset (write 1 to boot, 2 to re-run the selftest),
`0x20..0x2F` the effective key.

## Checks

At reset with `-bios`, the device runs its own selftest before booting and
prints:

```
ps3-boot-rom: selftest passed (AES-128 KAT, sealed container round trip, mask ROM replayed by the SPU interpreter)
```

It covers the AES-128 known answer, a sealed-container round trip and a replay
of the real mask ROM through the interpreter, so a broken instruction semantic
shows up there instead of as a plausible-looking boot. Register `0x0C` reads 1
when it passed.

Structural check of a loader stage (a SELF or a decrypted SPU ELF) on the same
interpreter:

```sh
./build-ps3/qemu-system-ppc64.exe -M rs6000-ps3 -display none \
    -global ps3-boot-rom.stage-elf=lv2ldr.self \
    -global ps3-boot-rom.stage-limit=200000
echo $?
```

Exit status: 0 stopped at a `stop` instruction (or reached the instruction
limit), 1 faulted, 2 could not be loaded (not a SELF/ELF, unreadable, or a
segment does not fit local storage). The run prints

```
ps3-spu-stage: <file> entry=0x12C00 segments=3 steps=450 result=stop stop=48 :: stop 48 at 0x13D8C after 450 instructions
```

`stop` is decimal; 48 is the loaders' signal 0x30. A stage run needs no
`-bios` and prints `no -bios image; the mask ROM is blank` because of it.

A loader that has been unselfed already is detected by its section content and
loaded as-is; a still-sealed SELF goes through the key ladder in `ps3_self.c`.

### The PPU stage: lv0 and above

`lv0` is 64-bit PowerPC, not SPU code, so it runs on the 970FX core rather than
on the SPU interpreter.  `ppu-elf` accepts either a plain 64-bit big-endian ELF
or the sealed SELF it is delivered in; the SELF is opened with the same loader
keysets `ps3_self.c` uses for the SPU stages.  The image is placed in RAM before
the machine reset, and the PPU is entered from the reset handler, so the SPU
half of the first stage has already run when the core starts.

lv0's ELF header names `0xC60`, but that address is in the zero-filled first
segment.  The real loader entry is `0xC40`, which sets up the stack and TOC:

```
0xC40  lis  r1, 0xBFF        r1 = 0xBFFFFF80
0xC44  ori  r1, r1, 0xFF80
0xC48  lis  r2, 0x080C       r2 = 0x080CDDE0 (TOC)
0xC4C  ori  r2, r2, 0xDDE0
0xC50  lis  r3, 0x0800
0xC54  ori  r3, r3, 0
0xC58  mtlr r3
0xC5C  blrl                  -> 0x08000000
```

Run it with:

```sh
./build-ps3/qemu-system-ppc64.exe -M rs6000-ps3 -display none \
    -global ps3-boot-rom.ppu-elf=lv0.self \
    -global ps3-boot-rom.ppu-entry=0xc40 \
    -global ps3-boot-rom.ppu-ticks=5
```

Observed with the 4.93 lv0 carve: two segments (0x0/0xC70 and
0x8000000/0xCBD50), entry `0xC40`, and the loader runs through its early setup
to `0x800CCB4`, the console path.  lv0 prints
`send_and_receive: write_init_msg fail -8` and loops at `0x800C5C0`: that is
lv0 talking to the System Controller over its virtual UART, which this model
only acknowledges (status word `0x100`, data at `0xFFF31C`) and does not answer
with a syscon reply.  The PPU is therefore running the real hypervisor code up
to its first hardware handshake, not failing on an unimplemented PPC opcode.

`ppu-dump` is the extraction half of the same path:

```sh
./build-ps3/qemu-system-ppc64.exe -M rs6000-ps3 -display none \
    -global ps3-boot-rom.ppu-elf=lv0.self \
    -global ps3-boot-rom.ppu-dump=lv0.dec
```

It opens the SELF, writes the full decrypted container and exits 0.  The ELF at
`0x90` then has real PowerPC segments; load it in IDA at `0x8000000` with the
PPC64 loader.

### lv0.2 is metadata, not a runnable stage

The CoreOS image also carries `lv0.2`, a 0x500-byte SELF header and metadata
record (1280 bytes, MD5 `b0c6e3ea17ee81a05fa173dca0590cd0` in the 4.93 PUP).
It is present only on the newer hardware revisions (late CECH-25xx, CECH-3xxx
and CECH-4xxx), where the revised lv0ldr.1 loads it so bootldr can check lv0's
signature with the non-vulnerable key.  Its section table points into lv0's
body, so it is not a program and has no entry point.  First-generation and
2xxx consoles do not carry it and keep the original sigfail path.  Do not pass it to
`ppu-elf`: the opener rejects it with

```
ps3-ppu: .../lv0.2: section 0 (0x10500/0xC70) runs past the file
```

This is also why `lv0.2` is not one of the `.2` loaders: `lv1ldr.2`,
`lv2ldr.2`, `appldr.2` and `isoldr.2` are sealed SPU SELFs, `metldr.2` and
`bootldr.2` (lv0ldr.2) are separate containers, and `lv0.2` is only the
signed record of lv0.  Older consoles without lv0.2 keep the original sigfail
path.

### metldr.2 opens, and what is inside it

A superslim `metldr.2` from the console's own flash opens with the channel-66
readout this tree already carries (PCK0), no other key:

| Container field | Value |
| --- | --- |
| sealed image | 63,776 bytes, MD5 `f317cf234ae6c0be803164d6d9fbc511`; header length field `0x00000F8E` |
| per-image key field | `953034B3CC0E4DA463D528B3` at `0x14` |
| key | the channel-66 readout mixed with that field (the sample tool's `Kp` derivation), *not* a static ERK/RIV pair |
| body | 63,712 bytes, MD5 `a0995a4a00d9f0a6566752ad4b286c5b`, `metldr.dec` next to the sample |

The result is not a SELF or an ELF: it is the loader's flat SPU image, linked
at LS `0x400`.  Decoding it as SPU code shows the shape of the stage:

* `0x400` is `ila $14, 0x6D0; bi $14` - the real entry is `0x6D0`.
* `0x6D0` sets the stack (`ila $2, 0x3DFA0`, so `r1` ends just below 256 KiB),
  saves the nine arguments in `r81..r89`, then walks the list at `0xFCC4`
  downwards, calling every entry until the `0xFFFFFFFF` sentinel: here `0x36D8`
  then `0x2738`, through `bisl $0,$3`.
* `0x410` is a second entry: a stage dispatcher.  It reads the byte at LS
  `0x8C`, subtracts `0x1E`, bounds-checks it against 6 and indexes a jump
  table at `0x43C` (`0x480`, `0x460`, `0x468`, `0x478`, `0x470`, `0x458`,
  `0x488`); each arm is a `stop` with its own signal (`0x1E`..`0x24` in
  selector order, `0x15` for an out-of-range one), so the hypervisor drives
  the stage by writing a command byte and reading the stop code back.
* the text decodes continuously `0x400..0xD6CC`; 383 `brsl` sites reach 143
  distinct functions, hottest `0xB5B8` (31 calls), `0x9108` (28), `0x8D90`
  (11), `0x8D48` and `0x8DF8` (10 each).
* `0xE460..0xFCA0` is 6,208 bytes at entropy 7.9 with 2% zeros - data, not
  code, and the stage's only high-entropy region.
* three sentinel-terminated pointer runs close the image: `0xFCB4`
  (`0x780`, `0x1B00`, `0x1C20`), `0xFCC0` (`0x2738`, `0x36D8`) and `0xFCCC`
  (`0x1AF0`, `0x1C10`, `0x2748`).

The 4301C NOR's `metldr` at `0x840` is a *different* image (63,920 bytes against
63,776 here), so a decryption of one says nothing about the other's bytes; both
open with the same kind of container, and this is the one from the second
sample's flash.

### Superslim keys: PCK0 and PCK1 are different keys

The superslim (CECH-4xxx) chain uses two per-console keys, and they are not
interchangeable:

| Key | Where it lives | What it opens |
| --- | --- | --- |
| PCK0 (`per_console_root_key_0`) | the channel-66 efuse readout (already in this tree as the ROM readout) | `metldr` / `metldr.2` and `bootldr` / `lv0ldr.2`, i.e. the sealed `.2` stage containers |
| PCK1 (`per_console_root_key_1`, `EID_root_key`) - the console's EID root key 1 | derived from PCK0, held inside `metldr`, copied to HDD sector 0 by `metldr`, cleared by `isoldr` | part of the EID, and it is the root for the further per-console keys |
| PCK2 (`per_console_root_key_2`, `EID0_key`) | AES-256-CBC over the EID0 seed with `isoldr`'s key and RIV, algorithm inside `isoldr` | the EID0 store |

So the channel-66 readout this model already carries is PCK0 and stops at the
`.2` loaders.  PCK1 is not a second efuse: it is *derived from PCK0* by
`metldr`, which is why the chain can be continued from the readout already in
the tree instead of needing a dump - the derivation and the `sector 0` copy are
what a superslim run has to model next.  PCK1 only exists between `metldr` and
`isoldr` (a patched `isoldr` is the usual way to dump it), and `isoldr` clearing
it is the reason EID0 work has to be gated on that stage not having run.  From
PCK1 come PCK2 and the rest of the per-console keys (naehrwert's
`ps3_decrypt_tools`), and the system controller side - cVTRM's SRK/SRH, with
AES-CBC-128 from an encrypted key table in Syscon, or AES-XTS-128 with keys
from the EID root key and Syscon seeds - hangs off the same root.

Key names and provenance here follow `docs/PCK.txt` in the ps3tools tree.

### The application stage: vsh.self

`appldr` is the last loader: it opens `/dev_flash/vsh/module/vsh.self` and
hands it to lv2, which creates the VSH process.  This model now does the
container and ELF work itself, so the application image can be brought up on
the PPU without lv2's process manager:

* the SELF metadata is opened with the application keyset (revision 0x1C is
  built in, and `vsh-erk` / `vsh-riv` accept any other pair as 64/32 hex
  digits);
* each `PT_LOAD` section is taken from its metadata descriptor, zlib-expanded
  when `compressed == 2`, and placed at its physical address;
* `e_entry` is treated as an OPD descriptor, so the PPU starts at its first
  word with `r2` loaded from its second word (the TOC).  The VSH's first
  instructions at `0x10230` are the usual `lis/ori/lwz` TOC setup, which
  confirms the descriptor.

`vsh-self` names the image, or `dev-flash` / `dev-flash3` name a firmware
root and the loader looks for `vsh/module/vsh.self` there:

```sh
Q=build-ps3/qemu-system-ppc64.exe
$Q -M rs6000-ps3 -display none \
   -global ps3-boot-rom.dev-flash=C:/rpcs3/build/bin/dev_flash \
   -global ps3-boot-rom.vsh-dump=vsh.dec
```

Without `vsh-run` this is load-only: the segments are mapped and the command
exits 0, which is the check that the application keyset, the zlib sections and
the addresses are right.  With `vsh-run=on` the PPU enters the VSH for a real
LLE run:

```sh
$Q -M rs6000-ps3 -display none \
   -global ps3-boot-rom.dev-flash=C:/rpcs3/build/bin/dev_flash \
   -global ps3-boot-rom.vsh-run=on \
   -global ps3-boot-rom.ppu-ticks=8 -global ps3-boot-rom.ppu-tick-ns=1000000 \
   -global ps3-boot-rom.ppu-trace=on
```

Observed with the 4.93 `vsh.self` (3,154,016 bytes): two segments,
`0x10000+0x6ABEA8` and `0x6C0000+0x91548`, both zlib.  The ELF entry is
`0x6D5AC8`; its OPD gives code `0x10230` and TOC `0x6F5558`.  The guest runs
from `_start` through its C runtime setup; the first lv2 call is
`sys_mutex_create` at `0x10390`.  The core is entered with MSR[FP] and
MSR[VR] set, because lv2 enables both for a user process - without them the
VSH's first float operation takes the `0x800` vector instead of running.

### The lv2 layer `vsh-run` answers

A bare 970FX has no handler at the `0xC00` vector and cannot trap `sc` itself,
so `vsh-run` installs a trampoline there.  It does not try to be a kernel in
guest code: it publishes the call number (r11) to the board's register window
at `0xF1040014` and waits for a result block at RAM `0x880`.  The C side
(`ps3_lv2_service`) reads the arguments straight out of the live GPRs, runs the
call, and leaves `r3` plus an exit flag; the trampoline returns with the same
`rfid` lv2 uses, or spins when the process asked to end.  `ppu-trace` logs each
call with the caller's `lr`.

The calls the VSH asks for, in the order it first asks for them:

| # | Key | Service | Model |
| --- | --- | --- | --- |
| 100 | `0x64` | `sys_mutex_create` | id from a counter |
| 348 | `0x15C` | `sys_memory_allocate` | 256-byte blocks from a bump heap at RAM `0x808`, starting at `0x1000000` |
| 105 | `0x69` | `sys_cond_create` | id |
| 95 | `0x5F` | `_sys_lwmutex_create` | id |
| 102/104 | `0x66`/`0x68` | `sys_mutex_lock`/`unlock` | succeed (a single thread) |
| 147 | `0x93` | `sys_time_get_timebase_frequency` | 79,800,000 |
| 30 | `0x1E` | `_sys_process_get_paramsfo` | a valid empty SFO header |
| 403 | `0x193` | `sys_tty_write` | bytes to the PPE UART |
| 22 | `0x16` | `_sys_process_exit` | flush the console, end the run |
| 128/129/134/137 | `0x80`, `0x81`, `0x86`, `0x89` | event queue and port create, destroy, disconnect | id / succeed |
| 324/325 | `0x144`/`0x145` | memory container create/destroy | id, 1 MiB granularity |
| 352 | `0x160` | `sys_memory_get_user_memory_size` | total RAM and what the heap has left |
| 389 | `0x185` | `sys_sm_set_fan_policy` | policy and manual duty are state; nothing turns |
| 409 | `0x199` | `sys_sm_get_fan_policy` | duty from the policy (auto `0x4E`, full `0xFF`), 45 C |
| 386 | `0x182` | `sys_sm_control_led` | front LED state, published to the display frontends |
| 500 | `0x1F4` | `sys_hid_manager_open` | handle from `0x100`, and a pad port brings libpad up |
| 502/503 | `0x1F6`/`0x1F7` | `sys_hid_manager_read`/`ioctl` | pad data, and the `0x054C:0x0268` HID identity |
| 508-514 | `0x1FC`-`0x202` | focus, permission and hot-key calls | succeed (`check_focus` 1) |
| 516-522 | `0x204`-`0x20A` | `sys_config_*` | ids from the counter; no service events are queued |
| 52 | `0x34` | `_sys_ppu_thread_create` | id, and the thread is reported but not scheduled |
| 50/51/53 | `0x32`/`0x33`/`0x35` | thread stop/restart/start | succeed |
| 141 | `0x8D` | `sys_timer_usleep` | succeed at once: the guest's 100 ms polls |

`_sys_process_get_paramsfo` was what used to stop the boot: liblv2 asks for
the process's PARAM.SFO, and with `-ENOSYS` it printed `liblv2 can't get
PARAM.SFO` and called `_sys_process_exit`.  It now gets a syntactically valid
SFO header (magic, version, two empty tables), and the VSH continues into its
own initialisation: mutexes and condition variables, event queues and ports,
a 3 MiB memory container, and its library registrations.

The thermal loop only needs an answer, so the fan is a stub with state: auto
reports the idle curve, full reports `0xFF`, manual reports what was set.  The
`temperature` out-pointer gets 45 (degrees C), which is what an idle CELL
reads as.  Calls the model does not implement answer `-1` (or `-ENOSYS`) and
are otherwise passed through, so a missing service does not stop the run by
itself.

With the pad and config services answering, the run gets through the VSH's
startup handshake.  `sys_timer_usleep` is the wait its initialisation and its
idle loop both use - 100 ms polls - and the model answers at once, because the
PPU is TCG and a real wait would stall the machine.  That matters: while the
call answered `-ENOSYS` the guest retried it forever at `lr=0x5DAC94`; with it
succeeding the boot continues, creating more threads (reported, not scheduled),
looking for `/dev_flash2/etc` and reporting `LIBBTSETTING:
btsetting_initialize() failed! (80010003)`.  Those are the next things this
bring-up lv2 does not have, not blockers of the handshake.  The first sleep is
reported as `ps3-ppu: lv2: sys_timer_usleep(100000 us)`.

### The gamepad ports

There is no USB stack: `sys_io` describes up to seven ports directly, and
`pad-count` / `pad-types` say how many exist and what sits in each one.  The
products are the ones RPCS3 knows, with their real vendor and product ids and
their libpad class profile, so a guitar is a `PCLASS_TYPE_GUITAR` with five
frets, a strum bar and a whammy, a drum kit is a `PCLASS_TYPE_DRUM` with the
cymbals its model has, and a Move navigation controller is a navigation
controller rather than a DualShock 3:

| `pad-types` | vid:pid | class | profile |
| --- | --- | --- | --- |
| `standard` | `054C:0268` | standard | 0 |
| `guitar` / `guitar-rb` | `12BA:0100` / `12BA:0200` | guitar | `0xFF` / `0x7FFF` |
| `drums` / `drums-rb` / `drums-rb3` / `drums-rr` | `12BA:0120`, `0210`, `0218`, `0300` | drum | `0xBB`, `0xFF`, `0xBF`, `0xFB` |
| `dj` | `12BA:0140` | DJ | `0x7FF` |
| `dancemat` | `1CCF:1010` | dance mat | `0xFF` |
| `navigation` | `054C:042F` | navigation | 0 |
| `skateboard` | `12BA:0400` | skateboard | 0 (no sticks, no rumble) |

```sh
$Q -M rs6000-ps3 -display none -global ps3-boot-rom.dev-flash=... \
   -global ps3-boot-rom.vsh-run=on \
   -global ps3-boot-rom.pad-count=2 \
   -global ps3-boot-rom.pad-types=standard,drums
```

`cellPadInit` (asked for by `sys_hid_manager_open` on a pad port, and by
libpad itself), `cellPadGetInfo`/`GetInfo2`/`PeriphInfo` and the per-port data
calls are answered from that table.  A pad reports the length a real one does
(8 bytes, 20 with press mode, 24 with sensor mode), sticks centred at 128, the
DS3's rest orientation when sensor mode is on, and the neutral value of every
peripheral control the product has (whammy `0x80`, five-way switch `0x19`, DJ
platters `0x80`).  Nothing is pressed: there is no input source yet, so the
buttons word is zero and `cellPadSetActDirect` only records the motors.

The ports are always in the state the properties described, so a port is
either there with a product or absent, and the services say which.  That is
what libpadconfig wants: with the sys_io exports answering `-1` the VSH's
`libpadconfig_stub.cc` assertion (`ret == CELL_OK`) fired and killed the run;
it now registers service `0x1030` (PADMANAGER), opens a config handle and gets
past it.

### The front LED, on the window title

`sys_sm_control_led` is the only path the guest has to the front panel, and a
virtual console has no lamp.  The model keeps the state (led 0 green, 1 red, 2
the blue disc LED; action 0 off, 1 on, else blink) and publishes a short text
through `qemu_console_set_status_led()`, which the display frontends show: a
GTK build puts it in the window title as `QEMU - green blink`, next to
`[Paused]`.  It starts as `green on` when the machine is realised, because a
running emulator is a console that is switched on.  Headless builds still log
every change as `ps3-ppu: lv2: front LED: green blink`.

Nothing else reads it - there is no power LED register, no GPIO and no syscon
command - so this is a pretence, not emulation of the lamp's wiring.  It exists
because the guest's own LED calls are otherwise invisible.

### Import and export linkage

lv2 links a process and its modules the way the loader left them: an import
slot holds the address of the OPD whose `{code, toc}` pair the caller's thunk
loads, and a link is a rewrite of that slot.  The model recovers the tables
from the images rather than from a linker map:

* the process's exports are a run of `PS3PrxEntry` records in its `.rodata`;
  a record only counts when its neighbour is one too, its name is a library
  name, and its first NID points at an OPD-shaped descriptor inside the image.
  The VSH publishes 16 libraries and 2,400 functions that way (`paf` alone is
  973), which is why the linkage table is 8,192 entries.
* both linkers run after every module load, so a library that arrives late
  still gets its slots filled.
* an import whose OPD still carries the linker placeholder `0x39800000` is
  filled by lv2.  When nothing provides the NID, the model plants a stub in
  `0x800000..0xA00000`: an OPD over a six-word trampoline that stores the NID
  at `0xA00`, calls `0x7FF`, and returns `-1`.  That is what an unimplemented
  lv2 service answers, and it keeps a missing library from becoming a branch to
  `0x39800000`.
* slots that already point at working stub code are left alone - those are the
  VSH's own `li r11, <n>; sc` thunks, and the `0xC00` trampoline answers them.

With that in place the run loads and starts `libfs_utility2.sprx` (module 205,
680 relocations, 11/11 `sysPrxForUser` imports linked) and then
`sys_audio.sprx` (module 206, 3,164 relocations), which is where the VSH's own
module loading begins to drive the model.

### lv2's low page and the `0xB0FAC0DE` fill

The VSH's initialisation builds a pool table in low memory.  The constructor is
at `0x52A2F0`; it zeroes `count * 24` bytes through the memset helper at
`0xAE5E8`, then stamps `0xB0FAC0DE` into the first two words of every 24-byte
record:

```
0x52A328  lwz   r5, 0x2288(r9)     r9 = 0x00700000, so count = 1300
0x52A32C  mulli r5, r5, 0x18       31,200 bytes
0x52A334  bl    0xAE5E8            memset(base, 0, 31,200)
0x52A33C  lis   r10, 0xB0FA
0x52A344  ori   r10, r10, 0xC0DE
0x52A36C  lwz   r0, 0(r31)         base
0x52A370  mulli r9, r8, 0x18       r9 = base + i * 24
0x52A374  add   r9, r9, r0
0x52A380  stw   r10, 4(r9)         record[i].+4 = 0xB0FAC0DE
0x52A384  stw   r10, 0(r9)         record[i].+0 = 0xB0FAC0DE
0x52A388  bdnz  0x52A36C
```

It is called with the arena argument `0x24`, so the table lands on
`0x24..0x79F0` - lv2's page, where a user store faults on hardware.  Two things
in that range are the model's, and the fill took both out:

* the `0xC00` `sc` trampoline, so the next `sc` executed the pattern and took
  the program exception at `0x700`;
* the heap word at `0x808`, which is `record[84].+4`, so the old bump pointer
  became `0xB0FAC0DE` and every later allocation handed the guest a block built
  on the pattern.

`rs6000_ps3_lv2_page` now gives lv2's page the properties the missing MMU would
have given it:

* `0x800..0x900` is an I/O window over the bump pointer and the result block.
  Reads pass through to RAM, stores are dropped, and the first one is reported
  with `pc`, `lr`, the argument registers and the top of the stack - that is how
the writer above was identified rather than guessed at.
* `0xC00..0xC60` is a ROM region holding the 23-word shim.  It is executable, a
  store from the guest is a no-op, and the vector therefore survives the fill.
* the container's bump pointer is device state (`lv2_heap`); `0x808` is only a
  copy for dumps, so no guest store can move the heap.

The fill still happens and is now harmless.  Verified by having the guest run
two stores itself (a `stw` of `0xB0FAC0DE` to `0xC00` and one to `0x808`, code
placed through the gdbstub): the vector still reads `9421FFE0` and the heap word
still reads 0.  A gdb `M` packet is not a valid test here - the debug stub
writes ROM on purpose (`address_space_write_rom`).

### Where that run stops now

With the page protected and the pad, config and sleep services answering, the
run goes past liblv2's start-up, the mutex/cond/queue set, module loading and
`libpadconfig`.  The stub that used to assert
(`libpadconfig_stub.cc:34 ret == CELL_OK`) now gets `CELL_OK`: `sys_io`
answers its `cellPad` imports, `0x209` registers service `0x1030` (PADMANAGER),
and `sys_timer_usleep` accepts the 100 ms waits.  With it answering `-ENOSYS`
the guest retried the sleep forever at `lr=0x5DAC94`; now the boot carries on:

```
ps3-ppu: lv2: thread "" created (id 0xEE) but not scheduled: this model runs one thread
ps3-ppu console: MakePath : /dev_flash2/etc failed 8003051e
ps3-ppu console: LIBBTSETTING: btsetting_initialize() failed! (80010003)
```

What is left at the end of the run is therefore not a trapped import: it is
`/dev_flash2` (only `dev-flash` and `dev-flash3` are mounted) and libbtsetting's
`sys_btsetting_*` calls.  Those are the next services to model.

The lv2 low page is installed **only for `vsh-run`**.  `0xC00` is inside the
page lv0 loads its own trampoline into (its entry is `0xC40`), so installing
the shim for a `ppu-elf` lv0 stage overwrote the hypervisor's first
instructions and sent it to `0` (`program interrupt at pc 0x700, srr0=0`).
Gating it on `vsh-run` puts lv0 back on its documented path to `0x800C5C0`.

## Using it with the low-level boot chain

The chain this model follows, in order:

| Step | Code | In the model |
| --- | --- | --- |
| 1 | 1 KiB SPU mask ROM, at power-on | `-bios`, runs during reset |
| 2 | `lv0ldr.2` container in flash, opened with the channel-66 readout | same run; the ROM jumps to LS `0x400` when the tag checks |
| 3 | the decrypted lv0ldr payload (SPU) | same run, on the SPU interpreter |
| 4 | `lv1ldr`, `lv2ldr`, `appldr`, `isoldr` SELFs | `stage-elf`, one run per loader |
| 5 | `lv0` (PPU hypervisor) | `ppu-elf` + `ppu-entry=0xc40`, runs on the 970FX |
| 6 | `vsh.self` (application layer) | `vsh-self` / `dev-flash`, mapped and optionally entered with `vsh-run` |

Steps 1-3 are one command. Step 4 has no automatic hand-off: each loader is
handed its work through the local store (wait flag at `0x3E000`, arguments at
`0x3E800`) and through channels the PPU-side code drives, and this machine does
not yet play that part. `stage-elf` is how a loader is inspected on its own,
and the hand-off can be faked with:

* `stage-wait=0x...` writes the 8-byte wait flag at LS `0x3E000`;
* `stage-args=@file` (or hex bytes) copies up to `0x800` bytes to LS `0x3E800`
  and points the loader's `$3` at that block;
* `stage-version=0x...` answers channel 73 with the version the loader asks
  for (isoldr's `stop 0x30` is the version check).

The preload is reported as `ps3-spu-stage: preloaded wait=..., N argument
byte(s) at LS 0x3E800, version=...`.  It is a mechanism, not a solved hand-off:
with zeros preloaded the loaders still stop where they did without it, because
the block the previous stage would build holds real pointers and counts.

### Inputs

| Input | What it must be |
| --- | --- |
| mask ROM | the 1 KiB SPU ROM (`rom.bin`); a 32-bit byte-swapped dump is converted on load |
| flash image | the NOR dump, or just the region holding the container; mapped at `flash-base`, default `0x20000000` |
| readout | 32 bytes in the order the ROM reads channel 66: K_lo (16 bytes), then K_hi (16 bytes) |
| stage | a SELF, sealed or already unselfed; a *decrypted* 32-bit big-endian SPU ELF also works |

The readout is per console. Without one the ROM reads 32 zero bytes and stops
at `stop 2`; that is the correct answer for a container sealed for a different
machine, not a model failure.

### 1. Boot the ROM and open lv0ldr.2

```sh
Q=build-ps3/qemu-system-ppc64.exe
$Q -M rs6000-ps3 \
   -bios rom.bin \
   -drive if=pflash,format=raw,file=CECH3001A.bin,readonly=on \
   -global ps3-boot-rom.readout-file=ch66.bin \
   -global ps3-boot-rom.ls-dump=ls.bin \
   -display none -nodefaults
```

A paired sample from the ps3tools tree, so the run can be tried before a real
readout is in hand:

```sh
Q=build-ps3/qemu-system-ppc64.exe
P=~/Documents/ps3tools-main
$Q -M rs6000-ps3 -bios $P/.tmp/rom/rom.bin \
   -drive if=pflash,format=raw,file=$P/.tmp/pctool_flash.bin,readonly=on \
   -global ps3-boot-rom.readout-file=$P/.tmp/dlt/readout.bin \
   -global ps3-boot-rom.ls-dump=ls.bin -display none -nodefaults
```

Expected log for that pair:

```
ps3-boot-rom: container verified, 191152 bytes of payload
ps3-spu: ... (67108864 instructions, 1 MFC gets, 13 puts)
ps3-spu: last put 0x4 bytes to EA 0xFFF318
ps3-spu: local store written to ls.bin
```

The run does not exit on its own. lv0ldr has no PPU-side firmware to complete
the hand-off, so it polls; the instruction limit (`1 << 26`) ends the SPU run
and the machine then sits idle. Stop it with Ctrl-C or a timeout.

While it runs, the boot ROM registers at `0xF1040000` report status `1`
(verified), the header block count at `0x04` and the payload byte count at
`0x08`; the plaintext starts at `0xF1000400`.

`-global ps3-boot-rom.container=NAME` opens a different container. When a NOR
dump carries no name, the device falls back to the two slots the chain uses:
`0xFC0000` (lv0ldr) and `0x840` (metldr). `-global ps3-boot-rom.spu=off` stops
after the container and does not run the payload.

If it says `stop 2, MAC mismatch`, the readout does not belong to that
container; a container cannot be used to recover its own readout.

### 2. Take the decrypted payload out

The `ls-dump` file is the layout `ls_sift.py` reads: 256 KiB of local store
followed by 16 KiB of zero padding. The payload starts at offset `0x400` and is
`block count * 16` bytes. Comparing it with an independent decrypt is the
strongest end-to-end check of the ROM path, key ladder, CTR and DMA model; the
device selftest runs a shorter version of it on every boot. For the sample
pair above the payload is byte-identical to `lv0ldr.dec` (191152 bytes,
SHA-256 prefix `17db3fde46a0bf9a`).

### 3. Run the rest of the chain stage by stage

```sh
$Q -M rs6000-ps3 -display none \
   -global ps3-boot-rom.stage-elf=lv1ldr.self \
   -global ps3-boot-rom.stage-limit=200000
```

Observed with the loader SELFs in the ps3tools tree:

| Stage | Entry | Segments | Steps | Result |
| --- | --- | --- | --- | --- |
| `lv1ldr.self` | `0x12C00` | 3 | 450 | `stop` 0x30 at `0x13D8C` |
| `lv2ldr.self` | `0x12C00` | 3 | 530 | `stop` 0x30 at `0x12E18` |
| `appldr.self` | `0x12C00` | 3 | 1252 | `stop` 0x30 at `0x13078` |
| `isoldr.self` | `0x25B50` | 2 | (limit) | spins at `0x25990`/`0x25998`, no MFC traffic |
| `lv1ldr.2.self` | `0x12C00` | 3 | 450 | `stop` 0x30 at `0x13D8C`, key 18 |
| `lv2ldr.2.self` | `0x12C00` | 3 | 530 | `stop` 0x30 at `0x12E18`, key 18 |
| `appldr.2.self` | `0x12C00` | 3 | 1252 | `stop` 0x30 at `0x13078`, key 18 |
| `isoldr.2.self` | `0x25B50` | 2 | (limit) | spins at `0x25990`/`0x25998`, no MFC traffic |

A decrypted ELF runs the same way and prints the byte count too:
`.tmp_lv1/lv1ldr.elf` gives entry `0x12C00`, 3 segments, 152368 bytes and the
same 450-step `stop` at `0x13D8C`.

These are the loaders' own decisions, not model faults. Each expects the
previous stage to have written its arguments at LS `0x3E800` and the wait flag
at `0x3E000`, and isoldr additionally asks for its version on channel 73 (0x30
is the documented version-mismatch stop). With nothing there, lv1ldr, lv2ldr
and appldr take their stop path and isoldr waits in its polling loop.

Useful on stage runs: `-global ps3-boot-rom.ls-dump=...` writes what the loader
built in place before it stopped (the usual way to see parsed headers, tables
and arguments), `-global ps3-boot-rom.spu-trace=on` logs every instruction, and
`-global ps3-boot-rom.stage-entry=0x...` overrides the entry point.

Use the SELFs for this. The `.tmp/stages/*.elf` carves in the ps3tools tree
have plaintext ELF headers but still-encrypted segments - loading one faults on
its first word (`unimplemented SPU opcode`) - while the SELF opener decrypts the
same image correctly.

### A top-to-bottom check

Run in this order, the stages cover the whole chain; each line is what the
build in this tree prints today (inputs from the ps3tools tree):

| Step | Command | Observed |
| --- | --- | --- |
| 1-3 | `-bios .tmp/rom/rom.bin -drive if=pflash,...,file=.tmp/pctool_flash.bin -global ps3-boot-rom.readout-file=.tmp/dlt/readout.bin -global ps3-boot-rom.ls-dump=ls.bin` | `container verified, 191152 bytes of payload`; the ROM opens it in the SPU interpreter too (`42765 instructions`); `selftest passed`; the payload runs to the `67108864`-instruction limit at `0x1F0BC`, 1 MFC get / 13 puts, last put `0xFFF318` |
| 4a | `stage-elf=lv1ldr.self` | entry `0x12C00`, 3 segments, `stop 48` at `0x13D8C` after 450 instructions |
| 4b | `stage-elf=lv2ldr.self` | entry `0x12C00`, 3 segments, `stop 48` at `0x12E18` after 530 instructions |
| 4c | `stage-elf=appldr.self` | entry `0x12C00`, 3 segments, `stop 48` at `0x13078` after 1252 instructions |
| 4d | `stage-elf=isoldr.self` | entry `0x25B50`, 2 segments, spins at `0x25990`/`0x25998`, no MFC traffic (needs channel 73) |
| 5 | `ppu-elf=lv0.elf ppu-entry=0xc40 ppu-ticks=5` (or the `lv0_493.self` carve) | segments `0x0`/`0xC70` and `0x8000000`/`0xCBD50`; runs to `0x800C5C0`, printing `send_and_receive: write_init_msg fail -8` (the syscon UART is unanswered) |
| 6 | `dev-flash=... dev-flash3=... ps3-boot-rom.vsh-run=on` | `vsh.self` entry `0x6D5AC8` -> code `0x10230`, TOC `0x6F5558`; libfs_utility2 and sys_audio load and link; PADMANAGER registers; the run reaches `/dev_flash2` and libbtsetting |

Steps 1-3 and 6 run the guest's own code from start to finish; step 5 runs lv0
until its first hardware handshake.  Step 4 is inspected loader by loader -
the hand-off between steps 3/4/5/6 is still driven by hand, in the order above,
which is why each stage is a separate command.

### Recovering a readout

It cannot be derived from the container. On a console, the SPU probe
(`spu_rom/lsprobe.py`) brings back local storage, and `spu_rom/ls_sift.py
dump.bin --container <container>` walks every 32-byte window, runs the ladder
on it, and keeps the window whose derived key reproduces the container's
CBC-MAC tag. For model work, use a container and readout that were sealed
together, as in the sample above.

### Decrypting a superslim (4301C) dump

`decrypt_4301c.py` carves and decrypts the two loader containers a CECH-4301C
keeps in NOR, and proves each result with the container's own CBC-MAC:

| Slot | Container | Opened by |
| --- | --- | --- |
| `0x000840` | `metldr.2` | the SPU mask ROM, at power-on |
| `0xFC0000` | `bootldr` / `lv0ldr` | lv0, after `metldr.2` handed it the key |

```sh
python decrypt_4301c.py flash_4301c.bin --info
python decrypt_4301c.py flash_4301c.bin --readout ch66.bin -o out/
python decrypt_4301c.py flash_4301c.bin --erk erk.bin --eid0 eid0.bin -o out/
python decrypt_4301c.py flash_4301c.bin --key 8E661E78CDD3D510B9EBC0ECB5F755DA
```

Three ways in, because the key is whatever that console has:

* `--readout` is the 32 bytes the mask ROM reads from channel 66, in its order.
  The container key is `Kp = AES-ENC(K_hi, hdr[0x20:0x30] XOR K_lo)`; both
  orderings of the same readout are tried.
* `--erk` is the console's 48-byte EID root key 1 - `PCK1`, the value
  `metldr` derives from PCK0 and copies to HDD sector 0, not the channel-66
  `PCK0` readout that opens the `.2` containers.  It derives eid0's
  "individuals" blob (`AES-256-CBC` over the published seed, both directions),
  and every key that blob can hand a container is swept; the ERK's halves are
  swept directly too.  `--eid0` is optional and only adds the eid0 CMAC check.
* `--key` is a 16-byte container key, for when the expanded value is known
  already (the SPU's `$7`, or a key recovered by another route).

A wrong key cannot pass the tag, so `MATCH` is proof rather than a guess; when
nothing authenticates the tool writes nothing and exits 3 (`--force` writes the
first candidate and labels it `UNVERIFIED`).  Outputs are `metldr.dec` and
`lv0ldr.dec`, and the reader is checked by `--selftest`, which seals a container
with a known key and reopens it.  On a paired sample the `lv0ldr` payload is
byte-identical to `ps3tools`' `bootldrdec.py` output (SHA-256
`17db3fde46a0bf9a...`).

### Companion files in the ps3tools tree

| Path | Contents |
| --- | --- |
| `lv1ldr.self`, `lv2ldr.self`, `appldr.self`, `isoldr.self` | the four loader SELFs |
| `lv0_c0.self` ... `lv0_c7.self` | their carves out of a decrypted lv0 (`_2` names are the small duplicates that could not be decrypted) |
| `.tmp_lv1/lv1ldr.elf` | a decrypted ELF, for the raw-ELF stage path |
| `spu_rom/ls_sift.py` | readout recovery from an LS dump |
| `bootldrdec.py` | container format, CCM/CTR routines the model mirrors |

## Expected messages

| Message | Meaning |
| --- | --- |
| `container verified, N bytes of payload` | tag check passed, payload copied to LS `0x400` |
| `stop 2, MAC mismatch (...)` | wrong or missing channel-66 readout (zeros by default) |
| `stop 1, invalid payload length (...)` | header length field rejected |
| `no flash image (...)` / `no ... container ...` | no `-drive if=pflash`, or the name is not in the image |
| `the mask ROM is N bytes, expected 0x400` | wrong `-bios` file; a 32-bit byte-swapped dump is converted automatically |
| `selftest FAILED (...)` | interpreter or crypto regression; do not trust later results |
