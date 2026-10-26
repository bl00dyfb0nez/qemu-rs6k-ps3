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

### A GUI build, for the window

`build-ps3` has no display backend at all (`-display help` lists only `none`),
which is what the headless checks want.  For the guest window, configure a
second tree with SDL.  Run the configure from a **UCRT64 login shell**: in a
plain MSYS shell the compiler check picks a `cc` it cannot run and configure
stops early, which surfaces as `ERROR: Unknown target name '0'` rather than as
a compiler error.

```sh
pacman -S --needed mingw-w64-ucrt-x86_64-SDL2
MSYSTEM=UCRT64 /c/msys64/usr/bin/bash -lc '
  cd /c/Users/Thewoodsman/qemu && mkdir -p build-ps3-gui &&
  cd build-ps3-gui &&
  ../configure --target-list=ppc64-softmmu --enable-sdl --disable-werror &&
  ninja'
```

The window shows the `ps3-vga` scanout - the boot ROM's own messages, then
whatever the guest draws - and the front LED rides in the title bar.

```sh
Q=build-ps3-gui/qemu-system-ppc64.exe
$Q -M rs6000-ps3 -bios .tmp/rom/rom.bin \
   -drive if=pflash,format=raw,file=.tmp/bootchain_flash.bin,readonly=on \
   -global ps3-boot-rom.readout-file=.tmp/dlt/readout.bin \
   -display sdl
```

The scanout reads `PS3 BOOT` / `SPU PAYLOAD: 67108864 INSTRUCTIONS` /
`LV0LDR.2 CONTAINER VERIFIED: 191152 BYTES`.  Add the application layer and the
same window carries on into VSH once the chain is done:

```sh
$Q -M rs6000-ps3 -bios .tmp/rom/rom.bin \
   -drive if=pflash,format=raw,file=.tmp/bootchain_flash.bin,readonly=on \
   -global ps3-boot-rom.readout-file=.tmp/dlt/readout.bin \
   -global ps3-boot-rom.dev-flash=/c/Users/Thewoodsman/Documents/rs3/dev_flash \
   -global ps3-boot-rom.dev-flash2=/c/Users/Thewoodsman/Documents/rs3/dev_flash2 \
   -global ps3-boot-rom.dev-flash3=/c/Users/Thewoodsman/Documents/rs3/dev_flash3 \
   -global ps3-boot-rom.vsh-run=on -global ps3-boot-rom.threads=on \
   -display sdl
```

Once the container verifies, the scanout also gets the console's boot screen:
`RS6K` with `Playstation 3 Emulator` under a rule, drawn below the stage lines
(`-global ps3-boot-rom.boot-logo=off` disables it).  The glyphs are the console
font scaled up; the artwork is the model's own.

Two seconds after the wordmark the home screen replaces it, the way the console
comes up to its home in about five seconds from the power button: the wave
background, the category row with Game selected, `USER1` in the corner and the
host's clock (the same clock `sys_ss` gives the guest).  It is a rendition of
the XMB, not Sony's artwork and not vsh.self's rendering: the real screen needs
the guest's own `cellGcm` frames, and until those arrive this is what the
window shows.  Nothing is drawn unless the chain verified - a console whose
trust chain stops shows its boot screen and stays there - and the guest's
scanout takes the screen the moment vsh.self programs `cellVideoOut`.

`-global ps3-vga.dump=home.ppm` writes the boot surface after every line and
once more for the home screen, so the window's contents can be inspected
without a display:

```sh
$Q -M rs6000-ps3 -bios .tmp/rom/rom.bin \
   -drive if=pflash,format=raw,file=.tmp/bootchain_flash.bin,readonly=on \
   -global ps3-boot-rom.readout-file=.tmp/dlt/readout.bin \
   -global ps3-vga.dump=.tmp/home.ppm -display sdl
```


A third line appears above the two chain lines - `VSH: 2 SEGMENT(S), 7291232
BYTES MAPPED, ENTERING` - and the log continues with the modules vsh.self
loads (`libfs_utility2`, `sys_audio`, `sys_config`, the `_sys_micin_main` /
`_sys_camera_main` workers).  The real image is the one from `dev_flash`:
entry `0x6D5AC8`, OPD to code `0x10230`, TOC `0x6F5558`, `7291232` bytes over
two zlib segments.

### Which application comes up: vsh.self or emer_init

lv2 decides, and the model follows the firmware's rule: the chain is checked
first (`ps3_chain_check`), then the application image.  With
`-global ps3-boot-rom.emer-self=emer_init.self`:

| Condition | Result |
| --- | --- |
| container verifies **and** `dev_flash/vsh/module/vsh.self` exists | `chain checks passed; lv2 starts /dev_flash/vsh.self` |
| no flash image, no readout, container fails its tag, or no vsh.self | `### Vflash recovery mode`, then the emergency program is loaded |

Observed on the recovery branch (a zeroed readout): `the lv0ldr.2 container
does not verify (stop 0x3); creating the vflash recover process (emergency
program)` and `ps3-vsh: emer_init.self: entry=0xE23F0, 2 segment(s),
0x1257128 bytes mapped into RAM, PPU entering it`.

What the emergency program needed to stay up, and now gets:

| Piece | Why emer_init stopped without it |
| --- | --- |
| `argc`/`argv` at process entry | it printed `argc [0] argv[1] [(null)]`, then exited `-1`; the process now starts with `argc = 1` and its image path as `argv[0]`, built in the stack by both the loader and the reset path |
| `sys_console_write` (0x18E) | its own printouts are the only progress it gives; they now reach the machine console |
| `sys_dbg_..._ppu_exception_handler` (0x3DC) | registration succeeds (nothing to install) instead of returning an error |
| `sys_ss_get_cache_of_flash_ext_flag` (0x36A) | one byte, `0xFE` (LSB clear = NOR); writing a word overran the caller's local, and the byte is also the recover mode emer_init reads back |
| `sys_ss_update_manager` (0x35F), `sys_ss_appliance_info_manager` (0x363) | a refusal sent it to the "unsupported flash" error page; both now zero their out buffer and succeed |

With those in place emer_init runs its own recovery code and stays alive:

```
is factory mode ret[fffffb03]
ErrorPage[6] Code[-2147290384]
TvSetting::cellSsAimGetDeviceType 80010003
RescueUtilityGetTvSetting 80010003
Gcm Init Memory Shortage.
```

Both of those gaps are now answered rather than stubbed.  `cellGcmSys`'s display
half lives in the import table beside cellVideoOut:

| NID | Service | What it does |
| --- | --- | --- |
| `0x8F71C2DF` | `cellSsAimGetDeviceType` | reports device type 1 (TV), the same sink the cellVideoOut EDID describes |
| `0xB477F06A` | `cellGcmInit` | fills the caller's `CellGcmContextData` (begin/end/current/callback) over the guest's command buffer |
| `0xE315A0B2` | `cellGcmGetConfiguration` | 240 MiB of local RSX memory and 240 MiB of io memory (the console's 256 MiB less the reserved part), plus the memory and core frequencies |
| `0xA53D12AE` | `cellGcmSetDisplayBuffer` | records offset, pitch, width and height per display id |
| `0xDC09357E` | `cellGcmSetFlip` | hands that buffer to `ps3_vga_guest_scanout()`, so a flip is what puts the guest's framebuffer on screen |

The RSX side also needed lv2's mapper, because that is how the VSH's memory is
backed: `sys_mmapper_allocate_address` (0x14A) and `sys_mmapper_search_and_map`
(0x151) hand out 1 MiB-aligned addresses from `0x10000000` upwards, the
shared-memory calls (0x14C/0x153) return ids, and map/unmap/access-right
(0x146, 0x147, 0x149, 0x14D-0x150) succeed because the memory is the same flat
RAM.  `sys_sm_initialize` (0x17E) and `sys_ss_get_cache_of_product_mode` (0x369,
0x00 = CEX retail) are answered as well.

What that changed in a run is measured, not assumed:

* the `Gcm Init Memory Shortage.` line is gone, and no run asks for the AIM
  device type through the import table any more - the recovery program in this
  configuration prints its factory-mode line and exits 0 before either call, so
  the shortage is fixed but the menu still is not drawn;
* the VSH run now allocates mapper addresses (`mmapper address: 0x10000000 at
  0x10000000`) instead of dying at an unmodelled 0x14A, and moves on to
  `sys_uart_initialize` (0x16F) and the `sysPrxForUser` imports;
* two 256 MiB allocations wrap back to the same address, because the model's
  RAM is 256 MiB and the mapper range is allocated out of it - the VSH allocates
  one, so it fits, but a guest asking for two would alias.

### What emer_init does at the end, and why it never draws

Disassembling the blocks the PPU executed shows the program's ending, not a
menu loop.  At `0x3ba90` it checks the flash (`bl 0x3afc4`), and then always
falls into a shutdown wrapper at `0x3bd04`:

```
0003bd10  li    r11, 0x17b      ; sys_sm_shutdown
0003bd14  sc
0003bd18  li    r3, 0
...
0003bd50  blr
```

The action is `0x100` when the check reports a restorable flash and `0`
otherwise, so the recovery program's last act is to write its recover byte into
the system controller's EEPROM and ask for a **restart in recovery mode**.  The
screen that appears in recovery mode belongs to the next boot (VSH reading that
byte), so making this program "stay in its loop" is not something the binary
does.  What the model now does with the ending is accept it:

```
ps3-ppu: lv2: sys_sm_shutdown(0x100) - the recovery program asks for a restart
         in recovery mode
ps3-ppu: process exited with status 0
```

Before that it prints `factory mode ON  recover flag[ff]` and
`ErrorPage[6] Code[-2147290383]`; the recover flag it reads comes through
`sys_ss_update_manager(0x600B)`, which is the next section.

### The syscon EEPROM, per RPCS3's `ps3_syscon`

`sys_ss_update_manager` op `0x600B` is a *read* of the system controller's
EEPROM (offset in the first argument, output byte pointer in the second) and
`0x600C` is the matching write.  Treating them as a buffer, as this handler used
to, wrote zeroes at the offset and left the caller's byte untouched, so
emer_init read a stale `0xFF`.

| Offset | Meaning | Value |
| --- | --- | --- |
| `0x48C07` | recover mode, the machine's state rather than a stored byte | `0x00` in service mode, `0xFF` otherwise |
| anything else | stored byte | `0xFF` until the guest writes one |

`0x6003` and `0x6011` report firmware 3.01 in the `0xVVVRRRPP` form RPCS3 writes
(`0x3001000000000000`), and `0x6007`/`0x6008` (flash initialized) succeed.

### The RSX front end

cellGcmSys.sprx is real code: it does not call a modelled `cellGcmInit`, it asks
lv2 for the device through `sys_rsx` and writes methods into a FIFO in RSX local
memory.  That front end now exists, with the semantics RPCS3's `sys_rsx`
documents:

| Syscall | What it does here |
| --- | --- |
| `0x29A`/`0x29B` device open/close | succeed |
| `0x29C` memory allocate | one 240 MiB region, handle 1, at local base `0x40000000` |
| `0x29E` context allocate | context `0x55555555`, three 4 KiB areas from the lv2 heap (DMA control, driver info, reports) |
| `0x2A0`/`0x2A1` iomap/iounmap | succeed; the local region is real RAM |
| `0x2A2` context attribute | `0x001` FIFO get/put, `0x102` flip, `0x103` queued buffer, `0x104` display buffer; anything else is accepted |
| `0x2A3` device map | writes the register window base `0x40000000` |

Local memory is a real 256 MiB `MemoryRegion` at `0x40000000`, so the offsets
`cellGcmSetDisplayBuffer` names are readable.  A flip (`0x102`) resolves the
buffer id and hands `0x40000000 + offset` to `ps3_vga_guest_scanout()`, which is
the same path the modelled `cellGcmSetFlip` used.  The FIFO front end at `0x001`
decodes packets, logs the first 24 method ids under `ppu-trace` and advances
get to put.

The method handlers behind the FIFO — surfaces, clear, blit, draws, the shader
pipeline and the DCP — are still missing, and no VSH run has reached `sys_rsx`
at all: with every syscall in its bring-up answered, vsh.self now sits in a
`sys_mutex_lock`/`sys_mutex_unlock` loop at `0x5390B8`/`0x52CA08`.  It is waiting
for a worker thread, and the model's scheduler still does not run one, so the
GPU work never starts.  That is the next wall, not the RSX syscalls.

A running window can be dumped from the monitor
(`-monitor tcp:127.0.0.1:55555,server,nowait`, then `screendump file.ppm`),
which is how the two screenshots in this section were taken.

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
| `pad-types` | `standard` | product in each port, comma separated (`standard`, `dualsense`, `guitar`, `guitar-rb`, `drums`, `drums-rb`, `drums-rb3`, `drums-rr`, `dj`, `dancemat`, `navigation`, `move`, `skateboard`); one name applies to every port |
| `pad-selftest` | off | drive one controller state through the pad and check the guest's `CellPadData` |
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
| 52 | `0x34` | `_sys_ppu_thread_create` | id; with `threads=on` a real context (see below) |
| 50/51/53 | `0x32`/`0x33`/`0x35` | thread stop/restart/start | succeed |
| 29 | `0x1D` | `sys_ppu_thread_exit` | the thread is retired and switched away |
| 44 | `0x2C` | `sys_ppu_thread_join` | blocks the caller until the target exits |
| 141 | `0x8D` | `sys_timer_usleep` | succeed at once: the guest's 100 ms polls |
| 650 | `0x28A`-`0x293` | `sys_rsxaudio_*` | the audio ring page, and the pull side of it |

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

### Threads and their entry environment

The scheduler is opt-in, `-global ps3-boot-rom.threads=on`.  With it off, a
created thread is reported and its body never runs, which is what the early
bring-up needed.  With it on, `_sys_ppu_thread_create` gets a real context and
the 1 ms tick switches between threads.

The call is the one sysPrxForUser's wrapper makes:

```
_sys_ppu_thread_create(id*, param*, arg, unk, prio, stack, flags, name*)
```

and `param` is RPCS3's `sys_ppu_thread_param_t`, `{ u32 entry; u32 tls; }`, which
is the part that is easy to get wrong:

* `param` itself is a pointer into the caller's stack.  `entry` is the address of
  the thread's OPD, so the code and TOC have to be read from that descriptor.
  Reading the pair as one 64-bit value put the TLS word where the entry belongs
  and started every such thread on whatever the TLS page happened to contain.
* the descriptor is lv2's packed 8-byte form, `{ u32 code; u32 toc }` (a
  16-byte word pair is accepted as a fallback).
* the `tls` word is where lv2 takes `r13` from.  A user thread starts with
  `r3 = arg`, `r2 = toc`, `r13 = tls` and a zeroed register file, not with the
  creator's registers.
* the creator is executing in lv2, so its `MSR[PR]` is clear.  A user thread
  must run with `PR` set or its `sc` takes the hypervisor vector `0x700`
  instead of the lv2 trampoline at `0xC00`; `FP` and `VR` are set as well.
* `r1` points at the top of the thread's stack (the requested size, 4 KiB when
  zero) and the return address is a per-thread stub that calls
  `sys_ppu_thread_exit(0)` and then spins; a body that simply returns ends
  cleanly.

With those in place the VSH's worker threads enter their own module code (for
example `sys_audio`'s `_sys_micin_main` at `0x14A8DAC`), make lv2 calls and
exit.

### What the workers wait in

A worker that has no work does not spin: it blocks inside an lv2 call.  The
model has to honour that or the pool burns the whole timeslice budget, so the
blocking services are modelled with real parking:

| Key | Service | Model |
| --- | --- | --- |
| `0x080` | `sys_event_queue_create` | a queue with key and depth in a 24-entry table |
| `0x081` | `sys_event_queue_destroy` | drops it and fails its waiters with `ESRCH` |
| `0x082` | `sys_event_queue_receive` | takes a queued event, or parks with the caller's timeout |
| `0x083` | `sys_event_queue_tryreceive` | never blocks; reports how many it took |
| `0x085` | `sys_event_queue_drain` | empties the queue |
| `0x086`/`0x087` | port create/destroy | a port is a name and the queue it feeds |
| `0x088`/`0x08C` | connect local/IPC | local ids, and a queue matched by key for IPC |
| `0x08A` | `sys_event_port_send` | queues `{ source, data1..3 }` and wakes the first waiter |
| `0x064`-`0x068` | mutex create/destroy/lock/trylock/unlock | owner-tracked; a contended lock parks |
| `0x069`-`0x06E` | cond create/destroy/wait/signal | wait releases the mutex; a signal retakes it |
| `0x05A`-`0x05E` | semaphore create/destroy/wait/post/value | counted; a wait at zero parks |

The park is the same mechanism in every case: the call sets the trampoline's
exit flag, the thread stops at `0xC58`, and the switch saves its frame with
`SRR0`/`SRR1`.  When a send, an unlock, a post or the timeout completes the
call, `ps3_thread_finish_call` runs the trampoline epilogue on that saved frame
(`r3` = result, `r12`/`CR`/`r0` from the frame, `r1 += 0x20`, `nip = SRR0`,
`MSR = SRR1`).  A receiver also gets the event in `r4..r7`.

The timeout is lv2's microseconds divided by the 1 ms tick and capped at 400
ticks, because `msmw2.sprx` polls a queue for 100 s during boot.  Zero means
wait for as long as it takes.  The exit flag is written by the publishing call
only, so a stale one cannot park the next call the guest makes - that mistake
stopped `_sys_micin_main` right after its first queue was created.

`sys_timer_usleep` stays a yield rather than a real sleep: a guest that asks
for 100 ms between polls would otherwise stall the boot, and the scheduler
already gives every runnable thread a slice.

### The sound driver

The guest reaches the audio hardware through lv2's `sys_rsxaudio` calls, which
`sys_audio.sprx` makes on behalf of `cellAudio`.  The model implements them:

| Key | Service | Model |
| --- | --- | --- |
| `0x28A` | `sys_rsxaudio_initialize` | a zeroed 4 KiB shared page from the lv2 heap, handle `1` |
| `0x28B` | `sys_rsxaudio_finalize` | drop the page and the handle |
| `0x28C`/`0x28D` | import/unimport shared memory | the page address |
| `0x28E`/`0x28F` | create/close connection | succeed |
| `0x290` | prepare process | succeed |
| `0x291`/`0x292` | start/stop process | start and stop the 5 ms ring drain |
| `0x293` | get DMA param | zero |

The page holds the three ring buffers of `rsxaudio_shmem`: the serial ring is
the stereo mix for HDMI and the AV multi out, and the two S/PDIF rings sit
next to it.  An entry names a 256-byte block - 32 stereo frames of big-endian
floats - and the guest publishes it by advancing `write_idx`.  The model's
timer takes entries while `read_idx` trails `write_idx`, converts each block to
S16 and hands it to QEMU's audio subsystem, then clears `valid`, advances
`read_idx` and writes `next_blk_idx` back.  Three rings exist but only the
serial one carries the mix; an idle ring costs nothing.

`ps3_audio.c` is the host side.  It opens a 48 kHz stereo `s16` voice on an
`-audiodev` backend, converts the guest's floats with clipping, and stays out
of the way otherwise; with no backend the rings are still drained, silently.

```sh
Q=build-ps3/qemu-system-ppc64.exe
$Q -M rs6000-ps3 -display none \
   -audiodev dsound,id=snd \
   -global ps3-boot-rom.dev-flash=C:/Users/Thewoodsman/Documents/rs3/dev_flash \
   -global ps3-boot-rom.audio=snd \
   -global ps3-boot-rom.vsh-run=on -global ps3-boot-rom.threads=on \
   -global ps3-boot-rom.ppu-ticks=3000 -global ps3-boot-rom.ppu-tick-ns=1000000
```

`wav` works for a file capture (`-audiodev wav,id=snd,path=out.wav`), `dsound`
is the Windows default, `none` is silence.  The backend opening is reported as
`ps3-audio: 48 kHz stereo out on "snd"`; the guest's own start of the stream
prints `ps3-audio: sound driver running, serial ring at 0x...`.  In this
bring-up the VSH gets its `sys_audio` module loaded and running before it
reaches `cellAudio` initialisation, so the ring is still empty there - the
backend and the drain path are in place, not yet exercised by that run.

### The microphone

The console's microphone is a USB audio class device, and `cellMic` is the
library in front of it: open, start, read, and the attributes.  Under LLE the
samples belong to `sys_audio`'s `_sys_micin_main` thread, which sleeps on a
`CELLMIC_DATA` event and only reads when one arrives - so the event matters as
much as the read.  Here device `0` is QEMU's capture input: `cellMicOpen` opens
a capture voice on the same `-audiodev` backend the speakers use, and the
samples the host delivers are handed to the guest the way the library hands
them over on hardware.

| entry point | what it does here |
| --- | --- |
| `cellMicInit` / `cellMicEnd` | one device, the capture voice; attributes reset to the library's defaults (gain `3`, volume `145`, AGC `0`, channel volumes `100`) |
| `cellMicOpen` / `OpenRaw` / `OpenEx` | open the voice at the guest's rate and channel count, `RAW` and/or `DSP` signal |
| `cellMicStart` / `StartEx` / `Stop` | let the tick pump fill the ring, or stop |
| `cellMicRead` / `ReadRaw` / `ReadDsp` | copy the ring to the guest: big-endian `s16` (`RAW`) or big-endian floats in [-1, 1] (`DSP`); `DSPTYPE = 1` makes the DSP stream the raw one |
| `cellMicGetFormat*` | `{channels, 2 or 4, 16 or 32, dataType 1, rate}` - the rate is the one the voice actually opened at |
| `cellMicIsOpen` / `IsAttached` / `GetType` | `1`/`1` while open, `CELLMIC_TYPE_USBAUDIO` (3) |
| `cellMicGetStatus` / `GetSignalState` | the running state, and the level: RMS of the last block on RPCS3's 40..90 dB scale |
| `cellMicSetNotifyEventQueue{,2}` / `Remove` | the queue the data events go to; an `ATTACH` is sent at once, then `DATA` whenever the ring has a block |
| `cellMicGetDeviceAttr` / `SetDeviceAttr` | LED, gain, volume, AGC, DSP type and the two channel volumes |

The rate is the interesting part: the audio core only knows a fixed set
(48000, 44100, 32000, 16000, 8000), so a guest that asks for something else is
opened at the closest supported rate and `cellMicGetFormat` reports that rate
back rather than a number it is not being fed at.  A host with no input, or a
backend that refuses capture, answers `CELL_MICIN_ERROR_DEVICE_NOT_SUPPORT`
(`0x80140110`) instead of pretending the device exists.

```sh
Q=build-ps3/qemu-system-ppc64.exe
$Q -M rs6000-ps3 -display none \
   -audiodev dsound,id=snd \
   -global ps3-boot-rom.audio=snd \
   -global ps3-boot-rom.mic-selftest=on
```

`mic-selftest` drives the handler the way the library does - init, open, start,
a ramp through the ring, a raw read checked byte for byte, the format and the
level, a read after close, end - and then opens the real input for 300 ms and
reports how many frames the host delivered:

```
ps3-audio: microphone capture at 48000 Hz, 2 channel(s) on "#default"
ps3-ppu: microphone selftest ok: init/open/start/read/format/level/close on a 48000 Hz stereo ring
ps3-ppu: microphone capture test: the host delivered 1114 frame(s) in 300 ms
```

Zero frames there means the input is silent or absent, which is a fact about
the host rather than a failure of the model; the selftest still passes.  The
queue is named by key, so a guest has to have created it with
`sys_event_queue_create` first - a key that names nothing is
`CELL_MICIN_ERROR_EVENT_QUEUE` (`0x8014010d`), as on hardware.

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
| `move` | `054C:03D5` | move | 0 |
| `dualsense` | `054C:0CE6` | standard | 0 |
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
platters `0x80`).  A port with no input reads zero in both digital words and
both sticks centred; `cellPadSetActDirect` only records the motors, because
there is nothing to rumble.

The ports are always in the state the properties described, so a port is
either there with a product or absent, and the services say which.  That is
what libpadconfig wants: with the sys_io exports answering `-1` the VSH's
`libpadconfig_stub.cc` assertion (`ret == CELL_OK`) fired and killed the run;
it now registers service `0x1030` (PADMANAGER), opens a config handle and gets
past it.

### The keyboard and the host's controller

Port 0 is the one the host can press.  QEMU's console keyboard arrives as key
events and the arrows, `Enter`, `Escape`, `Backspace`, `Space` and `Tab` map
onto d-pad up/right/down/left, cross, circle, square, start and select - enough
to boot and navigate a dialog on a machine with no controller plugged in.

A controller is not a console input device, so it does not go through the
keyboard's handler list.  `include/ui/input.h` publishes one whole
`QemuGamepadState` - the sixteen libpad bits and four axes at `-0x7FFF..0x7FFF`
with up and left negative - and the machine with pad ports keeps the latest
one.  `ui/sdl2.c` opens the first controller SDL reports and republishes the
state after every button, axis and trigger event; a DualSense, a DualShock 4 and
an Xbox pad all arrive through the same `SDL_GameController` mapping, so this
layer never has to know which one is plugged in.  Hot-plug is part of it: a new
controller opens, and a removed one publishes a zeroed state so nothing stays
pressed.

| SDL | libpad word | bit |
| --- | --- | --- |
| A / B / X / Y | digital2 | cross `0x0040`, circle `0x0020`, square `0x0080`, triangle `0x0010` |
| LB / RB | digital2 | L1 `0x0004`, R1 `0x0008` |
| triggers pulled past a quarter | digital2 | L2 `0x0001`, R2 `0x0002` |
| Back / Start / Guide | digital1 | select `0x0001`, start `0x0008`, PS `0x0100` |
| stick clicks | digital1 | L3 `0x0002`, R3 `0x0004` |
| d-pad | digital1 | up `0x0010`, right `0x0020`, down `0x0040`, left `0x0080` |
| left / right stick | words 6..7 / 4..5 | `0..255`, `0` up or left, `128` centred |

Press mode reports a pressed button at `255`, and the axes scale with half a
step of rounding so a centred stick reads `128` rather than `127`.  The
keyboard's two words are ORed in, so a run with no controller still gets through
the VSH's dialogs.

`pad-selftest` is the check that the mapping is right without a controller in
hand.  One state - d-pad left, cross, both sticks hard over - goes through the
same handler the display feeds, then the guest's `CellPadData` is read back and
the report length, both digital words, the four axes and the cross pressure are
checked; then the release (sticks recentre, nothing stays pressed) and the
detach:

```sh
$Q -M rs6000-ps3 -display none \
   -global ps3-boot-rom.pad-selftest=on \
   -global ps3-boot-rom.pad-types=dualsense
```

```
ps3-ppu: gamepad: the host's controller drives port 0 (sticks, d-pad, face and shoulder buttons)
ps3-ppu: gamepad: the host's controller is gone; port 0 sits at rest
ps3-ppu: pad selftest ok: port 0 is a dualsense (054C:0CE6) and the controller's d-pad, cross, sticks and pressures land in the guest's CellPadData
```

A stick on the wrong side or a face button in the wrong word would otherwise
only look like a broken game.  With `-display sdl` the same channel is live and
the two lines it adds are the display and the machine agreeing about what is
plugged in:

```
sdl: gamepad: "DualSense Wireless Controller" (axes, buttons and triggers drive the guest's pad)
ps3-ppu: gamepad: the host's controller drives port 0 (sticks, d-pad, face and shoulder buttons)
```

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

With the event queues and the synchronization services above, that same run
gets further.  The main thread no longer spins on the mutex at `0x5390B8`:
that loop was the guest's list lock around a handshake the workers never
finished, because `sys_event_queue_receive` answered `ENOSYS` and each worker
retried it forever.  With the receive blocking, the pool threads park there,
the main thread takes the core, and the boot proceeds through module loading,
`sys_hid_manager_open`, `sys_config_open` and `libpadconfig` (the
`libpadconfig_stub.cc:34` assertion no longer fires).

### The drives: lv2's storage layer

The VSH's media manager does not touch the ATA command block; it uses lv2's
`sys_storage` virtual-device calls.  Every one of them was unmodelled, so the
family answered `0` and the drive never connected: the VSH printed
`BD Drive connect error`, its `x3::LocalMdQueryThread` workers died, and the
main thread sat on the media list's mutex at `0x5390B8` waiting for a
handshake that could not happen.  The layer now answers:

| Syscall | What it does here |
| --- | --- |
| `0x262` device config | 6 storages, 17 devices, as lv2 reports them |
| `0x263` report devices | the 17 lv2 device ids (BD, HDD x3, NAND x7, NOR x4, USB) |
| `0x261` device info | `StorageDeviceInfo`: the media's own sector count and size; an empty drawer really reports 0 sectors |
| `0x258`/`0x259` open/close | a handle table of eight devices |
| `0x25A`/`0x25B` read/write | 2048-byte sectors from the BD image, 512-byte sectors from the HDD image; a BD write is refused, as on the drive |
| `0x25C`/`0x268` device command | success with a zeroed reply: there is no drive firmware to answer SCSI here |
| `0x25D`-`0x260`, `0x264`-`0x26F`, `0x2BB` | success (async I/O, medium events, regions, BD emu) |

The image is the one the machine already gives QEMU's ATAPI device at `0x1F0`:
`-drive if=ide,media=cdrom,file=disc.iso` attaches it, and the model opens the
same file read-only as `disc-file`, so the guest's own ATA driver and lv2's
storage layer see one disc.  A decrypted ISO is served sector for sector, which
is exactly what a drive hands a console for a dumped game - there is no
per-sector re-encryption to undo because the image is already the plaintext the
console would read.

The model's own files (the XMB's `vsh/resource/explore/xmb/*.xml`, the console's
`dev_flash2/etc`, and the rest of the guest's `dev_flash*` tree) are not a
special case: `sys_fs` maps every guest path to the host directory given by
`dev-flash`, so XML, `.sprx` and data files are served the way they are stored.

The thread services the VSH's `x3` layer also needs are real now:
`sys_ppu_thread_detach` (`0x2D`), `get_join_state` (`0x2E`), `set_priority`
(`0x2F`), `get_priority` (`0x30`), `get_stack_information` (`0x31`) and
yield (`0x2A`), backed by the priority, stack base and size lv2 records at
`_sys_ppu_thread_create`.

`sys_memory_get_page_attribute` (`0x15F`) writes lv2's `sys_page_attr_t`
(`{u64 attribute, u64 access_right, u32 page_size, u32 pad}`).  It used to put
the page size in the first word, so `page_size` read 0 and `attribute` was a
size: the caller that sized a mapping from it walked off into nothing.

### Where that run stops now

With the drive connected the boot goes much further: the BD enumerates,
`/dev_bdvd` opens, the `x3` threads (`_EventHandler`, `_PollingService`,
`LocalMdQueryThread`, `_CacheWriteThread`, `_BackupThread`) start, and the VSH
prints `Registry initialization start:............ done` - it is past the media
layer that used to hold it at `0x5390B8`.

The remaining stop is an exception the model leaves unhandled, and the trace
now names it to the instruction.  The 970's "hypervisor emulation assist"
vector (`0x700`) is what QEMU raises for an invalid or privileged instruction;
this model installs no handler there, so the first one ends the thread.

`-d int` gives the fault: `Raise exception at 0000000200000020 => HV_EMU (96)
error=21`.  `0x21` is `POWERPC_EXCP_PRIV_REG` (an `mtspr`/`mfspr` of a
privileged register), and the address is not code: `0x200000020` is the flash
window (`0x20000000`) plus `0x20`.  So the guest branched to a 64-bit value
whose two halves are `0x00000002` and `0x00000020` - the shape of two 32-bit
words read as one address.

The model's own report ties that to one call site:

```
thread 0x0 took the program interrupt vector at 0x700 (lr=0x200000020)
  r1=0xFFFE700 r2=0x6F5558 r11=0x8C r31=0x73CDB0
  frame 00000000 0FFFE800 006E7780 00000000 00000002 00000020 00000200 00002000
```

`r1+0x10`, the frame's LR save slot, holds `00000002 00000020`, and the last
lv2 call before the fault was the wrapper at VSH `0x1CBE08`:

```
1cbe04: f8 01 00 10   std  r0,16(r1)     ; save LR
1cbe08: 39 60 00 82   li   r11,0x82      ; sys_event_queue_receive
1cbe0c: 44 00 00 02   sc
1cbe10: e8 01 00 10   ld   r0,16(r1)     ; restore the same slot
1cbe20: 7c 08 03 a6   mtlr r0
1cbe30: 4e 80 00 20   blr              ; -> 0x200000020
```

So the return address is not a truncated pointer: the caller's LR slot was
overwritten with a four-word record `{2, 0x20, 0x200, 0x2000}`.  That record is
not stack garbage - the same sixteen bytes sit in the VSH's own data at
`0x1083CA0`, immediately after the path buffer at `0x1083C50` that holds
`/dev_flash/sys/internal/libf` and the descriptor `{ptr=0x1083CA0, 3, 0}` at
`0x1083C80`.  In other words a module-load record ends up copied over a stack
frame's linkage area, and the epilogue of the next call returns into it.

That places the next step in the PRX path (`sys_prx_load_module` /
`start_module` option blocks, and whatever writes the `0x1083C80` descriptor),
not in the syscall dispatcher: the run has still not reached `sys_rsx`.

A second, earlier fault in the same family shows up on the `x3` workers, and it
is the one to chase first because it happens before the main thread's:

```
thread 0x10C took the program interrupt vector at 0x700 (lr=0x184B8)
  r1=0x15C7D50 r2=0x6F5558 r3=0x2800204A r12=0x48002042
  r29=0x28002042 r30=0x4800204200000000 r31=0x2800204A ctr=0x543054
```

`0x184B8` is the VSH's `__cxa_finalize`, and the registers say what it was
doing: `r12` holds `0x48002042`, which is a branch *instruction word* (`b`,
opcode 18) and not an address; `r29` is the same word with `0x20000000`
removed, `r30` is it shifted left 32, and `r31`/`r3` are `0x2800204A`, i.e. a
pointer outside RAM (the model's RAM ends at `0x10000000`).  So the exit list a
worker walks holds words taken from code instead of function descriptors, and
the first dereference sends it to `0x700`.

Both faults are therefore the same shape - a 32-bit word from the wrong place
standing in for a 64-bit pointer - and both are downstream of a module that was
loaded and then started.  `sys_prx_start_module`'s option block is the place to
start: the model writes a 64-bit entry point at `opt+0x10` and, when
`opt[0] != 0x20`, another at `opt+0x20`, and the caller is expected to invoke
what it finds there.  A caller that instead keeps a descriptor list will read
those words as pointers.

`-global ps3-boot-rom.ppu-trace=on` now walks the back chain at the fault
(`chain[n] sp=... lr=... back=...`), so the caller of the frame that returned
into garbage is named in the log instead of guessed at.

The lv2 low page is installed **only for `vsh-run`**.  `0xC00` is inside the
page lv0 loads its own trampoline into (its entry is `0xC40`), so installing
the shim for a `ppu-elf` lv0 stage overwrote the hypervisor's first
instructions and sent it to `0` (`program interrupt at pc 0x700, srr0=0`).
Gating it on `vsh-run` puts lv0 back on its documented path to `0x800C5C0`.

### What the SPU interpreter is not

The SPE here is an instruction-level interpreter of the ISA subset the mask ROM
and the loaders use.  It is enough to open the container and run lv0ldr, and it
is not the SPE a game would need:

| Missing | Why it is not there |
| --- | --- |
| floating point: `fa`, `fs`, `fm`, `fma`, `fnms`, `frest`, `frsqest`, `fi`, `csflt`, `cuflt`, `cflts`, `cfltu`, the double-precision forms | the loaders do pure integer and crypto work |
| SPR access and most channel control | only the channels the loaders touch exist (66, 73, signal notify, MFC tag and a few others); status-and-control register access beyond those is absent, so it faults |
| memory protection | the SPU's protection/isolation instructions are not used by the early loaders |
| halt variants | only plain `stop` is present; `stopd` and its dependency forms are not |
| multiply variants | only `mpy`, `mpyu`, `mpyi`, `mpyui` and `mpya`; `mpys`, `mpyh`, `mpyhh` and the rest are absent |
| miscellaneous | the rarely-used permute, interpolate and special forms: anything the mask ROM -> lv0ldr / isoldr / appldr path does not need |
| cycle accuracy | instructions retire with no timing model at all, so nothing that measures, spins on a cycle budget or depends on dual-issue behaviour sees the real machine |
| more than one SPE | the model has a single SPE and no concurrent execution, so code that starts a second SPE or expects two running together does not get it |

None of that blocks the chain: the ROM and lv0ldr use only the integer, branch
and MFC subset that is implemented.  It does block anything that runs real SPE
code, which is the work after the RSX path.

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

### Rebuilding the flash image from the decrypted chain

`spu_rom/norbuild.py` goes the other way from the ROM: it seals the decrypted
stages back into their containers with the console's channel-66 key and writes
them into the NOR slots the mask ROM looks at - `metldr` at `0x840`, inside the
asecure_loader bank, and `lv0ldr.2` at `0xFC0000`, the bootldr region.  Nothing
is copied blindly: each container is opened with the readout first (its own
CBC-MAC decides, not a guess at the key), its plaintext is compared with the
decrypted stage, and the finished image is read back and re-opened.

```sh
py spu_rom/norbuild.py --readout .tmp/dlt/readout.bin \
    --stage lv0ldr=.tmp/pctool_lv0ldr.bin \
    --dec   lv0ldr=.tmp/lv0ldr_container.dec \
    --base  .tmp/4301c_flash493.bin \
    -o .tmp/bootchain_flash.bin
```

```
norbuild: bootchain_flash.bin, 1 stage(s), readout 72fe9adc185d6b93
  lv0ldr  bootldr region 0xFC0000  11947 blocks  191216 bytes  ch66 [0:16]/[16:32]  plain sha 17db3fde46a0bf9a
norbuild: wrote .tmp/bootchain_flash.bin, 16777216 bytes, sha 11d64119addc40b0...
```

Boot that file as the pflash drive, exactly as in step 1.  The run prints the
same verdict as the paired sample - `container verified, 191152 bytes of
payload`, the SPU interpreter replaying the ROM at `42765 instructions`,
`selftest passed` - and the payload it leaves at `0x400` of the `ls-dump` is
byte-identical to `lv0ldr_container.dec` (SHA-256 prefix `17db3fde46a0bf9a`).
`--dec` is what makes that a check rather than a claim.  A readout that does not
belong to the container is refused before a byte is written, as is a decrypted
stage whose bytes are not the container's plaintext.

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

## Storage: eMMC and booting from the disk

A 4xxx superslim such as the CECH-4201A has no NOR: metldr and the loaders
live on eMMC, and the console encrypts those sectors with the *encdec* keys
PCK1 derives - the same AES-256-CBC ladder as the ATA keys, over the two
`kgen.c` seeds at 0x00 and 0x20 instead of the SB indiv blocks.  The model
carries the medium and the ladder:

| Property | Meaning |
| --- | --- |
| `emmc-file` | raw eMMC image; created sparse at `emmc-size` if absent |
| `emmc-size` | bytes (default `12 * GiB`; `-global` takes a plain number, not `12G`) |
| `boot-medium` | where the boot ROM looks: `flash` (default, the pflash drive), `emmc` or `hdd` |
| `erk` / `erk-file` | PCK1; derives the encdec keys (and the ATA keys, unchanged) |

Every eMMC access goes through `ps3_emmc_crypt`: AES-128-CBC over 512-byte
sectors with the low half of the encdec data key, and an IV built from the
tweak half with the sector number folded in.  The ladder is the console's; the
byte placement of the sector number inside the IV is the model's, because the
controller's IV is not published - it sits in one function so a dump can
settle it.  Sector 7 is decrypted, re-encrypted and compared at startup, so a
ladder or IV mistake fails at boot instead of corrupting an image later.

Booting the superslim firmware:

```sh
Q=build-ps3/qemu-system-ppc64.exe
$Q -M rs6000-ps3 -bios .tmp/rom/rom.bin \
   -global ps3-boot-rom.emmc-file=CECH4201A.emmc \
   -global ps3-boot-rom.boot-medium=emmc \
   -global ps3-boot-rom.erk-file=erk48.bin \
   -global ps3-boot-rom.readout-file=ch66.bin -display none -nodefaults
```

`boot-medium=hdd` runs the same container search over the first 16 MiB of the
disk after the ATA decryption (sector 0 of a keyed disk is the wrapped key
sector and is left out), so a chain staged on the HDD boots as well.

Observed on this build:

| Run | Result |
| --- | --- |
| `boot-medium=emmc`, plaintext image made with `norbuild.py` | `eMMC: ... unkeyed`, sector 7 round trip, `container verified, 191152 bytes of payload` |
| `boot-medium=emmc` + `erk-file`, blank image | `encdec keys from the EID root key`, sector 7 round trip, `selftest passed` |
| `boot-medium=hdd`, unkeyed 64 MiB disk with the rebuilt image at 0 | `boot medium hdd`, `container verified, 191152 bytes of payload` |

## Expected messages

| Message | Meaning |
| --- | --- |
| `container verified, N bytes of payload` | tag check passed, payload copied to LS `0x400` |
| `stop 2, MAC mismatch (...)` | wrong or missing channel-66 readout (zeros by default) |
| `stop 1, invalid payload length (...)` | header length field rejected |
| `no flash image (...)` / `no ... container ...` | no `-drive if=pflash`, or the name is not in the image |
| `the mask ROM is N bytes, expected 0x400` | wrong `-bios` file; a 32-bit byte-swapped dump is converted automatically |
| `selftest FAILED (...)` | interpreter or crypto regression; do not trust later results |
