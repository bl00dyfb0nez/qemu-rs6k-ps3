# PS3 / Cell model (`rs6000-ps3`)

A local research model of the PS3 boot path inside this QEMU checkout: the Cell
memory interface controller, the SPU mask ROM and its container opener, the SPU
interpreter the decrypted loaders run on, a SELF opener for the later stages,
the RSX front end the graphics library talks to, and enough of lv2 for the real
`vsh.self` to run under it.  It is an experiment, not an upstream contribution:
see `AGENTS.md` and `docs/devel/code-provenance.rst`.  Nothing here is needed to
build or use the rest of QEMU.

This file is the short form: what to build, what to run and what passing looks
like.  The research behind every behaviour - per-call findings, disassembly
notes, the runs that settled each answer - lives in the ps3tools tree as
`PS3_MODEL.md` with `EMER_INIT.md`, `FAULT_HARNESS.md`, `FLASH_LAYOUT.md`,
`SUPERSLIM_MAP.md`, `KP_PROVENANCE.md`, `BOOTLDR_DISASM.md`,
`LV0_LV1_DISASM.md`, `CONFIG_RING_TO_CISD.md` and `THREAD.md` beside it.

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

### BIOS / mask-ROM credits

The SPU mask ROM the model replays (`-bios`) is the one published in zecoxao's
*The (Microcode?) ROM: bits shared and an overview*
(<https://www.psx-place.com/threads/the-microcode-rom-bits-shared-and-an-overview.49143/>)
with the write-up *Glitching the "Almost" Perfect Code...*
(<https://zecoxao.github.io/writeup/>).  The work behind those bits, as the
write-up credits it:

- Anonymous - imaging the ROM area, including the SPU pictures that held the
  actual mask ROM
- Proxima - decoding the bit images into the 0x400-byte ROM
- jestero - noticed that SPU registers keep their values across executions, and
  recovered register 7 from the channel-66 key expansion
- anergistic and lvx - the SPU analysis and tracing tools the ROM was read with
- wildcard, ZeroTolerance, DJ, Mina Ralwasser, golden, bguerville - the syscon
  master keys, patches and testbench work the ROM analysis stands on
- kafuu, esc0rtd3w, bguerville - QuasiCFW and BadWDSD, the flash-side work
- sagemono, MikeM64, flat_z, naehrwert, mysis, skgleba, xorloser, Myria, Kafuu
  - the remaining credits from that write-up

The model's own part is the replay: the SPU interpreter runs those 0x400 bytes
as instructions, the container opener and key ladder are a second
implementation checked against the ROM's result, and the flash layouts are the
offsets those bits address.  The ROM image is the user's to supply; no Sony
code is carried in this tree, and no per-console key is written to a log (only
fingerprints).

### ch66 is the boot ROM's public key; PCK1 comes out of lv0ldr.2

The 32 bytes the boot path calls channel 66 live in the *mask boot ROM* - the
0x400 bytes the SPUs execute first.  The ROM reads them on its own channel 66,
expands the key ladder from them and opens the flash container with it
(lv0ldr.2 on NOR, metldr.2 on NAND/eMMC).  ch66 is **public**, which is why a
container in a dump can be opened at all: it is the container key, not a
per-console secret, and it never encrypts disk data.

The per-console keys are one and two levels in, and they are read out in that
order:

1. **ch66 opens `lv0ldr.2`** - decrypt the container with the channel-66 ladder
   and **PCK1 is inside it**.  PCK1 is the per-console root: it is what the ATA
   and flash ladders are run on, and what the HDD image's key sector is wrapped
   under.
2. **PCK1 opens the loader** - `lv1ldr.self` on a NOR console, the loader its ros
   bank carries on a NAND/eMMC one - and what comes out of it is the ladder:
   **the EID root key (with its RIV) and the four static seeds** (SB-indiv data
   and tweak, encdec data and tweak) that PCK1 is run on for the ATA and flash
   keys.  The same ERK/RIV pair is what opens the application SELFs
   (`vsh.self` and the rest), so it is the key the SELF opener works from, not
   the container key.

So a NOR/NAND/eMMC dump carries the container and, inside it, that console's
PCK1, and the next stage's SELF carries the EID root key - but never ch66
itself, which belongs to the ROM.

The loader's seed block sits at a different offset on each medium, and it is
found by its content rather than assumed (the four seeds are published
constants, so a match identifies the block):

| Medium | Where | Offset seen |
| --- | --- | --- |
| NOR | `lv1ldr.self` in the ros bank | 0x1BB20 in the 4.93 image (0x1B5A0 in its ELF carve; the ATA seed is cited at 0x1D1E0 for some 4.xx revisions) |
| NAND/eMMC | the loader the ros1 standby bank (0xC0000, records at 0x40480 / 0x100490, `lv0` extent 0x1E948) carries | 0x2E0A0 in a decrypted stage carve |

A revision that moves it is reported at its own offset, and when both media's
loaders are given they must carry the same four seeds - that is a cross-check
on the reading, not a requirement of the format.

The model follows the same order: `readout` / `readout-file` supplies the 32
channel-66 bytes exactly as the ROM reads them (K_lo, then K_hi) and is what
opens and verifies the container; `pck1` / `pck1-file` (or the older
`erk` / `erk-file`, the same 48 bytes under the other name) supplies PCK1, which
is what `ps3_self.c` opens the loaders and application SELFs with and what the
ATA/flash ladders and an HDD image's key sector are built from; `lv1ldr` and
`nand-loader` supply the console's own loader images, whose seed block is read
out and used for those ladders instead of the model's copy of the constants.
No per-console key is ever written to a log, only fingerprints.

## Files

| Path | Contents |
| --- | --- |
| `hw/ppc/rs6000_ps3.c` | machine `rs6000-ps3`: `ps3-mic`, `ps3-boot-rom` (mask ROM, container opener, register window), lv2 services, RSX front end, `ps3-vga` scanout |
| `hw/ppc/ps3_spu.c`, `ps3_spu.h`, `ps3_spu_isa.h` | SPU interpreter, channels, MFC transfers, instruction tables |
| `hw/ppc/ps3_self.c`, `ps3_self.h` | SELF opener (ERK/RIV ladder, CTR sections) |
| `hw/ppc/ps3_aes/` | AES-128/256, the ATA and encdec ladders, XTS over HDD sectors |
| `hw/ppc/ps3_vga.c`, `ps3_vga.h` | display: boot text, wordmark, HDMI EDID, guest scanout |
| `hw/ppc/ps3_audio.c`, `ps3_audio.h` | host audio side of the rsxaudio rings, and the mic rings |
| `scripts/ps3_flash_layout.py` | NOR/NAND TOC and region map: carve, place, regenerate |
| `scripts/ps3_hdd_create.py` | raw HDD image with the ATA key sector wrapped under PCK1 |
| `scripts/ps3_hdd_tree.py` | the console's own file tree (`dev_flash`, `dev_flash2`, `dev_flash3`, `dev_hdd0`) inside that image |
| `scripts/ps3_ram_dump.py` | dump or peek at guest RAM while the machine runs (QMP) |
| `hw/ppc/Kconfig`, `hw/ppc/meson.build` | wiring; gated on `CONFIG_PS3` |

## Build

### Windows (MSYS2, UCRT64)

```sh
pacman -S --needed mingw-w64-ucrt-x86_64-{gcc,ninja,pkgconf,glib2,pixman,python}

cd ~/qemu
mkdir -p build-ps3 && cd build-ps3
../configure --target-list=ppc64-softmmu \
    --without-default-features --enable-tcg --disable-werror --disable-docs
ninja
```

`configure` creates a Python venv under `build-ps3/pyvenv` and installs meson
into it, so the first run needs network access.  The result is
`build-ps3/qemu-system-ppc64.exe`.  Incremental rebuild after editing sources:

```sh
ninja -C build-ps3
```

`ninja` re-runs `configure` itself when `configure`/`meson_options.txt` change;
after editing a `Kconfig` or changing an option, re-run the `../configure`
command inside `build-ps3`.  `build*/` is ignored by git and only
`ppc64-softmmu` is built.

### Linux / other hosts

Same steps with the distribution's packages (`gcc`, `ninja-build`,
`pkg-config`, `glib2-devel`, `pixman-devel`, `python3-venv`).

### A GUI build, for the window

`build-ps3` has no display backend (`-display help` lists only `none`), which
is what the headless checks want.  For the guest window, configure a second
tree with SDL.  Run the configure from a **UCRT64 login shell**: in a plain
MSYS shell the compiler check picks a `cc` it cannot run and configure stops
early with `ERROR: Unknown target name '0'` instead of a compiler error.

```sh
pacman -S --needed mingw-w64-ucrt-x86_64-SDL2
MSYSTEM=UCRT64 /c/msys64/usr/bin/bash -lc '
  cd /c/Users/Thewoodsman/qemu && mkdir -p build-ps3-gui &&
  cd build-ps3-gui &&
  ../configure --target-list=ppc64-softmmu --enable-sdl --disable-werror &&
  ninja'
```

The SDL build also carries QEMU's audio backends, so the same binary plays the
guest's sound (`build-ps3` builds `dsound` too, but a display backend makes it
the one build that is enough on its own).  The model itself is identical in
both trees.

### CI

`.github/workflows/ps3-build.yml` builds the model on Linux, Windows and macOS,
x64 and arm64, with the same minimal configuration (`ppc64-softmmu`, TCG, SDL),
then smoke-tests the binary: `-M help` must list `rs6000-ps3` and
`-display help` must list `sdl`.  Runners: Ubuntu 26.04 (x64/arm64), Windows
Server 2025 (MSYS2 UCRT64), Windows 11 arm64 (MSYS2 CLANGARM64), macOS 13 (x64)
and macOS 15 (arm64).

## Run

The Windows binary links the MSYS2 DLLs, so from outside an MSYS2 shell put
`ucrt64\bin` on `PATH` first:

```sh
export PATH="/c/msys64/ucrt64/bin:$PATH"
Q=build-ps3-gui/qemu-system-ppc64.exe          # the SDL build
```

### Boot the chain, then vsh.self, in the window

```sh
$Q -M rs6000-ps3 -display sdl -vga rsx,gl=on \
   -bios .tmp/rom/rom.bin \
   -drive if=pflash,format=raw,file=.tmp/bootchain_flash.bin,readonly=on \
   -global ps3-boot-rom.readout-file=.tmp/dlt/readout.bin \
   -global ps3-boot-rom.dev-flash=C:/Users/Thewoodsman/Documents/rs3/dev_flash \
   -global ps3-boot-rom.dev-flash2=C:/Users/Thewoodsman/Documents/rs3/dev_flash2 \
   -global ps3-boot-rom.dev-flash3=C:/Users/Thewoodsman/Documents/rs3/dev_flash3 \
   -global ps3-boot-rom.vsh-run=on -global ps3-boot-rom.threads=on
```

`-vga rsx` is the RSX driver: it selects this machine's display device (the
scanout the guest's `cellGcm` calls program) and reports `display: rsx (gl=on)`.
`gl=on` demands a GL scanout from the display backend (SDL/GTK with GL), `gl=off`
keeps the CPU compose path, and omitting `gl=` lets the backend decide.  `-vga
rsx` is optional: the machine creates the RSX display either way, and `-vga help`
lists `rsx  PS3 RSX display`.

The window carries the chain's own lines (`SPU PAYLOAD: 67108864 INSTRUCTIONS`,
`LV0LDR.2 CONTAINER VERIFIED: 191152 BYTES`), then the VSH's stdout, then the
boot wordmark.  The XMB is not drawn by the model: it is `vsh.self`'s own frame
and reaches the window the way RPCS3's does - the guest's `cellGcm` calls
program the RSX display buffer and flip it, and the scanout presents what the
guest wrote there.

### A disk-only console: the 20 GB image, booted into the VSH

```sh
$Q -M rs6000-ps3 -display sdl \
   -global ps3-boot-rom.hdd-file=.tmp/hdd_fs.img \
   -global ps3-boot-rom.boot-medium=hdd \
   -global ps3-boot-rom.vsh-run=on -global ps3-boot-rom.threads=on
```

The image's `dev_flash`, `dev_flash2`, `dev_flash3` and `dev_hdd0` trees become
the guest's mounts (unpacked once into `.tmp/hdd_fs.img.tree`), so the console
comes up from nothing but its disk:

```
ps3-boot-rom: dev_flash from the HDD image (.tmp/hdd_fs.img.tree\dev_flash)
ps3-boot-rom: dev_hdd0 from the HDD image (.tmp/hdd_fs.img.tree\dev_hdd0)
ps3-vsh: .tmp/hdd_fs.img.tree\dev_flash\vsh\module\vsh.self: entry=0x6D5AC8, ...
```

### A NAND/eMMC console: the 12 GB image, flash and storage in one chip

The SuperSlim's 12 GB console has no HDD and no NOR: its firmware lives in an
eMMC chip that is mapped like NAND (256 MiB flash region at device offset
0x40000, the storage area past it).  `scripts/ps3_emmc_create.py` writes that
layout from a NAND dump, and the model boots from it with `boot-medium=emmc`:

```sh
$Q -M rs6000-ps3 -display sdl -vga rsx,gl=on \
   -global ps3-boot-rom.emmc-file=.tmp/emmc_12g.img \
   -global ps3-boot-rom.boot-medium=emmc \
   -global ps3-boot-rom.readout-file=.tmp/dlt/readout.bin \
   -global ps3-boot-rom.vsh-run=on -global ps3-boot-rom.threads=on
```

All three media stay supported, and each one is a boot target of its own:

| medium | argument | chain comes from | file tree comes from |
| --- | --- | --- | --- |
| NOR flash | `-drive if=pflash,format=raw,file=...` | the NOR image | `dev-flash*` properties or an HDD |
| HDD (raw) | `boot-medium=hdd` + `hdd-file` | the first 16 MiB of the disk | the disk's own `dev_flash*`/`dev_hdd0` |
| NAND/eMMC | `boot-medium=emmc` + `emmc-file` | the eMMC's flash region | the eMMC's storage area |

Each medium is asked for the container its own boot ROM opens.  On NOR (and on
a chain staged on a disk) that is `lv0ldr.2`.  On NAND/eMMC it is `metldr.2` in
the asecure_loader region - the region the mask ROM is pointed at - and
`lv0ldr.2` is what metldr opens once it runs, so a NAND flash that carries
`metldr.2` and no `lv0ldr.2` is the other boot path, not a damaged console:

```
ps3-boot-rom: NAND/eMMC medium: the ROM opens metldr.2 (the asecure_loader);
              lv0ldr.2 is metldr's own next stage
```

The container is verified against the console's own channel-66 readout, so an
eMMC image needs the readout of the console the dump came from.  With another
console's readout the check says exactly that and the recover process comes up
instead:

```
ps3-boot-rom: stop 2, MAC mismatch (metldr.2 at flash 0x840)
ps3-boot-rom: ### Vflash recovery mode
```

### The recovery application, when the checks fail

lv2 picks the application, not the command line: the chain must verify and
`vsh.self` must exist, otherwise the vflash recover process comes up instead.
The recovery program is the flash's own (`/dev_flash/sys/emerge/emer_init.self`):
run any of the commands above without a channel-66 readout and the model takes
that path itself:

```
ps3-boot-rom: ### Vflash recovery mode
ps3-boot-rom: no channel-66 readout; creating the vflash recover process
              (emergency program): /dev_flash/sys/emerge/emer_init.self, 555056 bytes
```

With the chain verified and `vsh.self` present it says `chain checks passed; lv2
starts /dev_flash/vsh.self` instead.
Emer_init's own screen is drawn by the guest through `cellGcm`/`cellVideoOut`
like the XMB is, so what the window shows is its frame, not a host rendition.

### Sound

The model drives QEMU's audio subsystem: the guest's rsxaudio serial ring is
the stereo mix that would go to HDMI and the AV multi out, and every 256-byte
block the guest publishes is converted to 48 kHz s16 and played.

```sh
# the host's default backend (drop -nodefaults: it suppresses the default
# -audiodev, which is what makes a run come up silent)
$Q -M rs6000-ps3 -display sdl -global ps3-boot-rom.hdd-file=.tmp/hdd_fs.img \
   -global ps3-boot-rom.boot-medium=hdd \
   -global ps3-boot-rom.vsh-run=on -global ps3-boot-rom.threads=on

# or name the backend, and capture instead of playing
$Q -M rs6000-ps3 -display none -audiodev wav,id=snd,path=.tmp/out.wav \
   -global ps3-boot-rom.audio=snd \
   -global ps3-boot-rom.hdd-file=.tmp/hdd_fs.img \
   -global ps3-boot-rom.boot-medium=hdd \
   -global ps3-boot-rom.vsh-run=on
```

`dsound` is the Windows default, `wav` writes a file, `none` is silence.  The
backend opening is reported as `ps3-audio: 48 kHz stereo out on "snd"` and the
guest's own start of the stream as `ps3-audio: sound driver running, serial
ring at 0x...`.  The microphone is the mirror image: capture voices on the same
audiodev feed `sys_mic`'s rings.

### `ps3-boot-rom` properties (the ones a boot needs)

| Property | Default | Meaning |
| --- | --- | --- |
| `rom-file` / `drive` | - | set by `-bios` and `-drive if=pflash,...` |
| `erk-file`, `pck1-file`, `readout-file` | - | the EID root key + RIV read out of the loader (PCK1), 48 raw bytes / the mask boot ROM's channel-66 key, 32 raw bytes, K_lo then K_hi |
| `pck1`, `erk` | - | the same 48 bytes as hex (96 digits); `pck1` is the console's name for it |
| `lv1ldr`, `nand-loader` | - | the console's loader image the ladder seeds are read from: a NOR `lv1ldr.self`, and/or a NAND/eMMC loader, bank carve or dump.  A SELF is opened with PCK1 (the published loader keyset is accepted for a retail image, and says so); both are read and must agree |
| `container` | `lv0ldr.2` | container to look for in the flash image |
| `dev-flash`, `dev-flash2`, `dev-flash3` | - | firmware trees unpacked from the flash's ROS, as an alternative to an image |
| `hdd-file`, `hdd-size` | - / 20G | raw disk image, and the size the model gives a fresh one (1 TB max) |
| `emmc-file`, `emmc-size` | - / 12G | eMMC image, and the size the model gives a fresh one |
| `boot-medium` | `flash` | which medium the chain is read from: `flash` (NOR), `hdd`, `emmc` |
| `recover` | off | boot with the EEPROM's recover flag set, i.e. into the recovery loop |
| `vsh-run`, `threads`, `ppu-trace` | off | enter the application, run its threads, log the PPU |
| `ppu-ticks`, `ppu-tick-ns` | 0 / 10 ms | bounded runs and the progress period |
| `pad-count`, `pad-types` | 1 / `standard` | ports 1..7; `standard`, `dualsense`, `move`, `navigation`, `guitar`, `drums`, `dj`, `dancemat`, `skateboard` |
| `boot-logo` | on | draw the console wordmark on the boot screen |
| `idle-off-seconds` | off | the console's own idle shutdown timer |
| `audio` | default backend | the `-audiodev` id the sound driver opens |

`-global ps3-vga.dump=FILE` writes the surface the display is presenting, so the
window's pixels can be inspected without a display.

## Checks

| Check | Command | Passing looks like |
| --- | --- | --- |
| device selftest + mask ROM replay | any run with `-bios` | `selftest passed (AES-128 KAT, sealed container round trip, mask ROM replayed by the SPU interpreter)` |
| container opener | `-drive if=pflash,...` with the readout | `container verified, 191152 bytes of payload` |
| ladder seeds from the console's own loader | `-global ps3-boot-rom.pck1=... -global ps3-boot-rom.lv1ldr=lv1ldr.self` (optionally `-global ps3-boot-rom.nand-loader=...` too) | `NOR lv1ldr: ...: ladder seed block at 0x1BB20 - the ATA and flash ladders run on the console's own seeds`, and `the NOR and NAND loaders carry the same four seeds` when both are given.  A loader with no block (or a mismatched pair) stops the run with the reason |
| a loader stage | `-global ps3-boot-rom.stage-elf=lv2ldr.self` | exit 0, `stop 48 at ...` (the loaders' signal) |
| lv0 and above | `-global ps3-boot-rom.ppu-elf=lv0.self` | exit 0 at the next hand-off |
| vsh.self | `-global ps3-boot-rom.vsh-run=on` | `ps3-vsh: ... entry=0x6D5AC8 ... PPU entering it`, then `sys_prx_load_module` and the module set |
| the RSX front end | a boot with the RSX display | `ps3-rsx: device window ...`, `gcm context ...`, `ps3-rsx: draw done: ... pixel(s)` then `ps3-vga: guest owns the scanout` |
| sound | a boot with `-audiodev wav,id=snd,path=.tmp/out.wav -global ps3-boot-rom.audio=snd` | `ps3-audio: sound driver running, serial ring at 0x...` and a `.wav` whose samples are what the guest published |
| the CI smoke test | `qemu-system-ppc64 -M help` | `rs6000-ps3` is listed |

The two guest programs are built with the PS3 PPU toolchain in this tree:

```sh
AS=/c/msys64/usr/local/ps3dev/ppu/bin/powerpc64-ps3-elf-as.exe
LD=/c/msys64/usr/local/ps3dev/ppu/bin/powerpc64-ps3-elf-ld.exe
$AS -mcell -o .tmp/sys_audio_test.o .tmp/sys_audio_test.S
$LD -Ttext=0x02000000 -e _start -o .tmp/sys_audio_test.elf .tmp/sys_audio_test.o
```

## Tools in `scripts/`

| Tool | Use |
| --- | --- |
| `ps3_flash_layout.py list nor` / `dump` / `get` / `build` | read the flash TOC and regions, carve them out, rebuild an image byte for byte |
| `ps3_hdd_create.py --erk-file ... --size 20G -o disk.raw --verify` | raw disk: sector 0 is the ATA key block under PCK1, the rest XTS; `--size` takes `20G`/`512M`/`1MiB` or bytes, up to 1 TB |
| `ps3_hdd_tree.py` | put `dev_flash`, `dev_flash2`, `dev_flash3`, `dev_hdd0` trees into such an image (and take them out again) |
| `ps3_ram_dump.py --launch` / `--read ... --disasm` | dump guest RAM from a running machine over QMP, then read or disassemble it in place |
| `ps3_emmc_create.py [dump] --identify` / `-o emmc_12g.img --tree-root ...` | identify a NAND/eMMC dump (model, firmware, ldr revision, region table), then build the 12 GB image: flash region at 0x40000 and the `dev_flash*`/`dev_hdd0` tree past 256 MiB |

`scripts/PS3_TOOLS.md` is the index for those four: inputs, outputs, workflows
and what each one refuses to do.  No key is ever printed: the tools report
fingerprints only.

The key chain itself has a tool on the ps3tools side, `chain_keys.py`, next to
`bootldrdec.py` and `find_erk.py`:

| Invocation | What it does |
| --- | --- |
| `chain_keys.py --flash dump.bin --readout ch66.bin --scan-lv0 --eid0 eEID.bin` | open the container, read PCK1 out of it (accepted only when it authenticates the EID0's CMAC) |
| `chain_keys.py --pck1 <96 hex> --lv1ldr lv1ldr.self --nand-loader nand.bin --qemu` | open both loaders, report the seed block's offset against the NOR and NAND reference offsets, derive the ATA and encdec keys, and print the `-global` lines this model takes |
| `chain_keys.py --selftest` | seal a container and a loader, then prove each rung on them: tag, root-header check, seed discovery at both media's offsets, the ladder against a second implementation, and the EID0 check |

## Status

Working: the mask ROM replay and container opener, the flash/HDD/flash-image
paths (including the ATA ladder and XTS), the stage-by-stage chain, the serial
and RAM-dump tooling, the RSX front end (FIFO, NV4097 dispatch, a software
rasterizer), the display path (`cellVideoOut` -> EDID -> 720p/1080p -> the
guest's scanout), the pads/keyboard/controller input, the microphone, the front
LED and the sound rings.

Open: the real `vsh.self` boots, loads its module set (`paf_ext`, `qglbase`,
`msmw1/2`, `libsre`, `libadec`, `libac3dec`, `sys_audio`, `libfs_utility2`, ...),
completes `cellGcmInit` and reaches the RSX context, then sits in its own poll
loop waiting on services it expects from the platform layer (the device/media
event loop and the `system_plugin.rco` load are the two it reports).  The XMB
frame therefore has not been drawn yet; `emer_init` is the application that
comes up when the checks do not pass, and it draws its own screen through the
same cellGcm path.
