# PS3 / Cell model (`rs6000-ps3`)

A local research model of the PS3 boot path inside this QEMU checkout: the Cell
memory interface controller, the SPU mask ROM and its container opener, the SPU
interpreter the decrypted loaders run on, a SELF opener for the later stages,
the RSX front end the graphics library talks to, and enough of lv2 for the real
`vsh.self` to run under it.  It is an experiment, not an upstream contribution:
see `AGENTS.md` and `docs/devel/code-provenance.rst`.  Nothing here is needed to
build or use the rest of QEMU.

This file is the short form: what to build, what to run and what passing looks
like.  The reasoning behind each behaviour is in this file and in the comments
next to the code it describes: the model's logs are the record of the runs that
settled each answer, and every one of them names the call, the address and the
guest state it read.

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
No per-console key, and no value derived from one, is ever written to a log.

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
$Q -M rs6000-ps3 -display sdl,gl=on -vga rsx,gl=on \
   -global ps3-boot-rom.own-rom=on \
   -drive if=pflash,format=raw,file=.tmp/bootchain_flash.bin,readonly=on \
   -global ps3-boot-rom.hdd-file=.tmp/hdd_fs.img \
   -global ps3-boot-rom.readout-file=.tmp/dlt/readout.bin \
   -global ps3-boot-rom.vsh-run=on -global ps3-boot-rom.threads=on
```

`own-rom=on` is the form to run and the form to ship: the chain is opened,
decrypted and verified by the model's own container opener (`ps3_rom_open`),
and no mask boot ROM is supplied, loaded or executed, so a distribution of this
tree carries no Sony code.  The stages, their checks and the chain of trust are
the same ones the ROM path runs - the only thing dropped is the replay of the
0x400-byte ROM on the SPU interpreter.

Passing `-bios rom.bin` instead runs the ROM replay path, which is there to
check the model's opener against the ROM's result.  That means shipping a dump
of Sony's boot ROM, so it is a developer check, not a way to run the model.
`-bios` together with `own-rom=on` is refused: a run that says it does not use
the mask ROM must not have one loaded behind it.

The application comes from the image's own tree: `hdd-file` (or `emmc-file`)
carries `dev_flash`, `dev_flash2` and `dev_flash3`, and those are mounted from
it.  There are no folder-backed properties any more - a run that has no image is
a run with no `dev_flash`, which is exactly what recovery is for.

`-vga rsx` is the RSX driver: it selects this machine's display device (the
scanout the guest's `cellGcm` calls program) and reports `display: rsx (gl=on)`.
`gl=on` demands a GL scanout from the display backend (SDL/GTK with GL), `gl=off`
keeps the CPU compose path, and omitting `gl=` lets the backend decide.  `-vga
rsx` is optional: the machine creates the RSX display either way, and `-vga help`
lists `rsx  PS3 RSX display`.

### The ERK, read out of the loader

The console's own `lv1ldr` is sealed with the EID root key, so the key that
opens it is the ERK the ATA and encdec ladders run on - the loader image is where
that key comes from, and nothing has to be handed over separately:

```sh
$Q -M rs6000-ps3 -display sdl \
   -drive if=pflash,format=raw,file=.tmp/bootchain_flash.bin,readonly=on \
   -global ps3-boot-rom.lv1ldr=lv1ldr.self \
   -global ps3-boot-rom.hdd-file=.tmp/hdd_fs.img \
   -global ps3-boot-rom.vsh-run=on -global ps3-boot-rom.threads=on
```

```
ps3-boot-rom: NOR lv1ldr: PCK1: ladder seed block at 0x1BB20 - the ATA and flash
              ladders run on the console's own seeds; the ladder's ERK is the
              key given for it (PCK1)
```

A retail loader out of an update package carries the published keyset instead
of a per-console key, and the line says so (`the ladder's ERK is the loader's
published keyset`) rather than calling a package copy the console's.  When a key
is given as well (`pck1=`, `erk-file=`), it is tried first and, if the image is a
retail one that cannot carry it, the given ERK is kept for the ladder.

### A `.2` loader: the ERK it carries is wrapped

The loaders on a Metldr.2 console hold their ERK wrapped under the console's
eid_root_key, so no keyset opens them directly.  Give it (the `pck1` property)
and the model unwraps every 16-byte aligned window of the image's first 0x10000 bytes,
letting the loader's own root-header check say which one is the ERK; the winner
is then opened for real before it becomes the ladder's key:

```sh
$Q -M rs6000-ps3 -display sdl \
   -drive if=pflash,format=raw,file=.tmp/bootchain_flash.bin,readonly=on \
   -global ps3-boot-rom.lv1ldr=lv1ldr.2.self \
   -global ps3-boot-rom.pck2=$EID_ROOT_KEY \
   -global ps3-boot-rom.hdd-file=.tmp/hdd_fs.img \
   -global ps3-boot-rom.vsh-run=on -global ps3-boot-rom.threads=on
```

```
ps3-boot-rom: the console's eid_root_key read; the .2 loaders' ERK can be unwrapped
ps3-boot-rom: lv1ldr.2.self: the value at 0xAC0 unwraps under eid_root_key into the key
              this loader was sealed with
ps3-boot-rom: NOR lv1ldr: eid_root_key: ladder seed block at 0xA40 - ... the ladder's ERK
              is the ERK the loader carries, unwrapped under eid_root_key
```

A wrong eid_root_key unwraps nothing, and a `.2` loader given without one stops with
`a .2 loader needs the console's eid_root_key (pck2/pck2-file)` rather than guessing.

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
eMMC chip that is mapped like NAND (the 256 MiB flash area starts at device
offset 0, the storage area straight after it at 0x10000000).
`scripts/ps3_emmc_create.py` writes that layout from a NAND dump, and the model
boots from it with `boot-medium=emmc`:

```sh
$Q -M rs6000-ps3 -display sdl,gl=on -vga rsx,gl=on \
   -global ps3-boot-rom.emmc-file=.tmp/emmc_12g.img \
   -global ps3-boot-rom.boot-medium=emmc \
   -global ps3-boot-rom.readout-file=.tmp/dlt/readout.bin \
   -global ps3-boot-rom.vsh-run=on -global ps3-boot-rom.threads=on
```

All three media stay supported, and each one is a boot target of its own:

| medium | argument | chain comes from | file tree comes from |
| --- | --- | --- | --- |
| NOR flash | `-drive if=pflash,format=raw,file=...` | the NOR image | an HDD or eMMC image, else the ROS banks |
| HDD (raw) | `boot-medium=hdd` + `hdd-file` | the first 16 MiB of the disk | the disk's own `dev_flash*`/`dev_hdd0` |
| NAND/eMMC | `boot-medium=emmc` + `emmc-file` | the eMMC's flash region | the eMMC's storage area |

A NAND/eMMC chip keeps the same containers its NOR sibling does, at the front of
its flash area, and the 12 GB SuperSlim is the eMMC console while the 250 GB and
500 GB 40xx are NOR: both put the asecure_loader region at 0x800 and metldr's
container at 0x840, the region running to 0x2F000 with a ~0xF920-byte payload and
the rest zero-filled.  `CECH4201A.NAND.BIN` carries the name `metldr.2` at flash
0x820 and the header at 0x840, and that is the only copy anywhere in its 256 MiB.  The model resolves it by name there - it is not a fallback.
The eMMC's arena is 256 MiB from offset 0 of the chip, so those are absolute
offsets in the image as well: the region table sits at 0x200, and only a dump
that kept a 256 KiB reader preamble in front of the region has it at 0x40200.
The eMMC's own tree at 0x10000000 carries `dev_flash*`, `dev_hdd0` and the empty
`dev_hdd1` cache partition.

That container is sealed for the chip's own channel-66 root key.  Given a readout
that opens a NOR image, the eMMC's metldr still reports a MAC mismatch (the
ROM's `stop 2`), and the console falls through to the vflash recovery program,
which is the correct behaviour for a chip whose first container this ROM cannot
open.  Give the medium its own key when it differs:

```sh
   -global ps3-boot-rom.nand-readout-file=.tmp/dlt/4201A-readout.bin \
```

`nand-readout` takes the same 32 bytes as 64 hex digits, and either one is used
by both the chain check and the ROM whenever `boot-medium=emmc`; a failure then
names the container and the address it was found at.

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
| `erk-file`, `pck1-file`, `readout-file` | - | the console's 48-byte ERK + RIV (the name `pck1` gives the same value), or the mask boot ROM's channel-66 key, 32 raw bytes, K_lo then K_hi.  Optional: without it the ERK is the one the loader in `lv1ldr`/`nand-loader` carries |
| `pck1`, `erk` | - | the same 48 bytes as hex (96 digits); `pck1` is the console's name for it |
| `lv1ldr`, `nand-loader` | - | the console's loader image the ERK and the ladder seeds are read from: a NOR `lv1ldr.self`, and/or a NAND/eMMC loader, bank carve or dump.  The key that opens it *is* the ladder's ERK, so a loader alone keys the storage ladder; the published loader keyset is accepted for a retail image and says so, and both images are read and must agree |
| `pck2`, `pck2-file` | - | the console's eid_root_key (the ERK+RIV, 48 bytes; the property names are the old ones and are kept for scripts).  Only a `.2` loader needs it: that image carries its ERK wrapped, and eid_root_key is what unwraps it - the ERK the unwrap yields is then the ladder's key |
| `container` | `lv0ldr.2` | container to look for in the flash image |
| `hdd-file`, `emmc-file` | - | the drive, or the eMMC, the firmware trees and the application are mounted from |
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
| a `.2` loader, whose ERK is wrapped | `-global ps3-boot-rom.lv1ldr=lv1ldr.2.self -global ps3-boot-rom.pck2=<96 hex>` | `the value at 0x... unwraps under eid_root_key into the key this loader was sealed with`, then `NOR lv1ldr: eid_root_key: ladder seed block at 0x...` with `the ladder's ERK is the ERK the loader carries, unwrapped under eid_root_key`.  A wrong eid_root_key finds no window, and a `.2` loader with no eid_root_key given stops and says so |
| ladder seeds and ERK from the console's own loader | `-global ps3-boot-rom.lv1ldr=lv1ldr.self` - no key on the command line | `NOR lv1ldr: ...: ladder seed block at 0x1BB20 - the ATA and flash ladders run on the console's own seeds; the ladder's ERK is <where it came from>`, and `the NOR and NAND loaders carry the same four seeds` when both are given.  A loader with no block (or a mismatched pair) stops the run with the reason.  `pck1=`/`erk-file=` still override the ERK, and a retail image cannot carry a per-console key, so a given ERK is kept and that is reported |
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
| `ps3_emmc_create.py [dump] --identify` / `-o emmc_12g.img --tree-root ...` | identify a NAND/eMMC dump (model, firmware, ldr revision, region table), then build the 12 GB image: flash region at 0x40000 and the `dev_flash*`/`dev_hdd0`/`dev_hdd1` tree past 256 MiB |

`scripts/PS3_TOOLS.md` is the index for those four: inputs, outputs, workflows
and what each one refuses to do.  No key is ever printed, and nothing derived
from one is printed either.

## Status

Working: the mask ROM replay and container opener, the flash/HDD/flash-image
paths (including the ATA ladder and XTS), the stage-by-stage chain, the serial
and RAM-dump tooling, the RSX front end (FIFO, NV4097 dispatch, a software
rasterizer), the display path (`cellVideoOut` -> EDID -> 720p/1080p -> the
guest's scanout), the pads/keyboard/controller input, the microphone, the front
LED and the sound rings.

`mms_db` is the process's own library: `vsh.self` exports 563 functions of it,
and every mms module on the flash imports it (`mms.sprx` 185, `mms_db_full.sprx`
180, `mms_maintenance.sprx` 90).  Its entry carries the stub attribute, because
lv2 asks the *process* that owns a stub library for it - and here that process
is the VSH itself.  The process scan therefore registers stub-attribute entries
whose function descriptors live in the VSH image, and refuses the ones whose
descriptors are elsewhere (the kernel's `sys_io`/`sys_fs`); before that, every
mms import was answered 0 by a planted stub and the first worker that used the
answer as a pointer died on the 0x700 program-interrupt vector.

Open: the real `vsh.self` boots, loads its module set (`paf_ext`, `qglbase`,
`msmw1/2`, `libsre`, `libadec`, `libac3dec`, `sys_audio`, `libfs_utility2`, ...),
completes `cellGcmInit` and reaches the RSX context, starts `mms.sprx` with its
`mms_db` imports linked, and then reports two things of its own: its resource
inflate fails (`incorrect header check`, `invalid distance too far back`, ...)
and `CreateVmReserveArea: cellFsTruncate2 failed: 0x80010003` - the write side
of `sys_fs` it wants for its VM reserve area is not implemented, and the data
its resource loader inflates is not coming out of a plain read of
`system_plugin.rco` (a read of that file is byte-faithful, checked at 0x47EE4).
The XMB frame therefore has not been drawn yet; `emer_init` is the application
that comes up when the checks do not pass, and it draws its own screen through
the same cellGcm path.

The XMB's resource file can be had back out of a run: with `PS3_DUMP_RCO=<dir>`
in the environment, the model assembles every `.rco` the loader reads from the
8 KiB chunks it asks for (`read` always lands in one scratch buffer, so the file
never exists whole in RAM) and writes the copy there.
`/dev_flash/vsh/resource/system_plugin.rco` came back as 296,356 bytes, magic
`FRP\0`, version 0x130.  Its TOC is a zlib stream at 0xB0 - 61,856 bytes that
unpack to 190 entries: MainTree over an ImageTree (81), a SoundTree (9), a
TextTree (20), an ObjectTree (9) and an AnimTree (8) - and the file carries
three more streams (UTF-16 text tables at 0x61B4, 0x6B7C, 0x7544) and the 17
VAG payloads of its sound tree in the tail.  The copy holds what the reads
delivered, not the whole file: the loader reads the head and the sound section
in its first pass (0x0..0x81A4, then 0x2FEE4..0x485A4) and leaves the image
table unread until it has a screen to draw it on, so the gap in the copy is the
loader's own read pattern - the file on the extracted dev_flash tree is
byte-identical to the source, 0 differences over all 296,356 bytes.  The
inflate-range probe scans the reading thread at every lv2 call and the other
threads every 32nd, over a 2,000-call window, and reports when no stream is
left on any thread's stack to read.  Reading the wrapper's frame is not enough
for the VSH's own zlib: by the time lv2 is entered the wrapper has ended its
stream and nothing on the stack still names the ranges, so the probe records
r3..r6 at the wrapper's entry instead.  The entry is 0x40BE7C in this image:
it saves r5/r6/r3/r4 as `next_in`/`avail_in`/`next_out`/`avail_out` of a
0x38-byte stream, calls inflateInit_, inflate(..., Z_FINISH) and inflateEnd,
and formats `inflate failed - %s` from 0x690318 - found by dumping RAM and
scanning for the `lis`/`addi` pair that materialises that string's address (the
first reference is at 0x40BF70).  The hook itself is a function pointer the
machine installs (`ps3_pc_hook_fn`), so it costs one predictable branch per
translation block and nothing at all unless a dump was asked for.

`sys_config` is a real interface now, not an acknowledgement: `sys_config_open`
remembers the queue, `sys_config_add_service_listener` announces the two
implicit padmanager services (0x11/0x12) to it the way lv2 does - one queue
event carrying the event id in `data2` and the buffer size in `data3` - and
`sys_config_get_service_event` writes the `sys_config_service_event_t` back,
HID descriptor included.  The VSH's `_cfg_ev_hndlr` parks on its config queue
until a listener asks for those services, and the announcement is what wakes
it.

A worker that loops on a low-page exception vector is reported with the vector,
`SRR0`/`SRR1` and the word it faulted on, then retired (an unresolved-import
worker retires the same way), so the process that is waiting on its lock moves
on instead of stopping there.  The recovery application's own loop is intact:
`emer_init` prints `factory mode ON recover flag[ff]`, reports
`ErrorPage[6] Code[-2147290383]` (0x8002F2F1, the update search it cannot
complete), asks for `sys_sm_shutdown(0x100)` and is started again by the warm
reset.
