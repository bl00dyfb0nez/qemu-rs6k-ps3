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

### ch66 is the console's key; PCK1 is carried by metldr.2

The 32 bytes the boot path calls channel 66 are what the SPU's own channel
returns; the mask ROM reads them at 0x148, expands the key ladder from them and
opens the medium's first container with it.  They are **per console**, not a
public key: the same 32 bytes open only the containers sealed for that console.
Measured here, the PC tool's readout opens that console's `lv0ldr` and `metldr`
(MAC PASS) and both containers of `CECH4301C.NOR.BIN` fail (MAC FAIL), as do
CECHL's.  What is public is the container format and the published package key,
not a console's readout.  No NOR/NAND/eMMC dump carries it.

The per-console keys are one and two levels in:

1. **ch66 opens `metldr.2`** - the asecure_loader container the mask ROM is
   pointed at on both media (on NOR the model also finds `lv0ldr.2` at
   0xFC0000, which is the bootldr slot).  **metldr carries PCK1**, the 48-byte
   per_console_root_key_1 (32 key + 16 RIV): it copies it into local store
   0x00..0x30 and `isoldr` clears it.  PCK1 is what the ATA and flash ladders
   are run on, and what an HDD image's key sector is wrapped under.
2. **PCK1 opens the loader** - `lv1ldr.self` on a NOR console, the loader its ros
   bank carries on a NAND/eMMC one - and what comes out of it is the ladder:
   **the EID root key (with its RIV) and the four static seeds** (SB-indiv data
   and tweak, encdec data and tweak) that PCK1 is run on for the ATA and flash
   keys.  The same ERK/RIV pair is what opens the application SELFs
   (`vsh.self` and the rest), so it is the key the SELF opener works from, not
   the container key.

So a dump carries the container and, inside metldr, that console's PCK1 - but
never ch66 itself, which belongs to the ROM.  The model's selftest uses a fixed
32-byte *test vector* on channel 66; a capture of it proves the read path, not
a console key.  `ch66-capture` records the eight reads the ROM made.

The loader's seed block sits at a different offset on each medium, and it is
never assumed: the model looks for the published constants first, and when an
image does not carry them (a revision that changed the seeds, a loader out of
this console) it locates the block **by structure** instead.  Every 0x20-aligned
window of four 32-byte runs that read as key material is a candidate, both of
the loaders' interleaves are tried, and what accepts one is the console's own
storage: the keys the window derives have to turn the stored tree sector back
into its `PS3HDFS1` superblock, through the ATA ladder for an HDD and the encdec
ladder for an eMMC.  Nothing about the block's position or its values is baked
in.  Every medium that can answer has to say yes, so with both media given the
whole block is pinned; with one, the pair that medium uses is what is proved and
the window is reported where the proof found it.

The offsets each medium has been seen to use (reported, never required):

| Medium | Where | Offset seen |
| --- | --- | --- |
| NOR | `lv1ldr.self` in the ros bank | 0x1BB20 in the 4.93 image (0x1B5A0 in its ELF carve; the ATA seed is cited at 0x1D1E0 for some 4.xx revisions) |
| NAND/eMMC | the loader the ros1 standby bank (0xC0000, records at 0x40480 / 0x100490, `lv0` extent 0x1E948) carries | 0x2E0A0 in a decrypted stage carve |

A revision that moves it is reported at its own offset (and the structural
search says how many candidates it had to try), and when both media's loaders
are given they must carry the same four seeds - that is a cross-check on the
reading, not a requirement of the format.

The model follows the same order: `readout` / `readout-file` supplies the 32
channel-66 bytes exactly as the ROM reads them (K_lo, then K_hi) and is what
opens and verifies the container; `pck1` / `pck1-file` (or the older
`erk` / `erk-file`, the same 48 bytes under the other name) supplies PCK1, which
is what `ps3_self.c` opens the loaders and application SELFs with and what the
ATA/flash ladders and an HDD image's key sector are built from; `lv1ldr` and
`nand-loader` supply the console's own loader images, whose seed block is read
out and used for those ladders instead of the model's copy of the constants.
No per-console key, and no value derived from one, is ever written to a log.

### What the South Bridge does that the model does not

The keys above are not only derived, they are installed.  ENCDEC sits in the
South Bridge, and the host drives it from LV1 (Storage Manager in LPAR1, through
`sb_iso_spu_module.self` / `sv_iso_spu_module.self`): KGEN1 and KGEN2 exchange
host and device randoms, KSET carries a command under the resulting session
key, and the payloads use AES-CBC-192 - the static keys before the exchange,
selected by SB bus id v2, and the session key after it.  A KSET payload also
carries 24 magic bytes the device checks, and the ATA-key payload is laid out
differently from the ENCDEC-key one.  KGEN_FLASH resets the device, SB_CLEAR is
sent after the ATA keys are cleared, and 0x88 is the command `ps2_netemu` uses
for .VME cards and `ISO.BIN.ENC`.

Tweak handling differs by medium, and that is the part with a bearing on the
images here: HDD sectors reach LV1 with the tweak already XORed, while VFLASH
sectors are not - LV1 keeps a DMA region of sector numbers, ENCDEC encrypts
those tweaks, and LV1 pre- and post-XORs the encrypted values.  A patched LV1
that kills that XOR leaves VFLASH encrypted with the data key alone.

`ps3_xts_crypt_sector()` does both halves in one place - XOR with
`AES(tweak_key, sector)`, the data pass, XOR again - so the model is the
two-layer construction with the DMA step folded in, and `ps3_encdec.py
--storage` writes the "killed XOR" case above.  What that does not prove is
that a retail LV1 would read the result: that needs ENCDEC's encrypted tweak to
be exactly the sector number under the same key, which the model's known-answer
test pins for the model's half and not for Sony's.  The channel, the KSET
framing, the SB bus id selection and 0x88 are not modelled anywhere here; keys
on real hardware are set from the console's own Linux driver (`ps3encdec`) or
from LV1, never from these tools.  The static keys live in the two modules
named above; they are Sony's, and none of that material is carried in this
tree.

## The channel map: all 128 entries, and the loader's window

The SPU's channel space is 128 numbers wide (0x00-0x7F), and a model that
answers only the channels its own boot path happens to use cannot tell "nothing
is posted" from "this number means nothing".  `hw/ppc/ps3_spu.c` therefore
carries one table of all 128 entries - name, direction, implemented - and every
access goes through it.  The names and directions are the ISA's channel table.
The reserved numbers are named only where this console's own code uses them:

| Range | Model |
| --- | --- |
| 0x00-0x1E | the ISA's named channels, with storage and the counts/blocking rules the ISA gives them (event, signal, decrementer, SRR0, the MFC registers, mailboxes); 0x05, 0x06 and 0x0A stay reserved |
| 0x1F-0x3F | reserved, unimplemented |
| 0x40-0x44 | the loader's message block (below), anchored by the mask ROM itself |
| 0x45-0x47 | named by the ISA (bookmark, perf-monitor start/stop), unimplemented |
| 0x48, 0x4A-0x7F | reserved, unimplemented |
| 0x49 | the loader version, two words, read by isoldr/metldr |

34 of the 128 are implemented.  A reserved or named-but-unimplemented channel
behaves as a channel with no producer and no consumer: `rchcnt` is 0, `rdch`
blocks, and `wrch` is dropped and counted - never answered with a made-up zero
word, which is what the old `default:` arm did.  `rchcnt` is legal on an
outbound channel too - on 0x44 it is the room the host posted, while 0x40
reports 0 because the model keeps no queue behind the command word - so only
`rdch` requires a readable direction.  A blocking access now names what it
stopped on:

    blocked on a channel at 0x424 after 10 instructions
        (ch 0x41 loader status in: zero depth)

and every run that touches a channel prints the map's own view of it:

    ps3-spu: channels: 34 of 128 modelled, 13 touched
        (0x03,0x04,0x0D,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x42)

That line is a measurement, not a listing.  On a rejected 4301C container the
ROM stops at 0x1E4 (the tag check), so the set is the 13 channels it executed
before that point, and they are exactly the disassembly's channel instructions:
`rdch $36,$ch13` (machine status), `rdch $82/83,$ch3/4` (signal notify), the MFC
address/size/tag writes around 0x250, the tag-mask and tag-update writes at
0xF8/0x220, the tag-status read on 0x18 and `rdch $35,$ch66` at 0x148.  A
container that opens runs on to `wrch $ch64,$1` at 0x3C4, so 0x40 joins the set
(14); metldr's payload then adds 0x1D (SPU_RdInMbox, 15), while lv0ldr's payload
does not (14).  A run that hits a number outside the map says so:

    ps3-spu: channels: 1 channel(s) with an access the model does not define: 0x2E reserved x3

Only two images in this tree decode as SPU code - `metldr.2` and `lv0ldr.2`;
their channel instructions are the table below.  The earlier claim that
lv0ldr.2 also reads 0x55 and 0x75 with `rchcnt` does not survive the full
listing: lv0ldr.2 has exactly two `rchcnt`s, both on 0x17, and metldr has six,
on 0x17/0x1C/0x1D/0x1E/0x49.  Those two rows are removed rather than modelled
on a decode artifact.

| Channel | Use | What the code does |
| --- | --- | --- |
| 0x40 (64) | `wrch`, ROM x1, lv0ldr.2 x4 | stage -> PPU command word.  The ROM writes 1 at 0x3C4 and falls through to 0x400; `0xCE0` writes 0 then 2, `0xDF4`/`0xE14` a computed word then 2 - so **2 terminates a message** |
| 0x41 (65) | `rdch`, nothing that decodes | PPU -> stage status word.  Depth 0 until posted, a read then blocks |
| 0x42 (66) | `rdch`, mask ROM x8 | the 32-byte root key the ROM expands at 0x148 (the channel-66 section above) |
| 0x43 (67) | `rdch`, lv0ldr.2 x2 | PPU -> stage data, **finite**.  `0x1520` drains one word per pass until its counter reaches 0x17 (23 words), then `0x1560` reads 338 more, merging each into a buffer with `lqx`/`shufb`/`stqx`; both loops test the counter, never the value |
| 0x44 (68) | `wrch`, nothing that decodes | stage -> PPU data word.  Room is 0 until the host posts a sink, so the first write blocks instead of vanishing |
| 0x49 (73) | `rchcnt`, isoldr/metldr | loader version, two words, as a depth read: no word is consumed |

The window's four directions are anchored on the ROM's own use: at 0x3C4 the
mask ROM writes 1 to 0x40 and the next instruction is the hand-off, so 0x40 is
the stage's command word out and every word written there is recorded - a
`rom-exec` run reports `1 command(s) out on 0x40, last 0x1` before the payload
has run at all.  Producers are named on the command line, so nothing is
invented: `loader-status=` posts the words 0x41 hands over, `loader-feed=`
installs the finite 0x43 feed (a two-word feed drains and then blocks), and
`loader-sink=` posts the room 0x44 accepts.  All three default to nothing,
which is what a stage sees before the PPU side writes: a depth of 0 and a
blocking access.  A `loader-sink=4` run reports the sink draining:

    ps3-spu: loader channels: 1 command(s) out on 0x40, last 0xAA;
        0 status, 0 feed word(s) left; 3 sink word(s) left, 1 word(s) out on 0x44

What is still inference rather than measurement: that 0x41 and 0x44 are the
*opposite* directions of 0x40 and 0x43.  No image in this tree that decodes uses
either, so the pairing comes from the block's shape; the model implements it
because a channel with no direction is worse than a named guess, and
`scripts/ps3_loader_channels_test.py` pins the behaviour: all three depths are 0
with nothing posted, a posted status word reads once, a two-word feed drains and
then blocks, a 0x44 write blocks with no sink and drains a posted one, and a
reserved channel is counted as an access the map does not define.

## Files

| Path | Contents |
| --- | --- |
| `hw/ppc/rs6000_ps3.c` | machine `rs6000-ps3`: `ps3-mic`, `ps3-boot-rom` (mask ROM, container opener, register window), lv2 services, RSX front end, `ps3-vga` scanout |
| `hw/ppc/ps3_spu.c`, `ps3_spu.h`, `ps3_spu_isa.h` | SPU interpreter, the 128-entry channel map with per-channel accounting, MFC transfers, instruction tables |
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
ps3-boot-rom: NOR lv1ldr: PCK1: ladder seed block at 0x1BB20, found by the
              published constants - the ATA and flash ladders run on the
              console's own seeds; the ladder's ERK is the key given for it (PCK1)
```

An image whose block is not the published one is read just the same, located by
structure and confirmed against the storage it keys:

```
ps3-boot-rom: NOR lv1ldr: no published seed block; the window at 0x26000 was the
              1410th candidate whose keys open the console's storage
ps3-boot-rom: NOR lv1ldr: ...: ladder seed block at 0x26000, located by
              structure, by the keys it derives - ...
```

The search needs a storage image it can prove the window against; with none,
the line says so (`the block can be located by structure only against a storage
image it keys`) instead of accepting a guess.

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
boots from it with `boot-medium=emmc`.  Past the last byte the dump covers, the
area is written out as erased flash - 0xFF, which is what a chip returns from
blocks it has never written - so the tail from the dump's end (and always
0xF000000..0xFFFFFFF) is padding rather than a hole in the file:

```sh
$Q -M rs6000-ps3 -display sdl,gl=on -vga rsx,gl=on \
   -global ps3-boot-rom.emmc-file=.tmp/emmc_12g.img \
   -global ps3-boot-rom.boot-medium=emmc \
   -global ps3-boot-rom.own-rom=on \
   -global ps3-boot-rom.lv1ldr=lv1ldr.self \
   -global ps3-boot-rom.erk-file=.tmp/erk48.bin \
   -global ps3-boot-rom.vsh-run=on -global ps3-boot-rom.threads=on
```

`own-rom=on` is what makes this medium boot to the XMB.  The chain it runs is
not the mask ROM's: the model opens the medium's own loader (`lv1ldr`) with the
keyset or PCK1 it carries, reads the ATA and flash ladder seeds out of it, and
runs those ladders on the ERK - the same three inputs the firmware's own
loader uses.  That is why neither a channel-66 readout nor the dump's
per-console seal is needed on this path.

The builder seals the storage area with the console's own ERK when one is named
(`--erk-file erk48.bin`): PCK1 through the static encdec seeds gives the data
and tweak keys, and every 512-byte sector past 0x10000000 is XTS-AES-128 with
its own sector number as the tweak.  That is the same `ps3_xts_crypt_sector`
the HDD's data area uses - the tool is built from
`hw/ppc/ps3_aes/{aes,ps3_aes,ps3_encdec}.c`, so an image it writes is one the
model reads back - and the flash area stays plaintext NAND.  The seal runs past
2 GiB, so the tool is compiled with 64-bit offsets and seeks through the
platform's 64-bit call, checking where it landed; the build line is printed and
is part of what makes it rebuild.  Without an ERK the tree is stored as it
stands and the model says so and reads it unkeyed.

All three media stay supported, and each one is a boot target of its own:

| medium | argument | chain comes from | file tree comes from |
| --- | --- | --- | --- |
| NOR flash | `-drive if=pflash,format=raw,file=...` | the NOR image | an HDD or eMMC image, else the ROS banks |
| HDD (raw) | `boot-medium=hdd` + `hdd-file` | the first 16 MiB of the disk | the disk's own `dev_flash*`/`dev_hdd0` |
| NAND/eMMC | `boot-medium=emmc` + `emmc-file` | the eMMC's flash region | the eMMC's storage area |

A NAND/eMMC chip keeps the same containers its NOR sibling does, and the 12 GB
SuperSlim is the eMMC console while the 250 GB and 500 GB 40xx are NOR.  NAND
numbers its flash from 0 with bootldr first, so the region table sits at 0x40200,
asecure_loader at 0x40800 and metldr's container at 0x40840, the region running
to 0x6F000 with a ~0xF920-byte payload and the rest zero-filled; the model's
view starts at the table's block (NAND 0x40000, the part the HV leaves visible),
so metldr is at 0x840 of that view.  `CECH4201A.NAND.BIN` carries the name
`metldr.2` at view 0x820 and the header at 0x840, and that is the only copy
anywhere in its 256 MiB.  The model resolves it by name there - it is not a
fallback.  The image keeps the chip's own offsets: the dump's first byte goes in
at 0x40000, so the table lands at 0x40200 and the regions on the positions
`docs/flash.txt` lists (eEID 0x80800, ros 0xC0000, cvtrm 0xEC0000), and the
eMMC's tree at 0x10000000 carries `dev_flash*`, `dev_hdd0` and the empty
`dev_hdd1` cache partition.

That container is sealed for the chip's own channel-66 root key, and a flash
dump does not carry that key: it lives in the console's boot ROM.  Which of the
two paths runs is therefore explicit.

The mask-ROM path (no `own-rom`) is the ROM's own question, and with any other
console's readout, or none, it answers `stop 2` and the vflash recover process
comes up - which is what the real console does with a chip whose first
container its ROM cannot open:

```
ps3-boot-rom: stop 2, MAC mismatch (metldr.2 at flash 0x840)
ps3-boot-rom: ### Vflash recovery mode
```

The model's own loader path (`own-rom=on`) is the console's owner: it does not
run Sony's ROM and does not execute metldr, so the mask ROM's seal on that
container is not what starts the machine.  The chain is the medium's own
loader instead, and the run says so and keeps the container's seal visible as
the one thing this image cannot show:

```
ps3-boot-rom: the metldr.2 container at flash 0x840 is sealed for the console's
              own channel-66 key, which a dump does not carry; the chain is the
              medium's own loader (ladder seed block at 0x1BB20), and its keys
              open the storage
ps3-boot-rom: chain checks passed; lv2 starts /dev_flash/vsh/module/vsh.self
```

If a loader and the ERK are not given the eMMC stays on the recovery path and
says which of the two is missing, so a run never claims a chain it did not
check.  A console whose own readout *is* in hand still goes through the mask
ROM path unchanged, and then the container is opened and its tag checked -
give the medium its own key when it differs:

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

The shared page `sys_rsxaudio_initialize` hands out is 0x20000 bytes, the size
of RPCS3's `rsxaudio_shmem`: four DMA regions first, then the control block at
offset 0x1C000. `ctrl.ringbuf[3]` starts at that address, `ctrl.event_queue_1_id`
at `ctrl+0x694` and the other two 0x14 bytes apart, and every ring entry's payload
is named by `dma_addr`, an io address at 0x30000000 the page backs. A period is
256 samples: the 5.33 ms timer takes the entry at `read_idx`, plays it, clears
`valid`, advances `read_idx` modulo `rw_max_idx` and bumps `queue_notify_idx`, and
only every `queue_notify_step`-th block raises the port's queue event with the
payload RPCS3 sends - port name as the source, then port, block index and
timestamp. All of that is relative to the control block, not the page's base.

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
| `ch66-capture` | - | writes the eight `rdch $35,$ch66` words the ROM performed, 32 bytes in read order.  Fed from the SPU channel, never copied from `readout`; with `selftest=on` it is the mask ROM's own run.  The file is the same layout `readout-file` takes |
| `pck1`, `erk` | - | the same 48 bytes as hex (96 digits); `pck1` is the console's name for it |
| `lv1ldr`, `nand-loader` | - | the console's loader image the ERK and the ladder seeds are read from: a NOR `lv1ldr.self`, and/or a NAND/eMMC loader, bank carve or dump.  The key that opens it *is* the ladder's ERK, so a loader alone keys the storage ladder; the published loader keyset is accepted for a retail image and says so, and both images are read and must agree.  The seed block is the published one when the image carries it, and otherwise located by structure and proved against the `hdd-file`/`emmc-file` it keys |
| `pck2`, `pck2-file` | - | the console's eid_root_key (the ERK+RIV, 48 bytes; the property names are the old ones and are kept for scripts).  Only a `.2` loader needs it: that image carries its ERK wrapped, and eid_root_key is what unwraps it - the ERK the unwrap yields is then the ladder's key |
| `container` | `lv0ldr.2` | container to look for in the flash image, and the label its messages use.  A dump that does not carry the name falls back to the slot that name belongs to (`lv0ldr`/`bootldr` -> 0xFC0000, `metldr` -> 0x840) and only to that one: a name with no slot, e.g. `lv1ldr.2`, stops with `no container called lv1ldr.2`, rather than answering for the boot slot |
| `container-offset` | - | address a container at an exact flash offset, for a dump that holds more than one (`metldr.2` at 0x840, `lv0ldr.2` at 0xFC0000).  Unset means the name lookup, then the two fixed slots; set, the header at that offset is used and its span is bounds-checked before anything is allocated |
| `hdd-file`, `emmc-file` | - | the drive, or the eMMC, the firmware trees and the application are mounted from |
| `hdd-file`, `hdd-size` | - / 20G | raw disk image, and the size the model gives a fresh one (1 TB max) |
| `emmc-file`, `emmc-size` | - / 12G | eMMC image, and the size the model gives a fresh one |
| `boot-medium` | `flash` | which medium the chain is read from: `flash` (NOR), `hdd`, `emmc` |
| `recover` | off | boot with the EEPROM's recover flag set, i.e. into the recovery loop |
| `mbox-peer` | on | model lv2's end of the stage's inbound mailbox: when the stage polls channel 0x1D and the queue is empty, the peer posts `mbox-peer-msg` (a two-word message by default) once per poll.  This is what makes `metldr.2`'s `rchcnt ch29` loop release with no `spu-inbox`: `stop 21 at 0x490` after 24,765 instructions instead of the 67M-instruction limit.  `mbox-peer=off` restores the wait, and the words themselves do not change where the stage goes (0x0, 0x21, 0x80 and 0x11223344 all stop at 0x490 with the same count) |
| `mbox-peer-msg` | - | the peer's words as hex, comma separated, up to the mailbox's four slots (`0x21,0x0`).  They are a model parameter, not a console constant: the stage's own consumer tests only the low 7 bits of the first byte |
| `loader-status` | - | words a PPU-side producer has already posted on 0x41 (status in), hex and comma separated.  Empty by default, so a stage that reads 0x41 before the PPU writes blocks |
| `loader-feed` | - | the finite feed on 0x43 (data in), hex and comma separated.  The stage drains it word by word and the depth falls to 0; with nothing installed a read blocks |
| `loader-sink` | 0 | room the host posts on 0x44 (data out).  0 means the channel's depth is 0 and the stage's first `wrch 0x44` blocks; `loader-sink=4` accepts four words and then blocks again |
| `spu-inbox` | - | the older route to the same place: post these words at hand-off, before the stage runs, instead of answering its poll.  Both can be set; the injected words are consumed first |
| `rom-exec` | off | run the mask ROM itself over the selected container in the SPU interpreter, and take its tag check as the verdict (`stop 2 at 0x1E4` on a wrong readout, `reached 0x400` on a right one).  The C opener stays as a second opinion; plaintext equality alone is not treated as a pass, because both decrypt before the tag is checked.  The run's instruction budget is `4M + 64 * body bytes`: the ROM decrypts and MACs every block before the tag check, and a fixed 4M cut a 197 KiB `lv0ldr.2` off mid-body at 0x2FC, which is not a stop the ROM has |
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
| channel-66 capture | `-global ps3-boot-rom.ch66-capture=ch66.bin` (any run) | `channel-66 capture: 8 read(s), 32 bytes in read order -> ch66.bin`; without a mask ROM the file is the readout the boot consumed, and with `own-rom=off -bios rom.bin` it is what the ROM's `rdch $35,$ch66` loop returned.  `scripts/ps3_ch66_chain.py --synthetic` takes it through metldr -> PCK1 -> EID0 -> ENCDEC on the built-in opener, and needs the ROM only with `--rom-exec` |
| the ROM's own tag check | `-global ps3-boot-rom.rom-exec=on` | the synthetic image: `the mask ROM opened the container in the SPU interpreter (reached 0x400 after 44453 instructions)` and `container verified, 80 bytes of payload`; the pristine 4301C with a foreign readout: `the mask ROM did not open the container (stop 2 at 0x1E4)` then `stop 2, MAC mismatch (metldr.2 at flash 0x840)` |
| container opener | `-drive if=pflash,...` with the readout | `container verified, 191152 bytes of payload` |
| is a container sealed under a published key? | `py .tmp/probes/ps3_public_key_check.py --all-keys` (a probe, kept out of `scripts/`) | `no key tested opens a 4301C container` after the detector fires on all eight sample containers (4 consoles) and the ROM opens the `4th sample` `metldr` with a readout derived from its published key (`reached 0x400 after 3394985 instructions`); 631 candidate keys, 2,500 container/key pairs, 0 matches |
| every loader container in a dump | `py scripts/ps3_romexec_sweep.py` | one run per container at its own offset, on the built-in opener by default (no `-bios`, `own-rom=on`): both 4301C dumps give `stop 2, MAC mismatch` for `metldr.2` (0x840) and `lv0ldr.2` (0xFC0000) - the header is accepted and the tag is refused - and a deliberately misaligned point (`0xFC0040`) gives `stop 1, invalid payload length` from the span check (the block field there is 2229774634, not a count), so the address is doing the work.  The capture written by each run is the readout itself (with no `--readout`, 32 zero bytes).  The same sweep runs two sample consoles' own containers, with a readout derived from the key each is sealed under, so the acceptance branch is exercised on firmware: the `4th sample` (which ships `Kp` per container) and the `2nd sample` (which ships `rk10`, inverted through the AES schedule to `Kp` first), each giving `container verified, 63712 bytes` and `container verified, 196528 bytes` and then running its own SPU stage (`metldr.2` stops 21 at 0x490 once the mailbox peer answers its channel-0x1D poll; `lv0ldr.2` spends the budget at 0x20058 and never reads 0x1D).  A key match matrix finishes the run: each `Kp` opens only its own container, and the one real channel-66 capture in the tree opens both images of its console - so what matches and what does not is in the report, not implied.  `--rom-exec` replays a supplied mask ROM instead: the verdict is then spelled `stop 2 at 0x1E4` / `reached 0x400`, and a rejected container gets a channel map because the ROM's own code ran.  Each row records the map its image executed (`channels.touched`, `channels.clean`); an access the model does not define is flagged in the JSON and in the report's "Channel map per run" section, and makes the sweep exit 3 |
| a `.2` loader, whose ERK is wrapped | `-global ps3-boot-rom.lv1ldr=lv1ldr.2.self -global ps3-boot-rom.pck2=<96 hex>` | `the value at 0x... unwraps under eid_root_key into the key this loader was sealed with`, then `NOR lv1ldr: eid_root_key: ladder seed block at 0x...` with `the ladder's ERK is the ERK the loader carries, unwrapped under eid_root_key`.  A wrong eid_root_key finds no window, and a `.2` loader with no eid_root_key given stops and says so |
| ladder seeds and ERK from the console's own loader | `-global ps3-boot-rom.lv1ldr=lv1ldr.self` - no key on the command line | `NOR lv1ldr: ...: ladder seed block at 0x1BB20, found by the published constants - the ATA and flash ladders run on the console's own seeds; the ladder's ERK is <where it came from>`, and `the NOR and NAND loaders carry the same four seeds` when both are given.  A loader with no block (or a mismatched pair) stops the run with the reason.  `pck1=`/`erk-file=` still override the ERK, and a retail image cannot carry a per-console key, so a given ERK is kept and that is reported |
| a loader whose seeds are not the published ones | `lv1ldr` plus the `hdd-file`/`emmc-file` those seeds key | `no published seed block; the window at 0x... was the <n>th candidate whose keys open the console's storage`, then `ladder seed block at 0x..., located by structure, by the keys it derives`.  With no storage image to prove a window against, the run stops and says the block cannot be located |
| a loader stage | `-global ps3-boot-rom.stage-elf=lv2ldr.self` | exit 0, `stop 48 at ...` (the loaders' signal) |
| the channel map and the loader window's four directions | `py scripts/ps3_loader_channels_test.py` | five stages on the model's own channels: with nothing posted all three depths (0x41, 0x43, 0x44) are 0 and `rdch 0x41` blocks; with `loader-status=0x77`, `loader-feed=0x11,0x22` and `loader-sink=4` the status reads once, the feed drains in order, the depths return to 0, the sink falls 4 then 3, and one command plus one data word go out; with `loader-feed=0x11` the depth is 1 and the next read blocks; with no `loader-sink` the 0x44 depth is 0 and the first write blocks; and on reserved 0x2E `rchcnt` answers 0, `wrch` is dropped, and the run reports `0x2E reserved x3` |
| the sweep's channel parsing and exit contract | `py scripts/ps3_romexec_sweep_test.py` | 28 QEMU-free checks: both `ps3-spu: channels:` lines (clean, undefined, last-map-wins, zero touched, lowercase/spaces), the flag and per-row note, `exit_status()` = 0 for clean and 3 for a flagged row or failed sample, and the payload-wait regex that must not match a channel line (the bug that cut sample payloads off at the ROM verdict) |
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
| `ps3_emmc_create.py [dump] --identify` / `-o emmc_12g.img --tree-root ...` | identify a NAND/eMMC dump (model, firmware, ldr revision, region table), then build the 12 GB image: the dump at its NAND position 0x40000 (region table 0x40200, metldr.2 0x40840; view 0x840) and the `dev_flash*`/`dev_hdd0`/`dev_hdd1` tree at 0x10000000 |
| `ps3_qrc.py id` / `list` / `inflate` / `pack` / `verify` | the eight QGL containers: which firmware they came from (size and MD5 against the published table), their name and attribute pools, the QRCF image, a level-9 rebuild that is byte for byte the original, and a structural check of all of them |

`scripts/PS3_TOOLS.md` is the index for those: inputs, outputs, workflows and
what each one refuses to do.  No key is ever printed, and nothing derived from
one is printed either.

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

The NOR image passes the chain checks under the model's own loader (`own-rom`)
and reaches the VSH.  Which modules it then loads depends on which tree the
run reads, and that is worth separating, because the two configurations have
been conflated in earlier notes:

* With the HDD image's own tree (`.tmp/hdd_fs.img.tree/dev_flash`, the run
  `.tmp/qglboot.sh` performs), only `libfs_utility2` and `sys_audio` are loaded
  and the VSH settles into a `sys_cond_wait` hand-off between threads
  0x108/0x10B/0xCC/0xCD at 0x14E428 (`ScePafText`) - `syscall 0x6B` with cond
  ids 0x103 and 0xC9, each wake answered by another wait.  The main thread is
  alive at 0x9E5D8/0xB1374 the whole time; it never reaches the 0x700 vector
  in this configuration.  `qglbase` is not loaded at all here.
* With the full `Documents/rs3/dev_flash` tree (the older `dev-flash=` runs
  that produced the 36-module set and `custom_render_plugin.sprx: start entry
  0xF8BEBA8`), the module set loads and the XMB's resource work starts.  The
  `dev-flash=` property no longer exists on the device, so that configuration
  is reached through the flash/HDD media instead.

Two more things were settled on that configuration after the module work:

* Three modules in the dev_flash tree are sealed with the **3.41** application
  key, not a 4.xx one: `download_plugin.sprx`, `videorec.sprx` and
  `xai_plugin.sprx` open under `app-key-341`/`app-iv-341` and under none of the
  4.xx revisions, which is why lv2 used to refuse them with "no applicable
  keyset opened the root header (2 candidates)".  `self_app_keys` now carries
  that key next to the 4.20/4.xx pair and no decrypt refusal is left in the
  log (`grep -c "no applicable keyset"` is 0).
* With that fixed the VSH still loads only `libfs_utility2` and `sys_audio`,
  opens `/dev_flash/vsh/etc/layout_grid_table_720.txt`, reads 0x2000 bytes of it
  and settles.  The scheduler's new stall dump shows thread 0 at 0xB1674 is not
  spinning on a device: its `lbz r9,0x1C(r30)` reads `0xFFFE6DC`, a stack
  buffer, so that loop is parsing the table it just read and the "stalled N
  ticks" lines are preemption, not a deadlock.  Nothing allocates an RSX
  context in that run (`rsx: 0 vblank(s) ... no driver info`), so the next
  target is what should start the XMB's GCM path, not a lost wake-up.

The `0x700` report below is from the first configuration *without* `-icount`.
It is not reproducible with `-icount shift=6,sleep=off`, and the return
address it prints is not backed by any loaded module in that run: the RAM
dump taken at the stop has zeros at 0xE4A4988 and no module maps that high
(only 0xDB60000/0xDB70000 are occupied).  The `0xE4A4980` analysis further
down is sound for the run that *did* have qglbase at 0xE490000, but that run
is not this one, so treat the address as belonging to the module arena only
when the module map says so.

The eMMC image does not get that far yet - see the end of this section:

```
ps3-ppu: thread 0x0 took the program interrupt vector at 0x700 (lr=0xE4A4988)
ps3-ppu:   call site 0xE4A4980: 80490004 4E800421 E8410028 90610070
ps3-ppu:   r1=0xFFFEC80 r2=0x0 r3=0x7C7F1B78 r11=0xD65C508 r12=0xD640010
```

`0xE4A4980` is inside `qglbase.sprx` (`0xE490000 + 0x14980`), in the function
whose entry is `0xE4A47E0`.  That function is `qgl_base`'s export **NID
`0xF85CB651`** (export table at `0xE4F7CC4`, OPD `0xE4FDA44`), and it reads its
callee as `this+0x10`:

```
0E4A495C lwz r29, 0(r9)        ; the id being visited
0E4A4960 beq cr7, 0xE4A4AD4    ; this+0x10 == 0 -> no callback, skip
0E4A4974 lwz r0, 0(r9)         ; descriptor->code
0E4A4980 lwz r2, 4(r9)         ; descriptor->toc
0E4A4984 bctrl
```

`this+0x10` is a *callback descriptor*, `this+0xC` its argument, and the
function is exported for exactly one caller: **`raf.sprx`**.  raf's import table
has `qgl_base` with 145 functions (`0xE871584`), NID `0xF85CB651` sits at index
140, its slot `0xE88BCC8` holds the OPD `0xE4FDA44`, and the module's only call
site is `0xE845500`:

```
0E8454E8 mr   r3, r26          ; this  = a 0x50-byte block, allocated just above
0E8454EC addi r4, r1, 0xa4     ; ids[] = two words on raf's own stack
0E8454F0 li   r5, 2
0E8454F4 addi r6, r1, 0x80
0E8454F8 li   r7, 1
0E845500 bl   0xE8702A0        ; raf's stub for qgl_base:0xF85CB651
```

The descriptor is not raf's private business: it is handed in.  qglbase's
constructor is `0xE4A51F4`, and it copies its own arguments into the object
(`this+0xC = arg3`, `+0x10 = arg4`, `+0x14 = arg5`, `+0x18 = arg6`,
`+0x1C = arg7`, `+0x20 = arg8`).  raf's wrapper calls it as
`(this, 0x10, a1, a2, 0x10, a5, a6)`, so `this+0x10` is **raf's own first
argument**: an OPD for a resource provider, with `this+0xC` the handle (`0x10`)
that goes back into it as `r3`.  `qgl_base` calls that provider as
`(0x10, id)` and expects the resource's block back in `r3`, then records
`{handle, id, size}` in the `0x30`-byte entry table it just allocated at
`this+0x48`.  A zero `this+0x10` takes the `0xE4A4AD4` fallback, which allocates
the block through `sys_memory_allocate[_from_container]` (`sc 0x15C`/`0x15E`)
itself - so both spellings are legal, and neither implies a missing module.

The provider is whichever VSH module calls raf's exported entry with that
OPD.  raf exports eleven functions from library `raf` (`0xE8718C0`, NIDs
`0x064A1816`, `0x1131F36B`, `0x22496C93`, `0x290893FB`, `0x4AE98BFC`,
`0x507A76AC`, `0x57C25178`, `0x6BDD7EE8`, `0x7CDF2F53`, `0xAB768711`,
`0xB4E13C7A`), and the only modules in the image that import them are
`basic_plugins.sprx` (3 imports from `raf`) and `vshmain_ext.sprx` (6); every
other module gets its qgl work through `qgl_base` directly.  The wrapper itself
is reached from raf's own job worker at `0xE83F41C`, which loads the six
arguments out of a queued frame, so the OPD arrives from raf's caller and not
from a registration table inside qglbase.

In a fresh NOR boot with the trace armed at raf's entry, qglbase's initialiser
and core never execute.  Two `0x700` sites stand between the VSH and qgl work,
both of them `bctrl` through a pointer whose word is *text* rather than an OPD:
`vsh.self` at `0x365214` (`r9 = this+0x40`, and the word there is
`0x5F666C61` = "_fla", the middle of `dev_flash`) and `mms_db_full.sprx` at
`lr=0xEA56C54` (`ctr = 0x646576` = "dev").  A field that should hold an
interface OPD holds a copy of the device path, which is what an object whose
constructor never ran looks like - the string is the last writer of that
storage.  Which thread reaches one of them depends on scheduling: the same
build in a 45-second run with `ppu-trace` opened
`/dev_flash/vsh/resource/system_plugin.rco` and inflated its text stream
(`rco-inflate entry 1 ... 511 -> 3152 byte(s), a zlib stream`) instead of
stopping, while a 40-second run with the qgl trace armed parked two threads at
`0x700` and never opened a container.  A reproducible run therefore needs
`-icount shift=6,sleep=off` and enough guest time to get past the shim's park
loop.  The old `0x200000` receiver was a separate heap-walk failure (the
`0x50`-byte block came back inside `vsh.self`'s text); it is not the current
stop and does not need a registration to explain it.  `PS3_QGL_TRACE=1` logs
the entry, the descriptor's `+0xC`/`+0x10` (with the OPD's code and TOC) and any
`0x700` with its `lr`, so the caller of a broken descriptor is named by the
next run rather than inferred; the fault report now prints `r10` as well,
because every `bctrl` through an OPD under ELFv1 loads its TOC from `r10`.

Which of the two the main thread is in depends on how far it got, so both are
read from the same run's scheduler report.  In a 110-second headless NOR run the
main thread alternates between running at `0xBB9E0` and waiting at the shim's
halt loop `0xC58` on mutex `0x177`, `blocked=1 parked=1`: the owner is
`ScePafText` (thread `0x179`, created at entry `0x42C864` from lr `0x60CE90`),
which sits at `0x14E428`.  At the start of that run ScePafText is itself blocked
and parked (`blocked=1 parked=1 eq=-2 mutex=0x177 cond=0x178`), so the lock it
holds is one it took for a condition wait on `0x178`, and the dump does not
show what was meant to signal it: the hand-off only resumes once the model's
wake reaches that thread.  When the main thread gets the lock instead it goes
past this hand-off to the `0xE4A4980` call and lands on `0x700`.  Neither path has reached a
`cellGcmSetDisplayBuffer`/flip yet, which is why the run's own frame is still
an empty buffer.

A parked thread that a model-side wake finishes used to stay at the shim's halt
loop (`0xC58`): the wake folded the call and cleared `parked` but nothing asked
the scheduler for the context it had just made runnable, so the thread spun and
the stall detector retired it.  `ps3_thread_finish_call` now raises
`sched_pending`, which is what keeps the RSX interrupt thread's vblank delivery
going - `_gcm_intr_thread_system` is the thread that receives those events, and
it must survive for a frame to be flipped at all.  A 110-second NOR run now
shows 11k vblanks generated and 6 delivered with the guest still not flipping;
before the wake the count stopped at 1.

Where the eMMC image stops is one step earlier, in the chain rather than in the
VSH:

```
ps3-boot-rom: the emmc image's flash region starts at 0x40000 (a guest-view dump, bootldr masked)
ps3-boot-rom: the metldr.2 container at flash 0x840 does not verify (stop 0x3)
ps3-boot-rom: ### Vflash recovery mode
ps3-ppu console: factory mode ON  recover flag[ff]
ps3-ppu console: ErrorPage[6] Code[-2147290383]
```

The base is read correctly from the image's own region table (`0xFACE0FF` at
`0x40014`, the table at `0x40200`, `asecure_loader` at `0x40800`, metldr.2's
container at `0x40840`), but that container is sealed for the 40xx console's
channel-66 key and the readout the run is given is the 43xx one, so the ROM
open stops with 0x3.  The VSH therefore never starts on this image and
`emer_init` loops with ErrorPage[6].

That is the mask-ROM path.  The fallback for exactly this case - `own-rom` with
a medium's own ladder seeds - needs a *loader SELF*, not a scan of the dump: the
carve that used to be passed (`.tmp/lv1ldr_4201A.self`, the 0x1E948-byte blob at
NAND 0x100490) is not one - it starts inside a ROS record, so no window in it
derives keys and the model refuses to pretend it found one.  With the 4.93
`lv1ldr.self` out of the stock PUP (`scetool -d lv0`, then `lv0tool -option
export`), passed as `nand-loader`, the seed block is found at 0x1BB20 and its
keys open the eMMC's sealed storage:

```
ps3-boot-rom: NAND loader: the loader keyset - the image is a retail copy, the
              given ERK is kept: ladder seed block at 0x1BB20 ...
ps3-boot-rom: chain checks passed; lv2 starts /dev_flash/vsh/module/vsh.self
ps3-vsh: /dev_flash/vsh/module/vsh.self: entry=0x6D5AC8, 2 segment(s),
         0x7291232 bytes mapped into RAM, PPU entering it
```

metldr.2's own region and offset were already right; what was missing was the
loader the fallback reads its seeds from.  The same run with `recover=on` starts
`emer_init.self` out of the flash's ros and reaches `factory mode ON recover
flag[ff]` / `ErrorPage[6]` - the update-search loop below, not the chain.

### Both media, with the model's own loader

A reset used to take a different decision from power-on.  This medium's chain is
its loader's (`metldr.2` is sealed for a channel-66 key a dump does not carry),
which `ps3_chain_check` says at realize time, but `ps3_rom_boot` did not consult
that path: the first `qemu_system_reset_request` - which the VSH issues during
start-up - re-entered it and reported `stop 2, MAC mismatch (metldr.2 at flash
0x840)` for a chain that had just verified.  It now makes the same decision as
power-on and says `the chain is the medium's own loader; no container is opened
on this medium`.  That is the eMMC/4201A path; a NOR image is unaffected, since
the loader path only exists for a NAND/eMMC medium.

With that fixed, the same run reaches the same place on both media:

| run | medium | what comes up | observed |
| --- | --- | --- | --- |
| VSH | 4301C NOR + HDD tree | `vsh.self`, entry 0x6D5AC8 | 214 modules published, the layout tables read for 720/480/1080/272, `stopping after 2500 ticks at pc=0x9f7b4` |
| VSH | 4201A eMMC | `vsh.self` out of the eMMC's `dev_flash` | same entry, same module count, `stopping after 2500 ticks at pc=0x9f7b4`; the warm reset no longer reports a chain failure |
| recovery | 4301C NOR + HDD tree | `emer_init.self` from `ros0`, 555,056 bytes | `ErrorPage[6] Code[-2147290383]`, then the process exits and lv2 restarts it: 87 warm resets in 521 ticks |
| recovery | 4201A eMMC | `emer_init.self` from the eMMC's `ros` | same `ErrorPage[6]`, same restart loop, `stopping after 120 ticks at pc=0x101F8` |

The restart loop is the emergency program's own update search: it exits with
status 0, lv2 sees the recover flag still set and re-enters it, and the model
follows - `warm reset N: the recover flag is set, so lv2 starts the emergency
program again`.  It is bounded by `ppu-ticks`, but each restart costs a full
start-up (module registration, its own updater), so a recovery run needs a small
budget: `TICKS=120 timeout 330 .tmp/vshrerun.sh recemmc` finishes in about two
minutes, while 2500 ticks of recovery is over an hour of wall clock.  The menu
itself is still not reached; what the run shows is that the process, its flash
bank, its recover flag and its restart are the console's, and that the model no
longer reports a chain failure underneath it.

## Stock 4.93 on both models

The two consoles' images are now built from the official `PS3UPDAT` 4.93, not
from a modified firmware: `pupunpack` -> `unpkg` -> `cosunpkg` gives the
CORE_OS `content`, and `scripts/ps3_ros_bank.py install` writes it into both
recovery banks of a dump.  It keeps the layout each bank had (the NAND `ros`
region's 0x20-byte region header, ros0's record header, ros1 without one), so
the banks stay the shape the console's flash has.

* eMMC (CECH-42xxA dump): `.tmp/stock493/nand_4201A_493.bin` holds the stock
  4.93 banks (25 files each, `lv0` payload byte-identical to the PUP's), and
  `.tmp/stock493/emmc_493.img` is the 12 GB image built from it with the
  existing dev_flash tree, sealed by the encdec ladder.
* NOR (CECH-4301C): `.tmp/stock493/nor_4301C_493.bin` is the working 16 MiB
  flash image with the same 25-file 4.93 banks.

The *pristine* `CECH4301C.NOR.BIN` plus `.tmp/dlt/readout.bin` stops at the
lv0ldr.2 container (`stop 0x3`), so that readout does not verify that image's
lv0ldr.2 - the working image is the one that was re-sealed for it.  The eMMC
path does not depend on a readout at all: its chain is opened through the
loader's seeds, which is why the 42xx image boots with no channel-66 key.

Both boot the same 4.93 VSH (`entry=0x6D5AC8`, TOC `0x6F5558`) and stop in the
same place: 214 modules published from the HDD tree / the eMMC's dev_flash,
then `stopping after 1500 ticks at pc=0x9e538 (lr=0xbc068)` - the resource
inflate / `cellFsTruncate2` stage the Status section lists as open.  Both
recovery runs start `emer_init.self` from the flash's ros and loop on
`ErrorPage[6] Code[-2147290383]` (`0x8002F2F1`, the update search).

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

### The QGL containers (`vsh/resource/qgl/*.qrc`)

The XMB's pictures and shaders are not in the `.rco` files: they are the eight
containers in `/dev_flash/vsh/resource/qgl/` - `icons.qrc` (the icon fragments
and the `override/*/ICONS.mnu` settings), `icontex.qrc` (the icon textures, the
set a P3T theme replaces), `lines.qrc` (the wave, its sparks and the
wallpapers), `rhm.qrc` (the render helpers: copy, blur, cone filter), `raf.qrc`
(coldboot.raf, the uber-shader fragments and the theme fragments), `canyon.qrc`
and `earth.qrc` (the music player's two visualisers) and `store.qrc`.  Each is a
CXML container behind one of two wrappers:

```
QRCC | u32 unpacked length | zlib stream of a whole QRCF file
QRCF | u32 0x110           | the container image itself (stored)
```

so a QRCC's payload is a complete QRCF file, magic and all, and only
`icontex.qrc` ships as QRCF.  The QRCF image keeps its tree at `0x40`, a name
pool at `0x10` (a repeated `u32` followed by a NUL-terminated path, e.g.
`lib/rhm/Clear.fpo`), an attribute pool at `0x18` (`qrc`, `file-table`, `file`,
`src`, `id`, and one more in `icontex`) and the resources' bytes from `0x30`,
length at `0x34`.  The guest's own modules (`qglbase`, `raf`,
`qgl_gaia_app`, `qgl_canyon_app`, `custom_render_plugin`) read and inflate
them; the model serves the bytes and, at each open, checks the container the
loader is about to parse (`ps3-ppu: qgl: /dev_flash/vsh/resource/qgl/raf.qrc
QRCC 5457 -> 0x10E70 byte(s), 23 name(s), data 0x8F0+0x10580`), so a file from
another firmware or a short copy is named when it is asked for instead of much
later.

The tree in use checks out against the published table: `lines.qrc` is the
4.60~4.89 build (185,105 bytes, MD5 `261CD31A...`), `earth`/`store` are
4.40~4.89, `icontex` is 4.00~4.89, `raf` 4.10~4.89, `rhm` 4.00~4.89, and
`canyon`/`icons` match more than one row because the same bytes shipped in
3.5x and 4.4x (see `scripts/ps3_qrc.py id`).  Their name pools decode to the
counts the table lists for those builds: `icons` 60 (33 FPO, 3 VPO, 22 MNU,
1 DDS, 1 BMP), `raf` 23 (1 BIN, 20 FPO, 2 VPO), `rhm` 11 (8 + 3), `canyon` 412,
`lines` 159, `store` 80, `icontex` 71, `earth` 602.

None of them has been opened by a run yet, and that is the same fault as below:
the main thread dies at `0xE4A4988` inside `qglbase` before `raf` gets to
`sys_fs_open("raf.qrc")`.  The probe is therefore compiled in but not exercised
in a boot; `scripts/ps3_qrc.py verify` is what says the containers themselves
are sound in the meantime.

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
