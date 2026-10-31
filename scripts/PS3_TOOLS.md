# PS3 model tools (`scripts/ps3_*.py`)

Ten self-contained Python tools for the `rs6000-ps3` model.  They need nothing
but a Python 3 interpreter (`ps3_encdec.py` wants `pycryptodome`,
`ps3_ram_dump.py --disasm` additionally wants
`capstone`, and `ps3_emmc_create.py --erk-file` a C compiler, to build the seal
tool from `hw/ppc/ps3_aes`: it compiles with `-D_FILE_OFFSET_BITS=64` and seeks
through the platform's 64-bit call, because the storage area starts past 2 GiB,
and prints the compile line it used, rebuilding the tool whenever that line or
one of the sources changes - `--verify` reuses a tool already built from these
sources when no compiler is on `PATH`); no key, no firmware dump and no Sony code is
carried in this tree, and no per-console key is ever printed, nor anything
derived from one.

| Tool | What it does |
| --- | --- |
| `ps3_flash_layout.py` | reads a NOR/NAND dump's layout: the flash TOC, the `asecure_loader` header, the stage containers, the `ros` banks and the documented region map.  Carves regions out of an image and rebuilds one byte for byte (TOC included). |
| `ps3_hdd_create.py` | writes a model-specific raw HDD image. Sector 0 contains the model's `PS3ATA01` key block wrapped with AES-256-CBC; the remaining area is initially zero-filled. This format is not verified as a retail console disk. |
| `ps3_hdd_tree.py` | puts the console's own file tree (`dev_flash`, `dev_flash2`, `dev_flash3`, `dev_hdd0`) inside such an image, and lists what is in one. |
| `ps3_emmc_create.py` | builds the 12 GB eMMC image of a 40xxA from a NAND dump: the dump at its NAND position 0x40000, the erased tail of the NAND-mapped area written out as 0xFF up to 0x10000000, the `dev_flash*`/`dev_hdd0`/`dev_hdd1` tree there, and - given the console's ERK - that storage area sealed with the model's own XTS layer.  `--verify` reads a finished image back and checks it against the dump. |
| `ps3_disk_verify.py` | reads samples from an image or `\\.\PhysicalDriveN`, tries ATA keys derived from a candidate, and reports structural heuristics and the model key-block check. Read-only; a heuristic result is not proof of console ownership. |
| `ps3_encdec.py` | derives the console's ENCDEC ladder from PCK1 - the encdec and ATA data/tweak keys, each AES-256-CBC over the published seed block - and seals or opens an image's 512-byte sectors with the encdec pair (XTS-AES, the sector number as the tweak).  Writes the same bytes as the C seal tool `ps3_emmc_create.py` builds, with no compiler. |
| `ps3_capture_verify.py` | checks a 16/32/48-byte capture against a NOR or NAND dump's loader containers and EID0 CMAC, in memory, and prints only PASS/FAIL.  It is the gate `ps3_ram_dump.py --launch` uses and never prints or writes key material. |
| `ps3_ch66_chain.py` | takes the channel-66 readout the model boots with - the built-in opener's by default (a 32-byte `--readout`, or the console-less zeros), the replayed mask ROM's eight `rdch $35,$ch66` words with `--rom-exec` - and either walks a synthetic console from it to PCK1, EID0 CMAC and the ENCDEC/ATA pairs, or checks a real capture against a dump and refuses to invent anything when no container opens. |
| `ps3_ram_dump.py` | dumps (or peeks at) guest RAM while the machine runs, over QMP - no debugger, no patched binary - and reads or disassembles a dump in place. |
| `ps3_qrc.py` | reads the QGL QRC containers (`dev_flash/vsh/resource/qgl/`): which firmware they are (size and MD5 against the published table), the name and attribute pools, the unpacked QRCF image, a level-9 rebuild that is byte for byte the original, and a structural check of them all. |
| `ps3_loader_channels_test.py` | the 128-entry channel map and the loader window's four directions (0x40-0x44), judged by small SPU stages on the model: all three depths are 0 before the host posts, a posted status word reads once, a two-word feed drains in order and then blocks, a 0x44 write blocks with no sink and drains a posted one (4 to 3), one command plus one data word come out, and a reserved channel (0x2E) reports depth 0, drops the write and is counted as an access the map does not define. |
| `ps3_romexec_sweep_test.py` | the sweep's channel parsing, key routes and exit contract, with no QEMU and no dump: 51 checks over the two `ps3-spu: channels:` lines (clean, undefined, last-map-wins, zero touched, lowercase/spaces), the flag and per-row note, `exit_status()` on clean, flagged, failed-sample and matrix rows, the payload-wait regex that must not end on a channel line, the opener contract (the default run passes no `-bios` and says `own-rom=on`; `--rom-exec` is the only path that supplies a mask ROM and it turns `own-rom` off), the AES-128 schedule against FIPS-197 in both directions, the rk10 parser on a tool-shaped KEYS block, and the matrix primitive on a container sealed from the spec (opens from its readout, refuses a flipped bit, the zeros and a short readout). |

Every tool takes `--help`; the common sizes (`20G`, `512M`, `1MiB`, or bytes)
are understood anywhere a size is asked for.

## Flash: read, carve, rebuild

```sh
py scripts/ps3_flash_layout.py list nor
py scripts/ps3_flash_layout.py dump .tmp/flash.bin
py scripts/ps3_flash_layout.py get  .tmp/flash.bin --all .tmp/carve --slots
py scripts/ps3_flash_layout.py get  .tmp/flash.bin metldr=.tmp/metldr.bin
py scripts/ps3_flash_layout.py build nor --base .tmp/flash.bin \
    --from .tmp/carve --toc -o .tmp/rebuild.bin
```

`--slots` carves the TOC slot rather than the region's data length, so a rebuild
reproduces padding as well; `--toc` regenerates the TOC from the same table and
the build reads its own result back.  A `build` of an untouched carve is
byte-identical to the base image, which is the round trip to check first.

## Disk: create, fill, boot

```sh
# a 20 GiB model image keyed using the supplied ERK; not a retail disk format
py scripts/ps3_hdd_create.py --erk-file erk48.bin -o hdd.raw --verify

# put the firmware tree inside it (dev_flash, dev_flash2, dev_flash3, dev_hdd0)
py scripts/ps3_hdd_tree.py -o hdd.raw --size 20G --root /path/to/rs3
py scripts/ps3_hdd_tree.py hdd.raw --list

# boot the console from nothing but that disk
build-ps3-gui/qemu-system-ppc64.exe -M rs6000-ps3 -display sdl \
    -global ps3-boot-rom.hdd-file=hdd.raw \
    -global ps3-boot-rom.boot-medium=hdd \
    -global ps3-boot-rom.vsh-run=on -global ps3-boot-rom.threads=on
```

`--size` is capped at 1 TB (the largest the console's own ATA path is modelled
for); the image is sparse, so a 1 TB image costs its directories only.
`ps3_hdd_tree.py` writes plain images on purpose: keying the data area is a
separate step, and it refuses `--erk`/`--data-key` rather than writing blocks
the model would read as ciphertext.

## eMMC: build and verify (CECH-4201A, the 12 GB SuperSlim)

```sh
# what is the dump?  (SKU, firmware bank, ldr revision, region table)
py scripts/ps3_emmc_create.py CECH4201A.NAND.BIN --identify

# build the 12 GB image, tree and seal included
py scripts/ps3_emmc_create.py CECH4201A.NAND.BIN -o emmc_12g.img \
    --tree-root /path/to/rs3 --erk-file erk48.bin

# read it back: size, dump placement, erased padding, seal boundary, tree
py scripts/ps3_emmc_create.py CECH4201A.NAND.BIN -o emmc_12g.img \
    --verify --erk-file erk48.bin
```

`--verify` checks, against the dump it was built from:

| line | what it proves |
| --- | --- |
| `image` | the file is the size that was asked for |
| `dump` | 0x40000.. (or 0.. for a dump from NAND 0) is the dump's own bytes, and reports the first byte that differs |
| `padding` | every byte from the dump's end to 0x10000000 is erased flash (0xFF) |
| `seal start` | the sector just before 0x10000000 is still the dump/padding, so the seal begins at the storage area and not a sector or a block early |
| `seal` | the storage area opens through the model's XTS to `PS3HDFS1` - unsealed, read, and re-sealed; an image whose seal does not round trip is reported and left untouched |
| `tree` / `devices` | the root directory parses, and `dev_flash`, `dev_flash2`, `dev_flash3`, `dev_hdd0`, `dev_hdd1` are all there |

Without `--erk-file`/`--erk` the tree cannot be unsealed and that check says
`skipped`; with no compiler on `PATH` the same happens, using the seal tool the
build already produced.  Exit status is 1 if any check fails.

## NOR SuperSlim (CECH-4301C): `ps3_flash_layout.py`

The 40xxB/C (250/500 GB) and every earlier NOR console keep their firmware in
the 16 MiB NOR chip, not in an eMMC: the `asecure_loader` region is at 0x800,
its data at 0x840, and there is no storage area in the flash at 0x10000000.  The
all-in-one eMMC builder does not apply there - build and verify those images
with the layout tool, which works on the flash itself:

```sh
# identify, carve, then rebuild and compare byte for byte
py scripts/ps3_flash_layout.py list nor
py scripts/ps3_flash_layout.py get nor.bin --all .tmp/carve --slots
py scripts/ps3_flash_layout.py build nor --base nor.bin \
    --from .tmp/carve --toc -o .tmp/nor_rebuilt.bin
cmp nor.bin .tmp/nor_rebuilt.bin      # the round trip --verify is for eMMC
```

## Capture verification: a loader key must open this dump

`ps3_capture_verify.py` checks a 16/32/48-byte capture against the records in
the dump itself, in memory, and prints only PASS/FAIL:

```sh
py scripts/ps3_capture_verify.py --nor CECH4301C.NOR.BIN --capture capture.bin
py scripts/ps3_capture_verify.py --nor CECH4201A.NAND.BIN --capture capture.bin
py scripts/ps3_capture_verify.py --nor ... --capture ... --json
```

| capture | check |
| --- | --- |
| 32 bytes | channel-66 readout: `Kp = AES-128(K_hi, header[0x20] XOR K_lo)` in both half orders, then the loader's CBC-MAC |
| 48 bytes | PCK1 / ERK: EID0 section 0 AES-CMAC |
| 16 bytes | one AES-128 round key: inverted at all 11 indices, then the loader's CBC-MAC |

The dump decides the layout.  A 16 MiB image is NOR: `metldr.2` at 0x840,
`lv0ldr.2` at 0xFC0000, eEID at 0x2F000 and EID0 at 0x2F070.  A NAND dump, or
the 256 MiB flash area of an eMMC image, is `metldr.2` at 0x840 in the guest
view (0x40840 from NAND 0), eEID at 0x40800 (0x80800 from NAND 0) and EID0 at
+0x70.  A 4201A dump has no `lv0ldr.2` record because that is metldr's next
stage, not a flash container; the readout is checked against `metldr.2`.

Exit 0 means the required records passed; 3 means they did not.  No key bytes,
derived keys or hashes of the capture are printed or written.  `--selftest`
builds its own records and proves the positive and negative answers.

`ps3_ram_dump.py --launch` runs this check and refuses to start QEMU without
`--nor` and `--capture`:

```sh
py scripts/ps3_ram_dump.py --launch --nor CECH4301C.NOR.BIN \
    --capture capture.bin -o .tmp/ram.bin
py scripts/ps3_ram_dump.py --verify-only --nor ... --capture ...
```

The verified readout is passed as `readout-file` (NOR) or `nand-readout-file`
(NAND); a 48-byte ERK is passed as `erk-file`.  `--allow-unverified` exists
only for a run that does not open a loader, and says so in the command it
prints.

PCK1 is not an independent efuse: `docs/PCK.txt` records it as
`per_console_root_key_1`, derived from PCK0 by `metldr` and carried in `metldr`.
If the readout is what you have, do not wait for a 48-byte file - open the dump's
containers and let the EID0 CMAC pick the copy out:

```sh
py chain_keys.py --flash CECH4301C.NOR.BIN --readout capture.bin \
    --scan-lv0 --eid0 eEID_4301C.bin --out .tmp/chain.bin
```

It scans the decrypted `metldr` first, then `lv0ldr.2`, and accepts a 48-byte
window only when it authenticates EID0.  A loader with no raw copy is reported
as such; that scan is a model convenience, not the hardware derivation.

A 48-byte capture that passes here is the same PCK1 `ps3_encdec.py` checks.
Re-run its EID0 check and derive the ENCDEC ladder before sealing a disk:

```sh
py scripts/ps3_encdec.py verify --pck1 capture.bin --dump CECH4301C.NOR.BIN
py scripts/ps3_encdec.py keys   --pck1 capture.bin --out .tmp/encdec-keys.bin
```

### Channel-66 readout, and the synthetic chain

The 32 bytes on channel 66 are the readout, and the model takes it from the
caller: by default no mask ROM is loaded at all (`own-rom=on`) and the bytes are
`readout-file`'s, or all zeros when there is no capture - the console-less
control.  `-global ps3-boot-rom.ch66-capture=FILE` records whatever the boot
consumed, in read order, in the same 32-byte layout `readout-file` takes, so a
capture can be fed straight back into a boot.

The mask ROM's own eight `rdch $35,$ch66` reads come from the opt-in developer
path, where the 0x400-byte ROM is executed by the SPU interpreter and the device
writes what it read:

```sh
./build-ps3/qemu-system-ppc64.exe -M rs6000-ps3 -bios .tmp/rom/rom.bin \
    -global ps3-boot-rom.own-rom=off \
    -global ps3-boot-rom.ch66-capture=.tmp/ch66.bin -nographic
# channel-66 capture: 8 read(s), 32 bytes in read order -> .tmp/ch66.bin
```

With no 4301C readout, PCK1 or loader plaintext in the tree, the chain driver
builds a synthetic console around the readout: a chosen 48-byte PCK1, an
eEID whose EID0 section 0 is sealed and CMAC'd under it, and a
`synthetic metldr` container sealed under that PCK0 whose payload carries PCK1.
The container crypto, the ladder, the CMAC and the ENCDEC derivation are the
real ones, and the boot runs on the built-in opener, which verifies the
container the same way the ROM does.

```sh
py scripts/ps3_ch66_chain.py --synthetic
```

Observed (all PASS), with no mask ROM in the run:

```
channel-66 readout (built-in opener, console-less): .tmp/ch66_chain/rom_ch66.bin
  read order K_lo||K_hi, 32 bytes
synthetic PCK1: 48 bytes, fingerprint 2cf1754a201d75cd
synthetic metldr: 5 blocks, tag f31edbc2f840cb95f6886bd4bac9d3ca, Kp fingerprint a4e5e39a5ac641f6
PASS  the boot's channel-66 reads equal the readout it was handed
PASS  PCK1 read back from local store matches the sealed copy
PASS  PCK1 authenticates EID0 section 0's CMAC (AES-256-CBC encrypt)
PASS  sector 0 round-trips under the derived ATA pair
PASS  an XTS sector round-trips under the derived ENCDEC pair
wrote .tmp/ch66_chain/synthetic_encdec.bin (128 bytes, synthetic: ...)
```

`--rom-exec` makes the capture come from the ROM instead of the caller; the
rest of the run is identical, and the code under test is the same ladder.

The synthetic material is generated, never a console key; it lives under
`.tmp/` and is not for sealing an image.  A real capture takes the other mode,
which opens only what the capture actually opens and stops otherwise:

```sh
py scripts/ps3_ch66_chain.py --capture ch66.bin --flash CECH4301C.NOR.BIN \
    --eid0 eEID_4301C.bin
```

Run against this workspace's ROM capture and the pristine 4301C NOR, that
answers `FAIL the capture opens neither container; no PCK1 to confirm` and
exits 3.  The same rejection is visible at the ROM's own check with
`rom-exec=on` and a foreign readout:

```
the mask ROM did not open the container (stop 2 at 0x1E4)
stop 2, MAC mismatch (metldr.2 at flash 0x840)
```

That is the honest state of this console: the mask ROM's channel-66 read is
per-console, the dump does not carry it, and a capture that does not open
0x840 or 0xFC0000 cannot yield PCK1 or ENCDEC keys.

## Every loader container in a dump, at its own offset

A dump holds two channel-66 containers, and a name lookup resolves to whichever
it meets first, so each one is addressed explicitly (`container-offset`).  The
verdict is the built-in opener's by default - the model's own open, decrypt and
tag check, with no mask ROM, which is what lets the sweep run on a checkout with
no Sony image.  `--rom-exec` is the opt-in developer check that replays a
supplied mask ROM instead:

```sh
py scripts/ps3_romexec_sweep.py --readout .tmp/dlt/readout.bin --control
py scripts/ps3_romexec_sweep.py            # zero-readout control, no capture
py scripts/ps3_romexec_sweep.py --rom-exec  # the same sweep, mask ROM replayed
```

Observed on both 4301C dumps with no readout:

| dump | container | offset | size | verdict | readout | channels |
| --- | --- | --- | --- | --- | --- | --- |
| `CECH4301C.NOR.BIN` | `metldr.2` | 0x000840 | 63920 B | `stop 2, MAC mismatch` | 32 B zeros | no map |
| `CECH4301C.NOR.BIN` | `lv0ldr.2` | 0xFC0000 | 197104 B | `stop 2, MAC mismatch` | 32 B zeros | no map |
| `CECH4301C-verylate.NOR.BIN` | `metldr.2` | 0x000840 | 63920 B | `stop 2, MAC mismatch` | 32 B zeros | no map |
| `CECH4301C-verylate.NOR.BIN` | `lv0ldr.2` | 0xFC0000 | 197104 B | `stop 2, MAC mismatch` | 32 B zeros | no map |
| either, `--control` | misaligned point | 0xFC0040 | - | `stop 1, invalid payload length` (block count 2229774634 runs off the image) | 32 B zeros | no map |
| `4th sample` (real firmware) | `metldr.2` | 0x000840 | 63,776 B | opens: `container verified, 63712 bytes` | 32 B (derived from `Kp`) | 1 touched (0x1D) |
| `4th sample` (real firmware) | `lv0ldr.2` | 0xFC0000 | 196,592 B | opens: `container verified, 196528 bytes` | 32 B (derived from `Kp`) | 9 touched |
| `2nd sample` (real firmware) | `metldr.2` | 0x000840 | 63,776 B | opens: `container verified, 63712 bytes` | 32 B (derived from `rk10 -> Kp`) | 1 touched (0x1D) |
| `2nd sample` (real firmware) | `lv0ldr.2` | 0xFC0000 | 196,592 B | opens: `container verified, 196528 bytes` | 32 B (derived from `rk10 -> Kp`) | 9 touched |

A rejection under the built-in opener runs no image: the open, decrypt and tag
check are the model's own code, so there is nothing to attribute to an SPU and
no channel map is reported.  `--rom-exec` is what produces a map for a rejected
container - the ROM's own execution - and the accepted sample rows get theirs
from the container payload the model runs after the hand-off (`metldr.2` stops
21 at 0x490 once its channel-0x1D poll is answered; `lv0ldr.2` spends the whole
instruction budget at 0x20058).  Under `--rom-exec` the dump rows stop at 0x1E4,
before `wrch $ch64,$1`, so they touch 13 channels and an opened container adds
0x40.

Every run also records the 128-entry channel map it executed: `channels.touched`
and `channels.clean` in the JSON, a `channels` column in the report, and a
summary count.  A run that reads or writes a channel the model does not define
is flagged (`**FLAG** 0x2E reserved x3`) in both, listed under the report's
"Channel map per run" section, and makes the sweep exit 3 - the same failure
status as a sample container that did not open, and stated in the report's
header (`**Sweep failed (exit 3): ...**`).  The extension is the same as any
other tool's: a reserved channel, or a write to a read-only direction, fails the
sweep rather than being reported and ignored.

The sample rows are the point of the exercise: without them every run is a
rejection, and a regression in the acceptance branch would never show.  Each
sample container is placed at the slot it belongs to, and its readout is
derived from the key the file is sealed under (`K_lo = hdr[0x20] XOR
AES-DEC(K_hi, Kp)`) - no capture is invented and nothing is taken from a dump.

### Where the sample keys come from, and what they match

Two routes get to `Kp`, and both are exercised because they are different
halves of the same story:

* the **4th sample** ships `Kp` per container (`metldr_key.txt`,
  `lv0ldr_key.txt`) - a result;
* the **2nd sample** ships no key file.  Its tool publishes the last round key
  `rk10`, which is what a console's local store keeps at LS `0xa0`, and the
  sweep inverts the AES key schedule to recover `Kp` - a method.  The round key
  is read from that tool rather than copied here, and the inversion is checked
  forward before it is used: the schedule rebuilt from the recovered `Kp` must
  return the round key it was given.

The run then prints a **key match matrix**: every key against every container
in the run (the four sample containers, the tool sample console's two images,
and both dumps' four), checked by the CTR body and the CBC-MAC tag in Python.
`Kp` is per image, so each of those rows opens exactly one container; a
channel-66 readout is per console, so a real one opens every image of its own
console.  The tree holds one real readout (`.tmp/dlt/readout.bin`), which is
why exactly one row opens two:

```
per-image keys (Kp)
  4th sample metldr.2      metldr_key.txt        1 of 10: 4th sample metldr.2
  4th sample lv0ldr.2      lv0ldr_key.txt        1 of 10: 4th sample lv0ldr.2
  2nd sample metldr.2      decrypt_loader.py     1 of 10: 2nd sample metldr.2
  2nd sample lv0ldr.2      decrypt_loader.py     1 of 10: 2nd sample lv0ldr.2
console readouts
  9BF07E57 capture         readout.bin           2 of 10: tool sample metldr, tool sample lv0ldr
  no capture               32 zero bytes         0 of 10: none
```

That is the positive and the negative in one place: no per-image key moves to
another image or another console, and the only thing that crosses images is the
console's own 32 bytes.  A `Kp` cannot be turned back into such a readout
without the console's `K_hi`, which is why the sample rows derive a readout per
container and why the matrix is the honest place to compare them.  A key that
fails to open its own container in the matrix fails the sweep (exit 3): the
model's verdict and the arithmetic would then disagree.
After the hand-off the model runs the container's own SPU stage, which is where
the two samples part company: `metldr.2` ends at `stop 21 at 0x490` in 24,765
instructions (its mailbox peer answered), while `lv0ldr.2` runs to the
67,108,864-instruction limit at 0x20058.  Neither is a container failure, and it
is why the sweep stops at the chain verdict on the dump rows.

The `metldr.2` wait is a `rchcnt` poll of channel 0x1D (`SPU_RdInMbox`), not a
blocking `rdch`: `0xC640 rchcnt $2,$ch29` reads the mailbox depth and the helper
returns -2 while it is empty, so `0xC690 brnz $3,0xC688` spins - ten
instructions per pass, 6,710,856 passes at the limit, which is why the hot pair
is the helper's `0xC644`/`0xC664` and not the loop head.  A word (`0xC64C
rdch $8,$ch29`) goes into the 8-byte message at LS frame+0x20, and `0xC69C`
waits for the second one: one word posted still spins, two release it.  Nothing
else is missing - the stage issues no MFC command of its own, so there is no EA
to populate (the 17 gets counted at the limit are the ROM's body staging: one
64-byte header get plus sixteen 4096-byte chunk gets, all at 0x264 before the
hand-off).  The mailbox peer (`mbox-peer`, on by default) stands in for the lv2
writer, so the poll now releases on its own; `mbox-peer=off` reproduces the wait.
Once released the stage takes its teardown path (LS 0x6D0..0x12BF0 wiped,
registers $36..$127 cleared) and stops 21 at 0x490 - the same count and the same
stop for `0x0`, `0x21`, `0x80` and `0x11223344`, so the words end the poll
without steering what follows.

`lv0ldr.2` is a different shape: it never reads 0x1D (the peer's post count stays
0), and its payload never reaches the `rdch 0x43` data-in loop or the `rchcnt
0x49` version read - the only channel the whole run touches beyond the ROM's own
set is 0x40 (`wrch`, its command word out), and the rest is MFC.  Its limit PC
sits in a per-element call cycle `0x1FDD4 bisl $89 ->
0x20048` (a byte routine that exits on a zero byte), and 3,354,861 passes of
that cycle fill the whole 67.1M budget - a constant ~20 instructions per pass
from the first 2.8M instructions to the limit, so it is walking data, not
waiting.  The only external words it reads in that phase are four-byte MFC gets
from EA 0x240FFF508 and EA 0x24008E004, and it writes eight-byte records to EA
0x200511xxx; nothing there blocks, so the honest reading is that the list it
walks has no terminator in the model's memory rather than that a channel is
missing.

`--no-samples` drops the two sample rows.

`0x1E4` is the tag check, so every container's header is accepted (block count
and span agree) and only the sealing is refused - which is what an unknown
per-console key looks like.  `0xFC0040` is 0x40 into the container: the field the
model reads as a block count is 2229774634 in one dump and 2102114259 in the
other, so the address is refused before the ROM is even handed the header.  Different address, different and earlier answer, which is the
point - the offsets are doing real work and not merely decorating the log.
The two dumps carry different sealing material, but the tags are the weak part
of that: the key-derivation input at `+0x20` is per-container random, so even
two containers of one console have different tags.  The console-level marker is
the header nonce at `+0x14`: `d5956ed2...` is shared by both containers of one
dump and `b7d909b3...` by both of the other, while the two differ - which is
what points at two machines, and at one capture not opening both.

The capture is reported next to the verdict because the two failures are
different: a run that never reaches 0x148 has fewer than eight reads (or no
capture file at all, as the misaligned control), meaning the header was refused
before the key was read.  With no readout at all the ROM
still performs its eight reads (of zeros), so `8 read(s)` means the read path
ran, not that the key is right.

## Are these containers sealed under a published key?

`ps3_public_key_check.py` - now kept under `.tmp/probes/` with the other
scratch probes, not in `scripts/` - answers the only way it can be answered:
does a key we hold reproduce a container's stored tag?

```sh
py .tmp/probes/ps3_public_key_check.py --all-keys
```

Observed:

* the two spellings of the published pair (a `Kp` and its `rk10`) invert to the
  same key, so the sources are not describing different keys;
* the detector fires on all eight sample containers it has - `channel 66`,
  `second sample`, `second sample dot 2` (key found among the tokens in its own
  tool) and `4th sample` (its own `*_key.txt`) - so a negative means something;
* neither 4301C container matches any of the 631 candidate keys in the stores
  (2,500 container/key pairs, zero matches);
* end to end, the `4th sample` `metldr` - sealed under its own published key -
  opens in the ROM with a readout derived from that key alone:
  `the mask ROM opened the container in the SPU interpreter (reached 0x400
  after 3394985 instructions)`.

So: no key this tree holds opens either dump, and the method is proven able to
say yes.  What that does *not* prove is that the sealing key is per-console -
the header's derivation input is per-container random (`+0x20`), so every
container has a unique `Kp` no matter what the readout is.  The per-console
part is the channel-66 readout itself, and that is the artifact still missing.

The ROM's budget scales with the container (`4M + 64 * body bytes`).  A fixed
4M was enough for `metldr.2` and cut `lv0ldr.2` off mid-body at `0x2FC`, which
reads like a stall but is the model's limit, not a stop the ROM has.

The sweep is also what caught the name fallback answering for the wrong
container: `container=lv1ldr.2` used to fall through to the boot slot and
report `lv1ldr.2 at flash 0xFC0000`.  The fallback now maps a name to its own
slot (`lv0ldr`/`bootldr` -> 0xFC0000, `metldr` -> 0x840) and any other name
stops with `no container called <name> in the flash image`.

These two are the whole set for a raw dump.  The loaders below them
(`lv1ldr.2`, `lv2ldr.2`, `appldr.2`, `isoldr.2`) are SELFs inside **lv0**, which
is itself inside `lv0ldr.2`'s payload, so a dump holds them only encrypted under
the channel-66 key: until `lv0ldr.2` opens there is nothing there for `rom-exec`
to address, and once it does they are SELF checks, not container checks.

The IDA KIRK processor module (the `README.md` with `PLFM_KIRK`) disassembles
the PSP KIRK mask ROM; it is not a PS3 capture verifier and does not replace
this check.  It analyzes KIRK's own instruction set, not a PS3 loader.

The model uses separate ATA and ENCDEC seed pairs. `ps3_hdd_create.py` creates
a model-specific key sector; it has not been shown to create a retail-compatible
disk. The derived key material depends on the candidate ERK and seeds, not the
capacity of a disk. Matching a 20 GB image to a 1 TB drive also requires the
same sector cipher, byte order, LBA mapping and compatible filesystem layout;
equal derived keys alone are not proof that either medium will boot.

### ENCDEC: PCK1 to the keys, and the seal

`ps3_encdec.py` derives four keys from a supplied candidate PCK1 and applies
the model's XTS mode to image sectors. Its model-mode self-test does not establish
retail hardware compatibility. In particular, the reference slim ATA path below
uses a different key length and byte order.

```sh
py scripts/ps3_encdec.py selftest

# Read-only EID0 section 0 CMAC check. No keys are printed or written.
py scripts/ps3_encdec.py verify --pck1 erk48.bin --dump nor.bin
# Alternatively use --eid0 eEID.bin for an eEID or bare EID0 record.
# Exit 3 means the candidate did not authenticate the selected record.

# the four keys: written to a file, only their ids printed
py scripts/ps3_encdec.py keys --pck1 erk48.bin --out .tmp/encdec-keys.bin

# seal/open the storage area of a finished eMMC image (0x10000000 to the end)
py scripts/ps3_encdec.py seal --pck1 erk48.bin --image emmc_493.img --storage
py scripts/ps3_encdec.py open --pck1 erk48.bin --image emmc_493.img --storage

# a 512-aligned run in a disposable model image (not a physical drive)
py scripts/ps3_encdec.py seal --pck1 erk48.bin --image model.img --offset 0x200 \
    --length 0x100000
```

| seed | key |
| --- | --- |
| 0x00 | encdec data - XTS data key for the storage area |
| 0x20 | ATA data - the disk's XTS data key |
| 0x40 | encdec tweak |
| 0x60 | ATA tweak |

All four are AES-256-CBC under PCK1 with its own 16-byte RIV as the IV, so the
seeds are not the keys.  `--seeds` takes a loader image instead of the published
block (the four 0x20-byte blocks are found by content, in either interleave, as
`ps3_ladder_seeds()` does); `--pck1 -` reads a 48-byte key from stdin.
`verify` reads a bounded EID0 region and leaves its inputs untouched. A successful
CMAC authenticates the selected record under the implemented algorithm; it does
not establish disk compatibility. Explicit `--out` on `verify` or `keys` writes
the derived key material; omit it for a read-only check.

The two media take the pair through different ENCDEC commands on hardware: an
HDD's sectors reach LV1 with the tweak already XORed, while VFLASH's are XORed
by LV1 with tweaks ENCDEC encrypted in a DMA region (see PS3_MODEL.md).  This
tool computes both halves in one XTS pass, which makes `--storage` the
patched-LV1 case - the bytes the model reads, and not yet proof that a retail
LV1 would.

A decrypted loader body is not the same as a runtime local-store capture, and
its decryption alone has not demonstrated recovery of this console's PCK1.
The ROM reads channel 66 at runtime; the ROM image alone is not a recorded
readout. Validate any candidate against the correctly located EID0 record
before treating derived keys as belonging to a console. Earlier `find_erk.py`
scans of `eEID_4301C.bin` defaulted to offset 0 instead of the EID0 entry at
0x70 and are inconclusive. The verifier in the ps3tools project now recognizes
both the retail table and the older synthetic fixture layout; those old scans
have not been repeated.

## A disk: which PCK1 opens it

The tool derives an ATA pair using AES-256-CBC and the two "SB indiv" seeds,
then tries it against sampled sectors. Its `PS3ATA01` sector-0 block is a model
convention, not a demonstrated retail disk structure; arbitrary sector-0
windows are only heuristic candidates. Neither an unrecognized block nor a
pair that looks different establishes which console wrote a real drive.

The verifier tries two ATA paths described in the reference `ps3encdec`'s
`main.c`, plus the QEMU model's distinct format:

| path | cipher | key bytes | byte order |
| --- | --- | --- | --- |
| slim console | AES-XTS, tweak = LBA | 16 of each derived key | `_es16()` swap |
| FAT console | AES-CBC, zero IV | 24 of the data key (tweak unused) | `_es16()` swap |
| the model's images | AES-256-XTS | all 32 of each | none |

The pair was previously compared with the reference binary on synthetic
fixtures: the ATA derivation and both the slim XTS and `-p` FAT CBC decryption
paths agreed on those fixtures. A negative sampled-sector heuristic still
cannot prove that a candidate is wrong: offsets, sector contents, byte order,
format and untested variants can all affect the result. The reference builds with
`gcc -O2 -o .tmp/ps3encdec.exe src/{aes,aes_xts,getopt,kgen,main,util}.c`
from `Downloads/ps3encdec-master`, with `/c/msys64/usr/bin` on `PATH` so its
`cc1` can load (without that the compiler exits 1 and says nothing).

Sectors are sampled at LBA 1, 2, 3, 4, 8, 100, 1000, 10000, 100000 and 200000.
The tool skips all-zero raw sectors and scores the others by zeros and printable
text. This is a heuristic: zero sectors need not establish write history,
valid plaintext may lack these patterns, and matching patterns do not establish
filesystem integrity or key ownership.

```sh
# Inspect raw samples without a key, decryption, or writes.
py scripts/ps3_disk_verify.py --device disk.img --inspect

# Candidate-key heuristics do not authenticate a retail disk.
py scripts/ps3_disk_verify.py --device disk.img --pck1 erk48.bin
py scripts/ps3_disk_verify.py --device \\.\PhysicalDrive1 \
    --pck1 eid_root_key.bin --report .tmp/disk1.txt
```

`--inspect` reports raw sample statistics and returns 4 if any sample could not
be read. It does not verify the loader chain, an ERK, or disk compatibility.

RAW reads need an elevated process - the tool says so instead of failing with
a traceback; an image file does not. Verify the Windows device number before
opening a drive; these probes do not modify it.  `--save-sector` writes the 512 raw bytes
of LBA 0 for offline inspection and nothing else is written.  The report also
prints the raw state of each sampled sector. Exit status 0 means its model
block check or plaintext heuristic matched; 3 means no candidate matched that
heuristic; and 4 means no nonzero sample was found. These are not definitive
retail-drive authentication results.

A previous read-only probe of the 1 TB `\\.\PhysicalDrive1` reported 0 of 7
sampled nonzero sectors looking structured for either of two candidate keys,
under the modes it tried. That is a heuristic result, not proof that the drive
belongs to a different console. Those candidates have not been established as
the 4301C's PCK1. No 20 GB model image has been verified to match that drive.

## QGL containers: identify, list, rebuild

The XMB draws from eight CXML containers under
`dev_flash/vsh/resource/qgl/`.  Seven are `QRCC` (a `u32` unpacked length and a
zlib level-9 stream of a whole `QRCF` file); `icontex.qrc` is `QRCF` (stored).
The `QRCF` image keeps its tree at 0x40, its name pool at 0x10 (repeated `u32`
followed by a NUL-terminated path), its attribute pool at 0x18 (`qrc`,
`file-table`, `file`, `src`, `id`) and the resources from 0x30.

```sh
# which firmware is this tree?  (size and MD5, per file)
py scripts/ps3_qrc.py id dev_flash/vsh/resource/qgl

# what is in one container: header, pools, every name
py scripts/ps3_qrc.py list dev_flash/vsh/resource/qgl/raf.qrc -v

# the unpacked image, and back again (the rebuild is byte identical)
py scripts/ps3_qrc.py inflate raf.qrc -o raf.qrcf
py scripts/ps3_qrc.py pack raf.qrcf -o raf.qrc

# every container: ordering, pool and data extents, and the zlib round trip
py scripts/ps3_qrc.py verify "$TREE/dev_flash/vsh/resource/qgl"
```

`id` exits 1 when a file is not in the published table.  `verify` fails a
container whose pools are out of order, whose data extent does not end at the
file's end, whose name pool is empty, or whose stream is not what zlib level 9
produces; a `QRCF` file has no stream to re-check and is checked structurally
only.  The firmware table is the public one (psdevwiki `QRC` and
`CXML Containers`), so a tree rebuilt from a PUP reports the window it came
from rather than a guess.

## Seeing what a run is doing

```sh
# 25 s into a run: dump 256 MiB of guest RAM
py scripts/ps3_ram_dump.py --launch --after 25 -o .tmp/ram.bin --dev-flash=...

# a machine already started with -qmp tcp:127.0.0.1:4444,server=on,wait=off
py scripts/ps3_ram_dump.py --connect 127.0.0.1:4444 -o .tmp/ram.bin

# read it back: the file's offsets are guest addresses, so it disassembles in place
py scripts/ps3_ram_dump.py --read .tmp/ram.bin --at 0x5DAC60 --count 60 --disasm
```

`--launch` starts the model with the same options a boot uses (dev-flash roots if
given, `vsh-run` on), so one command gets from nothing to a dump.

## Exit status and errors

The tools exit 0 on success and non-zero with a one-line reason on failure
(`bad size`, `size is capped at 1 TB`, `<file> exists; remove it first`, `not a
SELF/ELF`, `qemu never opened its QMP port`).  A refusal leaves nothing behind:
no half-written image and no overwritten dump.
