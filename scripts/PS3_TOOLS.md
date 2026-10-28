# PS3 model tools (`scripts/ps3_*.py`)

Five self-contained Python tools for the `rs6000-ps3` model.  They need nothing
but a Python 3 interpreter (`ps3_ram_dump.py --disasm` additionally wants
`capstone`, and `ps3_emmc_create.py --erk-file` a C compiler, to build the seal
tool from `hw/ppc/ps3_aes`); no key, no firmware dump and no Sony code is
carried in this tree, and no per-console key is ever printed, nor anything
derived from one.

| Tool | What it does |
| --- | --- |
| `ps3_flash_layout.py` | reads a NOR/NAND dump's layout: the flash TOC, the `asecure_loader` header, the stage containers, the `ros` banks and the documented region map.  Carves regions out of an image and rebuilds one byte for byte (TOC included). |
| `ps3_hdd_create.py` | writes a raw HDD image the console would accept: sector 0 is the ATA key block (AES-256-CBC under PCK1), every other sector is XTS-AES under the pair it carries.  The data area is sparse and unformatted, which is what the guest formats on first boot. |
| `ps3_hdd_tree.py` | puts the console's own file tree (`dev_flash`, `dev_flash2`, `dev_flash3`, `dev_hdd0`) inside such an image, and lists what is in one. |
| `ps3_emmc_create.py` | builds the 12 GB eMMC image of a 40xxA from a NAND dump: the dump at its NAND position 0x40000, the `dev_flash*`/`dev_hdd0`/`dev_hdd1` tree at 0x10000000, and - given the console's ERK - that storage area sealed with the model's own XTS layer. |
| `ps3_ram_dump.py` | dumps (or peeks at) guest RAM while the machine runs, over QMP - no debugger, no patched binary - and reads or disassembles a dump in place. |

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
# a 20 GiB disk with the console's labels, keyed by the console's own ERK
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
