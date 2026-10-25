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

The boot-chain research this model rests on is theirs, not mine:

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
- Anonymous

and last but not least...Anonymous. Nothing above is a claim of
authorship by whoever wrote this file; it is a list of where the
knowledge came from.

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
from `_start` through its C runtime setup and reaches the lv2 boundary at
`0x60C5C0` (first syscall `0x16`, `_sys_process_exit`), then `0x3DC`.

A bare PPU has no handler at the `0xC00` vector, so `vsh-run` installs a small
trampoline there.  It records the syscall number at RAM `0x800`, returns
`-ENOSYS` in `r3`, restores `SRR0` and `rfid`s back to the caller.  That is a
bring-up probe, not an lv2 implementation: it lets the guest's own startup
path run far enough to identify the services it needs.  The next real step is
the lv2 syscall layer (process/thread creation, memory containers and the
module loader); until that exists, VSH can be mapped and entered, but not
completed.

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
not yet play that part. `stage-elf` is how a loader is inspected on its own.

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

### Recovering a readout

It cannot be derived from the container. On a console, the SPU probe
(`spu_rom/lsprobe.py`) brings back local storage, and `spu_rom/ls_sift.py
dump.bin --container <container>` walks every 32-byte window, runs the ladder
on it, and keeps the window whose derived key reproduces the container's
CBC-MAC tag. For model work, use a container and readout that were sealed
together, as in the sample above.

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
| 
