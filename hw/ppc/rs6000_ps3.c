/*
 * QEMU RS/6000-derived PlayStation 3 board
 *
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Local research model.  QEMU's code-provenance policy does not allow
 * AI-written code in upstream contributions; this file is an experiment and
 * is not intended to be submitted upstream.  Build and run instructions are
 * in PS3_MODEL.md at the top of the tree.
 *
 * The PS3 is a Cell BE: a 64-bit PowerPC PPU derived from the RS/6000 line,
 * eight SPUs, and a memory interface controller (MIC) that has to be
 * programmed before DRAM can be used.  Its first code is not a PC BIOS: the
 * mask ROM on each SPU opens the boot loader container (lv0ldr/bootldr) with a
 * per-console root key that only the ROM can read, verifies its CCM tag, wipes
 * local storage and falls through to the payload it just decrypted.
 *
 * This board gives that path somewhere to run:
 *
 *   - ps3-mic        the MIC's 64-bit MMIO registers, mmio_base 0xF050A000
 *   - ps3-boot-rom   the 0x400-byte SPU boot ROM and the 256 KiB local store
 *                    it wipes, plus the container opener the ROM carries and
 *                    the SPU interpreter the decrypted payload runs on
 *   - rs6000-ps3     a Cell PPU (970FX, the closest QEMU core), 256 MiB of
 *                    XDR, the flash window and the two devices above
 *
 * The MIC follows QEMU's rs6000_mc: a small set of presence/configuration
 * registers, with the operation bits of MIC_EXC completing rather than
 * staying set.  Unlike the RS/6000 controller, which is programmed through
 * ISA port I/O, the Cell controller is memory mapped, so the model is a
 * SysBus device with a MemoryRegion.
 *
 * Usage:
 *
 *   qemu-system-ppc64 -M rs6000-ps3 -bios rom.bin \
 *       -drive if=pflash,format=raw,file=CECH4301C.bin \
 *       -global ps3-boot-rom.readout-file=ch66.bin -nographic
 *
 * The ROM's own key is the 32-byte channel-66 readout.  It can be given as
 * `readout' (64 hex digits) or `readout-file' (32 raw bytes, in the order the
 * ROM reads them: K_lo first, then K_hi).  Without it the device feeds the ROM
 * 32 zero bytes, which is what the channel returns once metldr is loaded on
 * real hardware, and the tag check fails exactly as the ROM's "stop 2" path
 * does.  The container name defaults to lv0ldr.2 and falls back to the NOR
 * slots at 0xFC0000 and 0x840 when a dump carries no name.
 *
 * Once the container opens, its plaintext is placed at LS 0x400 - where the
 * mask ROM falls through to it - and executed by the SPU interpreter
 * (ps3_spu.c) rather than modelled in C.  Two things make the run visible:
 *
 *   -global ps3-boot-rom.ls-dump=ls.bin     the local store after the run,
 *                                           in the layout ls_sift.py reads
 *   -global ps3-boot-rom.spu-trace=on       one line per instruction
 *
 * `ps3-boot-rom.spu=off' keeps the container path and skips the payload run.
 * The device's own selftest replays the real 1 KiB mask ROM through the same
 * interpreter and checks that it produces the C opener's plaintext, so a
 * broken instruction semantic shows up as a failed selftest rather than as a
 * plausible-looking boot.
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "hw/core/boards.h"
#include "hw/core/cpu.h"
#include "hw/core/qdev-properties.h"
#include "hw/core/qdev-properties-system.h"
#include "hw/core/sysbus.h"
#include "hw/ppc/ppc.h"
#include "migration/vmstate.h"
#include "qapi/error.h"
#include "qom/object.h"
#include "system/address-spaces.h"
#include "system/block-backend.h"
#include "system/block-backend-io.h"
#include "system/blockdev.h"
#include "system/reset.h"
#include "system/runstate.h"
#include "system/system.h"

#include "ps3_spu.h"
#include "ps3_self.h"

#include <zlib.h>

#define TYPE_PS3_MIC "ps3-mic"
OBJECT_DECLARE_SIMPLE_TYPE(PS3MICState, PS3_MIC)

#define TYPE_PS3_BOOT_ROM "ps3-boot-rom"
OBJECT_DECLARE_SIMPLE_TYPE(PS3BootROMState, PS3_BOOT_ROM)

#define TYPE_RS6000_PS3_MACHINE MACHINE_TYPE_NAME("rs6000-ps3")

/* ---------------------------------------------------------------------- */
/* AES-128, encryption direction only: the boot ROM only ever encrypts.    */

static const uint8_t ps3_aes_sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
};

static const uint8_t ps3_aes_rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
};

static void ps3_aes_xtime(uint8_t *b)
{
    uint8_t hi = *b & 0x80;
    *b <<= 1;

    if (hi) {
        *b ^= 0x1B;
    }
}

static void ps3_aes_expand_key(const uint8_t key[16], uint8_t rk[176])
{
    int i;
    uint8_t t[4];

    memcpy(rk, key, 16);

    for (i = 4; i < 44; i++) {
        memcpy(t, rk + (i - 1) * 4, 4);

        if ((i % 4) == 0) {
            uint8_t first = t[0];

            t[0] = ps3_aes_sbox[t[1]];
            t[1] = ps3_aes_sbox[t[2]];
            t[2] = ps3_aes_sbox[t[3]];
            t[3] = ps3_aes_sbox[first];
            t[0] ^= ps3_aes_rcon[i / 4];
        }

        rk[i * 4 + 0] = rk[(i - 4) * 4 + 0] ^ t[0];
        rk[i * 4 + 1] = rk[(i - 4) * 4 + 1] ^ t[1];
        rk[i * 4 + 2] = rk[(i - 4) * 4 + 2] ^ t[2];
        rk[i * 4 + 3] = rk[(i - 4) * 4 + 3] ^ t[3];
    }
}

static void ps3_aes_encrypt(const uint8_t rk[176], const uint8_t in[16],
                            uint8_t out[16])
{
    uint8_t state[16];
    int round, i;

    memcpy(state, in, 16);

    for (i = 0; i < 16; i++) {
        state[i] ^= rk[i];
    }

    for (round = 1; round <= 10; round++) {
        uint8_t tmp[16];

        /* SubBytes and ShiftRows (row r rotates left by r).  The state is
         * column-major, so the flat index of (row r, column c) is 4*c + r. */
        for (i = 0; i < 16; i++) {
            int row = i % 4;
            int col = i / 4;

            tmp[i] = ps3_aes_sbox[state[((col + row) % 4) * 4 + row]];
        }

        if (round != 10) {
            /* MixColumns. */
            for (i = 0; i < 4; i++) {
                uint8_t a0 = tmp[i * 4 + 0];
                uint8_t a1 = tmp[i * 4 + 1];
                uint8_t a2 = tmp[i * 4 + 2];
                uint8_t a3 = tmp[i * 4 + 3];
                uint8_t x0 = a0, x1 = a1, x2 = a2, x3 = a3;
                uint8_t m0, m1, m2, m3;

                ps3_aes_xtime(&x0);
                ps3_aes_xtime(&x1);
                ps3_aes_xtime(&x2);
                ps3_aes_xtime(&x3);

                m0 = x0 ^ x1 ^ a1 ^ a2 ^ a3;
                m1 = a0 ^ x1 ^ x2 ^ a2 ^ a3;
                m2 = a0 ^ a1 ^ x2 ^ x3 ^ a3;
                m3 = x0 ^ a0 ^ a1 ^ a2 ^ x3;
                tmp[i * 4 + 0] = m0;
                tmp[i * 4 + 1] = m1;
                tmp[i * 4 + 2] = m2;
                tmp[i * 4 + 3] = m3;
            }
        }

        for (i = 0; i < 16; i++) {
            state[i] = tmp[i] ^ rk[round * 16 + i];
        }
    }

    memcpy(out, state, 16);
}

static void ps3_aes_ctr_block(const uint8_t rk[176], uint32_t counter,
                              const uint8_t suffix[12], uint8_t out[16])
{
    uint8_t block[16];

    block[0] = counter >> 24;
    block[1] = counter >> 16;
    block[2] = counter >> 8;
    block[3] = counter;
    memcpy(block + 4, suffix, 12);
    ps3_aes_encrypt(rk, block, out);
}

/* ---------------------------------------------------------------------- */
/* The Cell memory interface controller.                                   */

/*
 * Register offsets from the Cell Broadband Engine Hardware Initialization
 * Guide (2.2.2.3, Appendix E), the same set the boot ROM programs.  A few
 * names differ between revisions of the guide; the offsets do not.
 */
enum {
    PS3_MIC_CTL_CNFG2         = 0x040,
    PS3_MIC_AUX_TRC_BASE      = 0x050,
    PS3_MIC_AUX_TRC_MAX_ADDR  = 0x058,
    PS3_MIC_AUX_TRC_CUR_ADDR  = 0x060,
    PS3_MIC_CTL_CNFG_0        = 0x080,
    PS3_MIC_CALIBRATION_0     = 0x0A0,
    PS3_MIC_TM_THRESHOLD_0    = 0x0A8,
    PS3_MIC_QUE_BURSTSIZE_0   = 0x0B0,
    PS3_MIC_DEV_CFG_0         = 0x0C0,
    PS3_MIC_MEM_CFG_0         = 0x0C8,
    PS3_MIC_TRCD_PCHG_0       = 0x0D0,
    PS3_MIC_CMD_DUR_0         = 0x0D8,
    PS3_MIC_CMD_SPC_0         = 0x0E0,
    PS3_MIC_DF_CTL_0          = 0x0E8,
    PS3_MIC_XIO_PTCAL_DATA_0  = 0x0F0,
    PS3_MIC_ECC_ADDR_0        = 0x0F8,
    PS3_MIC_YRAC_DTA_0        = 0x100,
    PS3_MIC_YDRAM_DTA_0       = 0x108,
    PS3_MIC_YREG_STAT_0       = 0x110,
    PS3_MIC_INIT_CTL_0        = 0x118,
    PS3_MIC_INIT_CNTS_0       = 0x120,
    PS3_MIC_PTCAL_ADR_0       = 0x130,
    PS3_MIC_YRAC_DTA_1        = 0x140,
    PS3_MIC_YDRAM_DTA_1       = 0x148,
    PS3_MIC_YREG_STAT_1       = 0x150,
    PS3_MIC_INIT_CTL_1        = 0x158,
    PS3_MIC_INIT_CNTS_1       = 0x160,
    PS3_MIC_PTCAL_ADR_1       = 0x170,
    PS3_MIC_DEV_CFG_1         = 0x180,
    PS3_MIC_MEM_CFG_1         = 0x188,
    PS3_MIC_TRCD_PCHG_1       = 0x190,
    PS3_MIC_CMD_DUR_1         = 0x198,
    PS3_MIC_CMD_SPC_1         = 0x1A0,
    PS3_MIC_DF_CTL_1          = 0x1A8,
    PS3_MIC_XIO_PTCAL_DATA_1  = 0x1B0,
    PS3_MIC_ECC_ADDR_1        = 0x1B8,
    PS3_MIC_CTL_CNFG_1        = 0x1C0,
    PS3_MIC_CALIBRATION_1     = 0x1E0,
    PS3_MIC_TM_THRESHOLD_1    = 0x1E8,
    PS3_MIC_QUE_BURSTSIZE_1   = 0x1F0,
    PS3_MIC_REF_SCB           = 0x200,
    PS3_MIC_EXC               = 0x208,
    PS3_MIC_MNT_CFG           = 0x210,
    PS3_MIC_DF_CONFIG         = 0x218,
    PS3_MIC_FIR               = 0x230,
    PS3_MIC_FIR_DEBUG         = 0x238,
};

#define PS3_MIC_MMIO_BASE 0xF050A000
#define PS3_MIC_MMIO_SIZE 0x240

#define PS3_MIC_EXC_ZERO_ALL    (1ULL << 31)
#define PS3_MIC_EXC_REFRESH     (1ULL << 30)
#define PS3_MIC_EXC_SCRUB       (1ULL << 24)
#define PS3_MIC_EXC_PATTERN     (0x7ULL << 25)

struct PS3MICState {
    SysBusDevice parent_obj;

    MemoryRegion iomem;
    MemoryRegion *ram;      /* XDR, zeroed by the zero-all operation */
    uint64_t regs[PS3_MIC_MMIO_SIZE / 8];
    uint64_t writes;
    unsigned channels;
};

static const char *ps3_mic_reg_name(hwaddr offset)
{
    switch (offset) {
    case PS3_MIC_CTL_CNFG2:        return "CTL_CNFG2";
    case PS3_MIC_CTL_CNFG_0:       return "CTL_CNFG_0";
    case PS3_MIC_DEV_CFG_0:        return "DEV_CFG_0";
    case PS3_MIC_MEM_CFG_0:        return "MEM_CFG_0";
    case PS3_MIC_TRCD_PCHG_0:      return "TRCD_PCHG_0";
    case PS3_MIC_CMD_SPC_0:        return "CMD_SPC_0";
    case PS3_MIC_DF_CTL_0:         return "DF_CTL_0";
    case PS3_MIC_DEV_CFG_1:        return "DEV_CFG_1";
    case PS3_MIC_MEM_CFG_1:        return "MEM_CFG_1";
    case PS3_MIC_TRCD_PCHG_1:      return "TRCD_PCHG_1";
    case PS3_MIC_CMD_SPC_1:        return "CMD_SPC_1";
    case PS3_MIC_DF_CTL_1:         return "DF_CTL_1";
    case PS3_MIC_REF_SCB:          return "REF_SCB";
    case PS3_MIC_EXC:              return "EXC";
    case PS3_MIC_MNT_CFG:          return "MNT_CFG";
    case PS3_MIC_DF_CONFIG:        return "DF_CONFIG";
    default:                       return NULL;
    }
}

static uint64_t ps3_mic_read(void *opaque, hwaddr offset, unsigned size)
{
    PS3MICState *s = PS3_MIC(opaque);

    if ((offset & 7) || offset >= PS3_MIC_MMIO_SIZE) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "ps3-mic: bad read at 0x%" HWADDR_PRIx "\n", offset);
        return 0;
    }

    return s->regs[offset / 8];
}

static void ps3_mic_write(void *opaque, hwaddr offset, uint64_t value,
                          unsigned size)
{
    PS3MICState *s = PS3_MIC(opaque);
    const char *name;

    if ((offset & 7) || offset >= PS3_MIC_MMIO_SIZE) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "ps3-mic: bad write at 0x%" HWADDR_PRIx "\n", offset);
        return;
    }

    /*
     * MIC_EXC is the one register whose written value is not what a later
     * read returns: zero-all, scrub and pattern-load are operations that
     * complete, while the refresh enable is state.  The hardware clears the
     * operation bits, so a polling loop that writes 0xC0000000 and waits for
     * 0x80000000 to drop terminates instead of spinning forever.
     */
    if (offset == PS3_MIC_EXC) {
        if ((value & PS3_MIC_EXC_ZERO_ALL) && s->ram) {
            memset(memory_region_get_ram_ptr(s->ram), 0,
                   memory_region_size(s->ram));
        }

        s->regs[offset / 8] = value & PS3_MIC_EXC_REFRESH;

        if (value & PS3_MIC_EXC_ZERO_ALL) {
            info_report("ps3-mic: EXC zero-all completed");
        }
        if (value & PS3_MIC_EXC_SCRUB) {
            info_report("ps3-mic: EXC fast scrub completed");
        }
        if (value & PS3_MIC_EXC_PATTERN) {
            info_report("ps3-mic: EXC pattern load completed");
        }
    } else {
        s->regs[offset / 8] = value;

        name = ps3_mic_reg_name(offset);

        if (name && value) {
            info_report("ps3-mic: %s <- 0x%" PRIx64, name, value);
        }
    }

    if (value && offset < PS3_MIC_REF_SCB) {
        unsigned channel = offset >= PS3_MIC_YRAC_DTA_1 ? 2 : 1;

        if (channel > s->channels) {
            s->channels = channel;
        }
    }

    s->writes++;
}

static const MemoryRegionOps ps3_mic_ops = {
    .read = ps3_mic_read,
    .write = ps3_mic_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid = {
        .min_access_size = 8,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 8,
        .max_access_size = 8,
    },
};

static void ps3_mic_reset(DeviceState *dev)
{
    PS3MICState *s = PS3_MIC(dev);

    memset(s->regs, 0, sizeof(s->regs));
    s->writes = 0;
    s->channels = 0;
}

static void ps3_mic_realize(DeviceState *dev, Error **errp)
{
    PS3MICState *s = PS3_MIC(dev);

    memory_region_init_io(&s->iomem, OBJECT(s), &ps3_mic_ops, s,
                          "ps3-mic", PS3_MIC_MMIO_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
}

static const VMStateDescription vmstate_ps3_mic = {
    .name = "ps3-mic",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64_ARRAY(regs, PS3MICState, PS3_MIC_MMIO_SIZE / 8),
        VMSTATE_UINT64(writes, PS3MICState),
        VMSTATE_UINT32(channels, PS3MICState),
        VMSTATE_END_OF_LIST()
    },
};

static void ps3_mic_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = ps3_mic_realize;
    device_class_set_legacy_reset(dc, ps3_mic_reset);
    dc->vmsd = &vmstate_ps3_mic;
    object_class_property_add_link(klass, "ram", TYPE_MEMORY_REGION,
                                   offsetof(PS3MICState, ram),
                                   object_property_allow_set_link, 0);
}

static const TypeInfo ps3_mic_info = {
    .name = TYPE_PS3_MIC,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(PS3MICState),
    .class_init = ps3_mic_class_init,
};

/* ---------------------------------------------------------------------- */
/* The SPU boot ROM and the container it opens.                            */

#define PS3_ROM_SIZE        0x400
#define PS3_LS_SIZE         0x40000
#define PS3_CONTAINER_HDR   0x40
#define PS3_ROM_MAX_BLOCKS  0x3DC0

/*
 * lv0's early console.  Its putchar walks a pointer whose value is
 * 0x24000000000; the PPU's physical address reduction in this model lands the
 * status and data words at 0xFFF308 and 0xFFF31C.  The status bit it polls is
 * 0x100 (transmit holding register empty); the data word is one character.
 */
#define PS3_PPE_UART_BASE   0x000FFF000
#define PS3_PPE_UART_SIZE   0x1000
#define PS3_PPE_UART_STATUS 0x308
#define PS3_PPE_UART_DATA   0x31C

enum {
    PS3_BOOT_OK = 1,
    PS3_BOOT_BAD_HEADER,
    PS3_BOOT_BAD_MAC,
    PS3_BOOT_NO_CONTAINER,
    PS3_BOOT_BAD_ROM,
};

struct PS3BootROMState {
    SysBusDevice parent_obj;

    MemoryRegion rom_mr;      /* the 0x400-byte mask ROM, 32-bit byte-swapped */
    MemoryRegion ls_mr;       /* 256 KiB local store, plaintext lands at 0x400 */
    MemoryRegion regs_mr;     /* status and control */
    MemoryRegion flash_mr;    /* the console's flash image, when a drive is given */
    MemoryRegion uart_mr;     /* the PPU-side console lv0 polls */
    MemoryRegion uart_alias_mr;
    char uart_line[256];
    size_t uart_len;
    unsigned uart_hits;

    BlockBackend *blk;
    char *rom_file;
    char *container;
    char *readout;
    char *readout_file;
    uint8_t readout_bytes[32];
    bool has_readout;
    bool selftest;
    bool spu_run;
    bool spu_trace;
    char *ls_dump;
    uint64_t flash_base;

    PS3SPU *spu;
    char spu_why[160];
    uint64_t spu_insns;
    int spu_status;

    /* One SPU stage image run on its own, for the boot-chain tests. */
    char *stage_elf;
    char *stage_dump;
    char *stage_args;
    uint32_t stage_entry;
    uint64_t stage_limit;
    uint64_t stage_wait;
    uint64_t stage_version;

    /*
     * The PPU side of the chain.  lv0 and everything above it are 64-bit
     * PowerPC, not SPU code, so they need the real CPU core rather than the
     * SPU interpreter.  The stage loader places such an ELF in RAM and starts
     * the 970FX at its entry point; the timer below is how a headless test
     * bounds the run and reports where the core got to.
     */
    MemoryRegion *ram;
    char *ppu_elf;
    char *ppu_dump;
    uint32_t ppu_entry;
    uint64_t ppu_ticks;
    uint64_t ppu_tick_ns;
    QEMUTimer *ppu_timer;
    uint64_t ppu_tick_count;
    uint64_t ppu_last_pc;
    bool ppu_trace;
    char ppu_why[160];

    /*
     * The application layer: appldr opens /dev_flash/vsh/module/vsh.self and
     * hands it to lv2, which is what actually creates the VSH process.  The
     * loader below does the container work - application keyset, zlib segment
     * expansion, ELF mapping - so the image is in RAM exactly where lv2 would
     * put it.  vsh-run hands the PPU that entry point for a bare LLE run; the
     * lv2 layer itself is not modelled yet, so a run stops at the first lv2
     * call and the trace says which one.
     */
    char *vsh_self;
    char *vsh_dump;
    char *vsh_erk;
    char *vsh_riv;
    char *dev_flash;
    char *dev_flash3;
    bool vsh_run;
    uint32_t vsh_entry;
    uint32_t vsh_toc;
    unsigned vsh_segments;
    uint64_t vsh_bytes;
    char vsh_why[160];

    /* The lv2 layer vsh-run answers the guest's syscalls with. */
    uint32_t lv2_next_id;
    bool lv2_exited;
    int32_t lv2_exit_status;

    uint8_t rom[PS3_ROM_SIZE];
    size_t rom_len;
    uint8_t *flash;
    size_t flash_len;

    uint8_t key[16];          /* the payload key the ROM derived */
    uint32_t status;
    uint32_t blocks;
    uint32_t bytes;
    uint32_t selftest_result; /* 1 passed, 2 failed, 0 not run */
    uint64_t container_offset;
};

static uint32_t ps3_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

/*
 * The lv2 syscall trampoline used by vsh-run.
 *
 * lv2 is the Cell's operating system layer: a guest `sc` enters at 0xC00 with
 * the call number in r11 and the arguments in r3..r10.  A bare 970FX has no
 * handler there, so the trampoline does the one thing the guest cannot do for
 * itself - it publishes the call to the board by storing r11 in the register
 * window at 0xF1040014.  ps3_lv2_service() runs the call from there, reads the
 * arguments out of the live GPRs and leaves r3 plus an exit flag in the
 * scratch block at RAM 0x880; the trampoline returns them with the rfid lv2
 * itself would use.
 *
 * The .S source and the encoder that produces these words live beside each
 * other in the development tree (.tmp/ps3_lv2_shim.S, .tmp/shimasm.py); the
 * encoder is checked against the previous trampoline image, so the words
 * below need no assembler at runtime.
 */
static const uint32_t ps3_lv2_shim[] = {
    0x3D800000, 0x618CF104, 0x558C801E, 0x618C0014, 0x916C0000,
    0x3D800000, 0x618C0880, 0x806C0000, 0x800C0004, 0x2C000000,
    0x40820010, 0x7D9A02A6, 0x7D9A03A6, 0x4C000024, 0x48000000,
};

static void ps3_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}

/*
 * The lv2 scratch area: the 0xC00 trampoline collects the return value from
 * 0x880 and reads 0x884 to learn that the process has ended.  0x808 holds the
 * bump pointer sys_memory_allocate hands out blocks from.
 */
#define PS3_LV2_SCRATCH 0x880
#define PS3_LV2_HEAP    0x808

/* lv2 reports its errors as negative Cell error codes. */
#define PS3_LV2_EINVAL  ((int32_t)0x80010002)
#define PS3_LV2_ENOSYS  ((int32_t)0x80010003)
#define PS3_LV2_ENOMEM  ((int32_t)0x80010004)
#define PS3_LV2_EFAULT  ((int32_t)0x8001000D)

/*
 * The mask ROM is stored with each 32-bit word byte reversed (the dump's
 * spu_rom_byteswap.bin form).  Detect it by the AES ShiftRows pattern at
 * 0x210: 00 05 0A 0F ... natively, 0F 0A 05 00 ... swapped.
 */
static bool ps3_rom_is_swapped(const uint8_t *rom)
{
    static const uint8_t native[8] = { 0x00, 0x05, 0x0A, 0x0F, 0x04, 0x09, 0x0E, 0x03 };
    static const uint8_t swapped[8] = { 0x0F, 0x0A, 0x05, 0x00, 0x03, 0x0E, 0x09, 0x04 };

    if (!memcmp(rom + 0x210, native, sizeof(native))) {
        return false;
    }

    return !memcmp(rom + 0x210, swapped, sizeof(swapped));
}

static void ps3_rom_unswap(const uint8_t *in, uint8_t *out, size_t len)
{
    size_t i;

    for (i = 0; i + 4 <= len; i += 4) {
        out[i + 0] = in[i + 3];
        out[i + 1] = in[i + 2];
        out[i + 2] = in[i + 1];
        out[i + 3] = in[i + 0];
    }

    if (i < len) {
        memcpy(out + i, in + i, len - i);
    }
}

static bool ps3_container_find(const uint8_t *flash, size_t flash_len,
                               const char *name, uint64_t *offset,
                               char *why, size_t why_len)
{
    const size_t name_len = strlen(name);
    size_t at;

    for (at = 0; at + 0x20 + PS3_CONTAINER_HDR <= flash_len; at++) {
        const uint8_t *hdr;
        uint32_t blocks, total;

        if (memcmp(flash + at, name, name_len)) {
            continue;
        }

        if (at + 0x20 + PS3_CONTAINER_HDR > flash_len) {
            break;
        }

        hdr = flash + at + 0x20;
        blocks = ps3_be32(hdr);
        total = ps3_be32(hdr + 0x10);

        if (blocks != total || blocks == 0 ||
            blocks > PS3_ROM_MAX_BLOCKS ||
            at + 0x20 + PS3_CONTAINER_HDR + (size_t)blocks * 16 > flash_len) {
            continue;
        }

        *offset = at + 0x20;
        return true;
    }

    /*
     * NOR dumps do not always carry the name: the console's own SPU ROM is
     * handed the effective address of the container, not a string.  Fall
     * back to the two slots the PS3 boot chain uses - lv0ldr at 0xFC0000 and
     * metldr at 0x000840 - and accept a header that agrees with itself.
     */
    {
        static const size_t slots[] = { 0xFC0000, 0x000840 };
        size_t i;

        for (i = 0; i < ARRAY_SIZE(slots); i++) {
            size_t slot = slots[i];
            const uint8_t *hdr;
            uint32_t blocks, total;

            if (slot + PS3_CONTAINER_HDR > flash_len) {
                continue;
            }

            hdr = flash + slot;
            blocks = ps3_be32(hdr);
            total = ps3_be32(hdr + 0x10);

            if (blocks != total || blocks == 0 ||
                blocks > PS3_ROM_MAX_BLOCKS ||
                slot + PS3_CONTAINER_HDR + (size_t)blocks * 16 > flash_len) {
                continue;
            }

            *offset = slot;
            return true;
        }
    }

    snprintf(why, why_len, "no container called %s in the flash image", name);
    return false;
}

/*
 * The sequence the ROM at 0x15C-0x39C performs, given the header at `hdr' and
 * the 32 bytes the ROM read from channel 66:
 *
 *   K_payload = AES-128-ECB(K_hi, hdr[0x20..0x2F] XOR K_lo)
 *   CBC-MAC over hdr[0x00..0x2F], then over the plaintext
 *   CTR with a counter that counts DOWN from the block count, hdr[4..15] as
 *   the 12-byte suffix; only the last Size1 blocks are encrypted
 *   tag = CBC-MAC XOR AES-128-ECB(K_payload, 0 || suffix)
 */
static uint32_t ps3_rom_open(const uint8_t *hdr, const uint8_t *body,
                             size_t body_len, const uint8_t ch66[32],
                             uint8_t *plain, uint8_t key_out[16])
{
    uint32_t encrypted = ps3_be32(hdr);
    uint32_t total = ps3_be32(hdr + 0x10);
    uint8_t rk[176];
    uint8_t chain[16] = { 0 };
    uint8_t block[16];
    uint8_t tag[16];
    uint32_t i;
    int j;

    if (!total || total > PS3_ROM_MAX_BLOCKS || body_len < (size_t)total * 16) {
        return PS3_BOOT_BAD_HEADER;
    }

    if (encrypted > total) {
        encrypted = total;
    }

    /* K_payload = E(K_hi, hdr[0x20..0x2F] ^ K_lo). */
    for (j = 0; j < 16; j++) {
        block[j] = hdr[0x20 + j] ^ ch66[j];
    }

    ps3_aes_expand_key(ch66 + 16, rk);
    ps3_aes_encrypt(rk, block, key_out);

    ps3_aes_expand_key(key_out, rk);

    /* The header is authenticated as three blocks of associated data. */
    for (i = 0; i < 3; i++) {
        for (j = 0; j < 16; j++) {
            block[j] = hdr[i * 16 + j] ^ chain[j];
        }

        ps3_aes_encrypt(rk, block, chain);
    }

    /* Only the trailing `encrypted' blocks have a keystream; the rest of the
     * body is copied through by the ROM (the Size1 gate at 0x294). */
    for (i = 0; i < total; i++) {
        const uint8_t *ct = body + (size_t)i * 16;
        uint8_t *pt = plain + (size_t)i * 16;
        uint32_t counter = total - i;

        if (i < total - encrypted) {
            memcpy(pt, ct, 16);
        } else {
            uint8_t stream[16];

            ps3_aes_ctr_block(rk, counter, hdr + 4, stream);

            for (j = 0; j < 16; j++) {
                pt[j] = ct[j] ^ stream[j];
            }
        }

        for (j = 0; j < 16; j++) {
            block[j] = pt[j] ^ chain[j];
        }

        ps3_aes_encrypt(rk, block, chain);
    }

    /* S0 = E(K_payload, 0 || suffix); the stored tag is the MAC masked by S0. */
    ps3_aes_ctr_block(rk, 0, hdr + 4, tag);

    for (j = 0; j < 16; j++) {
        tag[j] ^= hdr[0x30 + j];
    }

    if (memcmp(tag, chain, 16)) {
        return PS3_BOOT_BAD_MAC;
    }

    return PS3_BOOT_OK;
}

/* The four instruction groups the 0x400-byte ROM carries, as the ROM runs
 * them.  The ROM builds its own AES tables so that no key material is ever in
 * local storage before it is used. */
static void ps3_rom_describe(const uint8_t *rom, bool swapped)
{
    info_report("ps3-boot-rom: 0x000 entry gate (SPU_RdMachStat bit 0x20000)");
    info_report("ps3-boot-rom: 0x020 AES tables built in LS "
                "(GF(2^8) log at LS[0x400], S-box into $16..$31)");
    info_report("ps3-boot-rom: 0x0E4 header DMA from SPU_RdSigNotify1/2, 0x40 bytes");
    info_report("ps3-boot-rom: 0x148 channel 66 read, 8 x 32-bit = 32-byte root key");
    info_report("ps3-boot-rom: 0x15C key ladder, 0x1B8 CBC-MAC over the header");
    info_report("ps3-boot-rom: 0x288 CTR decrypt (counter counts down), 0x390 tag check");
    info_report("ps3-boot-rom: 0x3A0 local store wiped, falls through to LS[0x400]");

    if (swapped) {
        info_report("ps3-boot-rom: image is 32-bit byte-swapped; converted for inspection");
    }

    if (ps3_rom_is_swapped(rom) && !swapped) {
        info_report("ps3-boot-rom: warning: image does not look like the Cell mask ROM");
    }
}

static void ps3_rom_set_status(PS3BootROMState *s, uint32_t status,
                               const char *why)
{
    s->status = status;

    switch (status) {
    case PS3_BOOT_OK:
        info_report("ps3-boot-rom: container verified, %u bytes of payload",
                    s->bytes);
        break;
    case PS3_BOOT_BAD_HEADER:
        info_report("ps3-boot-rom: stop 1, invalid payload length (%s)", why);
        break;
    case PS3_BOOT_BAD_MAC:
        info_report("ps3-boot-rom: stop 2, MAC mismatch (%s)", why);
        break;
    case PS3_BOOT_NO_CONTAINER:
        info_report("ps3-boot-rom: %s", why);
        break;
    case PS3_BOOT_BAD_ROM:
        info_report("ps3-boot-rom: %s", why);
        break;
    }
}

/*
 * The local store after a run, in the layout ls_sift.py reads: 256 KiB of
 * local store and 16 KiB of zero padding.  It is the only way to see what a
 * stage built in place, so both the container path and the stage path write
 * it when `ls-dump` is set.
 */
static void ps3_ls_write_dump(PS3BootROMState *s)
{
    uint8_t *ram;
    g_autofree uint8_t *blob = NULL;
    g_autoptr(GError) err = NULL;

    if (!s->ls_dump || !*s->ls_dump) {
        return;
    }

    ram = memory_region_get_ram_ptr(&s->ls_mr);
    blob = g_malloc(PS3_LS_SIZE + 0x4000);
    memcpy(blob, ram, PS3_LS_SIZE);
    memset(blob + PS3_LS_SIZE, 0, 0x4000);

    if (!g_file_set_contents(s->ls_dump, (const char *)blob,
                             PS3_LS_SIZE + 0x4000, &err)) {
        info_report("ps3-spu: cannot write %s: %s", s->ls_dump, err->message);
    } else {
        info_report("ps3-spu: local store written to %s", s->ls_dump);
    }
}

static void ps3_rom_boot(PS3BootROMState *s)
{
    const char *name = s->container ?: "lv0ldr.2";
    uint8_t ch66[32];
    uint8_t *plain;
    char why[160];
    uint32_t result;

    memory_region_set_readonly(&s->ls_mr, false);
    memset(memory_region_get_ram_ptr(&s->ls_mr), 0, PS3_LS_SIZE);

    if (s->rom_len != PS3_ROM_SIZE) {
        snprintf(why, sizeof(why), "the mask ROM is 0x%x bytes, expected 0x400",
                 (unsigned)s->rom_len);
        ps3_rom_set_status(s, PS3_BOOT_BAD_ROM, why);
        return;
    }

    if (!s->flash) {
        snprintf(why, sizeof(why),
                 "no flash image (%s); pass -drive if=pflash,format=raw,file=...",
                 name);
        ps3_rom_set_status(s, PS3_BOOT_NO_CONTAINER, why);
        return;
    }

    if (!ps3_container_find(s->flash, s->flash_len, name,
                            &s->container_offset, why, sizeof(why))) {
        ps3_rom_set_status(s, PS3_BOOT_NO_CONTAINER, why);
        return;
    }

    /*
     * The ROM's only source of the per-console key is channel 66.  When the
     * caller has a readout it is used as the ROM read it - first 16 bytes in
     * K_lo, second 16 in K_hi.  With no readout the channel returns zeros,
     * which is what it does once metldr is loaded, and the MAC fails.
     */
    if (s->has_readout) {
        memcpy(ch66, s->readout_bytes, sizeof(ch66));
    } else {
        memset(ch66, 0, sizeof(ch66));
        info_report("ps3-boot-rom: no channel-66 readout supplied; using zeros");
    }

    s->blocks = ps3_be32(s->flash + s->container_offset + 0x10);
    s->bytes = s->blocks * 16;

    plain = g_malloc0(s->bytes);

    result = ps3_rom_open(s->flash + s->container_offset,
                          s->flash + s->container_offset + PS3_CONTAINER_HDR,
                          s->bytes, ch66, plain, s->key);

    if (result == PS3_BOOT_OK) {
        uint8_t *ls = memory_region_get_ram_ptr(&s->ls_mr);

        memcpy(ls + 0x400, plain, s->bytes);

        /*
         * The ROM falls through to 0x400.  Run what it left there on the SPU
         * model, with the same channel-66 readout and the container's
         * effective address on the signal channels.
         */
        if (s->spu_run && s->spu) {
            ps3_spu_set_ch66(s->spu, ch66);
            ps3_spu_set_sig(s->spu, 0, s->container_offset);
            ps3_spu_set_trace(s->spu, s->spu_trace);
            s->spu_status = ps3_spu_run(s->spu, 0x400, 1 << 26,
                                        s->spu_why, sizeof(s->spu_why));
            s->spu_insns = ps3_spu_insns(s->spu);

            info_report("ps3-spu: %s (%" PRIu64 " instructions, %" PRIu64
                        " MFC gets, %" PRIu64 " puts)",
                        s->spu_why, s->spu_insns, ps3_spu_mfc_gets(s->spu),
                        ps3_spu_mfc_puts(s->spu));

            if (ps3_spu_mfc_puts(s->spu)) {
                info_report("ps3-spu: last put 0x%X bytes to EA 0x%X",
                            ps3_spu_last_put_size(s->spu),
                            ps3_spu_last_put_ea(s->spu));
            }

            ps3_ls_write_dump(s);
        }
    }

    g_free(plain);

    snprintf(why, sizeof(why), "%s at flash 0x%" PRIx64,
             name, s->container_offset);
    ps3_rom_set_status(s, result, why);
}

static void ps3_rom_selftest(PS3BootROMState *s)
{
    static const uint8_t kat_key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
    static const uint8_t kat_plain[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    };
    static const uint8_t kat_cipher[16] = {
        0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30,
        0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A,
    };
    uint8_t rk[176], got[16];
    uint8_t ch66[32];
    uint8_t hdr[PS3_CONTAINER_HDR];
    uint8_t body[3 * 16];
    uint8_t plain[3 * 16];
    uint8_t key[16];
    uint32_t result;
    int i;

    ps3_aes_expand_key(kat_key, rk);
    ps3_aes_encrypt(rk, kat_plain, got);

    if (memcmp(got, kat_cipher, 16)) {
        s->selftest_result = 2;
        info_report("ps3-boot-rom: selftest FAILED (AES-128 known answer)");
        return;
    }

    /* Seal a three-block container with a known readout, then open it with
     * the same ROM path used for a real flash image. */
    for (i = 0; i < 32; i++) {
        ch66[i] = i * 7 + 3;
    }

    memset(hdr, 0, sizeof(hdr));
    ps3_put_be32(hdr, 3);
    ps3_put_be32(hdr + 0x10, 3);

    for (i = 0; i < 12; i++) {
        hdr[4 + i] = 0x10 + i;
        hdr[0x14 + i] = 0x40 + i;
        hdr[0x20 + i] = 0x70 + i;
    }

    for (i = 0; i < 48; i++) {
        body[i] = (uint8_t)(i * 11 + 5);
    }

    /* Derive the payload key the same way the ROM does. */
    {
        uint8_t block[16];

        for (i = 0; i < 16; i++) {
            block[i] = hdr[0x20 + i] ^ ch66[i];
        }

        ps3_aes_expand_key(ch66 + 16, rk);
        ps3_aes_encrypt(rk, block, key);
        ps3_aes_expand_key(key, rk);
    }

    /* Build the ciphertext body and the tag. *s->temp is the sealed body. */
    {
        uint8_t mac[16] = { 0 };
        uint8_t block[16];
        uint8_t tag[16];

        for (i = 0; i < 3; i++) {
            int j;

            for (j = 0; j < 16; j++) {
                block[j] = hdr[i * 16 + j] ^ mac[j];
            }

            ps3_aes_encrypt(rk, block, mac);
        }

        for (i = 0; i < 3; i++) {
            uint8_t stream[16];
            int j;

            ps3_aes_ctr_block(rk, 3 - i, hdr + 4, stream);

            for (j = 0; j < 16; j++) {
                body[i * 16 + j] ^= stream[j];
                block[j] = (body[i * 16 + j] ^ stream[j]) ^ mac[j];
            }

            ps3_aes_encrypt(rk, block, mac);
        }

        ps3_aes_ctr_block(rk, 0, hdr + 4, tag);

        for (i = 0; i < 16; i++) {
            hdr[0x30 + i] = mac[i] ^ tag[i];
        }
    }

    result = ps3_rom_open(hdr, body, sizeof(body), ch66, plain, key);

    if (result != PS3_BOOT_OK) {
        s->selftest_result = 2;
        info_report("ps3-boot-rom: selftest FAILED (round trip returned %u)",
                    result);
        return;
    }

    for (i = 0; i < 48; i++) {
        if (plain[i] != (uint8_t)(i * 11 + 5)) {
            s->selftest_result = 2;
            info_report("ps3-boot-rom: selftest FAILED (plaintext mismatch)");
            return;
        }
    }

    /*
     * Now the same container through the SPU interpreter: the real 1 KiB mask
     * ROM executed from LS 0, with the readout on channel 66 and the
     * container's effective address on the signal channels.  The ROM has to
     * reach 0x400 with the same plaintext the C opener produced.  This is the
     * model's acceptance test: it is the ROM's own AES, table build, key
     * ladder and tag check running as instructions rather than as C.
     */
    if (s->rom_len == PS3_ROM_SIZE) {
        const uint32_t ea = 0x100000;
        uint8_t *flash = g_malloc0(ea + sizeof(hdr) + sizeof(body));
        uint8_t *ls = g_malloc0(PS3_LS_SIZE);
        PS3SPU *spu;
        char why[192];
        int status;

        /* The ROM arrives byte-swapped as often as not; the SPU fetches the
         * native form, which is what the device left in its own region. */
        const uint8_t *rom = memory_region_get_ram_ptr(&s->rom_mr);

        memcpy(flash + ea, hdr, sizeof(hdr));
        memcpy(flash + ea + sizeof(hdr), body, sizeof(body));
        memcpy(ls, rom, PS3_ROM_SIZE);

        spu = ps3_spu_new(ls, PS3_LS_SIZE, flash, ea + sizeof(hdr) + sizeof(body));
        ps3_spu_set_ch66(spu, ch66);
        ps3_spu_set_sig(spu, 0, ea);
        ps3_spu_set_reg(spu, 90, 0x450);   /* header hand-off, LS 0x410 */

        status = ps3_spu_run_to(spu, 0, 0x400, 4000000, why, sizeof(why));

        if (status != 0) {
            s->selftest_result = 2;
            info_report("ps3-boot-rom: selftest FAILED (mask ROM in the "
                        "interpreter: %s after %" PRIu64 " instructions)",
                        why, ps3_spu_insns(spu));
        } else if (memcmp(ls + 0x400, plain, sizeof(body))) {
            unsigned at = 0;

            for (i = 0; i + (int)sizeof(body) <= PS3_LS_SIZE; i += 16) {
                if (!memcmp(ls + i, plain, sizeof(body))) {
                    at = i;
                    break;
                }
            }

            s->selftest_result = 2;
            info_report("ps3-boot-rom: selftest FAILED (the interpreter's mask "
                        "ROM reached 0x400 but the plaintext does not match; "
                        "found at LS 0x%X, expected 0x400)", at);
        } else {
            info_report("ps3-boot-rom: the mask ROM in the SPU interpreter "
                        "opened the same container (%" PRIu64
                        " instructions, plaintext at LS 0x400)",
                        ps3_spu_insns(spu));
        }

        ps3_spu_free(spu);
        g_free(ls);
        g_free(flash);

        if (s->selftest_result == 2) {
            return;
        }
    }

    s->selftest_result = 1;
    info_report("ps3-boot-rom: selftest passed (AES-128 KAT, sealed container "
                "round trip, mask ROM replayed by the SPU interpreter)");
}

static uint64_t ps3_rom_regs_read(void *opaque, hwaddr offset, unsigned size)
{
    PS3BootROMState *s = PS3_BOOT_ROM(opaque);

    switch (offset) {
    case 0x00:
        return s->status;
    case 0x04:
        return s->blocks;
    case 0x08:
        return s->bytes;
    case 0x0C:
        return s->selftest_result;
    case 0x10:
        return s->container_offset;
    default:
        if (offset >= 0x20 && offset < 0x30) {
            return s->key[offset - 0x20];
        }
        return 0;
    }
}

static void ps3_lv2_service(PS3BootROMState *s);

static void ps3_rom_regs_write(void *opaque, hwaddr offset, uint64_t value,
                               unsigned size)
{
    PS3BootROMState *s = PS3_BOOT_ROM(opaque);

    switch (offset) {
    case 0x10:
        if (value == 1) {
            ps3_rom_boot(s);
        } else if (value == 2) {
            ps3_rom_selftest(s);
        }
        break;
    case 0x14:
        /* vsh-run's 0xC00 trampoline publishes each lv2 call here. */
        ps3_lv2_service(s);
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "ps3-boot-rom: write to 0x%" HWADDR_PRIx "\n", offset);
        break;
    }
}

static const MemoryRegionOps ps3_rom_regs_ops = {
    .read = ps3_rom_regs_read,
    .write = ps3_rom_regs_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static void ps3_rom_reset(DeviceState *dev)
{
    PS3BootROMState *s = PS3_BOOT_ROM(dev);

    s->status = 0;
    s->blocks = 0;
    s->bytes = 0;
    memset(s->key, 0, sizeof(s->key));

    /* Power-on: the model runs the ROM once the image it opens is in place. */
    if (s->rom_file) {
        if (s->selftest) {
            ps3_rom_selftest(s);
        }

        ps3_rom_boot(s);
    }

}

static int ps3_spu_stage(PS3BootROMState *s);
static int ps3_ppu_dump(PS3BootROMState *s);
static bool ps3_ppu_stage(PS3BootROMState *s, Error **errp);
static bool ps3_vsh_stage(PS3BootROMState *s, Error **errp);
static void ps3_ppu_reset_entry(void *opaque);

/*
 * The loaders' local-store hand-off, from docs/ldrs.txt in the ps3tools tree:
 * all four spin on the 32-bit word at 0x3E000 until it equals 0xFF, then read
 * their arguments from 0x3E800.  A stage run can therefore supply the flag and
 * the argument block before the first instruction, which is what a PPU-side
 * boot loader would have done.
 */
#define PS3_STAGE_WAIT_ADDR 0x3E000
#define PS3_STAGE_ARGS_ADDR 0x3E800
#define PS3_STAGE_ARGS_MAX  0x800

static bool ps3_stage_parse_hex(const char *text, uint8_t *out, size_t cap,
                                size_t *out_len)
{
    size_t n = 0;
    int hi = -1;

    for (; *text; text++) {
        int v;

        if (g_ascii_isspace(*text) || *text == ':' || *text == '_' ||
            *text == '-') {
            continue;
        }

        v = g_ascii_xdigit_value(*text);
        if (v < 0) {
            return false;
        }

        if (hi < 0) {
            hi = v;
        } else {
            if (n >= cap) {
                return false;
            }
            out[n++] = (hi << 4) | v;
            hi = -1;
        }
    }

    if (hi >= 0) {
        return false;
    }

    *out_len = n;
    return true;
}

static bool ps3_stage_preload(PS3BootROMState *s, uint8_t *ls,
                              char *why, size_t why_len)
{
    size_t args_len = 0;

    if (s->stage_wait) {
        for (unsigned i = 0; i < 8; i++) {
            ls[PS3_STAGE_WAIT_ADDR + i] =
                (s->stage_wait >> (56 - 8 * i)) & 0xFF;
        }
    }

    if (s->stage_args && *s->stage_args) {
        if (s->stage_args[0] == '@') {
            g_autofree gchar *buf = NULL;
            gsize len = 0;
            g_autoptr(GError) err = NULL;

            if (!g_file_get_contents(s->stage_args + 1, &buf, &len, &err)) {
                snprintf(why, why_len, "cannot read stage-args %s: %s",
                         s->stage_args + 1, err->message);
                return false;
            }
            if (len > PS3_STAGE_ARGS_MAX) {
                snprintf(why, why_len, "stage-args is %u bytes, at most 0x%X fit",
                         (unsigned)len, PS3_STAGE_ARGS_MAX);
                return false;
            }
            memcpy(ls + PS3_STAGE_ARGS_ADDR, buf, len);
            args_len = len;
        } else if (!ps3_stage_parse_hex(s->stage_args, ls + PS3_STAGE_ARGS_ADDR,
                                        PS3_STAGE_ARGS_MAX, &args_len)) {
            snprintf(why, why_len,
                     "stage-args must be hex bytes, or @file for a binary blob");
            return false;
        }
    }

    if (s->stage_version) {
        ps3_spu_set_ch73(s->spu, s->stage_version >> 32,
                         (uint32_t)s->stage_version);
    }

    /*
     * The loaders take the local-store address of their parameter block in
     * $3 (their first instruction saves $3 before any call clobbers it).
     * Point it at the block the caller asked us to preload.
     */
    if (args_len) {
        ps3_spu_set_reg(s->spu, 3, PS3_STAGE_ARGS_ADDR);
    }

    if (s->stage_wait || args_len || s->stage_version) {
        info_report("ps3-spu-stage: preloaded wait=0x%" PRIX64 ", %u argument "
                    "byte(s) at LS 0x%X, version=0x%" PRIX64,
                    s->stage_wait, (unsigned)args_len, PS3_STAGE_ARGS_ADDR,
                    s->stage_version);
    }

    return true;
}

static bool ps3_readout_from_hex(const char *text, uint8_t out[32])
{
    size_t len = strlen(text);
    size_t i;

    if (len != 64) {
        return false;
    }

    for (i = 0; i < 32; i++) {
        unsigned value;

        if (sscanf(text + i * 2, "%2x", &value) != 1) {
            return false;
        }

        out[i] = value;
    }

    return true;
}

static uint64_t ps3_ppe_uart_read(void *opaque, hwaddr addr, unsigned size)
{
    PS3BootROMState *s = opaque;

    if (s->ppu_trace && s->uart_hits < 4) {
        info_report("ps3-ppu: uart read 0x%" HWADDR_PRIX " size %u", addr,
                    size);
        s->uart_hits++;
    }

    if (addr == PS3_PPE_UART_STATUS) {
        return 0x100;      /* THR empty: lv0 may write the next character */
    }
    return 0;
}

static void ps3_uart_flush(PS3BootROMState *s)
{
    if (s->uart_len) {
        s->uart_line[s->uart_len] = 0;
        info_report("ps3-ppu console: %s", s->uart_line);
        s->uart_len = 0;
    }
}

/*
 * One console character.  lv0 polls the same port, and sys_tty_write feeds it
 * from the lv2 side, so both paths share this.
 */
static void ps3_uart_putc(PS3BootROMState *s, uint8_t ch)
{
    if (ch == '\r') {
        return;
    }

    if (ch == '\n' || s->uart_len + 1 >= sizeof(s->uart_line)) {
        ps3_uart_flush(s);
    } else {
        s->uart_line[s->uart_len++] = ch;
    }
}

static void ps3_ppe_uart_write(void *opaque, hwaddr addr, uint64_t value,
                               unsigned size)
{
    PS3BootROMState *s = opaque;

    if (addr != PS3_PPE_UART_DATA) {
        return;
    }

    ps3_uart_putc(s, value & 0xFF);
}

static const MemoryRegionOps ps3_ppe_uart_ops = {
    .read = ps3_ppe_uart_read,
    .write = ps3_ppe_uart_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

/*
 * The lv2 services vsh-run answers, in the order the VSH asks for them.
 *
 * This is not a kernel: there is no scheduler, and a call runs to completion
 * on the calling thread.  What it does have is the semantics liblv2 and the
 * VSH's C runtime depend on - process identity, the PARAM.SFO they check, the
 * memory they allocate, the sync objects they create and the console they
 * write to - so the guest runs its own startup code instead of stopping at
 * the first handshake.
 *
 * The trampoline published the call number but kept the registers, so the
 * arguments are read from the CPU here and the result is left in the scratch
 * block at RAM 0x880 for the trampoline to collect.
 */
static void ps3_lv2_service(PS3BootROMState *s)
{
    CPUState *cs = qemu_get_cpu(0);
    PowerPCCPU *cpu;
    uint8_t *ram;
    uint64_t ram_size;
    uint32_t nr, a0, a1, a2, a3;
    int32_t ret = PS3_LV2_ENOSYS;

    if (!cs) {
        return;
    }

    cpu = POWERPC_CPU(cs);
    ram = memory_region_get_ram_ptr(s->ram);
    ram_size = memory_region_size(s->ram);
    nr = cpu->env.gpr[11];
    a0 = cpu->env.gpr[3];
    a1 = cpu->env.gpr[4];
    a2 = cpu->env.gpr[5];
    a3 = cpu->env.gpr[6];

    if (s->ppu_trace) {
        info_report("ps3-ppu: lv2 syscall 0x%X (lr=0x%" PRIX64
                    ", pc=0x%" PRIX64 ")", nr, (uint64_t)cpu->env.lr,
                    (uint64_t)cpu->env.nip);
    }

    switch (nr) {
    case 0x001:                 /* sys_process_getpid */
        ret = 1;
        break;
    case 0x012:                 /* sys_process_getppid */
        ret = 0;
        break;
    case 0x016:                 /* _sys_process_exit(status) */
        s->lv2_exit_status = (int32_t)a0;
        s->lv2_exited = true;
        ps3_uart_flush(s);
        info_report("ps3-ppu: process exited with status %d",
                    s->lv2_exit_status);
        ps3_put_be32(ram + PS3_LV2_SCRATCH, 0);
        ps3_put_be32(ram + PS3_LV2_SCRATCH + 4, 1);
        qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
        return;
    case 0x01E:                 /* _sys_process_get_paramsfo(buf) */
        if ((uint64_t)a0 + 0x40 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        /* A valid, empty SFO header: magic, version, two tables, no entries. */
        memset(ram + a0, 0, 0x40);
        ps3_put_be32(ram + a0, 0x00505346);
        ps3_put_be32(ram + a0 + 0x04, 0x00000101);
        ps3_put_be32(ram + a0 + 0x08, 0x00000014);
        ps3_put_be32(ram + a0 + 0x0C, 0x00000014);
        ret = 0;
        break;
    case 0x05F:                 /* _sys_lwmutex_create(id*, ...) */
    case 0x064:                 /* sys_mutex_create(id*, attr*) */
    case 0x069:                 /* sys_cond_create(id*, mutex_id, attr*) */
        if ((uint64_t)a0 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        ps3_put_be32(ram + a0, ++s->lv2_next_id);
        ret = 0;
        break;
    case 0x060: case 0x061: case 0x062: case 0x063:     /* lwmutex */
    case 0x065: case 0x066: case 0x067: case 0x068:     /* mutex */
    case 0x06A: case 0x06B: case 0x06C: case 0x06D: case 0x06E: /* cond */
        ret = 0;
        break;
    case 0x093:                 /* sys_time_get_timebase_frequency */
        ret = 79800000;
        break;
    case 0x15C: {               /* sys_memory_allocate(size, flags, addr*) */
        uint32_t heap = ps3_be32(ram + PS3_LV2_HEAP);
        uint32_t end = (heap + a0 + 0xFF) & ~0xFFu;

        if (!a0) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        if ((uint64_t)a2 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        if (end < heap || (uint64_t)end + 0x100 > ram_size) {
            ret = PS3_LV2_ENOMEM;
            break;
        }
        ps3_put_be32(ram + a2, heap);
        ps3_put_be32(ram + PS3_LV2_HEAP, end);
        ret = 0;
        break;
    }
    case 0x193: {               /* sys_tty_write(channel, buf, len, written) */
        uint32_t i;

        if ((uint64_t)a1 + a2 > ram_size || (uint64_t)a3 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        for (i = 0; i < a2; i++) {
            ps3_uart_putc(s, ram[a1 + i]);
        }
        ps3_put_be32(ram + a3, a2);
        ret = 0;
        break;
    }
    default:
        if (s->ppu_trace) {
            info_report("ps3-ppu: lv2 syscall 0x%X is not modelled", nr);
        }
        break;
    }

    ps3_put_be32(ram + PS3_LV2_SCRATCH, (uint32_t)ret);
}

static void ps3_rom_realize(DeviceState *dev, Error **errp)
{
    PS3BootROMState *s = PS3_BOOT_ROM(dev);
    gchar *buf = NULL;
    gsize len = 0;
    GError *err = NULL;

    memory_region_init_io(&s->regs_mr, OBJECT(s), &ps3_rom_regs_ops, s,
                          "ps3-boot-rom.regs", 0x40);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->regs_mr);

    memory_region_init_ram(&s->ls_mr, OBJECT(s), "ps3.ls", PS3_LS_SIZE,
                           &error_fatal);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->ls_mr);

    memory_region_init_ram(&s->rom_mr, OBJECT(s), "ps3.spu-rom", PS3_ROM_SIZE,
                           &error_fatal);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->rom_mr);

    memory_region_init_io(&s->uart_mr, OBJECT(s), &ps3_ppe_uart_ops, s,
                          "ps3-ppe-uart", PS3_PPE_UART_SIZE);
    memory_region_add_subregion_overlap(get_system_memory(),
                                        PS3_PPE_UART_BASE, &s->uart_mr, 1);
    memory_region_init_alias(&s->uart_alias_mr, OBJECT(s), "ps3-ppe-uart-hi",
                             &s->uart_mr, 0, PS3_PPE_UART_SIZE);
    memory_region_add_subregion_overlap(get_system_memory(),
                                        0x24000FFF000ULL,
                                        &s->uart_alias_mr, 1);

    if (s->readout) {
        if (!ps3_readout_from_hex(s->readout, s->readout_bytes)) {
            error_setg(errp, "ps3-boot-rom: readout must be 64 hex digits");
            return;
        }

        s->has_readout = true;
    } else if (s->readout_file) {
        if (!g_file_get_contents(s->readout_file, &buf, &len, &err)) {
            error_setg(errp, "ps3-boot-rom: cannot read %s: %s",
                       s->readout_file, err->message);
            g_error_free(err);
            return;
        }

        if (len != 32) {
            g_free(buf);
            error_setg(errp, "ps3-boot-rom: the readout file must be 32 bytes");
            return;
        }

        memcpy(s->readout_bytes, buf, 32);
        s->has_readout = true;
        g_free(buf);
        buf = NULL;
    }

    if (s->rom_file) {
        if (!g_file_get_contents(s->rom_file, &buf, &len, &err)) {
            error_setg(errp, "ps3-boot-rom: cannot read %s: %s", s->rom_file,
                       err->message);
            g_error_free(err);
            return;
        }

        s->rom_len = MIN(len, sizeof(s->rom));
        memcpy(s->rom, buf, s->rom_len);
        g_free(buf);

        if (ps3_rom_is_swapped(s->rom)) {
            uint8_t native[PS3_ROM_SIZE];

            ps3_rom_unswap(s->rom, native, s->rom_len);
            memcpy(memory_region_get_ram_ptr(&s->rom_mr), native, s->rom_len);
            ps3_rom_describe(s->rom, true);
        } else {
            memcpy(memory_region_get_ram_ptr(&s->rom_mr), s->rom, s->rom_len);
            ps3_rom_describe(s->rom, false);
        }

        memory_region_set_readonly(&s->rom_mr, true);
    } else {
        info_report("ps3-boot-rom: no -bios image; the mask ROM is blank");
    }

    if (s->blk) {
        int64_t size = blk_getlength(s->blk);

        if (size <= 0) {
            error_setg(errp, "ps3-boot-rom: the flash drive has no size");
            return;
        }

        s->flash_len = size;
        s->flash = g_malloc0(s->flash_len);

        if (blk_pread(s->blk, 0, s->flash_len, s->flash, 0) < 0) {
            error_setg(errp, "ps3-boot-rom: cannot read the flash drive");
            return;
        }

        memory_region_init_ram(&s->flash_mr, OBJECT(s), "ps3.flash",
                               ROUND_UP(s->flash_len, 4 * KiB), &error_fatal);
        memcpy(memory_region_get_ram_ptr(&s->flash_mr), s->flash, s->flash_len);
        memory_region_set_readonly(&s->flash_mr, true);
        sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->flash_mr);
    }

    s->spu = ps3_spu_new(memory_region_get_ram_ptr(&s->ls_mr), PS3_LS_SIZE,
                         s->flash, s->flash_len);

    /*
     * A stage image is a whole run: load it, execute it, report, exit.  It is
     * the command-line form of the boot-chain tests, so the exit status is the
     * verdict and nothing after it needs the machine.
     */
    if (s->stage_elf) {
        exit(ps3_spu_stage(s));
    }

    /*
     * The PPU is the other half of the first stage: lv0 and up are 64-bit
     * PowerPC.  A dump is extraction only; an image is loaded into RAM and
     * described to the CPU, which then runs it in the normal VM loop (the
     * ppu-tick timer bounds and reports that run for the headless tests).
     */
    if (s->ppu_dump) {
        exit(ps3_ppu_dump(s));
    }

    /*
     * Load the PPU half here, before the machine reset runs: the reset handler
     * below then enters it after the SPU has run the mask ROM and the loader
     * payload in ps3_rom_reset.  The image is named separately because the SPU
     * model's external memory is a private copy of the flash image, not the
     * guest's RAM; wiring the two memories together is the next hand-off step.
     */
    if (s->ppu_elf) {
        if (!ps3_ppu_stage(s, errp)) {
            return;
        }
    }

    /*
     * The application layer.  With vsh-run off this is a load-and-map test:
     * the image is in RAM and described, then the run ends before the CPU
     * starts, so the mapping can be checked on its own.  With vsh-run on the
     * PPU enters the VSH and the tick timer reports how far it gets before it
     * needs an lv2 service the model does not provide yet.
     */
    if (!s->vsh_self && s->dev_flash) {
        s->vsh_self = g_build_filename(s->dev_flash, "vsh", "module",
                                       "vsh.self", NULL);
    }

    /*
     * dev_flash3 is the second writable firmware mount; some dumps put the
     * application tree there instead of dev_flash.  Use it when the first
     * path does not exist and the caller named no image directly.
     */
    if (s->dev_flash3) {
        g_autofree char *alt = g_build_filename(s->dev_flash3, "vsh",
                                                "module", "vsh.self", NULL);

        if ((!s->vsh_self || !g_file_test(s->vsh_self, G_FILE_TEST_EXISTS)) &&
            g_file_test(alt, G_FILE_TEST_EXISTS)) {
            g_free(s->vsh_self);
            s->vsh_self = g_strdup(alt);
        }
    }

    if (s->vsh_self) {
        if (!ps3_vsh_stage(s, errp)) {
            return;
        }

        if (!s->vsh_run) {
            exit(0);
        }
    }
}

/*
 * Load an SPU ELF (a decrypted boot-chain stage such as lv1ldr/appldr) into
 * local storage and run it from its entry point.  This is what lets the stage
 * tests execute the rest of the chain on the same interpreter the mask ROM and
 * lv0ldr.2 already run on, instead of checking the images structurally only.
 *
 * Returns 0 when the stage ran without faulting, 1 when it hit an opcode or an
 * address the model does not implement, 2 when the image could not be loaded.
 */
static int ps3_spu_stage(PS3BootROMState *s)
{
    g_autoptr(GError) err = NULL;
    g_autofree uint8_t *img = NULL;
    gsize len = 0;
    uint8_t *ls = memory_region_get_ram_ptr(&s->ls_mr);
    uint32_t phoff, phentsize, phnum, entry;
    unsigned loaded = 0;
    uint64_t bytes = 0;
    char why[160];
    int rc;

    if (!g_file_get_contents(s->stage_elf, (gchar **)&img, &len, &err)) {
        info_report("ps3-spu-stage: cannot read %s: %s", s->stage_elf,
                    err->message);
        return 2;
    }

    /*
     * A dump is extraction, not a run: open the container, decrypt its
     * sections in place and write the result back out.  It is how the
     * encapsulated images a loader carries are taken out for inspection
     * without a PC-side tool.  An ELF needs no opening and is copied as-is.
     */
    if (s->stage_dump) {
        if (len >= 0x200 && !memcmp(img, "SCE\0", 4)) {
            if (!ps3_self_decrypt(img, len, why, sizeof(why))) {
                info_report("ps3-spu-stage: %s: %s", s->stage_elf, why);
                return 1;
            }
        } else if (len < 52 || memcmp(img, "\177ELF", 4) ||
                   img[4] != 1 || img[5] != 2) {
            info_report("ps3-spu-stage: %s is neither a SELF nor a 32-bit "
                        "big-endian ELF", s->stage_elf);
            return 2;
        }

        if (!g_file_set_contents(s->stage_dump, (const char *)img, len, &err)) {
            info_report("ps3-spu-stage: cannot write %s: %s", s->stage_dump,
                        err->message);
            return 2;
        }

        info_report("ps3-spu-stage: %s: %" G_GSIZE_FORMAT " bytes written to %s",
                    s->stage_elf, len, s->stage_dump);
        return 0;
    }

    /*
     * A stage is either a decrypted SPU ELF or the SELF it is delivered in.
     * The SELF is opened here with the loader keysets the chain itself uses,
     * so a stage test needs nothing on the PC side but the firmware file.
     */
    if (len >= 0x200 && !memcmp(img, "SCE\0", 4)) {
        uint32_t stage_entry = 0;
        unsigned segments = 0;
        int opened = ps3_self_load_ls(img, len, ls, PS3_LS_SIZE, &stage_entry,
                                      &segments, why, sizeof(why));

        if (opened) {
            info_report("ps3-spu-stage: %s: %s", s->stage_elf, why);
            return opened == 1 ? 1 : 2;
        }

        /* Which keyset opened it, and whether the sections needed decrypting. */
        info_report("ps3-spu-stage: %s: %s", s->stage_elf, why);

        if (s->stage_entry) {
            stage_entry = s->stage_entry;
        }

        if (!ps3_stage_preload(s, ls, why, sizeof(why))) {
            info_report("ps3-spu-stage: %s: %s", s->stage_elf, why);
            return 2;
        }

        ps3_spu_set_trace(s->spu, s->spu_trace);
        rc = ps3_spu_run(s->spu, stage_entry, s->stage_limit ?: (1 << 22),
                         why, sizeof(why));
        ps3_ls_write_dump(s);
        info_report("ps3-spu-stage: %s entry=0x%X segments=%u steps=%" PRIu64
                    " result=%s stop=%u :: %s",
                    s->stage_elf, stage_entry, segments,
                    ps3_spu_insns(s->spu),
                    rc == 0 ? "stop" : rc == 1 ? "limit" : "fault",
                    ps3_spu_stop_code(s->spu), why);
        return rc == 2 ? 1 : 0;
    }

    if (len < 52 || memcmp(img, "\177ELF", 4) || img[4] != 1 || img[5] != 2) {
        info_report("ps3-spu-stage: %s is not a 32-bit big-endian ELF",
                    s->stage_elf);
        return 2;
    }

    entry    = ps3_be32(img + 24);
    phoff    = ps3_be32(img + 28);
    phentsize = (img[42] << 8) | img[43];
    phnum    = (img[44] << 8) | img[45];

    memory_region_set_readonly(&s->ls_mr, false);
    memset(ls, 0, PS3_LS_SIZE);

    for (unsigned i = 0; i < phnum; i++) {
        size_t o = (size_t)phoff + (size_t)i * phentsize;
        uint32_t type, off, vaddr, filesz, memsz;

        if (o + 32 > len) {
            info_report("ps3-spu-stage: program header %u is outside %s",
                        i, s->stage_elf);
            return 2;
        }

        type   = ps3_be32(img + o + 0);
        off    = ps3_be32(img + o + 4);
        vaddr  = ps3_be32(img + o + 8);
        filesz = ps3_be32(img + o + 16);
        memsz  = ps3_be32(img + o + 20);

        if (type != 1) {
            continue;
        }

        if (vaddr >= PS3_LS_SIZE || memsz > PS3_LS_SIZE - vaddr ||
            filesz > memsz || off > len || filesz > len - off) {
            info_report("ps3-spu-stage: segment %u (0x%X/0x%X) does not fit "
                        "local storage", i, vaddr, memsz);
            return 2;
        }

        memcpy(ls + vaddr, img + off, filesz);
        loaded++;
        bytes += filesz;
    }

    if (!loaded) {
        info_report("ps3-spu-stage: %s carries no loadable segment",
                    s->stage_elf);
        return 2;
    }

    if (s->stage_entry != 0) {
        entry = s->stage_entry;
    }

    if (!ps3_stage_preload(s, ls, why, sizeof(why))) {
        info_report("ps3-spu-stage: %s: %s", s->stage_elf, why);
        return 2;
    }

    ps3_spu_set_trace(s->spu, s->spu_trace);

    rc = ps3_spu_run(s->spu, entry, s->stage_limit ?: (1 << 22),
                     why, sizeof(why));

    info_report("ps3-spu-stage: %s entry=0x%X segments=%u bytes=%" PRIu64
                " steps=%" PRIu64 " result=%s stop=%u :: %s",
                s->stage_elf, entry, loaded, bytes, ps3_spu_insns(s->spu),
                rc == 0 ? "stop" : rc == 1 ? "limit" : "fault",
                ps3_spu_stop_code(s->spu), why);

    return rc == 2 ? 1 : 0;
}

/* ---------------------------------------------------------------------- */
/* The PPU stage: lv0 and the 64-bit PowerPC side of the chain.            */
/* ---------------------------------------------------------------------- */

static uint64_t ps3_be64(const uint8_t *p)
{
    return ((uint64_t)ps3_be32(p) << 32) | ps3_be32(p + 4);
}

/*
 * Open a PPU stage file: either a SELF (opened with the same loader keysets
 * the SPU stages use) or a plain 64-bit big-endian ELF.  The ELF header is
 * normally at the front of the certified file, but a SELF's extended header
 * leaves it at a small offset, so the first 0x400 bytes are searched.
 *
 * Returns a pointer to the ELF header inside `img' (which the caller owns),
 * or NULL with `why' set.
 */
static const uint8_t *ps3_ppu_open(uint8_t *img, size_t len,
                                   uint64_t *seg_shift,
                                   char *why, size_t why_len)
{
    const uint8_t *elf = img;
    size_t elf_len = len;

    *seg_shift = 0;

    if (len >= 4 && !memcmp(img, "SCE\0", 4)) {
        if (!ps3_self_decrypt(img, len, why, why_len)) {
            return NULL;
        }

        elf = NULL;
        for (size_t i = 0x20; i + 0x40 < MIN(len, (size_t)0x400); i += 4) {
            if (!memcmp(img + i, "\177ELF", 4)) {
                elf = img + i;
                elf_len = len - i;
                break;
            }
        }

        if (!elf) {
            snprintf(why, why_len, "no ELF header inside the SELF");
            return NULL;
        }

        /*
         * A SELF's program-header file offsets are relative to the certified
         * file, which starts header_len bytes into the container.  The section
         * table uses absolute offsets (lv0's first section is 0x10500 for a
         * 0x10000 ELF offset and a 0x500 header), so the same shift applies to
         * every loadable segment.  Without it the loader reads the header
         * block instead of the image and the PPU starts on ciphertext.
         */
        *seg_shift = ps3_be64(img + 0x10);
    }

    if (elf_len < 64 || memcmp(elf, "\177ELF", 4) ||
        elf[4] != 2 || elf[5] != 2) {
        snprintf(why, why_len, "not a 64-bit big-endian ELF");
        return NULL;
    }

    return elf;
}

/*
 * Extraction form of the PPU stage: open the container, write the decrypted
 * bytes back out.  A plain ELF needs no opening and is copied as it is.
 */
static int ps3_ppu_dump(PS3BootROMState *s)
{
    g_autoptr(GError) err = NULL;
    g_autofree uint8_t *img = NULL;
    gsize len = 0;
    char why[160];
    uint64_t seg_shift;
    const uint8_t *elf;

    if (!g_file_get_contents(s->ppu_elf, (gchar **)&img, &len, &err)) {
        info_report("ps3-ppu: cannot read %s: %s", s->ppu_elf, err->message);
        return 2;
    }

    elf = ps3_ppu_open(img, len, &seg_shift, why, sizeof(why));
    if (!elf) {
        info_report("ps3-ppu: %s: %s", s->ppu_elf, why);
        return 1;
    }

    if (!g_file_set_contents(s->ppu_dump, (const char *)img, len, &err)) {
        info_report("ps3-ppu: cannot write %s: %s", s->ppu_dump, err->message);
        return 2;
    }

    info_report("ps3-ppu: %s: %" G_GSIZE_FORMAT " bytes written to %s "
                "(ELF at 0x%" PRIXPTR ")",
                s->ppu_elf, len, s->ppu_dump,
                (uintptr_t)(elf - img));
    return 0;
}

static void ps3_ppu_reset_entry(void *opaque)
{
    PS3BootROMState *s = opaque;
    CPUState *cs = qemu_get_cpu(0);

    if (!cs || !s->ppu_entry) {
        return;
    }

    PowerPCCPU *cpu = POWERPC_CPU(cs);

    cpu->env.nip = s->ppu_entry;
    cpu->env.msr |= (1ULL << MSR_SF) | (1ULL << MSR_ME);
    cpu->env.msr &= ~((1ULL << MSR_IR) | (1ULL << MSR_DR));

    if (s->vsh_run && s->vsh_toc) {
        /*
         * lv2 enables floating point and Altivec for a user process before it
         * enters it; the VSH uses both, and without MSR[FP] its first float
         * operation would take the 0x800 vector instead of running.
         */
        cpu->env.msr |= (1ULL << MSR_FP) | (1ULL << MSR_VR);
        cpu->env.gpr[2] = s->vsh_toc;
        cpu->env.gpr[1] = memory_region_size(s->ram) - 0x100;
        cpu->env.gpr[3] = 0;
        cpu->env.gpr[4] = 0;
    }
}

static void ps3_ppu_tick(void *opaque)
{
    PS3BootROMState *s = opaque;
    CPUState *cs = qemu_get_cpu(0);
    PowerPCCPU *cpu = POWERPC_CPU(cs);

    s->ppu_last_pc = cpu->env.nip;
    s->ppu_tick_count++;

    if (s->ppu_trace) {
        info_report("ps3-ppu: tick %" PRIu64 " pc=0x%" PRIx64
                    " lr=0x%" PRIx64 " msr=0x%" PRIx64,
                    s->ppu_tick_count, (uint64_t)cpu->env.nip,
                    (uint64_t)cpu->env.lr, (uint64_t)cpu->env.msr);
    }

    if (s->ppu_ticks && s->ppu_tick_count >= s->ppu_ticks) {
        info_report("ps3-ppu: stopping after %" PRIu64 " ticks at pc=0x%"
                    PRIx64 " (lr=0x%" PRIx64 ")",
                    s->ppu_tick_count, s->ppu_last_pc,
                    (uint64_t)cpu->env.lr);
        qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
        return;
    }

    timer_mod(s->ppu_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + s->ppu_tick_ns);
}

/*
 * Load a 64-bit PowerPC ELF into guest RAM and start the PPU at its entry.
 * The PS3's physical addresses are the low 36 bits of the ELF's virtual ones;
 * lv0 links itself at 0 and 0x08000000, both of which are already physical, so
 * the normal case is a straight copy.  A high virtual address is reduced when
 * that is what makes it fit.
 */
static bool ps3_ppu_stage(PS3BootROMState *s, Error **errp)
{
    g_autoptr(GError) err = NULL;
    g_autofree uint8_t *img = NULL;
    gsize len = 0;
    const uint8_t *elf;
    uint64_t seg_shift;
    uint8_t *ram;
    uint64_t ram_size;
    uint64_t entry, phoff;
    unsigned phentsize, phnum, loaded = 0;
    uint64_t bytes = 0;
    CPUState *cs;
    PowerPCCPU *cpu;
    char why[160];

    if (!s->ram) {
        error_setg(errp, "ps3-ppu: no RAM link");
        return false;
    }

    if (!g_file_get_contents(s->ppu_elf, (gchar **)&img, &len, &err)) {
        error_setg(errp, "ps3-ppu: cannot read %s: %s", s->ppu_elf,
                   err->message);
        return false;
    }

    elf = ps3_ppu_open(img, len, &seg_shift, why, sizeof(why));
    if (!elf) {
        error_setg(errp, "ps3-ppu: %s: %s", s->ppu_elf, why);
        return false;
    }

    ram = memory_region_get_ram_ptr(s->ram);
    ram_size = memory_region_size(s->ram);

    entry = ps3_be64(elf + 0x18);
    phoff = ps3_be64(elf + 0x20);
    phentsize = ((unsigned)elf[0x36] << 8) | elf[0x37];
    phnum = ((unsigned)elf[0x38] << 8) | elf[0x39];

    if (phentsize < 56 || phoff + (uint64_t)phnum * phentsize >
        len - (size_t)(elf - img)) {
        error_setg(errp, "ps3-ppu: %s: program header table does not fit",
                   s->ppu_elf);
        return false;
    }

    for (unsigned i = 0; i < phnum; i++) {
        const uint8_t *ph = elf + phoff + (size_t)i * phentsize;
        uint32_t type = ps3_be32(ph + 0x00);
        uint64_t off = ps3_be64(ph + 0x08);
        uint64_t vaddr = ps3_be64(ph + 0x10);
        uint64_t paddr = ps3_be64(ph + 0x18);
        uint64_t filesz = ps3_be64(ph + 0x20);
        uint64_t memsz = ps3_be64(ph + 0x28);
        uint64_t pa = paddr ? paddr : vaddr;
        uint64_t file_off = seg_shift + off;
        const uint8_t *src;

        if (type != 1) {
            continue;
        }

        if (file_off > len || filesz > len - file_off || filesz > memsz) {
            error_setg(errp, "ps3-ppu: %s: segment %u runs past the file",
                       s->ppu_elf, i);
            return false;
        }

        src = img + file_off;

        if (pa + memsz > ram_size) {
            pa &= 0x0FFFFFFF;
        }

        if (pa + memsz > ram_size) {
            error_setg(errp, "ps3-ppu: %s: segment %u (0x%" PRIX64
                       "/0x%" PRIX64 ") does not fit RAM",
                       s->ppu_elf, i, pa, memsz);
            return false;
        }

        memset(ram + pa, 0, memsz);
        memcpy(ram + pa, src, filesz);
        loaded++;
        bytes += filesz;

        info_report("ps3-ppu: segment %u: 0x%" PRIX64 " + 0x%" PRIX64
                    " -> RAM 0x%" PRIX64 " (filesz 0x%" PRIX64 ")",
                    i, vaddr, memsz, pa, filesz);
    }

    if (!loaded) {
        error_setg(errp, "ps3-ppu: %s carries no loadable segment",
                   s->ppu_elf);
        return false;
    }

    if (s->ppu_entry) {
        entry = s->ppu_entry;
    } else if (entry + 4 <= ram_size) {
        /*
         * lv0's ELF header names 0xc60, which lands in the zero-filled first
         * segment; the console starts it at 0x08000000.  If the named entry is
         * a zero word or a branch-to-self, use the high segment instead, which
         * is where every lv0 build puts its code.
         */
        uint32_t first = ps3_be32(ram + entry);

        if (first == 0 || first == 0x48000000) {
            for (unsigned i = 0; i < phnum; i++) {
                const uint8_t *ph = elf + phoff + (size_t)i * phentsize;
                uint64_t vaddr = ps3_be64(ph + 0x10);

                if (ps3_be32(ph + 0x00) == 1 && vaddr >= 0x01000000) {
                    info_report("ps3-ppu: entry 0x%" PRIX64 " is not code, "
                                "using segment 0x%" PRIX64, entry, vaddr);
                    entry = vaddr;
                    break;
                }
            }
        }
    }

    if (entry >= ram_size) {
        entry &= 0x0FFFFFFF;
    }

    if (entry >= ram_size) {
        error_setg(errp, "ps3-ppu: entry 0x%" PRIX64 " is outside RAM", entry);
        return false;
    }

    cs = qemu_get_cpu(0);
    if (!cs) {
        error_setg(errp, "ps3-ppu: no CPU");
        return false;
    }

    cpu = POWERPC_CPU(cs);
    cpu->env.nip = entry;
    cpu->env.msr |= (1ULL << MSR_SF) | (1ULL << MSR_ME);
    cpu->env.msr &= ~((1ULL << MSR_IR) | (1ULL << MSR_DR));
    s->ppu_entry = entry;
    qemu_register_reset(ps3_ppu_reset_entry, s);
    s->ppu_last_pc = entry;

    info_report("ps3-ppu: %s: entry=0x%" PRIX64 ", %u segment(s), "
                "0x%" PRIX64 " bytes; PPU started", s->ppu_elf, entry,
                loaded, bytes);

    if (s->ppu_tick_ns) {
        s->ppu_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ps3_ppu_tick, s);
        timer_mod(s->ppu_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + s->ppu_tick_ns);
    }

    return true;
}

/*
 * Open vsh.self.  It is an application SELF, not a loader one: the metadata
 * root header is under the application keyset, so ps3_self_decrypt_app() is
 * the right opener.  A plain ELF is accepted too, which is what the
 * "decrypted" files in a dev_flash dump can be.
 */
static const uint8_t *ps3_vsh_open(PS3BootROMState *s, uint8_t *img, size_t len,
                                   uint64_t *header_len, uint32_t *meta_offset,
                                   char *why, size_t why_len)
{
    const uint8_t *elf;

    *header_len = 0;
    *meta_offset = 0;

    if (len < 0x40 || memcmp(img, "SCE\0", 4)) {
        if (len < 64 || memcmp(img, "\177ELF", 4) || img[4] != 2 ||
            img[5] != 2) {
            snprintf(why, why_len, "neither a SCE container nor a 64-bit "
                     "big-endian ELF");
            return NULL;
        }
        return img;
    }

    if (s->vsh_erk || s->vsh_riv) {
        if (!ps3_self_decrypt_key(img, len, s->vsh_erk, s->vsh_riv,
                                  why, why_len)) {
            return NULL;
        }
    } else if (!ps3_self_decrypt_app(img, len, why, why_len)) {
        return NULL;
    }

    *header_len = ps3_be64(img + 0x10);
    *meta_offset = ps3_be32(img + 0x0C);

    /* The extended header names the ELF header directly (offset 0x30). */
    elf = NULL;
    if (ps3_be64(img + 0x30) + 0x40 <= len) {
        const uint8_t *p = img + ps3_be64(img + 0x30);

        if (!memcmp(p, "\177ELF", 4)) {
            elf = p;
        }
    }

    if (!elf) {
        for (size_t i = 0x20; i + 0x40 < MIN(len, (size_t)0x400); i += 4) {
            if (!memcmp(img + i, "\177ELF", 4)) {
                elf = img + i;
                break;
            }
        }
    }

    if (!elf) {
        snprintf(why, why_len, "no ELF header inside the application SELF");
        return NULL;
    }

    return elf;
}

/*
 * Map the VSH into RAM the way lv2's ELF loader would: each PT_LOAD lands at
 * its physical address, its metadata section (when the container has one)
 * supplies the stored range, and compression 2 is zlib.  The segment headers
 * are the source of the stored range for a SELF; for a plain ELF the program
 * header's own file offset is used.
 */
static bool ps3_vsh_stage(PS3BootROMState *s, Error **errp)
{
    g_autoptr(GError) err = NULL;
    g_autofree uint8_t *img = NULL;
    gsize len = 0;
    const uint8_t *elf;
    uint8_t *ram;
    uint64_t ram_size, header_len, phoff, entry;
    uint32_t meta_offset;
    unsigned phnum, phentsize, loaded = 0, section_count = 0;
    uint64_t bytes = 0;
    char why[160];
    bool is_self;

    if (!s->ram) {
        error_setg(errp, "ps3-vsh: no RAM link");
        return false;
    }

    if (!g_file_get_contents(s->vsh_self, (gchar **)&img, &len, &err)) {
        error_setg(errp, "ps3-vsh: cannot read %s: %s", s->vsh_self,
                   err->message);
        return false;
    }

    is_self = len >= 4 && !memcmp(img, "SCE\0", 4);
    elf = ps3_vsh_open(s, img, len, &header_len, &meta_offset, why,
                       sizeof(why));
    if (!elf) {
        error_setg(errp, "ps3-vsh: %s: %s", s->vsh_self, why);
        return false;
    }

    phoff = is_self ? ps3_be64(img + 0x38) : ps3_be64(elf + 0x20);
    phentsize = ((unsigned)elf[0x36] << 8) | elf[0x37];
    phnum = ((unsigned)elf[0x38] << 8) | elf[0x39];

    if (phentsize < 0x38 || phnum > 0x20 ||
        phoff + (uint64_t)phnum * phentsize > len) {
        error_setg(errp, "ps3-vsh: %s: program header table 0x%" PRIX64
                   "/%u does not fit", s->vsh_self, phoff, phnum);
        return false;
    }

    if (is_self) {
        section_count = ps3_be32(img + meta_offset + 0x60 + 0x0C);
        if (section_count > 0x40 ||
            meta_offset + 0x80 + 0x30 * (uint64_t)section_count > header_len) {
            error_setg(errp, "ps3-vsh: %s: section table %u does not fit",
                       s->vsh_self, section_count);
            return false;
        }
    }

    ram = memory_region_get_ram_ptr(s->ram);
    ram_size = memory_region_size(s->ram);

    for (unsigned i = 0; i < phnum; i++) {
        const uint8_t *p = img + phoff + (size_t)i * phentsize;
        uint32_t type = ps3_be32(p);
        uint64_t p_off = ps3_be64(p + 0x08);
        uint64_t vaddr = ps3_be64(p + 0x10);
        uint64_t paddr = ps3_be64(p + 0x18);
        uint64_t filesz = ps3_be64(p + 0x20);
        uint64_t memsz = ps3_be64(p + 0x28);
        uint64_t pa = (paddr ? paddr : vaddr) & 0x0FFFFFFF;
        uint64_t src_off = 0, src_len = 0;
        uint32_t compression = 1;
        const uint8_t *src;

        if (type != 1 || !memsz) {
            continue;
        }

        if (is_self) {
            const uint8_t *entries = img + meta_offset + 0x80;

            for (unsigned j = 0; j < section_count; j++) {
                const uint8_t *e = entries + 0x30 * j;

                if (ps3_be32(e + 0x10) == 2 &&
                    ps3_be32(e + 0x14) == i) {
                    src_off = ps3_be64(e);
                    src_len = ps3_be64(e + 8);
                    compression = ps3_be32(e + 0x2C);
                    break;
                }
            }
        }

        if (!src_len) {
            src_off = header_len + p_off;
            src_len = filesz;
            compression = 1;
        }

        if (src_off > len || src_len > len - src_off) {
            error_setg(errp, "ps3-vsh: %s: segment %u data runs past the "
                       "file", s->vsh_self, i);
            return false;
        }

        if (pa + memsz > ram_size) {
            pa &= 0x0FFFFFFF;
        }
        if (pa + memsz > ram_size) {
            error_setg(errp, "ps3-vsh: %s: segment %u (0x%" PRIX64
                       "/0x%" PRIX64 ") does not fit RAM",
                       s->vsh_self, i, pa, memsz);
            return false;
        }

        src = img + src_off;
        memset(ram + pa, 0, memsz);

        if (compression == 2) {
            uLongf out = MIN(filesz ? filesz : memsz, memsz);
            uint8_t *buf = g_malloc0(MAX(out, (uLongf)1));
            int rc = uncompress(buf, &out, src, src_len);

            if (rc != Z_OK) {
                g_free(buf);
                error_setg(errp, "ps3-vsh: %s: segment %u zlib error %d",
                           s->vsh_self, i, rc);
                return false;
            }

            memcpy(ram + pa, buf, MIN((uint64_t)out, memsz));
            bytes += out;
            g_free(buf);
        } else {
            memcpy(ram + pa, src, MIN(src_len, memsz));
            bytes += MIN(src_len, memsz);
        }

        loaded++;
        info_report("ps3-vsh: segment %u: 0x%" PRIX64 " + 0x%" PRIX64
                    " -> RAM 0x%" PRIX64 " (stored 0x%" PRIX64
                    ", compression %u)", i, vaddr, memsz, pa, src_len,
                    compression);
    }

    if (!loaded) {
        error_setg(errp, "ps3-vsh: %s carries no loadable segment",
                   s->vsh_self);
        return false;
    }

    entry = ps3_be64(elf + 0x18) & 0x0FFFFFFF;

    if (s->vsh_entry) {
        entry = s->vsh_entry;
    }

    if (entry + 4 > ram_size) {
        error_setg(errp, "ps3-vsh: entry 0x%" PRIX64 " is outside RAM", entry);
        return false;
    }

    s->vsh_entry = entry;
    s->vsh_segments = loaded;
    s->vsh_bytes = bytes;

    if (s->vsh_dump) {
        if (!g_file_set_contents(s->vsh_dump, (const char *)img, len, &err)) {
            error_setg(errp, "ps3-vsh: cannot write %s: %s", s->vsh_dump,
                       err->message);
            return false;
        }
        info_report("ps3-vsh: decrypted container written to %s", s->vsh_dump);
    }

    info_report("ps3-vsh: %s: entry=0x%" PRIX64 ", %u segment(s), "
                "0x%" PRIu64 " bytes mapped into RAM%s", s->vsh_self, entry,
                loaded, bytes,
                s->vsh_run ? ", PPU entering it" : " (load-only)");

    if (s->vsh_run) {
        CPUState *cs = qemu_get_cpu(0);
        PowerPCCPU *cpu;
        uint32_t code = entry, rtoc = 0;

        if (!cs) {
            error_setg(errp, "ps3-vsh: no CPU");
            return false;
        }

        /*
         * e_entry names an OPD, not code: the descriptor's first word is the
         * function address and its second is the TOC the compiled code loads
         * into r2.  Entry code for this VSH begins with the usual
         * lis/ori/lwz TOC setup, which also confirms the descriptor.
         */
        if (entry + 8 <= ram_size) {
            uint32_t addr = ps3_be32(ram + entry);
            uint32_t toc = ps3_be32(ram + entry + 4);

            if (addr >= 0x10000 && addr < ram_size) {
                code = addr;
                rtoc = toc;
                info_report("ps3-vsh: OPD 0x%" PRIX64 " -> code 0x%X, TOC "
                            "0x%X", entry, code, rtoc);
            }
        }

        cpu = POWERPC_CPU(cs);
        s->vsh_toc = rtoc;
        cpu->env.nip = code;
        cpu->env.gpr[2] = rtoc;
        cpu->env.gpr[1] = ram_size - 0x100;
        cpu->env.gpr[3] = 0;
        cpu->env.gpr[4] = 0;
        cpu->env.msr |= (1ULL << MSR_SF) | (1ULL << MSR_ME) |
                        (1ULL << MSR_FP) | (1ULL << MSR_VR);
        cpu->env.msr &= ~((1ULL << MSR_IR) | (1ULL << MSR_DR));
        /*
         * The lv2 syscall boundary.  A bare PPU has no handler at the 0xC00
         * vector, so the first sc would run zeros and take a program
         * exception.  The shim is a bring-up lv2, not a full kernel: it
         * handles the calls the VSH's C runtime makes while it initializes
         * (memory, locks, timebase, tty), reports each number at 0xF1040014,
         * and returns -ENOSYS for anything else.
         */
        for (size_t i = 0; i < ARRAY_SIZE(ps3_lv2_shim); i++) {
            ps3_put_be32(ram + 0xC00 + i * 4, ps3_lv2_shim[i]);
        }

        /* lv2 scratch, then the heap above the VSH image and below the stack. */
        memset(ram + PS3_LV2_SCRATCH, 0, 8);
        s->lv2_next_id = 0;
        s->lv2_exited = false;
        s->lv2_exit_status = 0;
        ps3_put_be32(ram + PS3_LV2_HEAP, 0x01000000);

        s->ppu_entry = code;
        s->ppu_last_pc = code;
        qemu_register_reset(ps3_ppu_reset_entry, s);

        if (s->ppu_ticks) {
            s->ppu_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ps3_ppu_tick, s);
            timer_mod(s->ppu_timer,
                      qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + s->ppu_tick_ns);
        }
    }

    return true;
}

static const Property ps3_rom_properties[] = {
    DEFINE_PROP_DRIVE("drive", PS3BootROMState, blk),
    DEFINE_PROP_STRING("stage-elf", PS3BootROMState, stage_elf),
    DEFINE_PROP_LINK("ram", PS3BootROMState, ram, TYPE_MEMORY_REGION,
                     MemoryRegion *),
    DEFINE_PROP_STRING("ppu-elf", PS3BootROMState, ppu_elf),
    DEFINE_PROP_STRING("ppu-dump", PS3BootROMState, ppu_dump),
    DEFINE_PROP_UINT32("ppu-entry", PS3BootROMState, ppu_entry, 0),
    DEFINE_PROP_UINT64("ppu-ticks", PS3BootROMState, ppu_ticks, 0),
    DEFINE_PROP_UINT64("ppu-tick-ns", PS3BootROMState, ppu_tick_ns,
                       10 * 1000 * 1000),
    DEFINE_PROP_BOOL("ppu-trace", PS3BootROMState, ppu_trace, false),
    DEFINE_PROP_STRING("stage-dump", PS3BootROMState, stage_dump),
    DEFINE_PROP_STRING("stage-args", PS3BootROMState, stage_args),
    DEFINE_PROP_UINT32("stage-entry", PS3BootROMState, stage_entry, 0),
    DEFINE_PROP_UINT64("stage-limit", PS3BootROMState, stage_limit, 0),
    DEFINE_PROP_UINT64("stage-wait", PS3BootROMState, stage_wait, 0),
    DEFINE_PROP_UINT64("stage-version", PS3BootROMState, stage_version, 0),
    DEFINE_PROP_STRING("vsh-self", PS3BootROMState, vsh_self),
    DEFINE_PROP_STRING("vsh-dump", PS3BootROMState, vsh_dump),
    DEFINE_PROP_STRING("vsh-erk", PS3BootROMState, vsh_erk),
    DEFINE_PROP_STRING("vsh-riv", PS3BootROMState, vsh_riv),
    DEFINE_PROP_STRING("dev-flash", PS3BootROMState, dev_flash),
    DEFINE_PROP_STRING("dev-flash3", PS3BootROMState, dev_flash3),
    DEFINE_PROP_BOOL("vsh-run", PS3BootROMState, vsh_run, false),
    DEFINE_PROP_STRING("rom-file", PS3BootROMState, rom_file),
    DEFINE_PROP_STRING("container", PS3BootROMState, container),
    DEFINE_PROP_STRING("readout", PS3BootROMState, readout),
    DEFINE_PROP_STRING("readout-file", PS3BootROMState, readout_file),
    DEFINE_PROP_BOOL("selftest", PS3BootROMState, selftest, true),
    DEFINE_PROP_BOOL("spu", PS3BootROMState, spu_run, true),
    DEFINE_PROP_BOOL("spu-trace", PS3BootROMState, spu_trace, false),
    DEFINE_PROP_STRING("ls-dump", PS3BootROMState, ls_dump),
    DEFINE_PROP_UINT64("flash-base", PS3BootROMState, flash_base, 0x20000000),
};

static void ps3_rom_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = ps3_rom_realize;
    device_class_set_legacy_reset(dc, ps3_rom_reset);
    device_class_set_props(dc, ps3_rom_properties);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo ps3_rom_info = {
    .name = TYPE_PS3_BOOT_ROM,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(PS3BootROMState),
    .class_init = ps3_rom_class_init,
};

/* ---------------------------------------------------------------------- */
/* The board.                                                              */

#define PS3_RAM_SIZE       (256 * MiB)
#define PS3_BOOT_ROM_BASE  0xFFF00000
#define PS3_BOOT_ROM_WINDOW (1 * MiB)
#define PS3_LS_BASE        0xF1000000
#define PS3_BOOT_ROM_REGS  0xF1040000
#define PS3_FLASH_BASE     0x20000000

static void rs6000_ps3_cpu_reset(void *opaque)
{
    PowerPCCPU *cpu = opaque;
    CPUPPCState *env = &cpu->env;

    cpu_reset(CPU(cpu));

    /* The Cell PPU comes out of reset in 64-bit mode with translation off. */
    env->msr = (1ULL << MSR_SF) | (1ULL << MSR_ME);
    env->nip = PS3_BOOT_ROM_BASE + 0x100;
}

static void rs6000_ps3_init(MachineState *machine)
{
    MemoryRegion *sysmem = get_system_memory();
    MemoryRegion *ram = machine->ram;
    MemoryRegion *boot = g_new(MemoryRegion, 1);
    PowerPCCPU *cpu;
    DeviceState *mic, *rom;
    DriveInfo *dinfo;

    cpu = POWERPC_CPU(cpu_create(machine->cpu_type));

    /*
     * lv0 programs the decrementer and the time base early in its entry path
     * (mtspr 0x16 / mttbl / mttbu).  Without a timebase env those accesses
     * dereference a NULL tb_env in QEMU, so give the Cell PPU the real 79.8 MHz
     * timebase before it starts.
     */
    cpu_ppc_tb_init(&cpu->env, 79800000);

    qemu_register_reset(rs6000_ps3_cpu_reset, cpu);
    rs6000_ps3_cpu_reset(cpu);

    if (!ram) {
        ram = g_new(MemoryRegion, 1);
        memory_region_init_ram(ram, NULL, "ps3.ram", machine->ram_size,
                               &error_fatal);
    }

    memory_region_add_subregion(sysmem, 0, ram);

    /*
     * The PPU's reset vector lands here.  The real console's first code runs
     * on an SPU, not the PPU, so the PPU waits: a branch-to-self at the reset
     * vector, and the SPU side of the boot lives in ps3-boot-rom below.
     */
    memory_region_init_ram(boot, NULL, "ps3.boot", PS3_BOOT_ROM_WINDOW,
                           &error_fatal);
    memset(memory_region_get_ram_ptr(boot), 0, PS3_BOOT_ROM_WINDOW);
    {
        uint8_t *p = memory_region_get_ram_ptr(boot) + 0x100;

        /* b . */
        p[0] = 0x48;
        p[1] = 0x00;
        p[2] = 0x00;
        p[3] = 0x00;
    }
    memory_region_set_readonly(boot, true);
    memory_region_add_subregion(sysmem, PS3_BOOT_ROM_BASE, boot);

    mic = qdev_new(TYPE_PS3_MIC);
    object_property_set_link(OBJECT(mic), "ram", OBJECT(ram), &error_abort);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(mic), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(mic), 0, PS3_MIC_MMIO_BASE);

    rom = qdev_new(TYPE_PS3_BOOT_ROM);
    object_property_set_link(OBJECT(rom), "ram", OBJECT(ram), &error_abort);

    if (machine->firmware) {
        qdev_prop_set_string(rom, "rom-file", machine->firmware);
    }

    dinfo = drive_get(IF_PFLASH, 0, 0);

    if (dinfo) {
        qdev_prop_set_drive(rom, "drive", blk_by_legacy_dinfo(dinfo));
    }

    sysbus_realize_and_unref(SYS_BUS_DEVICE(rom), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(rom), 0, PS3_BOOT_ROM_REGS);
    sysbus_mmio_map(SYS_BUS_DEVICE(rom), 1, PS3_LS_BASE);
    sysbus_mmio_map(SYS_BUS_DEVICE(rom), 2, 0xE0000000);

    if (dinfo) {
        sysbus_mmio_map(SYS_BUS_DEVICE(rom), 3, PS3_FLASH_BASE);
    }

    info_report("rs6000-ps3: Cell PPU %s, %" PRIu64 " MiB XDR, MIC at 0x%X",
                machine->cpu_type, machine->ram_size / MiB,
                PS3_MIC_MMIO_BASE);
}

static void rs6000_ps3_machine_init(MachineClass *mc)
{
    mc->desc = "Sony PlayStation 3 (Cell, RS/6000-derived)";
    mc->init = rs6000_ps3_init;
    mc->max_cpus = 1;
    mc->default_ram_size = PS3_RAM_SIZE;
    mc->default_cpu_type = POWERPC_CPU_TYPE_NAME("970fx_v3.1");
    mc->default_ram_id = "ps3.ram";
    mc->is_default = false;
}

DEFINE_MACHINE("rs6000-ps3", rs6000_ps3_machine_init)

/* ---------------------------------------------------------------------- */

static void ps3_register_types(void)
{
    type_register_static(&ps3_mic_info);
    type_register_static(&ps3_rom_info);
}

type_init(ps3_register_types)
