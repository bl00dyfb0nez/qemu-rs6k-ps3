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

/*
 * g_stat/g_unlink: the disc's staging tree is checked and renamed with them,
 * beside the image the caller named.
 */
#include <glib/gstdio.h>

#define PS3_CALL_RING 16
typedef struct PS3Call {
    uint32_t nr;
    int tid;
    uint64_t lr;
    uint64_t sp;
    uint64_t srr0;
} PS3Call;

#include "qemu/units.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/sockets.h"
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
#include "system/block-backend-global-state.h"
#include "system/block-backend-io.h"
#include "system/blockdev.h"
#include "chardev/char-fe.h"
#include "qemu/option.h"
#include "qobject/qdict.h"
#include "system/reset.h"
#include "system/runstate.h"
#include "system/system.h"
#include "system/kvm.h"
#include "exec/icount.h"
#ifdef CONFIG_HVF
#include "system/hvf.h"
#endif
#ifdef CONFIG_WHPX
#include "system/whpx.h"
#endif
#include "hw/ide/isa.h"
#include "hw/core/irq.h"
#include "hw/isa/isa.h"
#include "ui/console.h"
#include "ui/input.h"

#include "ps3_spu.h"
#include "ps3_self.h"
#include "ps3_vga.h"
#include "ps3_audio.h"
#include "ps3_aes/ps3_aes.h"

#include <zlib.h>
#include <math.h>

#define TYPE_PS3_MIC "ps3-mic"
OBJECT_DECLARE_SIMPLE_TYPE(PS3MICState, PS3_MIC)

#define TYPE_PS3_BOOT_ROM "ps3-boot-rom"
OBJECT_DECLARE_SIMPLE_TYPE(PS3BootROMState, PS3_BOOT_ROM)

#define TYPE_RS6000_PS3_MACHINE MACHINE_TYPE_NAME("rs6000-ps3")

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
/* Where the model exposes every SPE's local store to the PPU.  SPE 0 also
 * keeps the old 0xF1000000 window used by the boot path. */
#define PS3_SPES_LS_BASE    0xF2000000
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

/*
 * A PRX module the lv2 layer loaded for the VSH.  The image stays where it was
 * mapped; the entry records the ELF's entry if it names one, and later lv2
 * calls use the base to answer "which module owns this address".
 */
#define PS3_LV2_MODULE_MAX  64
#define PS3_LV2_MODULE_PATH 96
/*
 * The VSH alone publishes 2,400 functions (paf is 973 of them), and every
 * module adds its own, so the linkage table has to be roomier than a handful
 * of libraries' worth.
 */
#define PS3_LV2_EXPORT_MAX  8192

/* The gamepad ports libpad numbers; sys_io describes all of them. */
#define PS3_PAD_PORT_MAX    7

/*
 * The AV channel's buffers: the VSH's AV library keeps 0x800 bytes of replies
 * and hands the device 0x800 bytes of commands at a time.
 */
#define PS3_AV_RX_SIZE      0x800
#define PS3_AV_TX_SIZE      0x1000
#define PS3_AV_VERSION      0x205
#define PS3_AV_REPLY_BIT    0x80000000u

/* lv2's sockets: a small table, guest handles are indices above 0x2FF. */
#define PS3_NET_MAX         32
#define PS3_NET_FD_BASE     0x300

/*
 * An unresolved import's stub OPD carries this placeholder as its code word:
 * the linker had nothing to write, so it is the loader's job.
 */
#define PS3_PRX_STUB_PLACEHOLDER 0x39800000u

/*
 * Where the model plants stubs for imports lv2 cannot resolve: between the
 * VSH image and the heap, one 0x20-byte OPD plus trap code per (library, NID).
 */
#define PS3_LV2_STUB_BASE  0x800000
#define PS3_LV2_STUB_END   0xA00000
#define PS3_LV2_STUB_STRIDE 0x40
#define PS3_LV2_MISSING_CALL 0x7FF
/* The stub leaves the NID here before it traps; the trap reads it back. */
#define PS3_LV2_STUB_NID   0x0A00

/*
 * One exported function: a NID a library publishes, and the guest address of
 * the OPD that describes it.  lv2's linkage is by (library name, NID) because
 * the NID alone is not unique across libraries.
 */
typedef struct PS3Lv2Export {
    char lib[28];
    uint32_t nid;
    uint32_t opd;
    uint8_t owner;            /* module index + 1, 0 for none */
} PS3Lv2Export;

/*
 * What a planted stub stands for.  The trampoline can only carry the NID, and
 * a NID alone does not name the library, so the linker records the pair.
 */
#define PS3_LV2_STUB_RECORDS 2048

typedef struct PS3Lv2Stub {
    char lib[28];
    uint32_t nid;
    uint32_t at;
} PS3Lv2Stub;

/*
 * Which module on the flash publishes a library.  The VSH links against the
 * console's own modules, so a module whose import has no provider yet means
 * the module that publishes it has not been asked for; the directory is
 * scanned once and every library it can supply is remembered here.
 */
typedef struct PS3Lv2Provider {
    char lib[28];
    char path[PS3_LV2_MODULE_PATH];
} PS3Lv2Provider;

typedef struct PS3Lv2Module {
    uint32_t id;
    uint32_t base;
    uint32_t size;
    uint32_t entry;
    char path[PS3_LV2_MODULE_PATH];
    /*
     * The PRX library header at the start of the image names the module, its
     * attributes and the two tables lv2 has to walk.  The addresses are the
     * guest's, and only valid once the relocations have been applied.
     */
    char name[28];
    uint16_t attributes;
    uint8_t version[2];
    uint32_t exports_start, exports_end;
    uint32_t imports_start, imports_end;
    uint32_t start_opd, stop_opd, prologue_opd;
    unsigned segments;
    bool started;
} PS3Lv2Module;

/* Guest file handles: small integers, handed out in order. */
#define PS3_LV2_FD_MAX  32
#define PS3_LV2_SECTOR  512

/*
 * lv2's storage layer: the BD drive and the disk, behind sys_storage_*.
 *
 * The guest never touches the ATA command block for these: lv2's storage API
 * is a "virtual device" one, and the VSH's x3 media manager enumerates the
 * drives, opens the Blu-ray one and reads its sectors through it.  The device
 * ids are lv2's; the low part names the drive kind, bits 32..39 the partition
 * of it.  RPCS3's sys_storage.h has the same list.
 */
#define PS3_STOR_MAX        8
#define PS3_STOR_BDVD       0x101000000000006ULL
#define PS3_STOR_ATA_HDD    0x101000000000007ULL
#define PS3_STOR_NAND       0x100000000000001ULL
#define PS3_STOR_NAND_UNK   0x100000000000003ULL
#define PS3_STOR_NOR        0x100000000000004ULL
#define PS3_STOR_USB        0x10300000000000AULL
#define PS3_STOR_DEVICES    17
#define PS3_STOR_SECT_BD    0x800

/*
 * PPU threads.  One core still runs guest code, but lv2's threads are now real:-
 * each has a saved context, and the blocking calls the VSH makes (sleep, join,
 * exit) hand the core to the next runnable one.  The switch happens from the
 * tick timer, never in the middle of the syscall trampoline.
 *
 * lv2 does not only switch when a thread asks it to: a thread owns the core
 * for a timeslice and is then preempted, whatever it is doing.  That matters
 * here because the VSH's service workers poll a flag in a loop and never call
 * lv2 at all - `_sys_micin_main` sits in one at 0x14A8DAC - so a yield-only
 * scheduler gives them the core once and never takes it back.  The slice is
 * counted in scheduler ticks (1 ms of virtual time each).
 */
/*
 * lv2's object tables.  These are the sizes the VSH needs, not the console's:
 * a boot creates more than thirty threads and more than sixty mutexes before
 * its registry is up, and a table that fills makes the application see EAGAIN
 * from create and ESRCH from every later destroy.
 */
#define PS3_THREAD_MAX 128
#define PS3_SCHED_SLICE_TICKS 4

/*
 * lv2's event queues and ports.
 *
 * A queue holds sys_event_t records - { source, data1, data2, data3 } - and a
 * port is the sending end of one.  This is how the VSH's service workers are
 * driven: each has a queue, and whoever has work for it sends an event.
 *
 * sys_event_queue_receive blocks when the queue is empty, so it is the one
 * service that can leave a thread waiting *inside* a call.  The trampoline's
 * exit flag parks such a thread at its halt loop, and the call is finished
 * later, from the frame and SRR0/SRR1 the park recorded - by a send, or by the
 * timeout running out in the scheduler tick.
 */
#define PS3_EQ_MAX 64
#define PS3_EQ_DEPTH 8
#define PS3_EP_MAX 64
#define PS3_EQ_EVENT_SIZE 32

/*
 * A wait's timeout, in scheduler ticks (1 ms of virtual time each).  lv2 takes
 * microseconds and the VSH asks for up to a minute at a time - msmw2.sprx polls
 * a queue for 100 s while the system comes up, which is why RPCS3 caps the same
 * wait during a VSH boot.  The model caps it too, so a boot still completes in
 * a run of a few thousand ticks; the event path itself is unaffected.
 */
#define PS3_EQ_TIMEOUT_MAX_TICKS 400

/*
 * The MIO2 service.
 *
 * sys_audio.sprx, the module the VSH loads for cellAudio, is not the driver:
 * it is a client of lv2's MIO2 service, the layer that owns the console's AV
 * and audio hardware.  The module opens the device by creating an IPC port
 * for the service key 0x80004D494F323200 - "MIO22", in the bytes of the key -
 * and an event queue of its own at key + 1, and then it sends requests
 * through the port and waits in that queue for the answers.
 *
 * A request names the slot of the client's own ring that the answer must go
 * into (bits 44..48 of data1), carries a command in the high 11 bits of data1
 * and an argument word in the low 32, and drops the pointers the caller gave
 * it in data2 and data3.  The answer goes back to the queue the caller made
 * for it, echoing data1's high word - the slot has to come back for the
 * client's ring to complete - with the command's result word in the low half,
 * which is the word the module's wrappers test for failure.
 *
 * The device the model speaks for is there and idle: the bring-up commands
 * report the values a stereo 48 kHz output reports, and the commands the
 * model has no meaning for are answered the same way and named in the trace,
 * so a missing one shows up as a client that goes on to fail somewhere else
 * rather than as a request that hangs.
 */
#define PS3_MIO2_KEY      0x80004D494F323200ULL
#define PS3_MIO2_REPLIES  3     /* the caller makes key + 1 .. key + 3 */
#define PS3_MIO2_EQ_SIZE  0x40
#define PS3_MIO2_RATE     48000
#define PS3_MIO2_CHANNELS 2

/*
 * The console's microphone.
 *
 * cellMic is a thin library: open, start, read and a handful of attributes.
 * The samples behind it come from a USB audio class device, and on this
 * machine that device is QEMU's capture input.  A capture voice is opened when
 * the guest opens device 0 and closed when it closes it; the scheduler tick
 * pulls what the host captured into this ring, and hands the guest a
 * CELLMIC_DATA event whenever there is a block to read - which is how
 * sys_audio's own mic thread learns there is something waiting.
 */
#define PS3_MIC_DEVICES       1
#define PS3_MIC_RING_FRAMES   8192      /* ~170 ms of stereo at 48 kHz */
#define PS3_MIC_BLOCK_FRAMES  256       /* 5.3 ms at 48 kHz, as RPCS3's period */
#define PS3_MIC_CHUNK_FRAMES  1024      /* one read's conversion window */
#define PS3_MIC_PERIOD_TICKS  5
#define PS3_MIC_DEFAULT_RATE  48000
#define PS3_MIC_SELFTEST_EA   0x000F0000  /* scratch the selftest zeroes again */

typedef struct PS3Event {
    uint64_t source, data1, data2, data3;
} PS3Event;

typedef struct PS3EventQueue {
    bool used;
    bool model;                 /* the model owns it: a service, not the guest */
    uint32_t id;
    uint64_t key;
    uint32_t size;
    uint32_t head;
    uint32_t count;
    PS3Event event[PS3_EQ_DEPTH];
} PS3EventQueue;

typedef struct PS3EventPort {
    bool used;
    uint32_t id;
    uint32_t type;              /* SYS_EVENT_PORT_LOCAL or _IPC */
    int eq;                     /* index into the queue table, -1 if none */
    uint64_t key;               /* IPC key, when the peer is not in the model */
    uint64_t name;
} PS3EventPort;

/*
 * The RSX.
 *
 * lv2's sys_rsx is the interface the console's graphics library (cellGcmSys)
 * is built on, and every constant below is one of its contracts with that
 * library: the layout of the driver info page lv2 hands out (RPCS3's
 * RsxDriverInfo), the DMA control block, the report area, and the io window
 * cellGcmSys maps its command buffer into.
 *
 * The FIFO is a ring of command packets in main memory.  The PPU writes them
 * and rings the doorbell (context attribute 0x001) with the io offset of its
 * put pointer; the RSX consumes packets until it reaches put and publishes its
 * new get pointer.  That is the whole clock of the RSX: no tick drives it.
 */
#define PS3_RSX_LOCAL_BASE    0x40000000u
#define PS3_RSX_LOCAL_SIZE    0x10000000u
#define PS3_RSX_CONTEXT_ID    0x55555555u
#define PS3_RSX_MEM_HANDLE    0x5A5A5A5Bu
#define PS3_RSX_MAIN_SIZE     0x10000000u   /* 256 MiB of XDR the io window covers */
#define PS3_RSX_IO_PAGES      512           /* io is in 1 MiB pages */
#define PS3_RSX_TILES         15
#define PS3_RSX_ZCULLS        8
#define PS3_RSX_VBLANK_NS     16683300ull   /* 59.94 Hz */

/* RsxDriverInfo: the page cellGcmSys reads and writes. */
#define PS3_RSX_DI_VERSION    0x000
#define PS3_RSX_DI_GPU        0x004
#define PS3_RSX_DI_MEM_SIZE   0x008
#define PS3_RSX_DI_CHANNEL    0x00C
#define PS3_RSX_DI_NVCORE     0x010
#define PS3_RSX_DI_MEMFREQ    0x014
#define PS3_RSX_DI_NOTIFY     0x02C
#define PS3_RSX_DI_REPORTS    0x030
#define PS3_RSX_DI_REPTABLE   0x034
#define PS3_RSX_DI_SYSMODE    0x054
#define PS3_RSX_DI_HEAD       0x10B8
#define PS3_RSX_DI_HEAD_STRIDE 0x40
#define PS3_RSX_DI_HANDLERS   0x12C0
#define PS3_RSX_DI_USERCMD    0x12CC
#define PS3_RSX_DI_QUEUE      0x12D0
#define PS3_RSX_DI_LASTERROR  0x12F4
#define PS3_RSX_DI_SIZE       0x12F8

#define PS3_RSX_HEAD_FLIPTIME 0x00
#define PS3_RSX_HEAD_FLAGS    0x08
#define PS3_RSX_HEAD_OFFSET   0x0C
#define PS3_RSX_HEAD_FLIPID   0x10
#define PS3_RSX_HEAD_QUEUED   0x14
#define PS3_RSX_HEAD_VTLOW    0x1C
#define PS3_RSX_HEAD_SECONDT  0x20
#define PS3_RSX_HEAD_VCOUNT   0x30
#define PS3_RSX_HEAD_VTHIGH   0x3C

/* RsxDmaControl and RsxReports. */
#define PS3_RSX_DMA_PUT       0x40
#define PS3_RSX_DMA_GET       0x44
#define PS3_RSX_DMA_REF       0x48
#define PS3_RSX_REPORTS_SIZE  0x9400    /* 1024 semaphores, 64 notify, 2048 report */
#define PS3_RSX_NOTIFY_OFF    0x1000
#define PS3_RSX_REPORT_OFF    0x1400

/* The handler bits events are filtered against, as RPCS3 names them. */
#define PS3_RSX_EVENT_VBLANK      (1ull << 1)
#define PS3_RSX_EVENT_FLIP_BASE   (1ull << 3)
#define PS3_RSX_EVENT_QUEUE_BASE  (1ull << 5)
#define PS3_RSX_EVENT_USER_CMD    (1ull << 7)
#define PS3_RSX_EVENT_SECOND_BASE (1ull << 10)

/* FIFO packet kinds (RPCS3's RSX_METHOD_* masks). */
#define PS3_RSX_CALL_EMPTY    0x00000003u

/*
 * The NV4097 methods the display path decodes.  The numbers are RPCS3's
 * gcm_enums.h values already shifted down to the method field, which is what
 * the FIFO's register field carries (the io offset divided by four).
 */
#define PS3_RSX_SET_CLEAR     0x764       /* NV4097_SET_COLOR_CLEAR_VALUE */
#define PS3_RSX_CLEAR_SURFACE 0x765       /* NV4097_CLEAR_SURFACE */
#define PS3_RSX_SET_TARGET    0x088       /* NV4097_SET_SURFACE_COLOR_TARGET */
#define PS3_RSX_SET_FORMAT    0x082       /* NV4097_SET_SURFACE_FORMAT */
#define PS3_RSX_SET_PITCH_A   0x083       /* NV4097_SET_SURFACE_PITCH_A */
#define PS3_RSX_SET_OFFSET_A  0x084       /* NV4097_SET_SURFACE_COLOR_AOFFSET */
#define PS3_RSX_SET_BEGIN_END 0x602       /* NV4097_SET_BEGIN_END */
#define PS3_RSX_SET_BLEND     0x0C4       /* NV4097_SET_BLEND_ENABLE */
#define PS3_RSX_SET_BLEND_S   0x0C5       /* NV4097_SET_BLEND_FUNC_SFACTOR */
#define PS3_RSX_SET_BLEND_D   0x0C6       /* NV4097_SET_BLEND_FUNC_DFACTOR */
#define PS3_RSX_SET_BLEND_EQ  0x0C8       /* NV4097_SET_BLEND_EQUATION */
#define PS3_RSX_SET_COLORMASK 0x0C9       /* NV4097_SET_COLOR_MASK */
#define PS3_RSX_SET_SCISSOR_H 0x230       /* NV4097_SET_SCISSOR_HORIZONTAL */
#define PS3_RSX_SET_SCISSOR_V 0x231       /* NV4097_SET_SCISSOR_VERTICAL */
#define PS3_RSX_SET_VIEWPORT_H 0x280      /* NV4097_SET_VIEWPORT_HORIZONTAL */
#define PS3_RSX_SET_VIEWPORT_V 0x281      /* NV4097_SET_VIEWPORT_VERTICAL */
#define PS3_RSX_SET_DEPTHTEST 0x29D       /* NV4097_SET_DEPTH_TEST_ENABLE */
#define PS3_RSX_SET_VTX_OFF   0x5A0       /* NV4097_SET_VERTEX_DATA_ARRAY_OFFSET */
#define PS3_RSX_SET_VTX_BASE  0x5CE       /* NV4097_SET_VERTEX_DATA_BASE_OFFSET */
#define PS3_RSX_SET_VTX_INDEX 0x5CF       /* NV4097_SET_VERTEX_DATA_BASE_INDEX */
#define PS3_RSX_SET_VTX_FMT   0x5D0       /* NV4097_SET_VERTEX_DATA_ARRAY_FORMAT */
#define PS3_RSX_INLINE_ARRAY  0x606       /* NV4097_INLINE_ARRAY */
#define PS3_RSX_SET_INDEX_ADDR 0x607      /* NV4097_SET_INDEX_ARRAY_ADDRESS */
#define PS3_RSX_SET_INDEX_DMA 0x608       /* NV4097_SET_INDEX_ARRAY_DMA */
#define PS3_RSX_ARRAY_ELEM16  0x603       /* NV4097_ARRAY_ELEMENT16 */
#define PS3_RSX_ARRAY_ELEM32  0x604       /* NV4097_ARRAY_ELEMENT32 */
#define PS3_RSX_DRAW_ARRAYS   0x605       /* NV4097_DRAW_ARRAYS */
#define PS3_RSX_DRAW_INDEXED  0x609       /* NV4097_DRAW_INDEX_ARRAY */
#define PS3_RSX_SET_CULL      0x60F       /* NV4097_SET_CULL_FACE_ENABLE */

#define PS3_RSX_ATTRS         16
#define PS3_RSX_CLAUSE_MAX    1024        /* vertex ranges per draw clause */
#define PS3_RSX_INLINE_MAX    4096        /* words of inline vertex data */

/* The transform program and its constants, as RPCS3's nv4097 names them. */
#define PS3_RSX_SET_TRANSFORM_PROGRAM      0x2E0  /* NV4097_SET_TRANSFORM_PROGRAM */
#define PS3_RSX_SET_TRANSFORM_PROGRAM_LOAD 0x7A7  /* NV4097_SET_TRANSFORM_PROGRAM_LOAD */
#define PS3_RSX_SET_TRANSFORM_PROGRAM_START 0x7A8 /* NV4097_SET_TRANSFORM_PROGRAM_START */
#define PS3_RSX_SET_TRANSFORM_CONST_LOAD   0x7BF  /* NV4097_SET_TRANSFORM_CONSTANT_LOAD */
#define PS3_RSX_SET_TRANSFORM_CONSTANT     0x7C0  /* NV4097_SET_TRANSFORM_CONSTANT */
#define PS3_RSX_VPROG_INST    512                 /* 8 KiB of vp40 */
#define PS3_RSX_VPROG_WORDS   (PS3_RSX_VPROG_INST * 4)
#define PS3_RSX_VCONST        512                 /* 8 KiB of constants */

/*
 * The fragment stage, as RPCS3's nv4097 names it.  The graphics library
 * uploads the fp40 program into local memory and names its address with
 * SET_SHADER_PROGRAM; each texture's eight registers start at SET_TEXTURE_OFFSET
 * and repeat every eight methods.
 */
#define PS3_RSX_SET_SHADER_PROGRAM 0x239          /* NV4097_SET_SHADER_PROGRAM */
#define PS3_RSX_SET_TEXTURE        0x680          /* NV4097_SET_TEXTURE_OFFSET */
#define PS3_RSX_SET_SHADER_CONTROL 0x758          /* NV4097_SET_SHADER_CONTROL */
#define PS3_RSX_FPROG_BYTES    16384              /* the program plus its constants */
#define PS3_RSX_TEX_MAX        16                 /* the fp's texture units */
#define PS3_RSX_FP_TEMP        16
#define PS3_RSX_FP_INPUTS      16

/*
 * One vertex after the fetch: the attribute registers as they arrive, and the
 * colour the rasterizer interpolates.  `w' is the position's fourth
 * component, which decides whether the position is clip space or already in
 * window coordinates.
 */
typedef struct PS3RsxVertex {
    float x, y, z, w;
    float r, g, b, a;
    /*
     * The vertex program's output registers: output 0 is the position in the
     * four fields above, and the fragment stage reads the rest as its
     * varying inputs (COL0 is output 1, FOGC output 5, TEX0..TEX7 outputs
     * 7..14, TEX8 output 15 and TEX9 output 6, which is RPCS3's table).
     */
    float var[16][4];
} PS3RsxVertex;

typedef struct PS3RsxTexture {
    uint32_t offset, format, address, control0, control1, filter;
    uint32_t image_rect, border;
} PS3RsxTexture;

typedef struct PS3RsxTile {
    bool bound;
    uint32_t location, offset, size, pitch, comp, base;
} PS3RsxTile;

typedef struct PS3RsxZcull {
    bool bound;
    uint32_t width, height, cull_start, offset;
    uint32_t z_format, aa_format, dir, format, func, ref, mask;
} PS3RsxZcull;

/*
 * The synchronization the VSH's thread pool is built on.  A thread that has
 * to wait for a mutex or a condition is parked inside its call exactly like
 * one waiting on an event queue, so the same completion path wakes it.
 */
#define PS3_MUTEX_MAX 256
#define PS3_COND_MAX 128

typedef struct PS3Mutex {
    bool used;
    uint32_t id;
    uint32_t owner;             /* thread id, 0 = free */
} PS3Mutex;

/*
 * lv2's lightweight mutex.  What makes it "light" is that its state lives in
 * the guest's own `sys_lwmutex_t`, which the library locks with lwarx/stwcx
 * before it ever calls lv2; `_sys_lwmutex_lock` is only the slow path, and it
 * has to agree with that word or the library spins.  So the words here are the
 * guest's, and the model reads and writes the block it was handed at create:
 *
 *   0x00  owner       thread id, or 0xFFFFFFFF when free
 *   0x04  waiter      set while the lock has waiters parked in lv2
 *   0x08  attribute   0 recursive, 1 not recursive (the protocol word)
 *   0x0C  recursive_count
 *   0x10  sleep_queue the pseudo-id lv2 hands back for the lock
 */
#define PS3_LWMUTEX_MAX 256
#define PS3_LWMUTEX_FREE      0xFFFFFFFFu
#define PS3_LWMUTEX_RESERVED  0xFFFFFFFDu

#define PS3_LWMUTEX_ATTR_RECURSIVE 0u

typedef struct PS3Lwmutex {
    bool used;
    uint32_t id;
    uint32_t control;           /* guest sys_lwmutex_t */
    uint32_t owner;             /* thread id, 0 = free */
    uint32_t attribute;         /* the protocol word create was given */
    unsigned parked;            /* threads parked on it */
} PS3Lwmutex;

typedef struct PS3Cond {
    bool used;
    uint32_t id;
    uint32_t mutex;             /* the mutex a wait releases and retakes */
} PS3Cond;

/*
 * lv2's read/write lock.  The library keeps no state of its own here, so this
 * record is the whole lock: a reader takes it while no writer holds it and no
 * writer is queued (the queue is what keeps a stream of readers from starving
 * a writer), and the last reader out hands it to the first queued writer.
 * The VSH's PAF layer locks its tables this way - with the calls unmodelled
 * the library's own exchange still ran, so the stall showed up as a thread
 * waiting forever on a condition rather than as a failed call.
 */
#define PS3_RWLOCK_MAX 64

typedef struct PS3RWLock {
    bool used;
    uint32_t id;
    unsigned readers;           /* readers holding it */
    unsigned wait_writers;      /* writers queued for it */
    uint32_t writer;            /* writing thread id, 0 = none */
} PS3RWLock;

#define PS3_SEM_MAX 64

typedef struct PS3Sem {
    bool used;
    uint32_t id;
    int32_t count;
    int32_t max;
} PS3Sem;

/*
 * The application layer's SPEs.  A title reaches lv2's sys_spu interface
 * through libspu: it imports an SPU ELF (_sys_spu_image_import), creates a
 * thread group, initialises each thread from that image, starts the group and
 * joins it.  The model keeps the imported images and the groups here; the
 * local store and the DMA of the running SPE belong to ps3_spu.c.
 */
#define PS3_SPU_LV2_GROUPS 4
#define PS3_SPU_IMAGES     8

typedef struct PS3SPUImageSeg {
    uint32_t type;          /* 1 copy, 2 fill, 4 info */
    uint32_t ls;            /* destination in local storage */
    uint32_t size;
    uint32_t addr;          /* source EA for a copy, the word for a fill */
} PS3SPUImageSeg;

typedef struct PS3SPUImage {
    bool used;
    uint32_t id;
    uint32_t entry;
    unsigned nsegs;
    PS3SPUImageSeg seg[0x20];
} PS3SPUImage;

typedef struct PS3SPULv2Group {
    bool used;
    /*
     * The low byte is the SPE number, as lv2's SPU thread ids have it: the
     * address a sys_spu_thread_* call names is group_id | spu_num.
     */
    uint32_t id;
    unsigned count;
    uint8_t *ls;            /* count * 256 KiB of local store */
    PS3SPEGroup *spes;
    bool thread[PS3_SPE_MAX];
    uint32_t cfg[PS3_SPE_MAX];  /* sys_spu_thread_set_spu_cfg */
    bool started;
    bool terminated;
    uint32_t exit_cause;
} PS3SPULv2Group;

typedef struct PS3Thread {
    bool used;
    bool dead;
    bool blocked;
    bool main;
    bool fault_reported;        /* it landed on a vector; said so once */
    /* Waiting inside an lv2 call: the call is finished when it is woken. */
    bool parked;
    /*
     * The trampoline's frame has already been folded up for the call in
     * flight.  Both the scheduler and the wake path can reach the point where
     * they collect r3/r0/r12 and step r1 past the trampoline, and doing that
     * twice walks the thread's stack pointer 0x20 into its own frame - the
     * epilogue then reads a local instead of the saved LR and returns into the
     * stack.  The flag is cleared when a new `sc` is dispatched.
     */
    bool call_collected;
    /*
     * The SRR0 the folded frame belongs to.  A preemption between the store
     * that publishes a call (0xC24) and the instruction after it replays that
     * store, and the replay must not fold the same frame a second time; the
     * value says which call the folded frame is, so a replay is recognised.
     */
    uint64_t call_folded_srr0;
    int wait_eq;                /* index of the queue it waits on */
    uint32_t wait_ea;           /* guest sys_event_t the call writes to */
    int32_t wait_ticks;         /* -1 = no timeout, else ticks left */
    uint32_t wait_mutex_id;     /* mutex it must own before it can return */
    uint32_t wait_lwmutex_id;   /* lightweight mutex it waits to acquire */
    uint32_t wait_rwlock_id;    /* read/write lock it waits to acquire */
    bool wait_rwlock_write;     /* and whether it waits as the writer */
    uint32_t wait_cond_id;      /* condition it waits on, 0 = none */
    uint32_t wait_sem_id;       /* semaphore it waits on, 0 = none */
    uint32_t id;
    uint32_t join_target;
    /*
     * A join in flight: the joiner is parked until the target exits, and the
     * target's exit status goes to join_ea when it does.  lv2 writes that word
     * when the join completes, not when it is called.
     */
    uint32_t join_ea;
    uint32_t exit_status;
    /* lv2's thread attributes: the priority the creator asked for, the stack
     * it was given, and whether it can still be joined.  The VSH's x3 layer
     * asks for all three around the media threads it starts. */
    int32_t prio;
    bool detached;
    uint32_t stack_base, stack_size;
    /* Returning here lands on `li r11,0x29; sc`, i.e. sys_ppu_thread_exit. */
    uint32_t exit_stub;
    /* When it last had the CPU, and whether its current stall was reported. */
    uint64_t last_run;
    bool stall_reported;
    /* The code page it kept returning to, and whether that was reported. */
    uint64_t spin_page;
    unsigned spin_ticks;
    bool spin_reported;
    /* A sys_uart_receive that had to wait: where its bytes go, and how many. */
    uint32_t uart_buf, uart_size;
    uint64_t gpr[32];
    uint64_t lr, ctr, xer, msr, nip;
    /*
     * A thread can be switched out between its `sc` and the trampoline's
     * `rfid`; the return address and MSR of that exception live here, so they
     * belong to the thread's context too.  Without them a resumed trampoline
     * returns through another thread's SRR0.
     */
    uint64_t srr0, srr1;
    uint32_t crf[8];
} PS3Thread;

/* One entry of the disc's ISO 9660 tree; defined with the reader below. */
typedef struct PS3IsoNode PS3IsoNode;

struct PS3BootROMState {
    SysBusDevice parent_obj;

    MemoryRegion rom_mr;      /* the 0x400-byte mask ROM, 32-bit byte-swapped */
    MemoryRegion ls_mr;       /* every SPE's local store, 256 KiB per SPE */
    MemoryRegion ls_alias_mr; /* 256 KiB view of SPE 0 at 0xF1000000 */
    MemoryRegion regs_mr;     /* status and control */
    MemoryRegion flash_mr;    /* the console's flash image, when a drive is given */
    MemoryRegion uart_mr;     /* the PPU-side console lv0 polls */
    MemoryRegion uart_alias_mr;
    char uart_line[256];
    size_t uart_len;
    unsigned uart_hits;
    /*
     * The same console, on a chardev: `-serial stdio' makes the guest's UART
     * a real terminal, and a socket or pty makes it scriptable.  Without one
     * the log and the display are the console, which is what the model did
     * before there was a backend.
     */
    CharFrontend chr;
    bool chr_ready;
    uint8_t uart_in[256];
    unsigned uart_in_head, uart_in_tail;

    BlockBackend *blk;
    char *rom_file;
    char *container;
    char *readout;
    char *readout_file;
    uint8_t readout_bytes[32];
    bool has_readout;
    bool selftest;
    bool mic_selftest;              /* drive the cellMic path once at start */
    bool pad_selftest;              /* one controller state through the pad */
    bool spu_run;
    bool spu_trace;
    char *ls_dump;
    char *prx_dump;                 /* decrypted module images, one per file */
    uint64_t flash_base;

    PS3SPU *spu;
    PS3SPEGroup *spes;        /* the eight SPEs, sharing one external memory */
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
    /* The last lv2 calls, for the report a vector makes. */
    PS3Call call_ring[PS3_CALL_RING];
    unsigned call_ring_pos;
    unsigned ppu_fault_reports;
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
    char *audio_dev;             /* the -audiodev id the sound driver uses */
    char *vsh_self;
    char *vsh_dump;
    char *vsh_erk;
    char *vsh_riv;
    char *dev_flash;
    char *dev_flash2;
    char *dev_flash3;
    /*
     * The USB storage the guest sees as dev_usb000: a directory on the host,
     * which is what an attached FAT32 stick's contents are.  There is no USB
     * stack and no block layer in the model, so sys_fs serves its files.
     */
    char *usb_dir;
    /*
     * What the guest sees as dev_hdd0.  A fresh image has no PS3 filesystem,
     * which is exactly the new-HDD case: the VSH's recovery offers to format,
     * and this directory is where the format and the system files land.
     */
    char *hdd_dir;
    char *hdd1_dir;              /* dev_hdd1: a title's data area */
    bool vsh_run;
    uint32_t vsh_entry;
    uint32_t vsh_toc;
    unsigned vsh_segments;
    uint64_t vsh_bytes;
    char vsh_why[160];

    /* The lv2 layer vsh-run answers the guest's syscalls with. */
    uint32_t lv2_next_id;
    /* This call blocks its thread: the trampoline parks it when it returns. */
    bool lv2_park;
    PS3EventQueue eq[PS3_EQ_MAX];
    PS3EventPort ep[PS3_EP_MAX];
    PS3Mutex mtx[PS3_MUTEX_MAX];
    PS3RWLock rw[PS3_RWLOCK_MAX];
    PS3Lwmutex lwm[PS3_LWMUTEX_MAX];
    bool lwmutex_reported;          /* the guest's own lock was reported */
    PS3Cond cond[PS3_COND_MAX];
    PS3Sem sem[PS3_SEM_MAX];
    uint32_t lv2_container_size;
    /* The application layer's SPEs (sys_spu). */
    PS3SPULv2Group spug[PS3_SPU_LV2_GROUPS];
    PS3SPUImage spuimg[PS3_SPU_IMAGES];
    uint32_t spu_next_id;
    /* Where the next sys_mmapper address is handed out (RSX-backed ranges). */
    uint32_t lv2_mmap_next;
    /*
     * The system controller's EEPROM, as RPCS3's ps3_syscon keeps it: sparse,
     * unwritten bytes read 0xFF, and offset 0x48C07 is not a stored byte but
     * the console's recover mode (0x00 in service mode).
     */
    struct {
        uint32_t off;
        uint8_t val;
    } syscon_ee[32];
    int syscon_ee_n;
    bool syscon_recover;

    /*
     * The RSX.  Its local memory is real memory the guest can map with
     * sys_rsx_context_iomap, and the display buffers cellGcmSys points it at
     * live there, which is what the scanout reads.  The device is made of the
     * three areas lv2 hands lv2's graphics library - DMA control, driver info
     * and reports - the io window the library maps its FIFO into, and the FIFO
     * consumer, which runs on the doorbell rather than on a tick.
     */
    MemoryRegion rsx_local;
    bool rsx_ready;
    uint32_t rsx_context;           /* 0x55555555 while a context exists */
    uint32_t rsx_mem_handle;
    bool rsx_mem_allocated;
    uint32_t rsx_local_size;
    uint32_t rsx_dma, rsx_driver, rsx_reports, rsx_device;
    uint32_t rsx_event_port, rsx_event_queue;
    uint32_t rsx_get, rsx_put;      /* io offsets from the last doorbell */
    uint32_t rsx_iomap_ea[PS3_RSX_IO_PAGES];
    uint8_t rsx_iomap_used[PS3_RSX_IO_PAGES];
    uint32_t rsx_db_offset[8], rsx_db_pitch[8], rsx_db_w[8], rsx_db_h[8];
    unsigned rsx_db_count;          /* highest display buffer + 1 */
    uint32_t rsx_head_queued[2], rsx_head_flags[2];
    bool rsx_vsync, rsx_second_vhandler;
    uint32_t rsx_surface_format, rsx_surface_pitch, rsx_surface_offset;
    uint32_t rsx_surface_target, rsx_clear_color, rsx_begin_end;
    uint64_t rsx_vblanks, rsx_flips, rsx_methods, rsx_draws;
    /*
     * The vertex pipeline's state.  The arrays are what SET_VERTEX_DATA_ARRAY
     * OFFSET/FORMAT describe, the index array is the one DRAW_INDEX_ARRAY
     * reads, and the viewport and scissor are the two registers that decide
     * where a primitive lands on the surface.
     */
    uint32_t rsx_vtx_off[PS3_RSX_ATTRS];
    uint32_t rsx_vtx_fmt[PS3_RSX_ATTRS];
    uint32_t rsx_vtx_base, rsx_vtx_index_base;
    uint32_t rsx_index_addr, rsx_index_dma;
    uint32_t rsx_viewport_h, rsx_viewport_v;
    uint32_t rsx_scissor_h, rsx_scissor_v;
    uint32_t rsx_blend, rsx_blend_s, rsx_blend_d, rsx_blend_eq;
    uint32_t rsx_color_mask, rsx_cull, rsx_depth_test;
    /*
     * The draw clause.  A primitive is opened by SET_BEGIN_END with its type,
     * the draw calls in between append vertex ranges to it, and the closing
     * SET_BEGIN_END(0) rasterizes the lot - which is how a strip can span
     * several draw calls.
     */
    uint32_t rsx_prim, rsx_clause_indexed;
    struct {
        uint32_t start, count;
    } rsx_clause[PS3_RSX_CLAUSE_MAX];
    unsigned rsx_clause_n;
    uint8_t rsx_inline[PS3_RSX_INLINE_MAX * 4];
    unsigned rsx_inline_words;
    uint64_t rsx_prims, rsx_pixels;
    bool rsx_draw_reported, rsx_noattr_reported, rsx_immediate_reported;
    /*
     * The vertex program.  The graphics library uploads vp40 instructions
     * through SET_TRANSFORM_PROGRAM_LOAD/SET_TRANSFORM_PROGRAM and their
     * constants through SET_TRANSFORM_CONSTANT_LOAD/SET_TRANSFORM_CONSTANT;
     * ps3_rsx_vprog_run() executes them for each vertex.
     */
    uint32_t rsx_vprog[PS3_RSX_VPROG_WORDS];
    uint32_t rsx_vprog_load, rsx_vprog_word, rsx_vprog_start;
    uint32_t rsx_vconst[PS3_RSX_VCONST][4];
    uint32_t rsx_vconst_load, rsx_vconst_word;
    bool rsx_vprog_ready, rsx_vprog_fallback_reported;
    /*
     * The fragment program and the textures it samples.  The program is
     * copied out of local (or main) memory when SET_SHADER_PROGRAM names it;
     * ps3_rsx_fprog_run() executes the fp40 for a pixel and
     * ps3_rsx_tex_sample() reads a texel through the texture registers.
     */
    uint8_t rsx_fprog[PS3_RSX_FPROG_BYTES];
    uint32_t rsx_fprog_addr;
    unsigned rsx_fprog_len;
    bool rsx_fprog_ready, rsx_fprog_reported;
    uint32_t rsx_shader_control;
    PS3RsxTexture rsx_tex[PS3_RSX_TEX_MAX];
    uint64_t rsx_shaded;            /* pixels the fp40 produced */
    PS3RsxTile rsx_tiles[PS3_RSX_TILES];
    PS3RsxZcull rsx_zculls[PS3_RSX_ZCULLS];
    QEMUTimer *rsx_vblank_timer;
    unsigned rsx_methods_logged;
    /*
     * The container's bump pointer lives here, not at RAM 0x808.  0x808 is
     * inside lv2's low page and the VSH's initialisation memsets that range;
     * keeping the authority in the device is what makes the model immune to
     * it.  The word at 0x808 is only a copy for dumps.
     */
    uint32_t lv2_heap;
    bool lv2_exited;
    int32_t lv2_exit_status;
    uint8_t lv2_fan_policy;         /* 0 auto, 1 manual, 2 full */
    uint8_t lv2_fan_duty;
    bool lv2_usleep_reported;       /* the idle loop's sleep was reported */
    bool lv2_storage_reported;      /* the BD drive's enumeration was reported */
    bool lv2_btsetting_reported;    /* sys_btsetting_if's first call */
    bool lv2_av_reported;           /* the guest read the sink's EDID */
    bool lv2_video_reported;        /* cellVideoOut configured a mode */

    /*
     * The GCM display path: the buffer the guest registers with
     * cellGcmSetDisplayBuffer and the flip it asks for.  The RSX itself is not
     * modelled, but this is the same scanout cellVideoOut programs, so a frame
     * the guest hands over is what the window shows.
     */
    struct {
        uint32_t offset, pitch, width, height;
        bool set;
    } gcm_display[8];
    bool lv2_time_reported;         /* sys_time_get_current_time's first call */
    uint8_t lv2_video_res;          /* the mode the guest selected */
    bool lv2_audio_reported;        /* the sound driver started */

    /*
     * The sound driver.  sys_audio reaches the hardware through lv2's
     * sys_rsxaudio calls: initialize hands out a handle, import_shared_memory
     * publishes a page of ring buffers the guest fills with PCM, and
     * start_process tells the hardware to pull.  This model keeps that page
     * and drains the serial ring to the host's audiodev.
     */
    PS3Audio *audio;
    uint32_t rsxaudio_handle;
    uint32_t rsxaudio_shmem;
    bool rsxaudio_running;
    QEMUTimer *rsxaudio_timer;
    uint64_t rsxaudio_blocks;

    /*
     * The microphone's state: what cellMic was told, and the samples the host
     * captured that the guest has not read yet.  Device 0 is the capture
     * voice; the rest of cellMic's eight slots are simply absent.
     */
    bool mic_init;
    bool mic_opened;
    bool mic_started;
    unsigned mic_channels;          /* 1 or 2, as the guest opened it */
    uint32_t mic_sig_type;          /* DSP, RAW or AUX from cellMicOpenEx */
    uint32_t mic_rate;              /* the rate the voice was opened at */
    uint32_t mic_dsp_rate;
    uint32_t mic_attr_gain, mic_attr_volume, mic_attr_agc, mic_attr_led;
    uint32_t mic_attr_dsptype;
    uint32_t mic_chanvol[2];
    uint64_t mic_eq_key;            /* the queue cellMicSetNotifyEventQueue named */
    uint64_t mic_eq_source;
    int16_t mic_ring[PS3_MIC_RING_FRAMES * 2];
    unsigned mic_head, mic_used;    /* in frames */
    float mic_energy_db;            /* the level cellMicGetSignalState reports */
    uint32_t mic_tick;
    bool mic_queued;
    QEMUTimer *mic_capture_timer;   /* the selftest's real-capture check */
    /*
     * The pad's two digital words, as libpad numbers them: digital1 carries
     * select, the stick buttons, start, the d-pad and PS, digital2 the
     * shoulders, the triggers and the four face buttons.  They are kept apart
     * because PS (digital1 bit 8) and L2 (digital2 bit 0) would otherwise be
     * the same bit in one flattened word.
     */
    uint16_t kbd_d1, kbd_d2;        /* what the keyboard presses */
    QemuInputHandlerState *kbd;
    bool kbd_reported;
    /* And the same two words from the host's controller, plus its sticks. */
    uint32_t host_buttons;          /* QEMU_GAMEPAD_* bits */
    int host_lx, host_ly, host_rx, host_ry;
    bool host_pad_connected;        /* as the display last said */
    /* The console's auto-off: one hour without input and it powers down. */
    QEMUTimer *idle_timer;
    uint32_t idle_off_seconds;
    bool idle_off_reported;
    int lv2_fd[PS3_LV2_FD_MAX];     /* guest handle -> host descriptor */
    bool lv2_fd_open[PS3_LV2_FD_MAX];
    /*
     * A directory handle is a GDir of the host tree, opened on the guest's
     * behalf.  The console's lv2 hands out the same fd numbering to files and
     * directories, so these slots share it and only the matching array says
     * which kind a handle is.
     */
    GDir *lv2_dir[PS3_LV2_FD_MAX];
    gchar *lv2_dir_path[PS3_LV2_FD_MAX];
    unsigned lv2_dir_step[PS3_LV2_FD_MAX];

    /*
     * The HDD: one raw image, the size a superslim ships with.  Its sectors
     * are XTS-AES with keys metldr derives from the console's EID root key
     * (PCK1), so the image is the same disk whatever the host filesystem is.
     */
    char *hdd_file;
    uint64_t hdd_size;
    BlockBackend *hdd;
    bool hdd_created;
    char *erk_prop;                 /* the EID root key, hex */
    char *erk_file;                 /* or a 48-byte file */
    uint8_t erk[48];                /* 32 bytes of key, 16 of IV */
    bool has_erk;
    char *pck2_prop;                /* per-console root key 2, hex */
    char *pck2_file;                /* or a 48-byte file */
    uint8_t pck2[48];
    bool has_pck2;
    uint8_t hdd_data_key[32];
    uint8_t hdd_tweak_key[32];
    bool hdd_keyed;

    /*
     * The Blu-ray drive's image, which is the same one the machine gives
     * QEMU's ATAPI device at 0x1F0: the guest's own ATA driver and lv2's
     * sys_storage then see one disc.  `disc_size' is the media's size, so an
     * empty drawer reports zero sectors instead of pretending to have a disc.
     */
    char *disc_file;                /* the image the drive was given */
    BlockBackend *disc;             /* opened read-only, lv2's view of it */
    uint64_t disc_size;
    /*
     * The disc's filesystem: the ISO 9660 tree the path mapper mounts as
     * dev_bdvd, the directory its entries are staged in, and whether the
     * descriptors have been read yet.  See ps3_iso_setup.
     */
    PS3IsoNode *iso_root;
    char *iso_tree;
    bool iso_parsed;
    struct {
        bool used;
        uint64_t device;
    } stor[PS3_STOR_MAX];

    /*
     * The eMMC: the superslim's firmware medium.  A 4xxx console has no NOR -
     * metldr and the loaders live on eMMC - so the image here is the whole
     * flash, encrypted with the encdec keys PCK1 derives (the same ladder as
     * the disk, different seeds).  `boot-medium` says which of the three
     * media the boot ROM looks in: pflash (default), emmc or hdd.
     */
    char *emmc_file;
    uint64_t emmc_size;
    BlockBackend *emmc;
    bool emmc_created;
    uint8_t emmc_data_key[32];
    uint8_t emmc_tweak_key[32];
    bool emmc_keyed;
    bool tree_emmc;                 /* the file tree is on the eMMC */
    char *boot_medium;
    bool boot_logo;                 /* the boot screen, once the chain is done */
    QEMUTimer *home_timer;          /* the home screen after the wordmark */
    /*
     * The application lv2 starts.  It comes from one of two places and nowhere
     * else: /dev_flash/vsh/module/vsh.self inside the HDD image, or - in
     * recovery - emer_init.self read out of the flash's own recovery banks.
     * `app_img' holds the latter, because there is no host file to name.
     */
    uint8_t *app_img;
    size_t app_img_len;
    char *app_path;                 /* the guest path, for argv and the log */
    bool recovery;                  /* lv2 started the emergency program */
    bool recover_prop;              /* the EEPROM's recover flag at boot */
    /*
     * The console's warm reset, as the recovery program's restart asks for it.
     * sys_sm_shutdown(0x100) has written the EEPROM's recover byte and pulls
     * the system reset line; the model records the request and lets QEMU's own
     * reset run ps3_ppu_reset_entry, instead of the process's exit ending the
     * run.  `recovery_boots' counts the restarts, so a recovery loop is
     * visible in the log rather than looking like a run that never finished.
     */
    bool warm_reset;
    unsigned recovery_boots;
    bool reset_registered;          /* the reset entry is registered once */

    /*
     * The console's gamepad ports (sys_io/cellPad) and its front LED
     * (sys_sm_control_led).  There is no USB stack and no lamp: the ports are
     * described by these fields and the LED is a string the display frontends
     * show, which is as much hardware as this model pretends to have.
     */
    uint8_t pad_ports;              /* ports described, 1..7 */
    uint8_t pad_types[PS3_PAD_PORT_MAX]; /* index into ps3_pad_products[] */
    char *pad_types_prop;           /* the pad-types property text */
    uint32_t pad_max_connect;       /* cellPadInit's argument, 0 = closed */
    uint32_t pad_setting[PS3_PAD_PORT_MAX];
    uint8_t pad_motor[PS3_PAD_PORT_MAX][2]; /* the two vibration motors */
    int net_fd[PS3_NET_MAX];        /* host sockets behind the guest's */
    bool net_used[PS3_NET_MAX];
    uint8_t *net_pending[PS3_NET_MAX]; /* a synthesized DNS reply */
    unsigned net_pending_len[PS3_NET_MAX];
    bool net_iface_reported;

    /* The guest's PPU threads and the round-robin that runs them. */
    PS3Thread thr[PS3_THREAD_MAX];
    int thr_cur;
    bool sched_pending;
    bool sched_queued;              /* a switch is on the vCPU's work list */
    bool all_parked_reported;       /* the all-parked dump was printed */
    uint32_t hb_tick;               /* ticks towards the next heartbeat */
    uint32_t thr_slice;             /* ticks the current thread has had */
    uint64_t sched_ticks;           /* ticks since the scheduler started */
    QEMUTimer *sched_timer;
    bool threads_enabled;           /* opt in: run lv2's threads for real */
    uint32_t hid_next_handle;       /* sys_hid_manager_open's handles */
    uint8_t led_action[3];          /* green, red, blue: 0 off 1 on 2 blink */
    char led_text[24];
    PS3Lv2Module lv2_mod[PS3_LV2_MODULE_MAX];
    unsigned lv2_mod_count;
    PS3Lv2Provider *lv2_provider;
    unsigned lv2_provider_count, lv2_provider_max;
    bool lv2_provider_scanned;
    int lv2_preload_depth;
    bool lv2_known_reported[8];
    bool lv2_ref_unknown;
    bool lv2_mms_db_reported;
    PS3Lv2Export lv2_export[PS3_LV2_EXPORT_MAX];
    bool lv2_export_full;
    uint32_t lv2_stub_next;
    PS3Lv2Stub lv2_stub_record[PS3_LV2_STUB_RECORDS];
    unsigned lv2_stub_records;
    unsigned lv2_export_count;
    unsigned lv2_reloc_probe;       /* lines left for the relocation probe */
    /* The process image, scanned for the import table appldr would supply. */
    uint32_t vsh_lo, vsh_hi;

    /*
     * The AV device behind sys_uart: libavst opens the port and speaks the
     * console's AV protocol over it (see ps3_av_*).
     */
    bool av_up;
    uint8_t av_rx[PS3_AV_RX_SIZE];  /* replies and events the guest reads */
    unsigned av_rx_len;
    uint8_t av_tx[PS3_AV_TX_SIZE];  /* what the guest has sent */
    unsigned av_tx_len;
    uint16_t av_version;            /* the protocol version AV_INIT named */
    uint32_t av_event_bits;         /* the events it asked to be told about */
    uint8_t av_hdmi_mode;           /* PS3AV_HDMI_BEHAVIOR_* it set */
    bool av_hdcp_done;              /* the link authenticated once */

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
 * The words are this program, already linked, so the runtime needs no
 * assembler:
 *
 *     stwu  r1, -32(r1)
 *     stw   r0, 8(r1)        lv2's `sc` preserves every register but r3
 *     mfcr  r0
 *     stw   r0, 12(r1)
 *     stw   r12, 16(r1)
 *     lis   r12, 0
 *     ori   r12, r12, 0xF104
 *     slwi  r12, r12, 16
 *     ori   r12, r12, 0x14
 *     stw   r11, 0(r12)      publish the call to the board
 *     lis   r12, 0
 *     ori   r12, r12, 0x880
 *     lwz   r3, 0(r12)       return value
 *     lwz   r0, 4(r12)       exit flag
 *     cmpwi r0, 0
 *     bne   halt
 *     lwz   r12, 16(r1)
 *     lwz   r0, 12(r1)
 *     mtcrf 0xFF, r0
 *     lwz   r0, 8(r1)
 *     addi  r1, r1, 32
 *     rfid
 * halt:
 *     b     halt
 */
static const uint32_t ps3_lv2_shim[] = {
    0x9421FFE0, 0x90010008, 0x7C000026, 0x9001000C, 0x91810010,
    0x3D800000, 0x618CF104, 0x558C801E, 0x618C0014, 0x916C0000,
    0x3D800000, 0x618C0880, 0x806C0000, 0x800C0004, 0x2C000000,
    0x4082001C, 0x81810010, 0x8001000C, 0x7C0FF120, 0x80010008,
    0x38210020, 0x4C000024, 0x48000000,
};

static void ps3_put_be16(uint8_t *p, uint16_t v)
{
    p[0] = v >> 8;
    p[1] = v & 0xFF;
}

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
#define PS3_LV2_ESRCH   ((int32_t)0x80010005)
#define PS3_LV2_ENOENT  ((int32_t)0x80010006)
#define PS3_LV2_EPERM   ((int32_t)0x80010009)
#define PS3_LV2_EFAULT  ((int32_t)0x8001000D)
#define PS3_LV2_EISDIR  ((int32_t)0x80010012)
#define PS3_LV2_EEXIST  ((int32_t)0x80010014)
#define PS3_LV2_ENOTCONN ((int32_t)0x80010016)
#define PS3_LV2_EISCONN ((int32_t)0x80010015)
#define PS3_LV2_EAGAIN  ((int32_t)0x80010001)
#define PS3_LV2_EDEADLK ((int32_t)0x80010008)
#define PS3_LV2_EBUSY   ((int32_t)0x8001000A)
#define PS3_LV2_ETIMEDOUT ((int32_t)0x8001000B)
#define PS3_LV2_EACCES  ((int32_t)0x80010029)
/*
 * The SDK the firmware's own modules were built with: 4.93.  Services that
 * ask for it pick an interface revision from it, so it has to be a version
 * whose revisions this firmware's modules expect.
 */
#define PS3_LV2_SDK_VERSION 0x00490001
#define PS3_LV2_EIO     ((int32_t)0x8001002B)
#define PS3_LV2_ENOTDIR ((int32_t)0x8001002E)
#define PS3_LV2_ENOTMOUNTED ((int32_t)0x8001003A)
#define PS3_LV2_EBADF   ((int32_t)0x8001002A)


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

    if (status == PS3_BOOT_OK) {
        ps3_vga_printf("LV0LDR.2 CONTAINER VERIFIED: %u BYTES", s->bytes);
    } else {
        ps3_vga_printf("BOOT STOP 0x%X: %s", status, why);
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

/*
 * The recovery OS filesystem inside the flash.
 *
 * ros0 and ros1 are the console's two recovery banks, and each one holds its
 * own little filesystem: a 0x20-byte header (word 1 at 0x14 is the entry
 * count, 0x19 on the superslim), then that many 0x30-byte entries of
 * { u64 offset, u64 size, char name[32] }, with the offsets relative to the
 * bank and the files laid out in order behind the table.  Everything the flash
 * boots - lv0, lv0.2, lv1.self, lv2_kernel.self, emer_init.self - is a file in
 * it, which is why the recovery program is taken from the image and not from a
 * host path.
 */
#define PS3_ROS_BANKS 2
#define PS3_ROS_MAX_ENTRIES 0x100

/* The flash's own fields are big-endian 64-bit; ps3_be64 is defined below. */
static uint64_t ps3_ros_be64(const uint8_t *p)
{
    return ((uint64_t)ps3_be32(p) << 32) | ps3_be32(p + 4);
}

/*
 * Every file the ROS filesystem stores carries a 0x10-byte record header in
 * front of the container (the entries a carving tool writes out have it
 * stripped, which is why one dump's emer_init.self begins with "SCE\0" and a
 * flash bank's begins 16 bytes earlier).  The payload is what a loader opens.
 */
static const uint8_t *ps3_ros_payload(const uint8_t *data, size_t len,
                                      size_t *payload_len)
{
    if (len >= 4 && !memcmp(data, "SCE\0", 4)) {
        *payload_len = len;
        return data;
    }
    if (len >= 0x14 && (!memcmp(data + 0x10, "SCE\0", 4) ||
                        !memcmp(data + 0x10, "\177ELF", 4))) {
        *payload_len = len - 0x10;
        return data + 0x10;
    }
    *payload_len = len;
    return data;
}

/* A NOR image's two banks; a NAND/eMMC image names its single `ros` region in
 * the flash region table instead (0x80000 long, two 0x700000 banks inside). */
static const struct {
    const char *name;
    uint32_t offset;
} ps3_ros_nor[PS3_ROS_BANKS] = {
    { "ros0", 0x0C0000 },
    { "ros1", 0x7C0000 },
};

/* A bank's filesystem header sits at its start in a NOR carve, and 0x20 bytes
 * in when the bank is part of a NAND `ros` region (which starts with its own
 * header).  The entry count tells the two apart. */
static unsigned ps3_ros_fs_base(const uint8_t *bank, uint64_t limit)
{
    unsigned base;

    for (base = 0; base <= 0x20; base += 0x20) {
        uint32_t count;

        if ((uint64_t)base + 0x18 > limit) {
            continue;
        }
        count = ps3_be32(bank + base + 0x14);
        if (count && count <= PS3_ROS_MAX_ENTRIES) {
            return base;
        }
    }
    return 0;
}

/* The recovery banks this flash has: each one's offset, length and name. */
static int ps3_ros_banks(PS3BootROMState *s, uint64_t *off, uint64_t *limit,
                         const char **name)
{
    unsigned i;
    int n = 0;

    if (s->flash_len >= 0x210 && ps3_be32(s->flash + 0x200) == 1) {
        uint32_t count = ps3_be32(s->flash + 0x204);

        if (count && count <= 64) {
            for (i = 0; i < count; i++) {
                const uint8_t *e = s->flash + 0x210 + (uint64_t)i * 0x30;
                uint64_t at, len;
                char entry[33];

                if (0x210 + (uint64_t)(i + 1) * 0x30 > s->flash_len) {
                    break;
                }
                memcpy(entry, e + 0x10, 32);
                entry[32] = 0;
                if (strcmp(entry, "ros")) {
                    continue;
                }
                at = 0x200 + ps3_ros_be64(e);
                len = ps3_ros_be64(e + 8);
                if (at >= s->flash_len) {
                    return 0;
                }
                if (len > s->flash_len - at) {
                    len = s->flash_len - at;
                }
                while (len >= 0x700000 && n < PS3_ROS_BANKS) {
                    off[n] = at;
                    limit[n] = 0x700000;
                    name[n] = "ros";
                    at += 0x700000;
                    len -= 0x700000;
                    n++;
                }
                if (len && n < PS3_ROS_BANKS) {
                    off[n] = at;
                    limit[n] = len;
                    name[n] = "ros";
                    n++;
                }
                return n;
            }
        }
    }

    for (i = 0; i < PS3_ROS_BANKS; i++) {
        off[n] = ps3_ros_nor[i].offset;
        limit[n] = 0x700000;
        name[n] = ps3_ros_nor[i].name;
        n++;
    }
    return n;
}

/*
 * Find one file in the flash's recovery banks.  The result is a copy the caller
 * owns; the bank's own name is written to `where' so a log line says which bank
 * answered (a console boots ros0 and falls back to ros1).
 */
static bool ps3_flash_ros_read(PS3BootROMState *s, const char *name,
                               uint8_t **out, size_t *out_len,
                               char *where, size_t where_len,
                               int *bank_out)
{
    uint64_t bank_off[PS3_ROS_BANKS], bank_limit[PS3_ROS_BANKS];
    const char *bank_name[PS3_ROS_BANKS];
    unsigned bank;
    int nbanks;

    *out = NULL;
    *out_len = 0;

    if (!s->flash || s->flash_len < 0x10000) {
        snprintf(where, where_len, "no flash image");
        return false;
    }

    nbanks = ps3_ros_banks(s, bank_off, bank_limit, bank_name);

    for (bank = 0; bank < (unsigned)nbanks; bank++) {
        const uint8_t *at = s->flash + bank_off[bank];
        uint64_t limit = bank_limit[bank];
        unsigned fs = ps3_ros_fs_base(at, limit);
        uint32_t count, i;

        if ((uint64_t)fs + 0x20 > limit) {
            continue;
        }
        count = ps3_be32(at + fs + 0x14);
        if (!count || count > PS3_ROS_MAX_ENTRIES ||
            (uint64_t)fs + 0x20 + (uint64_t)count * 0x30 > limit) {
            continue;
        }

        for (i = 0; i < count; i++) {
            const uint8_t *e = at + fs + 0x20 + (uint64_t)i * 0x30;
            char entry[33];
            uint64_t off = ps3_ros_be64(e);
            uint64_t size = ps3_ros_be64(e + 8);

            memcpy(entry, e + 0x10, 32);
            entry[32] = 0;
            if (strcmp(entry, name)) {
                continue;
            }
            if (!size || fs + off > limit || size > limit - (fs + off)) {
                snprintf(where, where_len, "%s: %s runs past the flash",
                         bank_name[bank], name);
                return false;
            }
            {
                size_t pay_len;
                const uint8_t *pay = ps3_ros_payload(at + fs + off, size,
                                                     &pay_len);

                *out = g_memdup2(pay, pay_len);
                *out_len = pay_len;
            }
            snprintf(where, where_len, "%s", bank_name[bank]);
            if (bank_out) {
                *bank_out = (int)bank;
            }
            return true;
        }
    }

    snprintf(where, where_len, "not in the recovery banks");
    return false;
}

/*
 * In recovery the console's /dev_flash is the flash itself: the ROS bank it
 * booted becomes the firmware root the emergency program reads, and the disk's
 * dev_flash is not mounted at all.  The bank's files are written out once, next
 * to the HDD image, so sys_fs can serve them like any other file.
 *
 * Returns the directory, or NULL when the bank cannot be unpacked (an image
 * whose ros holds nothing is a console with no recovery program).
 */
static gchar *ps3_flash_ros_mount(PS3BootROMState *s, unsigned bank,
                                  Error **errp)
{
    g_autofree gchar *root = NULL;
    g_autofree gchar *dest = NULL;
    const char *anchor = s->hdd_file ?: s->emmc_file;
    uint64_t bank_off[PS3_ROS_BANKS], bank_limit[PS3_ROS_BANKS];
    const char *bank_name[PS3_ROS_BANKS];
    const uint8_t *at;
    uint64_t limit, base;
    unsigned fs;
    uint32_t count, i;
    int nbanks;
    bool wrote = false;

    /* Next to the disk image, or in the temporary directory for a console
     * that has no disk at all (a recovery boot off the flash alone). */
    if (anchor) {
        root = g_strconcat(anchor, ".ros", NULL);
    } else {
        root = g_build_filename(g_get_tmp_dir(), "ps3-ros", NULL);
    }
    dest = g_build_filename(root, "dev_flash", NULL);
    g_mkdir_with_parents(dest, 0755);

    nbanks = ps3_ros_banks(s, bank_off, bank_limit, bank_name);
    if (bank >= (unsigned)nbanks) {
        return NULL;
    }
    at = s->flash + bank_off[bank];
    limit = bank_limit[bank];
    base = fs = ps3_ros_fs_base(at, limit);
    if ((uint64_t)fs + 0x20 > limit) {
        return NULL;
    }
    count = ps3_be32(at + base + 0x14);
    if (!count || count > PS3_ROS_MAX_ENTRIES ||
        (uint64_t)fs + 0x20 + (uint64_t)count * 0x30 > limit) {
        return NULL;
    }
    for (i = 0; i < count; i++) {
        const uint8_t *e = at + base + 0x20 + (uint64_t)i * 0x30;
        uint64_t off = ps3_ros_be64(e);
        uint64_t size = ps3_ros_be64(e + 8);
        g_autofree char *path = NULL;
        g_autofree char *dir = NULL;
        g_autoptr(GError) err = NULL;
        char entry[33];

        memcpy(entry, e + 0x10, 32);
        entry[32] = 0;
        if (!size || base + off > limit || size > limit - (base + off)) {
            continue;
        }
        path = g_build_filename(dest, entry, NULL);
        dir = g_path_get_dirname(path);
        g_mkdir_with_parents(dir, 0755);
        {
            size_t pay_len;
            const uint8_t *pay = ps3_ros_payload(at + base + off, size,
                                                &pay_len);

            if (!g_file_set_contents(path, (const char *)pay, pay_len, &err)) {
                error_setg(errp, "ps3-boot-rom: cannot unpack %s from %s: %s",
                           entry, bank_name[bank], err->message);
                return NULL;
            }
        }
        wrote = true;
    }

    if (!wrote) {
        return NULL;
    }

    info_report("ps3-boot-rom: dev_flash is the flash's %s (unpacked to %s)",
                bank_name[bank], dest);
    return g_strdup(dest);
}

/*
 * Which container the medium's own boot ROM opens.
 *
 * A NOR console (and a chain staged on a disk) keeps lv0ldr.2 in its flash and
 * that is what the ROM finds.  A NAND console's first container is metldr.2 in
 * the asecure_loader region - the region the mask ROM is pointed at - and
 * lv0ldr.2 is what metldr opens once it runs, so a NAND/eMMC flash that carries
 * metldr.2 but no lv0ldr.2 is a healthy console, not a broken one.  The search
 * tries the configured name first and then, for such a medium, metldr.2.
 */
static bool ps3_chain_container(PS3BootROMState *s, const char **name_out,
                                uint64_t *offset, char *why, size_t why_len)
{
    static const char nand_first[] = "metldr.2";
    const char *name = s->container ?: "lv0ldr.2";
    bool nand_medium;

    *name_out = name;
    if (ps3_container_find(s->flash, s->flash_len, name, offset, why,
                           why_len)) {
        return true;
    }

    nand_medium = s->boot_medium && !strcmp(s->boot_medium, "emmc");
    if (nand_medium && strcmp(name, nand_first)) {
        char why2[160];

        if (ps3_container_find(s->flash, s->flash_len, nand_first, offset,
                               why2, sizeof(why2))) {
            info_report("ps3-boot-rom: the flash has no %s; this is a "
                        "NAND/eMMC medium, so the chain opens %s (the "
                        "asecure_loader) instead", name, nand_first);
            *name_out = nand_first;
            return true;
        }
    }

    return false;
}

/*
 * The chain's own result, before anything is allowed to run: the container is
 * in the flash, the readout opens it and its tag checks.  lv2 asks the same
 * question of the vflash filesystem before it starts /dev_flash/vsh.self.
 */
static bool ps3_chain_check(PS3BootROMState *s, char *why, size_t why_len)
{
    const char *name;
    uint64_t offset = 0;
    uint32_t blocks, result;
    uint8_t *plain, key[16];

    if (!s->flash) {
        snprintf(why, why_len, "no flash image");
        return false;
    }

    if (!ps3_chain_container(s, &name, &offset, why, why_len)) {
        return false;
    }

    if (!s->has_readout) {
        snprintf(why, why_len, "no channel-66 readout");
        return false;
    }

    blocks = ps3_be32(s->flash + offset + 0x10);
    plain = g_malloc0((size_t)blocks * 16);
    result = ps3_rom_open(s->flash + offset, s->flash + offset + PS3_CONTAINER_HDR,
                          (size_t)blocks * 16, s->readout_bytes, plain, key);
    g_free(plain);

    if (result != PS3_BOOT_OK) {
        snprintf(why, why_len, "the %s container does not verify (stop 0x%X)",
                 name, result);
        return false;
    }

    return true;
}

/*
 * Two seconds of virtual time: the wordmark, then the home screen.  A real
 * console is at its home screen about five seconds after the power button,
 * and the chain above has already spent the first ones.
 *
 * The home screen is vsh.self's own frame, not the model's: what this machine
 * shows is whatever the guest programs into the RSX's display buffer through
 * cellGcmSetDisplayBuffer and cellGcmSetFlip.  Nothing is drawn on the host
 * for it, so the screen stays on the boot text until the guest's graphics
 * library takes the scanout.
 */
#define PS3_HOME_DELAY_NS   (2 * NANOSECONDS_PER_SECOND)

static void ps3_rom_home_tick(void *opaque)
{
    (void)opaque;
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

    if (!ps3_chain_container(s, &name, &s->container_offset, why,
                             sizeof(why))) {
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

            ps3_vga_printf("SPU PAYLOAD: %" PRIu64 " INSTRUCTIONS",
                           s->spu_insns);

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

    /*
     * The chain is done, so put the console's boot screen up: the wordmark,
     * below the stage lines so both stay readable.  vsh.self's scanout takes
     * the screen over when the guest programs cellVideoOut.
     */
    if (result == PS3_BOOT_OK && s->boot_logo) {
        ps3_vga_boot_logo("RS6K", "Playstation 3 Emulator");

        /*
         * And then the home screen, the way the console comes up to it: the
         * wordmark stays up long enough to read, then the wave replaces it.
         * It is only ever drawn for a chain that verified - a console whose
         * trust chain stops has nothing to show.
         */
        if (!s->home_timer) {
            s->home_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                         ps3_rom_home_tick, s);
        }
        timer_mod(s->home_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                                 PS3_HOME_DELAY_NS);
    }
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

    {
        char why[192];

        if (ps3_spu_isa_selftest(why, sizeof(why))) {
            s->selftest_result = 2;
            info_report("ps3-boot-rom: selftest FAILED (SPU %s)", why);
            return;
        }
    }

    s->selftest_result = 1;
    info_report("ps3-boot-rom: selftest passed (AES-128 KAT, sealed container "
                "round trip, mask ROM replayed by the SPU interpreter, full "
                "SPU ISA check)");
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

    /* Power-on has no capture device open, whatever the guest left behind. */
    ps3_audio_mic_close(s->audio);
    s->mic_init = false;
    s->mic_opened = false;
    s->mic_started = false;
    s->mic_eq_key = 0;
    s->mic_eq_source = 0;
    s->mic_head = 0;
    s->mic_used = 0;

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

/*
 * The console's input side: a chardev byte waits in a small ring and the
 * guest's UART port hands it out on a read.  The ring is what a terminal or a
 * socket writes into, so the guest sees keystrokes at the console the way it
 * would on a serial line.
 */
#define PS3_UART_IN_MASK 0xFF

static int ps3_uart_can_receive(void *opaque)
{
    PS3BootROMState *s = opaque;

    return PS3_UART_IN_MASK + 1 -
           ((unsigned)(s->uart_in_head - s->uart_in_tail) & PS3_UART_IN_MASK);
}

static void ps3_uart_receive(void *opaque, const uint8_t *buf, int size)
{
    PS3BootROMState *s = opaque;

    while (size-- > 0) {
        if ((((unsigned)(s->uart_in_head - s->uart_in_tail)) & PS3_UART_IN_MASK) ==
            PS3_UART_IN_MASK) {
            return;                    /* the ring is full; drop the rest */
        }
        s->uart_in[s->uart_in_head++ & PS3_UART_IN_MASK] = *buf++;
    }
}

/* Put one console character on the chardev, if there is one. */
static void ps3_uart_chr_putc(PS3BootROMState *s, uint8_t ch)
{
    if (!s->chr_ready) {
        return;
    }
    if (ch == '\n') {
        uint8_t crlf[2] = { '\r', '\n' };

        qemu_chr_fe_write_all(&s->chr, crlf, 2);
        return;
    }
    qemu_chr_fe_write_all(&s->chr, &ch, 1);
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
    if (addr == PS3_PPE_UART_DATA) {
        if (s->uart_in_head != s->uart_in_tail) {
            return s->uart_in[s->uart_in_tail++ & PS3_UART_IN_MASK];
        }
    }
    return 0;
}

static void ps3_uart_flush(PS3BootROMState *s)
{
    if (s->uart_len) {
        s->uart_line[s->uart_len] = 0;
        info_report("ps3-ppu console: %s", s->uart_line);

        /* The guest's own output goes to the display as well as the log. */
        ps3_vga_puts(s->uart_line);
        s->uart_len = 0;
    }
}

/*
 * One console character.  lv0 polls the same port, and sys_tty_write feeds it
 * from the lv2 side, so both paths share this.
 */
static void ps3_uart_putc(PS3BootROMState *s, uint8_t ch)
{
    ps3_uart_chr_putc(s, ch);

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
 * The memory container: a bump heap above the loaded image.  Both allocate
 * calls hand out 256-byte aligned blocks from it, and free is a no-op, which
 * is all the guest's allocator needs from a container this simple.
 */
static int32_t ps3_lv2_alloc(PS3BootROMState *s, uint8_t *ram,
                             uint64_t ram_size, uint32_t size, uint32_t out)
{
    uint32_t heap = s->lv2_heap;
    uint32_t end = (heap + size + 0xFF) & ~0xFFu;

    if (!size) {
        return PS3_LV2_EINVAL;
    }
    if ((uint64_t)out + 4 > ram_size) {
        return PS3_LV2_EFAULT;
    }
    if (end < heap || (uint64_t)end + 0x100 > ram_size) {
        return PS3_LV2_ENOMEM;
    }

    ps3_put_be32(ram + out, heap);
    s->lv2_heap = end;
    ps3_put_be32(ram + PS3_LV2_HEAP, end);
    return 0;
}

static uint16_t ps3_be16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static uint64_t ps3_be64(const uint8_t *p)
{
    return ((uint64_t)ps3_be32(p) << 32) | ps3_be32(p + 4);
}

static bool ps3_lv2_guest_string(uint8_t *ram, uint64_t ram_size,
                                 uint32_t addr, char *out, size_t cap)
{
    size_t i;

    for (i = 0; i + 1 < cap; i++) {
        if ((uint64_t)addr + i >= ram_size) {
            return false;
        }
        out[i] = ram[addr + i];
        if (!out[i]) {
            return true;
        }
    }

    out[cap - 1] = 0;
    return false;
}

/*
 * The disc's filesystem.
 *
 * A console mounts the drive at /dev_bdvd and reads the media's own
 * filesystem through lv1.  The model mounts the same image itself and serves
 * its files under /dev_bdvd, so a guest path resolves to a file inside the
 * disc image - which is what the update flow reads when the file is on a
 * disc: /dev_bdvd/PS3_UPDATE/PS3UPDAT.PUP.
 *
 * The image is read as ISO 9660, the directory structure an optical image
 * carries.  The descriptors and directory records are parsed once, the first
 * time a dev_bdvd path is looked up; the tree is mirrored into a staging
 * directory beside the image as directories are asked for, and a file's own
 * bytes are copied the first time the guest resolves it.  A listing therefore
 * covers the whole disc without the model copying a disc's worth of data at
 * boot.
 *
 * Nothing is written back: the same as a pressed disc, the media is
 * read-only.
 */
#define PS3_ISO_SECTOR      2048u
#define PS3_ISO_CHUNK       (128u * 1024u)
#define PS3_ISO_DEPTH       16u
#define PS3_ISO_NAME_MAX    256u

struct PS3IsoNode {
    char name[PS3_ISO_NAME_MAX];
    bool dir;
    uint32_t lba;               /* the entry's first extent, 2048-byte */
    uint64_t size;              /* ... and its length in bytes */
    bool staged;                /* a file: the staging copy is complete */
    struct PS3IsoNode *up;
    struct PS3IsoNode **kid;
    unsigned nkids;
};

/* A little-endian 32-bit field: the image's own byte order, not the guest's. */
static uint32_t ps3_iso_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* Read `bytes' of the image from 2048-byte sector `lba'.  A read that runs
 * past the media stops there and is zero-filled, which is what a drive does at
 * the end of a disc. */
static bool ps3_iso_read(PS3BootROMState *s, uint32_t lba, uint64_t bytes,
                         uint8_t *out)
{
    uint64_t off = (uint64_t)lba * PS3_ISO_SECTOR;
    uint64_t avail;

    if (!s->disc || off >= s->disc_size) {
        return false;
    }

    avail = s->disc_size - off;
    if (bytes > avail) {
        memset(out + avail, 0, bytes - avail);
        bytes = avail;
    }

    return bytes == 0 || blk_pread(s->disc, off, bytes, out, 0) >= 0;
}

/* ISO 9660 gives a file name a ";1" version suffix and a name with no
 * extension a trailing dot; the guest asks for neither. */
static void ps3_iso_name(const uint8_t *rec, size_t len, char *out, size_t cap)
{
    size_t i, n = MIN(len, cap - 1);

    for (i = 0; i < n; i++) {
        out[i] = (char)rec[i];
    }
    out[n] = 0;

    for (i = 0; i + 1 < n; i++) {
        if (out[i] == ';' && g_ascii_isdigit(out[i + 1])) {
            out[i] = 0;
            break;
        }
    }

    n = strlen(out);
    if (n && out[n - 1] == '.') {
        out[n - 1] = 0;
    }

    /* An ISO name is upper case; the guest's paths are not necessarily. */
    for (i = 0; i < n; i++) {
        out[i] = g_ascii_toupper(out[i]);
    }
}

/*
 * One ISO 9660 directory record.  `*off' points at the record's length byte and
 * is advanced past it; a zero length byte means the rest of the sector is
 * padding and the offset is moved to the sector's end.  The extent and the
 * data length are stored twice, little- and big-endian, and the little-endian
 * copy is the one read.  The name follows a length byte at 0x20, and "." and
 * ".." (name lengths 0 and 1) are skipped: the model's directory reader
 * synthesises those itself.
 */
static bool ps3_iso_record(const uint8_t *blk, unsigned *off, PS3IsoNode *out)
{
    unsigned o = *off, len = blk[o], namelen;

    if (!len || len < 34 || o + len > PS3_ISO_SECTOR) {
        *off = PS3_ISO_SECTOR;
        return false;
    }

    namelen = blk[o + 32];
    *off = o + len;

    if (namelen == 0 || namelen == 1 || namelen > len - 33) {
        return false;               /* ".", "..", or a record that is wrong */
    }

    out->lba = ps3_iso_le32(blk + o + 2);
    out->size = ps3_iso_le32(blk + o + 10);
    out->dir = (blk[o + 25] & 2) != 0;
    out->staged = false;
    out->up = NULL;
    out->kid = NULL;
    out->nkids = 0;
    ps3_iso_name(blk + o + 33, namelen, out->name, sizeof(out->name));

    return out->name[0] != 0;
}

/* The staging path of a node: the staging directory, then its names from the
 * root down. */
static gchar *ps3_iso_staged_path(PS3BootROMState *s, PS3IsoNode *node)
{
    PS3IsoNode *chain[PS3_ISO_DEPTH + 2];
    g_autoptr(GString) path = g_string_new(s->iso_tree);
    unsigned n = 0;

    for (; node->up && n < ARRAY_SIZE(chain); node = node->up) {
        chain[n++] = node;
    }

    while (n) {
        g_string_append_c(path, G_DIR_SEPARATOR);
        g_string_append(path, chain[--n]->name);
    }

    return g_string_free(g_steal_pointer(&path), false);
}

static bool ps3_iso_load_dir(PS3BootROMState *s, PS3IsoNode *dir,
                             unsigned depth);

/*
 * One directory's records, read extent by extent.  A record's extent is where
 * its own data starts, so a directory with more records than fit in one sector
 * continues in the next: the loop follows the data length, not the records.
 */
static bool ps3_iso_load_dir(PS3BootROMState *s, PS3IsoNode *dir,
                             unsigned depth)
{
    g_autofree uint8_t *blk = g_malloc0(PS3_ISO_SECTOR);
    uint64_t left = dir->size;
    uint32_t lba = dir->lba;
    bool any = false;

    if (depth > PS3_ISO_DEPTH) {
        return true;
    }

    while (left) {
        uint64_t bytes = MIN(left, (uint64_t)PS3_ISO_SECTOR);
        unsigned off = 0;

        if (!ps3_iso_read(s, lba, bytes, blk)) {
            return false;
        }
        memset(blk + bytes, 0, PS3_ISO_SECTOR - bytes);
        left -= bytes;
        lba++;

        while (off < PS3_ISO_SECTOR) {
            g_autofree PS3IsoNode *kid = g_new0(PS3IsoNode, 1);

            if (!ps3_iso_record(blk, &off, kid)) {
                continue;           /* padding, "." or "..": nothing added */
            }

            kid->up = dir;
            dir->kid = g_renew(PS3IsoNode *, dir->kid, dir->nkids + 1);
            dir->kid[dir->nkids++] = g_steal_pointer(&kid);
            any = true;

            if (dir->kid[dir->nkids - 1]->dir) {
                if (!ps3_iso_load_dir(s, dir->kid[dir->nkids - 1],
                                      depth + 1)) {
                    return false;
                }
            } else {
                /*
                 * A staging copy from an earlier run is as good as a fresh
                 * one: the media cannot change under it, so its length is the
                 * record's length means the file is already there.
                 */
                PS3IsoNode *file = dir->kid[dir->nkids - 1];
                g_autofree gchar *path = ps3_iso_staged_path(s, file);
                GStatBuf st;

                if (g_stat(path, &st) == 0 &&
                    (uint64_t)st.st_size == file->size) {
                    file->staged = true;
                }
            }
        }
    }

    (void)any;
    return true;
}

/* Walk a path under the disc's root, one component at a time.  Matching is
 * case-insensitive: the image stores upper-case ISO names, while the guest
 * names the path the way the disc's own metadata does. */
static PS3IsoNode *ps3_iso_lookup(PS3IsoNode *root, const char *path)
{
    PS3IsoNode *node = root;

    while (node && path && *path) {
        const char *slash;
        PS3IsoNode *next = NULL;
        size_t len;
        unsigned i;

        while (*path == '/') {
            path++;
        }
        if (!*path) {
            break;
        }

        slash = strchr(path, '/');
        len = slash ? (size_t)(slash - path) : strlen(path);

        for (i = 0; i < node->nkids; i++) {
            if (strlen(node->kid[i]->name) == len &&
                !g_ascii_strncasecmp(node->kid[i]->name, path, len)) {
                next = node->kid[i];
                break;
            }
        }

        node = next;
        path = slash ? slash + 1 : path + len;
    }

    return node;
}

/*
 * Materialise one directory in the staging tree: the directory itself, and one
 * placeholder per child - a subdirectory of its own, or an empty file of the
 * entry's length.  The placeholders are what makes a listing complete; a
 * file's bytes arrive the first time the guest resolves it.
 */
static bool ps3_iso_stage_dir(PS3BootROMState *s, PS3IsoNode *dir)
{
    g_autofree gchar *host = ps3_iso_staged_path(s, dir);
    unsigned i;

    if (dir->staged) {
        return true;
    }
    dir->staged = true;

    if (g_mkdir_with_parents(host, 0755) < 0) {
        dir->staged = false;
        return false;
    }

    for (i = 0; i < dir->nkids; i++) {
        PS3IsoNode *kid = dir->kid[i];
        g_autofree gchar *path = ps3_iso_staged_path(s, kid);
        int fd;

        if (kid->dir) {
            if (!ps3_iso_stage_dir(s, kid)) {
                return false;
            }
            continue;
        }

        fd = g_open(path, O_WRONLY | O_CREAT | O_BINARY, 0644);
        if (fd < 0 || ftruncate(fd, kid->size) < 0) {
            if (fd >= 0) {
                close(fd);
            }
            return false;
        }
        close(fd);
    }

    return true;
}

/* Copy one file out of the image, once, on the first look-up that needs it. */
static bool ps3_iso_extract(PS3BootROMState *s, PS3IsoNode *file)
{
    g_autofree gchar *host = ps3_iso_staged_path(s, file);
    g_autofree gchar *tmp = g_strconcat(host, ".part", NULL);
    g_autofree uint8_t *buf = g_malloc(PS3_ISO_CHUNK);
    uint64_t left = file->size;
    uint32_t lba = file->lba;
    FILE *out;

    if (file->staged) {
        return true;
    }

    out = fopen(tmp, "wb");
    if (!out) {
        return false;
    }

    while (left) {
        uint64_t bytes = MIN(left, (uint64_t)PS3_ISO_CHUNK);
        uint64_t sectors = (bytes + PS3_ISO_SECTOR - 1) / PS3_ISO_SECTOR;

        if (!ps3_iso_read(s, lba, sectors * PS3_ISO_SECTOR, buf) ||
            fwrite(buf, 1, bytes, out) != bytes) {
            fclose(out);
            g_unlink(tmp);
            return false;
        }

        left -= bytes;
        lba += sectors;
    }

    fclose(out);

    if (g_rename(tmp, host) < 0) {
        g_unlink(tmp);
        return false;
    }

    file->staged = true;
    return true;
}

/* Count the tree, for the line the model prints when the disc is mounted. */
static void ps3_iso_count(const PS3IsoNode *node, uint64_t *dirs,
                          uint64_t *files, uint64_t *bytes)
{
    unsigned i;

    for (i = 0; i < node->nkids; i++) {
        const PS3IsoNode *kid = node->kid[i];

        if (kid->dir) {
            (*dirs)++;
            ps3_iso_count(kid, dirs, files, bytes);
        } else {
            (*files)++;
            *bytes += kid->size;
        }
    }
}

/*
 * Parse the descriptor set once: sector 16 onwards holds volume descriptors,
 * each identified by "CD001" at 0x01 and its own type at 0x00, and the set
 * ends at the terminator (type 255).  Type 1 is the primary descriptor, whose
 * root directory record at 0x9C names the extent the whole tree hangs from.
 * The guest's /dev_bdvd is the staging tree that mirrors it.
 */
static bool ps3_iso_setup(PS3BootROMState *s)
{
    g_autofree uint8_t *vd = g_malloc(PS3_ISO_SECTOR);
    uint64_t dirs = 0, files = 0, bytes = 0;
    const uint8_t *root = NULL;
    PS3IsoNode *pup;
    unsigned i;

    if (s->iso_parsed) {
        return s->iso_root != NULL;
    }
    s->iso_parsed = true;

    if (!s->disc || !s->disc_file || !s->disc_size) {
        return false;               /* an empty drawer, not a broken disc */
    }

    for (i = 16; i < 64; i++) {
        if (!ps3_iso_read(s, i, PS3_ISO_SECTOR, vd) ||
            memcmp(vd + 1, "CD001", 5)) {
            break;
        }
        if (vd[0] == 255) {
            break;                  /* the descriptor set ends here */
        }
        if (vd[0] == 1) {
            root = vd + 0x9C;
            break;
        }
    }

    if (!root) {
        info_report("ps3-bdvd: %s carries no ISO 9660 primary descriptor, so "
                    "the disc is not mounted as dev_bdvd", s->disc_file);
        return false;
    }

    s->iso_tree = g_strconcat(s->disc_file, ".bdvd", NULL);
    s->iso_root = g_new0(PS3IsoNode, 1);
    s->iso_root->dir = true;
    s->iso_root->lba = ps3_iso_le32(root + 2);
    s->iso_root->size = ps3_iso_le32(root + 10);

    if (!ps3_iso_load_dir(s, s->iso_root, 0)) {
        info_report("ps3-bdvd: %s: the directory tree could not be read",
                    s->disc_file);
        return false;
    }

    ps3_iso_count(s->iso_root, &dirs, &files, &bytes);
    info_report("ps3-bdvd: %s: ISO 9660, %" PRIu64 " director%s and %" PRIu64
                " file(s), %" PRIu64 " MiB; mounted as dev_bdvd",
                s->disc_file, dirs, dirs == 1 ? "y" : "ies", files,
                bytes / MiB);

    /* The file the recovery and update flows read, named at boot so the run
     * says whether the disc can carry the update. */
    pup = ps3_iso_lookup(s->iso_root, "PS3_UPDATE/PS3UPDAT.PUP");
    if (pup && !pup->dir) {
        info_report("ps3-bdvd: /PS3_UPDATE/PS3UPDAT.PUP is on the disc, "
                    "%" PRIu64 " bytes; the guest reads it as "
                    "dev_bdvd/PS3_UPDATE/PS3UPDAT.PUP", pup->size);
    } else {
        info_report("ps3-bdvd: the disc carries no "
                    "/PS3_UPDATE/PS3UPDAT.PUP");
    }

    return true;
}

/* `/dev_bdvd[/...]' as a host path: the entry's copy in the staging tree. */
static gchar *ps3_lv2_bdvd_path(PS3BootROMState *s, const char *rest)
{
    PS3IsoNode *node;

    if (!ps3_iso_setup(s)) {
        return NULL;
    }

    node = ps3_iso_lookup(s->iso_root, rest);
    if (!node) {
        return NULL;
    }

    if (node->dir) {
        if (!ps3_iso_stage_dir(s, node)) {
            info_report("ps3-bdvd: %s could not be staged beside %s",
                        node->name, s->disc_file);
            return NULL;
        }
    } else {
        /*
         * The file's directory is staged first: it is what makes a listing of
         * that directory complete, and the placeholder it writes for this file
         * is what the copy below replaces.
         */
        if ((node->up && !ps3_iso_stage_dir(s, node->up)) ||
            !ps3_iso_extract(s, node)) {
            info_report("ps3-bdvd: %s could not be staged beside %s",
                        node->name, s->disc_file);
            return NULL;
        }
    }

    return ps3_iso_staged_path(s, node);
}

/*
 * Map a guest path onto the firmware tree the machine was given.  lv2 and the
 * VSH name modules as /dev_flash/... or /dev_flash3/...; the roots are the
 * directories the machine maps those devices to.
 */
static gchar *ps3_lv2_host_path(PS3BootROMState *s, const char *guest)
{
    const char *root;
    const char *rest;

    if (!strncmp(guest, "/dev_bdvd", 9) &&
        (guest[9] == 0 || guest[9] == '/')) {
        return ps3_lv2_bdvd_path(s, guest + 9);
    }

    if (!strcmp(guest, "/dev_flash")) {
        root = s->dev_flash;
        rest = "";
    } else if (!strcmp(guest, "/dev_flash2")) {
        root = s->dev_flash2;
        rest = "";
    } else if (!strcmp(guest, "/dev_flash3")) {
        root = s->dev_flash3;
        rest = "";
    } else if (!strncmp(guest, "/dev_flash/", 11)) {
        root = s->dev_flash;
        rest = guest + 11;
    } else if (!strncmp(guest, "/dev_flash2/", 12)) {
        root = s->dev_flash2;
        rest = guest + 12;
    } else if (!strncmp(guest, "/dev_flash3/", 12)) {
        root = s->dev_flash3;
        rest = guest + 12;
    } else if (!strncmp(guest, "/dev_hdd0/", 10)) {
        root = s->hdd_dir;
        rest = guest + 10;
    } else if (!strcmp(guest, "/dev_hdd0")) {
        root = s->hdd_dir;
        rest = "";
    } else if (!strncmp(guest, "/dev_hdd1/", 10)) {
        root = s->hdd1_dir;
        rest = guest + 10;
    } else if (!strcmp(guest, "/dev_hdd1")) {
        root = s->hdd1_dir;
        rest = "";
    } else if (!strncmp(guest, "/dev_usb000/", 12)) {
        root = s->usb_dir;
        rest = guest + 12;
    } else if (!strcmp(guest, "/dev_usb000")) {
        root = s->usb_dir;
        rest = "";
    } else {
        root = s->dev_flash;
        rest = guest[0] == '/' ? guest + 1 : guest;
    }

    if (!root) {
        return NULL;
    }

    return g_build_filename(root, rest, NULL);
}

/*
 * A SELF keeps each program segment in a metadata section that says where the
 * stored bytes are and how they are packed; the ELF's p_offset describes the
 * expanded image instead, so a loader that follows it reads the wrong block.
 */
static bool ps3_lv2_self_section(const uint8_t *img, gsize len,
                                 unsigned index, const uint8_t **data,
                                 uint64_t *stored, uint32_t *compression)
{
    uint64_t meta = ps3_be32(img + 0x0C);
    uint64_t header = ps3_be64(img + 0x10);
    uint32_t count;
    unsigned i;

    if (meta + 0xA0 > header || header > len) {
        return false;
    }

    count = ps3_be32(img + meta + 0x60 + 0x0C);
    if (count > 0x40) {
        return false;
    }

    for (i = 0; i < count; i++) {
        const uint8_t *e = img + meta + 0x80 + 0x30 * (size_t)i;
        uint64_t offset = ps3_be64(e);

        if (ps3_be32(e + 0x10) != 2 || ps3_be32(e + 0x14) != index) {
            continue;
        }

        *stored = ps3_be64(e + 8);
        if (offset > len || *stored > len - offset) {
            return false;
        }
        *data = img + offset;
        *compression = ps3_be32(e + 0x2C);
        return true;
    }

    return false;
}

/*
 * A relocation lands on an instruction's immediate field or on a data word, so
 * a patch that finds something else there is worth saying out loud: it is
 * either the record's target or the reader's arithmetic, and the guest is
 * about to execute whatever the patch left behind.  These are the field forms
 * lv2's records name - the `addi'/`addis', `ori'/`oris', `xori'/`xoris' and
 * `andi.'/`andis.' immediates, the DS forms, and the relative branches that
 * carry the REL24 and REL14 records.
 */
static bool ps3_lv2_reloc_field_insn(uint32_t word)
{
    switch (word >> 26) {
    case 14: case 15:               /* addi, addis    */
    case 24: case 25:               /* ori, oris      */
    case 26: case 27:               /* xori, xoris    */
    case 28: case 29:               /* andi., andis.  */
    case 58: case 62:               /* ld, std (DS)   */
    case 16: case 18:               /* bc, b (rel)    */
        return true;
    default:
        return false;
    }
}

/*
 * The Cell compiler ends an lv2 wrapper with `extsw r3, r3', and a module that
 * carries one with a byte out of place carries a word the guest will execute
 * and fault on.  The scan says when it appeared: before the relocation table
 * runs, the image arrived that way; after it, a record patched the wrong
 * place.  Only the trace asks for it.
 */
static void ps3_lv2_scan_extsw(PS3BootROMState *s, const uint8_t *ram,
                               uint64_t ram_size, const char *guest,
                               const char *when, uint64_t base,
                               const uint32_t *vaddr, const uint32_t *memsz,
                               unsigned loads)
{
    unsigned i, hits = 0;

    if (!s->ppu_trace) {
        return;
    }

    for (i = 0; i < loads; i++) {
        uint64_t at, end = base + vaddr[i] + memsz[i];

        for (at = base + vaddr[i]; at + 4 <= end && at + 4 <= ram_size;
             at += 4) {
            uint32_t w = ps3_be32(ram + at);

            if ((w & 0xFFFFFF00u) != 0x7C630700u || (w & 0xFFu) == 0xB4) {
                continue;
            }
            if (hits++ < 8) {
                info_report("ps3-ppu: prx: %s: %s: 0x%" PRIX64
                            " holds 0x%08X", guest, when, at, w);
            }
        }
    }

    if (hits) {
        info_report("ps3-ppu: prx: %s: %s: %u word(s) reading `extsw r3, "
                    "r3' with a byte out of place", guest, when, hits);
    }
}

/*
 * Apply one PRX relocation record.  lv2's record is not an Elf64_Rela: it
 * names two segments by index, the target inside the first and the value
 * inside the second, so the addend is an address in the module's own image.
 */
static bool ps3_lv2_reloc_one(uint8_t *ram, uint64_t ram_size, uint64_t target,
                              uint64_t value, uint32_t type)
{
    uint32_t insn;

    if (target + 8 > ram_size) {
        return false;
    }

    switch (type) {
    case 1:                     /* R_PPC64_ADDR32 */
        ps3_put_be32(ram + target, (uint32_t)value);
        break;
    case 4:                     /* R_PPC64_ADDR16_LO */
        ram[target] = value >> 8;
        ram[target + 1] = value;
        break;
    case 5:                     /* R_PPC64_ADDR16_HI */
        ram[target] = value >> 24;
        ram[target + 1] = value >> 16;
        break;
    case 6:                     /* R_PPC64_ADDR16_HA */
        value = (value >> 16) + ((value & 0x8000) ? 1 : 0);
        ram[target] = value >> 8;
        ram[target + 1] = value;
        break;
    case 10:                    /* R_PPC64_REL24 */
        insn = ps3_be32(ram + target);
        insn = (insn & 0xFC000003) |
               (((uint32_t)(value - target) >> 2) & 0x03FFFFFC);
        ps3_put_be32(ram + target, insn);
        break;
    case 11:                    /* R_PPC64_REL14 */
        insn = ps3_be32(ram + target);
        insn = (insn & 0xFFFF0003) |
               (((uint32_t)(value - target) >> 2) & 0x0000FFFC);
        ps3_put_be32(ram + target, insn);
        break;
    case 38:                    /* R_PPC64_ADDR64 */
        ps3_put_be32(ram + target, (uint32_t)(value >> 32));
        ps3_put_be32(ram + target + 4, (uint32_t)value);
        break;
    case 44:                    /* R_PPC64_REL64 */
        value -= target;
        ps3_put_be32(ram + target, (uint32_t)(value >> 32));
        ps3_put_be32(ram + target + 4, (uint32_t)value);
        break;
    case 57:                    /* R_PPC64_ADDR16_LO_DS */
        ram[target] = value >> 10;
        ram[target + 1] = value >> 2;
        break;
    default:
        return false;
    }

    return true;
}

/*
 * The PRX library header sits at the first byte of a module's first segment.
 * It names the module and points at the two tables lv2 walks: the libraries it
 * exports (`.lib.ent`) and the ones it imports (`.lib.stub`).  The PRX
 * relocation table covers these pointers too, so after relocation they are
 * guest addresses and can be read straight out of RAM.
 */
#define PS3_PRX_LIB_ATTRIBUTE  0x0001   /* the entry names a library */
#define PS3_PRX_LIB_STUB       0x0008   /* the entry is an imported library */
#define PS3_PRX_LIB_MANAGEMENT 0x8000   /* the entry holds the module hooks */
#define PS3_PRX_START_NID      0xBC9A0086u
#define PS3_PRX_STOP_NID       0xAB779874u
#define PS3_PRX_PROLOGUE_NID   0x0D10FD3Fu

/* One export/import table entry; `size` is zero when it is the full 0x2C. */
#define PS3_PRX_ENTRY_MIN      0x1C
#define PS3_PRX_ENTRY_FULL     0x2C

typedef struct PS3PrxEntry {
    uint32_t size;                 /* stride to the next entry */
    uint16_t version;
    uint16_t attributes;
    uint16_t num_func;
    uint16_t num_var;
    uint32_t name;                 /* char[28] */
    uint32_t nids;                 /* u32[num_func + num_var] */
    uint32_t addrs;                /* exports: OPDs, imports: slots */
    uint32_t vnids;
    uint32_t vstubs;
} PS3PrxEntry;

static void ps3_put_be64(uint8_t *p, uint64_t v)
{
    ps3_put_be32(p, (uint32_t)(v >> 32));
    ps3_put_be32(p + 4, (uint32_t)v);
}

static PS3Lv2Module *ps3_lv2_module(PS3BootROMState *s, uint32_t id)
{
    for (unsigned i = 0; i < s->lv2_mod_count; i++) {
        if (s->lv2_mod[i].id && s->lv2_mod[i].id == id) {
            return &s->lv2_mod[i];
        }
    }

    return NULL;
}

/* A guest path's module, so a library is never loaded twice. */
static PS3Lv2Module *ps3_lv2_module_by_path(PS3BootROMState *s,
                                            const char *path)
{
    for (unsigned i = 0; i < s->lv2_mod_count; i++) {
        if (s->lv2_mod[i].id && !strcmp(s->lv2_mod[i].path, path)) {
            return &s->lv2_mod[i];
        }
    }

    return NULL;
}

static bool ps3_prx_entry(const uint8_t *ram, uint64_t ram_size, uint32_t addr,
                          uint32_t end, PS3PrxEntry *e)
{
    const uint8_t *p;

    if ((uint64_t)addr + PS3_PRX_ENTRY_MIN > end ||
        (uint64_t)addr + PS3_PRX_ENTRY_MIN > ram_size) {
        return false;
    }

    p = ram + addr;
    e->size = p[0] ? p[0] : PS3_PRX_ENTRY_FULL;
    e->version = ps3_be16(p + 2);
    e->attributes = ps3_be16(p + 4);
    e->num_func = ps3_be16(p + 6);
    e->num_var = ps3_be16(p + 8);
    e->name = ps3_be32(p + 0x10);
    e->nids = ps3_be32(p + 0x14);
    e->addrs = ps3_be32(p + 0x18);
    e->vnids = ps3_be32(p + 0x1C);
    e->vstubs = ps3_be32(p + 0x20);

    return e->size >= PS3_PRX_ENTRY_MIN;
}

/* Do `count' words at `addr' stay inside RAM? */
static bool ps3_prx_array(uint64_t ram_size, uint32_t addr, unsigned count)
{
    return (uint64_t)addr + 4ull * count <= ram_size;
}

/*
 * `owner' is the module slot this export belongs to, plus one, and zero for
 * the process's own exports.  Storing the value as given matters: the unload
 * path drops the exports of slot `i' by matching `i + 1', and an offset added
 * here would have made the process's exports (the VSH's `vsh', `allocator',
 * `sdk' and `stdc' libraries) look like they belonged to slot zero - the first
 * module the VSH unloads would then take every one of them with it.
 */
static void ps3_lv2_add_export(PS3BootROMState *s, const char *lib,
                               uint32_t nid, uint32_t opd, unsigned owner)
{
    PS3Lv2Export *e;

    if (s->lv2_export_count == PS3_LV2_EXPORT_MAX) {
        if (!s->lv2_export_full) {
            s->lv2_export_full = true;
            info_report("ps3-ppu: lv2: export table full at %d, later "
                        "libraries will not link", PS3_LV2_EXPORT_MAX);
        }
        return;
    }

    e = &s->lv2_export[s->lv2_export_count++];
    g_strlcpy(e->lib, lib, sizeof(e->lib));
    e->nid = nid;
    e->opd = opd;
    e->owner = owner;
}

/*
 * Is this import slot still waiting for lv2?  A slot holds the address of the
 * OPD the caller loads {code, toc} from.  It is pending when that OPD is
 * missing, empty, or still carries the linker's placeholder.
 */
static bool ps3_lv2_slot_pending(const uint8_t *ram, uint64_t ram_size,
                                 uint32_t slot)
{
    uint32_t opd, code;

    if ((uint64_t)slot + 4 > ram_size) {
        return false;
    }

    opd = ps3_be32(ram + slot);
    if (!opd || (uint64_t)opd + 8 > ram_size) {
        return true;
    }

    code = ps3_be32(ram + opd);
    return !code || code == PS3_PRX_STUB_PLACEHOLDER;
}

/*
 * A stub for an import lv2 cannot resolve.  It is an OPD whose code is a
 * six-word trampoline: the NID goes in r12, the "missing import" call number
 * in r11, and the trap returns -1, which is what an unimplemented lv2 service
 * answers with.  The run continues and the work list says what was missing.
 */
static const char *ps3_video_out_name(uint32_t nid);
static const char *ps3_cellmic_name(uint32_t nid);

static uint32_t ps3_lv2_stub(PS3BootROMState *s, uint8_t *ram,
                             uint64_t ram_size, const char *lib,
                             uint32_t nid)
{
    uint32_t at = s->lv2_stub_next;
    uint8_t *code;

    if (!at) {
        at = PS3_LV2_STUB_BASE;
    }

    /*
     * The same import in twenty modules is the same function: one trampoline
     * answers all of them.  Sharing keeps the records table (which is what
     * names a missing NID) from overflowing on a boot that loads the whole
     * VSH module set, and keeps the stub page for the ones that differ.
     */
    for (unsigned i = 0; i < s->lv2_stub_records; i++) {
        if (s->lv2_stub_record[i].nid == nid &&
            !strcmp(s->lv2_stub_record[i].lib, lib)) {
            return s->lv2_stub_record[i].at;
        }
    }

    if ((uint64_t)at + PS3_LV2_STUB_STRIDE > PS3_LV2_STUB_END ||
        (uint64_t)at + PS3_LV2_STUB_STRIDE > ram_size) {
        return 0;
    }

    s->lv2_stub_next = at + PS3_LV2_STUB_STRIDE;
    memset(ram + at, 0, PS3_LV2_STUB_STRIDE);

    if (ps3_video_out_name(nid)) {
        info_report("ps3-ppu: %s imports %s:0x%08X (the AV handler "
                    "answers it)", lib, ps3_video_out_name(nid), nid);
    }
    if (ps3_cellmic_name(nid)) {
        info_report("ps3-ppu: %s imports %s:0x%08X (the microphone handler "
                    "answers it)", lib, ps3_cellmic_name(nid), nid);
    }

    if (s->lv2_stub_records < PS3_LV2_STUB_RECORDS) {
        PS3Lv2Stub *rec = &s->lv2_stub_record[s->lv2_stub_records++];

        g_strlcpy(rec->lib, lib, sizeof(rec->lib));
        rec->nid = nid;
        rec->at = at;
    }

    code = ram + at + 8;
    ps3_put_be32(ram + at, at + 8);                    /* OPD: code     */
    ps3_put_be32(ram + at + 4, 0);                     /* OPD: toc      */
    ps3_put_be32(code + 0x00, 0x3D800000u | (nid >> 16));
    ps3_put_be32(code + 0x04, 0x618C0000u | (nid & 0xFFFF));
    /*
     * The NID goes to a fixed scratch cell, not a register: the syscall
     * trampoline keeps the GPRs for the call's arguments and would otherwise
     * hand back its own r12.
     */
    /*
     * stw r12, PS3_LV2_STUB_NID(0): RS is r12, rA=0 means the displacement is
     * absolute.  0x90000000 would be stw r0, which stores whatever the caller
     * happened to leave in r0 - the module's own return address, in practice.
     */
    ps3_put_be32(code + 0x08, 0x91800000u | PS3_LV2_STUB_NID);
    ps3_put_be32(code + 0x0C, 0x39600000u | PS3_LV2_MISSING_CALL);
    ps3_put_be32(code + 0x10, 0x44000002u);            /* sc            */
    ps3_put_be32(code + 0x14, 0x4E800020u);            /* blr           */

    return at;
}

static const PS3Lv2Stub *ps3_lv2_stub_lookup_nid(const PS3BootROMState *s,
                                               uint32_t nid)
{
    unsigned i;

    for (i = 0; i < s->lv2_stub_records; i++) {
        if (s->lv2_stub_record[i].nid == nid) {
            return &s->lv2_stub_record[i];
        }
    }

    return NULL;
}

static uint32_t ps3_lv2_find_export(PS3BootROMState *s, const char *lib,
                                    uint32_t nid)
{
    for (unsigned i = 0; i < s->lv2_export_count; i++) {
        if (s->lv2_export[i].nid == nid &&
            !strcmp(s->lv2_export[i].lib, lib)) {
            return s->lv2_export[i].opd;
        }
    }

    return 0;
}

/*
 * Walk a module's export table and record every published NID.  The
 * management entry is not a library: it carries the module's own start, stop
 * and prologue hooks, which `_sys_prx_start_module` hands back to the caller so
 * it can run them.
 */
static void ps3_lv2_register_exports(PS3BootROMState *s, uint8_t *ram,
                                     uint64_t ram_size, PS3Lv2Module *m,
                                     uint32_t start, uint32_t end)
{
    uint32_t addr;
    unsigned added = 0;

    if (!start || end <= start || end > ram_size) {
        return;
    }

    for (addr = start; addr + PS3_PRX_ENTRY_MIN <= end; ) {
        PS3PrxEntry e;
        char lib[28];

        if (!ps3_prx_entry(ram, ram_size, addr, end, &e) ||
            !ps3_lv2_guest_string(ram, ram_size, e.name, lib, sizeof(lib)) ||
            !ps3_prx_array(ram_size, e.nids,
                            e.num_func + e.num_var) ||
            !ps3_prx_array(ram_size, e.addrs,
                            e.num_func + e.num_var)) {
            break;
        }

        if (e.attributes & PS3_PRX_LIB_ATTRIBUTE) {
            /*
             * A library exports functions and variables in one table; the
             * variable entries' addresses are the variables themselves, not
             * OPDs, and an importer's slot receives them the same way.
             */
            for (unsigned i = 0; i < e.num_func + e.num_var; i++) {
                ps3_lv2_add_export(s, lib, ps3_be32(ram + e.nids + 4 * i),
                                   ps3_be32(ram + e.addrs + 4 * i),
                                   (unsigned)(m - s->lv2_mod) + 1);
                added++;
            }

            info_report("ps3-ppu: prx: %s: exports %s (v%u.%u, %u symbol(s))",
                        m->path, lib, e.version >> 8, e.version & 0xFF,
                        e.num_func + e.num_var);
        } else if (e.attributes & PS3_PRX_LIB_MANAGEMENT) {
            for (unsigned i = 0; i < e.num_func + e.num_var; i++) {
                uint32_t nid = ps3_be32(ram + e.nids + 4 * i);
                uint32_t opd = ps3_be32(ram + e.addrs + 4 * i);

                if (nid == PS3_PRX_START_NID) {
                    m->start_opd = opd;
                } else if (nid == PS3_PRX_STOP_NID) {
                    m->stop_opd = opd;
                } else if (nid == PS3_PRX_PROLOGUE_NID) {
                    m->prologue_opd = opd;
                }
            }
        } else if (!(e.attributes & PS3_PRX_LIB_STUB)) {
            info_report("ps3-ppu: prx: %s: entry 0x%X has attributes 0x%X",
                        m->path, addr, e.attributes);
        }

        addr += e.size;
    }

    m->exports_start = start;
    m->exports_end = end;

    info_report("ps3-ppu: prx: %s: %u export(s) registered, start 0x%X "
                "stop 0x%X prologue 0x%X", m->path, added, m->start_opd,
                m->stop_opd, m->prologue_opd);
}

static int32_t ps3_lv2_prx_load_path(PS3BootROMState *s, uint8_t *ram,
                                     uint64_t ram_size, const char *guest);
static bool ps3_lv2_prx_preload(PS3BootROMState *s, uint8_t *ram,
                                uint64_t ram_size, const char *lib);

/*
 * Reference-style imports.
 *
 * A library whose attribute word has 0x2000 set does not call its imports
 * through the stub slots alone: for each function the entry carries a list of
 * places in the module's own text that hold that function's address, as
 * {type, address, addend} records terminated by a zero type.  lv2 patches
 * each one the way a relocation would - the whole 32-bit word for type 1, the
 * low or high half for 4 and 6, the 14-bit branch displacement for 57 - and a
 * module whose lists are left alone runs with `lis r9, 0` where the address
 * should be, which is a jump to null several calls later.
 */
static void ps3_lv2_patch_refs(PS3BootROMState *s, uint8_t *ram,
                               uint64_t ram_size, uint32_t fref, uint32_t addr)
{
    unsigned n;

    for (n = 0; n < 4096; n++, fref += 12) {
        uint32_t type, at, rdata;

        if ((uint64_t)fref + 12 > ram_size) {
            return;
        }
        type = ps3_be32(ram + fref);
        if (!type) {
            return;
        }
        at = ps3_be32(ram + fref + 4);
        rdata = addr + ps3_be32(ram + fref + 8);
        if ((uint64_t)at + 4 > ram_size) {
            continue;
        }

        switch (type) {
        case 1:
            ps3_put_be32(ram + at, rdata);
            break;
        case 4:
            ps3_put_be16(ram + at, rdata & 0xFFFF);
            break;
        case 6:
            ps3_put_be16(ram + at, (rdata >> 16) + ((rdata & 0x8000) ? 1 : 0));
            break;
        case 57:
            ps3_put_be16(ram + at, (rdata & 0xFFFC) >> 2);
            break;
        default:
            if (!s->lv2_ref_unknown) {
                s->lv2_ref_unknown = true;
                info_report("ps3-ppu: prx: reference type %u is not handled "
                            "(at 0x%X)", type, at);
            }
            break;
        }
    }
}

/*
 * Resolve a module's import table against what is registered so far.  An
 * import entry is a library name, a NID array and an array of 4-byte slots;
 * lv2 writes the exported OPD's address into each slot, and the module's stub
 * code loads the OPD from there and branches through it.
 */
static unsigned ps3_lv2_link_imports(PS3BootROMState *s, uint8_t *ram,
                                     uint64_t ram_size, PS3Lv2Module *m,
                                     uint32_t start, uint32_t end)
{    uint32_t addr;
    unsigned total = 0, linked = 0, stubbed = 0;

    if (!start || end <= start || end > ram_size) {
        return 0;
    }

    for (addr = start; addr + PS3_PRX_ENTRY_MIN <= end; ) {
        PS3PrxEntry e;
        char lib[28];
        unsigned got = 0, missed = 0;

        if (!ps3_prx_entry(ram, ram_size, addr, end, &e) ||
            !ps3_lv2_guest_string(ram, ram_size, e.name, lib, sizeof(lib)) ||
            !ps3_prx_array(ram_size, e.nids,
                            e.num_func + e.num_var) ||
            !ps3_prx_array(ram_size, e.addrs,
                            e.num_func + e.num_var)) {
            break;
        }

        /*
         * Nothing publishes this library yet.  The console's flash carries
         * every module the VSH links against, so the one that publishes this
         * name is opened and loaded first: that is the dependency order the
         * real lv2's load would have enforced before the caller ran at all.
         */
        if (e.num_func &&
            !ps3_lv2_find_export(s, lib, ps3_be32(ram + e.nids))) {
            ps3_lv2_prx_preload(s, ram, ram_size, lib);
        }

        /*
         * Function imports are nids[]/addrs[].  Variable imports are their
         * own arrays (vnids[]/vstubs[]) and are not OPDs, so they are left to
         * the module's own references rather than filled here; reading them
         * out of the function arrays would patch memory past both tables.
         */
        for (unsigned i = 0; i < e.num_func; i++) {
            uint32_t slot = e.addrs + 4 * i;
            uint32_t nid = ps3_be32(ram + e.nids + 4 * i);
            uint32_t opd = ps3_lv2_find_export(s, lib, nid);

            total++;

            if (!opd) {
                /*
                 * Leave the module's own stub alone when it already runs
                 * real code: that is its syscall thunk, and the shim answers
                 * the trap.  Only a placeholder needs lv2 to fill it in.
                 */
                if (!ps3_lv2_slot_pending(ram, ram_size, slot) ||
                    !(opd = ps3_lv2_stub(s, ram, ram_size, lib, nid))) {
                    continue;
                }
                missed++;
                stubbed++;
            }

            ps3_put_be32(ram + slot, opd);

            /*
             * The 0x2000 attribute means the entry also carries one
             * reference list per function, right after the NID array.
             */
            if (e.attributes & 0x2000) {
                uint32_t fref = ps3_be32(ram + e.nids +
                                         4 * (e.num_func + i));

                if (fref) {
                    ps3_lv2_patch_refs(s, ram, ram_size, fref, opd);
                }
            }
            got++;
            linked += missed ? 0 : 1;
        }

        if (got) {
            info_report("ps3-ppu: prx: %s: linked %u/%u import(s) from %s%s",
                        m->path, got, e.num_func, lib,
                        missed ? " (placeholder stubs)" : "");
        }
        if (missed) {
            info_report("ps3-ppu: prx: %s: %u import(s) from %s have no "
                        "provider yet; they trap to the model",
                        m->path, missed, lib);
        }

        addr += e.size;
    }

    m->imports_start = start;
    m->imports_end = end;

    if (total && !linked) {
        info_report("ps3-ppu: prx: %s: %u import(s) unresolved, %u stubbed",
                    m->path, total, stubbed);
    }

    return linked;
}

/*
 * A new module's exports can satisfy imports that another module (or the
 * process) asked for earlier, so every known import table is walked again.
 * lv2 does the same: modules are linked in both directions as they appear.
 */
static void ps3_lv2_relink_all(PS3BootROMState *s, uint8_t *ram,
                               uint64_t ram_size)
{
    for (unsigned i = 0; i < s->lv2_mod_count; i++) {
        PS3Lv2Module *m = &s->lv2_mod[i];

        if (m->imports_end > m->imports_start) {
            ps3_lv2_link_imports(s, ram, ram_size, m, m->imports_start,
                                 m->imports_end);
        }
    }
}

/*
 * The process's own import table.
 *
 * lv2 learns it from the SceProcessParam that appldr builds, and this model
 * starts after appldr, so the table is recovered from the image instead: an
 * imported library entry is the one that carries the stub flag, names a
 * library and points at a slot array.  Only libraries a loaded module actually
 * exports are patched, so a stray match elsewhere in the image cannot do any
 * damage.
 */
/* A library name is a short run of letters, digits and underscores. */
static bool ps3_lv2_library_name(const uint8_t *ram, uint64_t ram_size,
                                 uint32_t addr, char *out, size_t cap)
{
    size_t n;

    if (!ps3_lv2_guest_string((uint8_t *)ram, ram_size, addr, out, cap)) {
        return false;
    }

    n = strlen(out);
    if (n < 2 || n > 27 || (!g_ascii_isalpha(out[0]) && out[0] != '_')) {
        return false;
    }

    for (size_t i = 0; i < n; i++) {
        if (!g_ascii_isalnum(out[i]) && out[i] != '_') {
            return false;
        }
    }

    return true;
}

/* One table entry plus its library name, with everything bounds-checked. */
static bool ps3_lv2_entry(const uint8_t *ram, uint64_t ram_size, uint32_t addr,
                          uint32_t end, PS3PrxEntry *e, char *lib, size_t cap)
{
    if (!ps3_prx_entry(ram, ram_size, addr, end, e) ||
        (e->size != PS3_PRX_ENTRY_MIN && e->size != PS3_PRX_ENTRY_FULL) ||
        !e->num_func || e->num_func > 1200 ||
        !ps3_prx_array(ram_size, e->nids, e->num_func + e->num_var) ||
        !ps3_prx_array(ram_size, e->addrs, e->num_func + e->num_var)) {
        return false;
    }

    return ps3_lv2_library_name(ram, ram_size, e->name, lib, cap);
}

/* Tables come in runs; a lone struct in the middle of data is a coincidence. */
static bool ps3_lv2_entry_chained(const uint8_t *ram, uint64_t ram_size,
                                  uint32_t addr, uint32_t end,
                                  const PS3PrxEntry *e)
{
    PS3PrxEntry next;
    char lib[28];

    if (ps3_lv2_entry(ram, ram_size, addr + e->size, end, &next, lib,
                      sizeof(lib))) {
        return true;
    }

    return addr >= e->size &&
           ps3_lv2_entry(ram, ram_size, addr - e->size, end, &next, lib,
                         sizeof(lib));
}

/* Does `opd' look like a function descriptor inside [lo, hi)? */
static bool ps3_lv2_opd_ok(const uint8_t *ram, uint64_t ram_size, uint32_t opd,
                           uint32_t lo, uint32_t hi)
{
    uint32_t code;

    if ((uint64_t)opd + 8 > ram_size) {
        return false;
    }

    code = ps3_be32(ram + opd);
    return code >= lo && code < hi;
}

/*
 * The process's own exports: what the executable publishes for the modules it
 * loads (the VSH exports `sysPrxForUser`, `vsh`, `stdc` and so on).  appldr
 * registers these for lv2; this model recovers them from the image, and the
 * OPD check keeps the scan honest - an export entry lists function
 * descriptors, an import entry lists pointers to stubs.
 */
static unsigned ps3_lv2_register_process_exports(PS3BootROMState *s,
                                                 uint8_t *ram,
                                                 uint64_t ram_size)
{
    uint32_t addr;
    unsigned added = 0;

    if (!s->vsh_lo || s->vsh_hi <= s->vsh_lo) {
        return 0;
    }

    for (addr = s->vsh_lo; addr + PS3_PRX_ENTRY_MIN <= s->vsh_hi; addr += 4) {
        PS3PrxEntry e;
        char lib[28];

        if (!ps3_lv2_entry(ram, ram_size, addr, s->vsh_hi, &e, lib,
                           sizeof(lib)) ||
            !ps3_lv2_entry_chained(ram, ram_size, addr, s->vsh_hi, &e) ||
            !(e.attributes & PS3_PRX_LIB_ATTRIBUTE) ||
            (e.attributes & PS3_PRX_LIB_STUB) ||
            !ps3_lv2_opd_ok(ram, ram_size, ps3_be32(ram + e.addrs),
                            s->vsh_lo, s->vsh_hi)) {
            continue;
        }

        for (unsigned i = 0; i < e.num_func; i++) {
            uint32_t opd = ps3_be32(ram + e.addrs + 4 * i);

            if (!ps3_lv2_opd_ok(ram, ram_size, opd, s->vsh_lo, s->vsh_hi)) {
                continue;
            }
            ps3_lv2_add_export(s, lib, ps3_be32(ram + e.nids + 4 * i), opd,
                               0);
            added++;
        }

        info_report("ps3-ppu: lv2: process exports %s (%u function(s))",
                    lib, e.num_func);
    }

    return added;
}

/*
 * The process's imports: one slot per imported function, holding the address
 * of the OPD whose {code, toc} pair the caller's thunk loads.  A link rewrites
 * the slot, which is what lv2 does - the stub itself is left alone, so a slot
 * that still points at an unresolved stub OPD is recognisable by that stub's
 * placeholder code word.
 */
static unsigned ps3_lv2_link_process(PS3BootROMState *s, uint8_t *ram,
                                     uint64_t ram_size)
{
    uint32_t addr;
    unsigned linked = 0, missing = 0, stubbed = 0, entries = 0;

    if (!s->vsh_lo || s->vsh_hi <= s->vsh_lo) {
        return 0;
    }

    for (addr = s->vsh_lo; addr + PS3_PRX_ENTRY_MIN <= s->vsh_hi; addr += 4) {
        PS3PrxEntry e;
        char lib[28];

        if (!ps3_lv2_entry(ram, ram_size, addr, s->vsh_hi, &e, lib,
                           sizeof(lib)) ||
            !ps3_lv2_entry_chained(ram, ram_size, addr, s->vsh_hi, &e) ||
            !(e.attributes & PS3_PRX_LIB_STUB) ||
            !(e.attributes & PS3_PRX_LIB_ATTRIBUTE)) {
            continue;
        }

        entries++;
        for (unsigned i = 0; i < e.num_func; i++) {
            uint32_t slot = e.addrs + 4 * i;
            uint32_t nid = ps3_be32(ram + e.nids + 4 * i);
            uint32_t opd = ps3_lv2_find_export(s, lib, nid);

            if (!opd) {
                missing++;
                /* Same rule as a module's imports: keep a working stub. */
                if (!ps3_lv2_slot_pending(ram, ram_size, slot) ||
                    !(opd = ps3_lv2_stub(s, ram, ram_size, lib, nid))) {
                    continue;
                }
                stubbed++;
            }

            if (ps3_be32(ram + slot) != opd) {
                ps3_put_be32(ram + slot, opd);
            }
            if (!stubbed || opd < PS3_LV2_STUB_BASE) {
                linked++;
            }
        }
    }

    if (entries) {
        info_report("ps3-ppu: lv2: process imports: %u of %u function(s) "
                    "linked over %u librar%s, %u trapped",
                    linked, linked + missing, entries,
                    entries == 1 ? "y" : "ies", stubbed);
    }

    return linked;
}

/*
 * lv2's module loader, as far as the VSH needs it: open the SELF with the
 * application keyset, expand the stored sections, place the PT_LOAD segments
 * in a module region, run the PRX relocation table against that region, and
 * then link the module's exports and imports the way lv2 does.  The load is
 * the contract the caller sees: a relocated image and a module id.
 */
static int32_t ps3_lv2_prx_load_path(PS3BootROMState *s, uint8_t *ram,
                                     uint64_t ram_size, const char *guest)
{
    g_autofree gchar *host = NULL;
    g_autofree gchar *img = NULL;
    gsize len = 0;
    GError *err = NULL;
    const uint8_t *elf;
    uint64_t elf_off = 0;
    bool is_self;
    uint64_t phoff, span = 0, base, mod_size, heap;
    unsigned phentsize, phnum, loads = 0, i;
    uint32_t load_vaddr[8], load_memsz[8];
    uint32_t entry = 0, relocations = 0;
    int64_t lib_hdr_off = 0;      /* PRX library header, from segment 0 */
    char why[160];

    host = ps3_lv2_host_path(s, guest);
    if (!host) {
        info_report("ps3-ppu: prx: %s: no firmware root is set", guest);
        return PS3_LV2_ENOENT;
    }

    if (!g_file_get_contents(host, &img, &len, &err)) {
        info_report("ps3-ppu: prx: %s: cannot read (%s)", guest,
                    err ? err->message : "unknown");
        g_clear_error(&err);
        return PS3_LV2_ENOENT;
    }

    is_self = len >= 0x40 && !memcmp(img, "SCE\0", 4);
    if (is_self) {
        if (!ps3_self_decrypt_app((uint8_t *)img, len, why, sizeof(why))) {
            info_report("ps3-ppu: prx: %s: %s", guest, why);
            return PS3_LV2_EINVAL;
        }

        /*
         * The decrypted container, before lv2 places it: the only way to see
         * a module's own text and tables as its linker left them, which is
         * what a fault in a module's own code has to be read against.
         */
        if (s->prx_dump && *s->prx_dump) {
            g_autofree gchar *name = g_path_get_basename(host);
            g_autofree gchar *out = g_build_filename(s->prx_dump, name, NULL);

            g_file_set_contents(out, img, len, NULL);
        }

        for (i = 0x20; i + 0x40 < MIN(len, (gsize)0x400); i += 4) {
            if (!memcmp(img + i, "\177ELF", 4)) {
                elf_off = i;
                break;
            }
        }
        if (!elf_off) {
            info_report("ps3-ppu: prx: %s: no ELF header inside the SELF",
                        guest);
            return PS3_LV2_EINVAL;
        }
    }

    if (elf_off + 0x40 > len || memcmp(img + elf_off, "\177ELF", 4) ||
        img[elf_off + 4] != 2 || img[elf_off + 5] != 2) {
        info_report("ps3-ppu: prx: %s: not a 64-bit big-endian ELF", guest);
        return PS3_LV2_EINVAL;
    }

    elf = (const uint8_t *)img + elf_off;
    entry = (uint32_t)ps3_be64(elf + 0x18);
    phoff = ps3_be64(elf + 0x20);
    phentsize = ps3_be16(elf + 0x36);
    phnum = ps3_be16(elf + 0x38);

    if (phentsize != 0x38 || !phnum || phnum > 16 ||
        elf_off + phoff + (uint64_t)phnum * phentsize > len) {
        info_report("ps3-ppu: prx: %s: program headers do not fit", guest);
        return PS3_LV2_EINVAL;
    }

    for (i = 0; i < phnum; i++) {
        const uint8_t *ph = elf + phoff + (uint64_t)i * phentsize;

        if (ps3_be32(ph) != 1) {
            continue;
        }
        if (loads == ARRAY_SIZE(load_vaddr) ||
            ps3_be64(ph + 0x28) > ram_size) {
            info_report("ps3-ppu: prx: %s: too many segments", guest);
            return PS3_LV2_EINVAL;
        }
        load_vaddr[loads] = ps3_be64(ph + 0x10);
        load_memsz[loads] = ps3_be64(ph + 0x28);
        span = MAX(span, (uint64_t)load_vaddr[loads] + load_memsz[loads]);
        if (!loads) {
            /*
             * The library header is not part of any segment's stored bytes:
             * lv2 finds it at `p_paddr - p_offset' inside the first segment,
             * which is where the certified file put it.
             */
            lib_hdr_off = (int64_t)ps3_be64(ph + 0x18) -
                          (int64_t)ps3_be64(ph + 0x08);
        }
        loads++;
    }

    if (!loads) {
        info_report("ps3-ppu: prx: %s carries no loadable segment", guest);
        return PS3_LV2_EINVAL;
    }

    /* The module gets its own 64 KiB-aligned block above the heap. */
    mod_size = (span + 0xFFFF) & ~(uint64_t)0xFFFF;
    heap = s->lv2_heap;
    base = (heap + 0xFFFF) & ~(uint64_t)0xFFFF;
    if (!base || base + mod_size > ram_size ||
        base + mod_size > 0xFFFFFFFFull) {
        info_report("ps3-ppu: prx: %s: no room for 0x%" PRIX64 " bytes",
                    guest, mod_size);
        return PS3_LV2_ENOMEM;
    }

    memset(ram + base, 0, mod_size);
    s->lv2_heap = (uint32_t)(base + mod_size);
    ps3_put_be32(ram + PS3_LV2_HEAP, s->lv2_heap);

    for (i = 0; i < phnum; i++) {
        const uint8_t *ph = elf + phoff + (uint64_t)i * phentsize;
        uint64_t vaddr = ps3_be64(ph + 0x10);
        uint64_t filesz = ps3_be64(ph + 0x20);
        uint64_t memsz = ps3_be64(ph + 0x28);
        const uint8_t *src = NULL;
        uint64_t stored = 0;
        uint32_t compression = 1;

        if (ps3_be32(ph) != 1) {
            continue;
        }

        if (is_self) {
            if (!ps3_lv2_self_section((const uint8_t *)img, len, i, &src,
                                      &stored, &compression)) {
                info_report("ps3-ppu: prx: %s: no stored section for "
                            "segment %u", guest, i);
                return PS3_LV2_EINVAL;
            }
        } else {
            uint64_t off = ps3_be64(ph + 0x08);

            if (off > len || filesz > len - off) {
                info_report("ps3-ppu: prx: %s: segment %u runs past the "
                            "file", guest, i);
                return PS3_LV2_EINVAL;
            }
            src = (const uint8_t *)img + off;
            stored = filesz;
        }

        if (!filesz || filesz > memsz) {
            info_report("ps3-ppu: prx: %s: segment %u sizes look wrong",
                        guest, i);
            return PS3_LV2_EINVAL;
        }

        if (compression == 2) {
            uLongf out = filesz;
            int rc = uncompress(ram + base + vaddr, &out, src, stored);

            if (rc != Z_OK || out != filesz) {
                info_report("ps3-ppu: prx: %s: segment %u does not expand "
                            "(zlib %d, 0x%" PRIX64 " of 0x%" PRIX64 ")",
                            guest, i, rc, (uint64_t)out, filesz);
                return PS3_LV2_EINVAL;
            }
        } else {
            memcpy(ram + base + vaddr, src, MIN(stored, filesz));
        }

        if (memsz > filesz) {
            memset(ram + base + vaddr + filesz, 0, memsz - filesz);
        }

        info_report("ps3-ppu: prx: %s: segment %u: vaddr 0x%" PRIX64
                    " paddr 0x%" PRIX64 " off 0x%" PRIX64
                    " memsz 0x%" PRIX64 " -> RAM 0x%" PRIX64, guest, i,
                    vaddr, ps3_be64(ph + 0x18), ps3_be64(ph + 0x08),
                    memsz, base + vaddr);
    }

    ps3_lv2_scan_extsw(s, ram, ram_size, guest, "as loaded", base,
                       load_vaddr, load_memsz, loads);

    /* Relocations: the PT_SCE_PPURELA table, in lv2's own record format. */
    for (i = 0; i < phnum; i++) {
        const uint8_t *ph = elf + phoff + (uint64_t)i * phentsize;
        uint64_t filesz = ps3_be64(ph + 0x20);
        const uint8_t *src = NULL;
        uint64_t stored = 0;
        uint32_t compression = 1;
        g_autofree uint8_t *rela = NULL;
        const uint8_t *table;
        uint64_t offset;

        if (ps3_be32(ph) != 0x700000A4) {
            continue;
        }

        if (is_self) {
            if (!ps3_lv2_self_section((const uint8_t *)img, len, i, &src,
                                      &stored, &compression)) {
                info_report("ps3-ppu: prx: %s: no relocation section", guest);
                return PS3_LV2_EINVAL;
            }
        } else {
            uint64_t off = ps3_be64(ph + 0x08);

            if (off > len || filesz > len - off) {
                return PS3_LV2_EINVAL;
            }
            src = (const uint8_t *)img + off;
            stored = filesz;
        }

        table = src;
        if (compression == 2) {
            uLongf out = filesz;
            int rc;

            rela = g_malloc(filesz ? filesz : 1);
            rc = uncompress(rela, &out, src, stored);
            if (rc != Z_OK || out != filesz) {
                info_report("ps3-ppu: prx: %s: relocation table does not "
                            "expand (zlib %d)", guest, rc);
                return PS3_LV2_EINVAL;
            }
            table = rela;
        }

        for (offset = 0; offset + 24 <= filesz; offset += 24) {
            uint64_t target_off = ps3_be64(table + offset);
            unsigned index_value = table[offset + 10];
            unsigned index_addr = table[offset + 11];
            uint32_t type = ps3_be32(table + offset + 12);
            uint64_t ptr = ps3_be64(table + offset + 16);
            uint64_t target, value;

            if (index_addr >= loads ||
                (index_value != 0xFF && index_value >= loads)) {
                info_report("ps3-ppu: prx: %s: relocation %" PRIu64
                            " names segment %u/%u", guest,
                            offset / 24, index_value, index_addr);
                return PS3_LV2_EINVAL;
            }

            target = base + load_vaddr[index_addr] + target_off;
            if (target_off >= load_memsz[index_addr]) {
                info_report("ps3-ppu: prx: %s: relocation %" PRIu64
                            " runs past its segment", guest, offset / 24);
                return PS3_LV2_EINVAL;
            }

            value = (index_value == 0xFF ? 0 : base + load_vaddr[index_value]) + ptr;
            if (s->ppu_trace && s->lv2_reloc_probe < 24) {
                uint64_t word = target & ~(uint64_t)3;
                uint32_t before = word + 4 <= ram_size ?
                                  ps3_be32(ram + word) : 0;

                if (!ps3_lv2_reloc_field_insn(before)) {
                    s->lv2_reloc_probe++;
                    info_report("ps3-ppu: prx: %s: relocation %" PRIu64
                                " type %u at 0x%" PRIX64 " finds 0x%08X "
                                "(not a field word), value 0x%" PRIX64,
                                guest, offset / 24, type, target, before,
                                value);
                }
            }
            if (!ps3_lv2_reloc_one(ram, ram_size, target, value, type)) {
                info_report("ps3-ppu: prx: %s: relocation type %u is not "
                            "handled", guest, type);
                return PS3_LV2_EINVAL;
            }
            relocations++;
        }
    }

    ps3_lv2_scan_extsw(s, ram, ram_size, guest, "after relocation", base,
                       load_vaddr, load_memsz, loads);

    if (s->lv2_mod_count == PS3_LV2_MODULE_MAX) {
        info_report("ps3-ppu: prx: %s: module table is full", guest);
        return PS3_LV2_ENOMEM;
    }

    {
        PS3Lv2Module *m = &s->lv2_mod[s->lv2_mod_count++];
        uint32_t hdr = (uint32_t)(base + load_vaddr[0] + lib_hdr_off);
        uint32_t exports_start = 0, exports_end = 0;
        uint32_t imports_start = 0, imports_end = 0;

        m->id = ++s->lv2_next_id;
        m->base = (uint32_t)base;
        m->size = (uint32_t)mod_size;
        m->entry = entry;
        m->segments = loads;
        m->started = false;
        g_strlcpy(m->path, guest, sizeof(m->path));

        /*
         * The PRX library header.  A module that has none is still a valid
         * load - it just exports and imports nothing - so a header that does
         * not look like one is only reported, not refused.
         */
        if (hdr + 0x34 <= ram_size) {
            uint32_t n = hdr + 4;

            m->attributes = ps3_be16(ram + hdr);
            m->version[0] = ram[hdr + 2];
            m->version[1] = ram[hdr + 3];

            for (i = 0; i < sizeof(m->name) - 1 && ram[n + i]; i++) {
                m->name[i] = ram[n + i];
            }
            m->name[i] = 0;

            exports_start = ps3_be32(ram + hdr + 0x24);
            exports_end   = ps3_be32(ram + hdr + 0x28);
            imports_start = ps3_be32(ram + hdr + 0x2C);
            imports_end   = ps3_be32(ram + hdr + 0x30);

            info_report("ps3-ppu: prx: %s: library '%s' v%u.%u, attributes "
                        "0x%X, exports 0x%X..0x%X, imports 0x%X..0x%X",
                        guest, m->name, m->version[0], m->version[1],
                        m->attributes, exports_start, exports_end,
                        imports_start, imports_end);

            ps3_lv2_register_exports(s, ram, ram_size, m, exports_start,
                                     exports_end);
        }

        info_report("ps3-ppu: prx: %s: module %u at 0x%X (0x%X bytes, "
                    "%u segment(s), %u relocation(s))",
                    guest, m->id, m->base, m->size, loads, relocations);

        /* The new exports first, then this module's own imports. */
        ps3_lv2_relink_all(s, ram, ram_size);
        ps3_lv2_link_imports(s, ram, ram_size, m, imports_start, imports_end);
        ps3_lv2_link_process(s, ram, ram_size);

        return (int32_t)m->id;
    }
}

static int32_t ps3_lv2_prx_load(PS3BootROMState *s, uint8_t *ram,
                                uint64_t ram_size, uint32_t path_addr)
{
    char guest[PS3_LV2_MODULE_PATH];

    if (!ps3_lv2_guest_string(ram, ram_size, path_addr, guest,
                              sizeof(guest))) {
        return PS3_LV2_EFAULT;
    }

    return ps3_lv2_prx_load_path(s, ram, ram_size, guest);
}

/*
 * The module directory as a table of what it can supply.
 *
 * A module's library header sits at `p_paddr - p_offset' inside its first
 * segment and names every library the module publishes, so reading it answers
 * "who exports this?" without placing or relocating anything.  The whole
 * directory is read once, on the first import that has no provider, and the
 * answers are kept: a boot with many missing libraries pays for one pass.
 */
static uint8_t *ps3_lv2_prx_first_segment(const uint8_t *img, gsize len,
                                          uint64_t *seg_len, int64_t *hdr_off)
{
    const uint8_t *elf = NULL;
    uint64_t elf_off = 0, seg_off = 0, seg_filesz = 0, seg_memsz = 0;
    uint32_t meta, sections;
    uint64_t header_len;
    unsigned phentsize, phnum, i;
    uint8_t *out;
    gsize at;

    for (at = 0x20; at + 4 <= MIN(len, (gsize)0x400); at += 4) {
        if (!memcmp(img + at, "\177ELF", 4)) {
            elf_off = at;
            break;
        }
    }
    if (!elf_off) {
        return NULL;
    }
    elf = img + elf_off;

    *hdr_off = 0;
    *seg_len = 0;
    if (elf_off + 0x40 > len) {
        return NULL;
    }

    phentsize = ps3_be16(elf + 0x36);
    phnum = ps3_be16(elf + 0x38);
    if (phentsize != 0x38 || !phnum || phnum > 16 ||
        elf_off + ps3_be64(elf + 0x20) + (uint64_t)phnum * phentsize > len) {
        return NULL;
    }

    meta = ps3_be32((const uint8_t *)img + 0x0C);
    header_len = ps3_be64((const uint8_t *)img + 0x10);
    sections = meta && (uint64_t)meta + 0x6C + 4 <= len ?
               ps3_be32((const uint8_t *)img + meta + 0x6C) : 0;

    for (i = 0; i < phnum; i++) {
        const uint8_t *ph = elf + ps3_be64(elf + 0x20) + (uint64_t)i * phentsize;

        if (ps3_be32(ph) != 1) {
            continue;
        }
        seg_off = ps3_be64(ph + 0x08);
        seg_filesz = ps3_be64(ph + 0x20);
        seg_memsz = ps3_be64(ph + 0x28);
        *hdr_off = (int64_t)ps3_be64(ph + 0x18) - (int64_t)seg_off;
        break;
    }
    if (!seg_filesz || seg_filesz > 64 * 1024 * 1024) {
        return NULL;
    }

    for (unsigned s = 0; s < sections; s++) {
        uint64_t e = (uint64_t)meta + 0x80 + 0x30 * s;
        uint64_t stored_off, stored_len;
        uint32_t compression;

        if (e + 0x30 > len || ps3_be32((const uint8_t *)img + e + 0x10) != 2 ||
            ps3_be32((const uint8_t *)img + e + 0x14) != 0) {
            continue;
        }
        stored_off = ps3_be64((const uint8_t *)img + e);
        stored_len = ps3_be64((const uint8_t *)img + e + 8);
        compression = ps3_be32((const uint8_t *)img + e + 0x2C);
        if (stored_off > len || stored_len > len - stored_off) {
            return NULL;
        }
        if (compression == 2) {
            uLongf out_len = seg_filesz;

            out = g_malloc(seg_filesz);
            if (uncompress(out, &out_len, img + stored_off, stored_len) !=
                Z_OK || out_len != seg_filesz) {
                g_free(out);
                return NULL;
            }
            *seg_len = seg_filesz;
            return out;
        }
        break;
    }

    if (header_len + seg_off + seg_filesz > len) {
        return NULL;
    }
    out = g_memdup2(img + header_len + seg_off, seg_filesz);
    *seg_len = seg_filesz;
    return out;
}

static void ps3_lv2_provider_add(PS3BootROMState *s, const char *lib,
                                 const char *path)
{
    for (unsigned i = 0; i < s->lv2_provider_count; i++) {
        if (!strcmp(s->lv2_provider[i].lib, lib)) {
            return;             /* the first module that names it wins */
        }
    }
    if (s->lv2_provider_count == s->lv2_provider_max) {
        unsigned grow = s->lv2_provider_max ? s->lv2_provider_max * 2 : 64;

        s->lv2_provider = g_renew(PS3Lv2Provider, s->lv2_provider, grow);
        s->lv2_provider_max = grow;
    }

    g_strlcpy(s->lv2_provider[s->lv2_provider_count].lib, lib,
              sizeof(s->lv2_provider[0].lib));
    g_strlcpy(s->lv2_provider[s->lv2_provider_count].path, path,
              sizeof(s->lv2_provider[0].path));
    s->lv2_provider_count++;
}

/* Every library the container at `path' publishes, into the table. */
static void ps3_lv2_provider_read(PS3BootROMState *s, const char *path,
                                  const uint8_t *img, gsize len)
{
    g_autofree uint8_t *seg = NULL;
    uint64_t seg_len = 0;
    int64_t hdr_off = 0;
    uint32_t hdr, at, end;

    seg = ps3_lv2_prx_first_segment(img, len, &seg_len, &hdr_off);
    if (!seg || hdr_off < 0 || (uint64_t)hdr_off + 0x34 > seg_len) {
        return;
    }
    hdr = (uint32_t)hdr_off;
    at = ps3_be32(seg + hdr + 0x24);
    end = ps3_be32(seg + hdr + 0x28);

    while ((uint64_t)at + PS3_PRX_ENTRY_MIN <= end &&
           (uint64_t)at + PS3_PRX_ENTRY_MIN <= seg_len) {
        unsigned size = seg[at] ? seg[at] : PS3_PRX_ENTRY_FULL;
        uint16_t attributes = ps3_be16(seg + at + 4);
        uint32_t name = ps3_be32(seg + at + 0x10);

        if ((attributes & PS3_PRX_LIB_ATTRIBUTE) && name) {
            char lib[28];

            if (ps3_lv2_library_name(seg, seg_len, name, lib, sizeof(lib))) {
                ps3_lv2_provider_add(s, lib, path);
            }
        }

        if (size < PS3_PRX_ENTRY_MIN) {
            break;
        }
        at += size;
    }
}

static void ps3_lv2_provider_scan(PS3BootROMState *s)
{
    g_autofree gchar *dir = NULL;
    GDir *d;
    const char *entry;
    unsigned files = 0;

    s->lv2_provider_scanned = true;
    if (!s->dev_flash) {
        return;
    }
    dir = g_build_filename(s->dev_flash, "vsh", "module", NULL);
    d = g_dir_open(dir, 0, NULL);
    if (!d) {
        return;
    }

    while ((entry = g_dir_read_name(d))) {
        g_autofree gchar *host = NULL;
        g_autofree gchar *img = NULL;
        gsize len = 0;
        char guest[PS3_LV2_MODULE_PATH];
        char why[160];

        if (!g_str_has_suffix(entry, ".sprx")) {
            continue;
        }
        host = g_build_filename(dir, entry, NULL);
        if (!g_file_get_contents(host, (gchar **)&img, &len, NULL)) {
            continue;
        }
        if (len < 0x40 || memcmp(img, "SCE\0", 4) ||
            !ps3_self_decrypt_app((uint8_t *)img, len, why, sizeof(why))) {
            continue;
        }
        g_snprintf(guest, sizeof(guest), "/dev_flash/vsh/module/%s", entry);
        ps3_lv2_provider_read(s, guest, (const uint8_t *)img, len);
        files++;
    }
    g_dir_close(d);

    info_report("ps3-ppu: prx: %u module(s) in %s publish %u librar%s lv2 can "
                "load on demand", files, dir, s->lv2_provider_count,
                s->lv2_provider_count == 1 ? "y" : "ies");
    if (s->ppu_trace) {
        g_autoptr(GString) names = g_string_new(NULL);

        for (unsigned i = 0; i < s->lv2_provider_count; i++) {
            g_string_append_printf(names, "%s%s", i ? " " : "",
                                   s->lv2_provider[i].lib);
        }
        info_report("ps3-ppu: prx: on demand: %s", names->str);
    }
}

static const char *ps3_lv2_provider_for(PS3BootROMState *s, const char *lib)
{
    if (!s->lv2_provider_scanned) {
        ps3_lv2_provider_scan(s);
    }

    for (unsigned i = 0; i < s->lv2_provider_count; i++) {
        if (!strcmp(s->lv2_provider[i].lib, lib)) {
            return s->lv2_provider[i].path;
        }
    }

    return NULL;
}

/*
 * Load the module that publishes `lib' before the module importing it, the way
 * lv2's own load would have refused the caller until its libraries were there.
 * The nesting is bounded: a library whose provider needs the library it is
 * being loaded for is a cycle the flash does not have, and six levels is more
 * than the VSH's deepest chain.
 */
static bool ps3_lv2_prx_preload(PS3BootROMState *s, uint8_t *ram,
                                uint64_t ram_size, const char *lib)
{
    const char *path;
    int32_t id;

    if (s->lv2_preload_depth >= 6) {
        return false;
    }
    path = ps3_lv2_provider_for(s, lib);
    if (!path || ps3_lv2_module_by_path(s, path)) {
        return false;
    }

    info_report("ps3-ppu: prx: %s is published by %s; loading it before the "
                "module that imports it", lib, path);
    s->lv2_preload_depth++;
    id = ps3_lv2_prx_load_path(s, ram, ram_size, path);
    s->lv2_preload_depth--;

    return id > 0;
}

/* ---------------------------------------------------------------------- */
/*
 * The console's gamepad ports.
 *
 * There is no USB stack under this model.  The seven ports libpad numbers are
 * described directly, and each one is told which product the guest should find
 * in it (property `pad-types`).  The products, their class ids, class profiles
 * and capability masks are the ones RPCS3 uses, so libpad classifies a guitar
 * as a guitar and a drum kit as a drum kit instead of calling every port a
 * DualShock 3.
 *
 * A port's data is a CellPadData: a big-endian length in bytes followed by 64
 * big-endian 16-bit words.  The word numbers used here are libpad's own
 * (CELL_PAD_BTN_OFFSET_*): 2 and 3 are the digital button words, 4..7 the two
 * sticks, 8..19 the pressure values, 20..23 the motion sensors and 24 upwards
 * the controls a peripheral adds on top of them.
 */
#define PS3_PAD_CONNECT_MAX         127
#define PS3_PAD_DATA_SIZE           (4 + 64 * 2)
#define PS3_PAD_INFO_SIZE           (12 + 127 * 2 + 127 * 2 + 127)
#define PS3_PAD_INFO2_SIZE          (12 + 4 * PS3_PAD_PORT_MAX * 4)
#define PS3_PAD_PERIPH_INFO_SIZE    (12 + 6 * PS3_PAD_PORT_MAX * 4)
#define PS3_PAD_PERIPH_DATA_SIZE    (8 + PS3_PAD_DATA_SIZE)
#define PS3_PAD_CAPABILITY_SIZE     (32 * 4)

#define PS3_PAD_STATUS_CONNECTED    0x1
#define PS3_PAD_SETTING_PRESS_ON    0x2
#define PS3_PAD_SETTING_SENSOR_ON   0x4

#define PS3_PAD_CAP_CONFORMITY      0x01
#define PS3_PAD_CAP_PRESS_MODE      0x02
#define PS3_PAD_CAP_SENSOR_MODE     0x04
#define PS3_PAD_CAP_HP_STICK        0x08
#define PS3_PAD_CAP_ACTUATOR        0x10
#define PS3_PAD_CAP_STANDARD        0x1F    /* all of a DualShock 3's */

/* libpad's errors, the ones these services answer with. */
#define PS3_PAD_E_INVALID_PARAMETER   ((int32_t)0x80121102u)
#define PS3_PAD_E_ALREADY_INITIALIZED ((int32_t)0x80121103u)
#define PS3_PAD_E_UNINITIALIZED       ((int32_t)0x80121104u)
#define PS3_PAD_E_NO_DEVICE           ((int32_t)0x80121107u)
#define PS3_PAD_E_UNSUPPORTED_GAMEPAD ((int32_t)0x80121108u)
#define PS3_PAD_E_TOO_MANY_DEVICES    ((int32_t)0x80121109u)

/* libpad's data word numbers, and the peripheral ones this model reports. */
enum {
    PS3_PAD_W_DIGITAL1 = 2,
    PS3_PAD_W_DIGITAL2 = 3,
    PS3_PAD_W_ANALOG_RX = 4,
    PS3_PAD_W_ANALOG_RY = 5,
    PS3_PAD_W_ANALOG_LX = 6,
    PS3_PAD_W_ANALOG_LY = 7,
    PS3_PAD_W_SENSOR_X = 20,
    PS3_PAD_W_DJ_DECK1_PLATTER = 30,
    PS3_PAD_W_GUITAR_WHAMMY = 31,
    PS3_PAD_W_DJ_DECK2_PLATTER = 34,
    PS3_PAD_W_GUITAR_5WAY = 37,
};

typedef struct PS3PadProduct {
    const char *name;
    uint16_t vendor;
    uint16_t product;
    uint32_t pclass;                /* CELL_PAD_PCLASS_TYPE_* */
    uint32_t profile;               /* CELL_PAD_PCLASS_PROFILE_* */
    uint32_t capability;            /* CELL_PAD_CAPABILITY_* */
} PS3PadProduct;

/*
 * One entry per product libpad knows a class profile for.  The vendor and
 * product ids are the ones the peripherals report over USB; the class profile
 * says which of the peripheral's controls the device has.
 */
static const PS3PadProduct ps3_pad_products[] = {
    /* name          vid     pid    class   profile     capabilities */
    { "standard",   0x054C, 0x0268, 0x0000, 0x00000000, PS3_PAD_CAP_STANDARD },
    { "guitar",     0x12BA, 0x0100, 0x0001, 0x000000FF, PS3_PAD_CAP_STANDARD },
    { "guitar-rb",  0x12BA, 0x0200, 0x0001, 0x00007FFF, PS3_PAD_CAP_STANDARD },
    { "drums",      0x12BA, 0x0120, 0x0002, 0x000000BB, PS3_PAD_CAP_STANDARD },
    { "drums-rb",   0x12BA, 0x0210, 0x0002, 0x000000FF, PS3_PAD_CAP_STANDARD },
    { "drums-rb3",  0x12BA, 0x0218, 0x0002, 0x000000BF, PS3_PAD_CAP_STANDARD },
    { "drums-rr",   0x12BA, 0x0300, 0x0002, 0x000000FB, PS3_PAD_CAP_STANDARD },
    { "dj",         0x12BA, 0x0140, 0x0003, 0x000007FF, PS3_PAD_CAP_STANDARD },
    { "dancemat",   0x1CCF, 0x1010, 0x0004, 0x000000FF, PS3_PAD_CAP_STANDARD },
    { "navigation", 0x054C, 0x042F, 0x0005, 0x00000000, PS3_PAD_CAP_STANDARD },
    /* The Move motion controller: its own product id and HID class. */
    { "move",       0x054C, 0x03D5, 0x0006, 0x00000000, PS3_PAD_CAP_STANDARD },
    /*
     * The DualSense (and the Edge, which shares the id).  It is a PS5 pad, so
     * libpad has no class for it; its inputs are the standard pad's, which is
     * what a PS3 game sees when one is plugged in through a USB adapter.
     */
    { "dualsense",  0x054C, 0x0CE6, 0x0000, 0x00000000, PS3_PAD_CAP_STANDARD },
    /* A skateboard has no sticks, no pressures and no rumble. */
    { "skateboard", 0x12BA, 0x0400, 0x8001, 0x00000000,
      PS3_PAD_CAP_CONFORMITY | PS3_PAD_CAP_PRESS_MODE |
      PS3_PAD_CAP_SENSOR_MODE },
};

/* The sys_io services this layer answers, by NID as the VSH imports them. */
#define PS3_NID_SYS_CONFIG_START            0x068FCBC6u
#define PS3_NID_SYS_CONFIG_ADD_LISTENER     0x6AE10596u
#define PS3_NID_SYS_CONFIG_REGISTER_SERVICE 0x78F058A2u
#define PS3_NID_SYS_CONFIG_REMOVE_LISTENER  0xF5D9D571u
#define PS3_NID_SYS_CONFIG_UNREGISTER_SRV   0x5F81900Cu
#define PS3_NID_CELLPAD_CLEAR_BUF           0x0D5F2C14u
#define PS3_NID_CELLPAD_INFO_PRESS_MODE     0x0E2DFAADu
#define PS3_NID_CELLPAD_INIT                0x1CF98800u
#define PS3_NID_CELLPAD_LDD_REGISTER        0x20A97BA2u
#define PS3_NID_CELLPAD_GET_INFO            0x3AAAD464u
#define PS3_NID_CELLPAD_GET_RAW_DATA        0x3F797DFFu
#define PS3_NID_CELLPAD_PERIPH_GET_INFO     0x4CC9B68Du
#define PS3_NID_CELLPAD_END                 0x4D9B75D5u
#define PS3_NID_CELLPAD_SET_PORT_SETTING    0x578E3C98u
#define PS3_NID_CELLPAD_GET_DATA_EXTRA      0x6BC09C61u
#define PS3_NID_CELLPAD_INFO_SENSOR_MODE    0x78200559u
#define PS3_NID_CELLPAD_PERIPH_GET_DATA     0x8A00F264u
#define PS3_NID_CELLPAD_GET_DATA            0x8B72CDA1u
#define PS3_NID_CELLPAD_LDD_GET_PORT        0x8B8231E5u
#define PS3_NID_CELLPAD_GET_INFO2           0xA703A51Du
#define PS3_NID_CELLPAD_LDD_INSERT          0xBAFD6409u
#define PS3_NID_CELLPAD_SET_SENSOR_MODE     0xBE5BE3BAu
#define PS3_NID_CELLPAD_GET_CAPABILITY      0xDBF4C59Cu
#define PS3_NID_CELLPAD_LDD_UNREGISTER      0xE442FAA8u
#define PS3_NID_CELLPAD_SET_ACT_DIRECT      0xF65544EEu
#define PS3_NID_CELLPAD_SET_PRESS_MODE      0xF83F8182u

/* The sysPrxForUser helpers libpad's threading needs. */
#define PS3_NID_SYS_PPU_THREAD_CREATE       0x24A1EA07u
#define PS3_NID_SYS_MEMSET                  0x68B9B011u

static const struct {
    uint32_t nid;
    const char *name;
} ps3_sys_io_names[] = {
    { PS3_NID_SYS_CONFIG_START,            "sys_config_start" },
    { PS3_NID_SYS_CONFIG_ADD_LISTENER,     "sys_config_add_service_listener" },
    { PS3_NID_SYS_CONFIG_REGISTER_SERVICE, "sys_config_register_service" },
    { PS3_NID_SYS_CONFIG_REMOVE_LISTENER,  "sys_config_remove_service_listener" },
    { PS3_NID_SYS_CONFIG_UNREGISTER_SRV,   "sys_config_unregister_service" },
    { PS3_NID_CELLPAD_INIT,                "cellPadInit" },
    { PS3_NID_CELLPAD_END,                 "cellPadEnd" },
    { PS3_NID_CELLPAD_GET_DATA,            "cellPadGetData" },
    { PS3_NID_CELLPAD_GET_RAW_DATA,        "cellPadGetRawData" },
    { PS3_NID_CELLPAD_GET_DATA_EXTRA,      "cellPadGetDataExtra" },
    { PS3_NID_CELLPAD_GET_INFO,            "cellPadGetInfo" },
    { PS3_NID_CELLPAD_GET_INFO2,           "cellPadGetInfo2" },
    { PS3_NID_CELLPAD_PERIPH_GET_INFO,     "cellPadPeriphGetInfo" },
    { PS3_NID_CELLPAD_PERIPH_GET_DATA,     "cellPadPeriphGetData" },
    { PS3_NID_CELLPAD_GET_CAPABILITY,      "cellPadGetCapabilityInfo" },
    { PS3_NID_CELLPAD_SET_ACT_DIRECT,      "cellPadSetActDirect" },
    { PS3_NID_CELLPAD_SET_PORT_SETTING,    "cellPadSetPortSetting" },
    { PS3_NID_CELLPAD_SET_PRESS_MODE,      "cellPadSetPressMode" },
    { PS3_NID_CELLPAD_SET_SENSOR_MODE,     "cellPadSetSensorMode" },
    { PS3_NID_CELLPAD_INFO_PRESS_MODE,     "cellPadInfoPressMode" },
    { PS3_NID_CELLPAD_INFO_SENSOR_MODE,    "cellPadInfoSensorMode" },
    { PS3_NID_CELLPAD_CLEAR_BUF,           "cellPadClearBuf" },
    { PS3_NID_CELLPAD_LDD_REGISTER,        "cellPadLddRegisterController" },
    { PS3_NID_CELLPAD_LDD_GET_PORT,        "cellPadLddGetPortNo" },
    { PS3_NID_CELLPAD_LDD_INSERT,          "cellPadLddDataInsert" },
    { PS3_NID_CELLPAD_LDD_UNREGISTER,      "cellPadLddUnregisterController" },
    { PS3_NID_SYS_PPU_THREAD_CREATE,       "sys_ppu_thread_create" },
    { PS3_NID_SYS_MEMSET,                  "_sys_memset" },
};

static const char *ps3_sys_io_name(uint32_t nid)
{
    unsigned i;

    for (i = 0; i < ARRAY_SIZE(ps3_sys_io_names); i++) {
        if (ps3_sys_io_names[i].nid == nid) {
            return ps3_sys_io_names[i].name;
        }
    }

    return NULL;
}

static const PS3PadProduct *ps3_pad_product(const PS3BootROMState *s,
                                            unsigned port)
{
    return &ps3_pad_products[s->pad_types[port]];
}

/* How many of the described ports the guest currently sees connected. */
static unsigned ps3_pad_connect(const PS3BootROMState *s)
{
    return MIN(s->pad_ports, MIN(s->pad_max_connect, PS3_PAD_PORT_MAX));
}

/* A CellPadData word, in place: the length is four bytes, then the words. */
/*
 * lv2's network services: the wired link.  The PS3's Ethernet is virtualized
 * below lv2 (gelic is driven through lv1 hypercalls on a real console), and
 * the guest here reaches the network only through these sys_net calls, so the
 * hosts's own stack is what the link is backed by.  Addresses are NetBSD/PS3
 * sockaddr: length, family, big-endian port, 4-byte address.
 */

static void ps3_net_close_fd(int fd)
{
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
}

static void ps3_net_set_nonblock(int fd)
{
#ifdef _WIN32
    u_long one = 1;

    ioctlsocket(fd, FIONBIO, &one);
#else
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
#endif
}

/* Index of the guest handle's slot, or -1 when it is not a live socket. */
static int ps3_net_index(PS3BootROMState *s, int guest_fd)
{
    int i = guest_fd - PS3_NET_FD_BASE;

    if (i < 0 || i >= PS3_NET_MAX || !s->net_used[i]) {
        return -1;
    }
    return i;
}

static int ps3_net_alloc(PS3BootROMState *s, int host_fd)
{
    unsigned i;

    for (i = 0; i < PS3_NET_MAX; i++) {
        if (!s->net_used[i]) {
            s->net_used[i] = true;
            s->net_fd[i] = host_fd;
            return PS3_NET_FD_BASE + i;
        }
    }
    return -EMFILE;
}

static bool ps3_net_decode_addr(const uint8_t *p, uint32_t len,
                                struct sockaddr_in *sin)
{
    if (!p || len < 8 || p[1] != 2) {
        return false;
    }

    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_port = (p[2] << 8) | p[3];
    memcpy(&sin->sin_addr, p + 4, 4);
    return true;
}

static void ps3_net_encode_addr(uint8_t *p, const struct sockaddr_in *sin)
{
    p[0] = 16;
    p[1] = 2;
    p[2] = sin->sin_port >> 8;
    p[3] = sin->sin_port;
    memcpy(p + 4, &sin->sin_addr, 4);
    memset(p + 8, 0, 8);
}

/*
 * The guest's resolver asks the nameserver it was given over UDP.  There is no
 * nameserver at that address in this model, so a query to it is answered here:
 * the name is resolved with the host resolver and the reply is queued on the
 * socket for the guest's next recvfrom.  This is what makes names, and with
 * them the console's time servers, resolve over the wired link.
 */
#define PS3_NET_DNS_IP  "\x0a\x00\x02\x03"   /* 10.0.2.3 */

static int ps3_dns_query_name(const uint8_t *q, unsigned len, char *out,
                              unsigned cap, unsigned *end)
{
    unsigned p = 12, o = 0;

    while (p < len && q[p]) {
        unsigned n = q[p++];

        if (n > 63 || p + n > len || o + n + 2 > cap) {
            return -1;
        }
        if (o) {
            out[o++] = '.';
        }
        memcpy(out + o, q + p, n);
        o += n;
        p += n;
    }
    out[o] = 0;

    if (p + 5 > len) {
        return -1;
    }
    *end = p + 5;                 /* zero label + qtype + qclass */
    return (int)o;
}

static unsigned ps3_dns_reply(const uint8_t *q, unsigned qlen, uint8_t *out,
                              unsigned cap)
{
    struct addrinfo hints, *res = NULL;
    char name[256];
    unsigned end, len;
    uint8_t ip[4] = { 0, 0, 0, 0 };
    bool found = false;

    if (qlen < 17 || cap < qlen + 16 ||
        ps3_dns_query_name(q, qlen, name, sizeof(name), &end) < 0) {
        return 0;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(name, NULL, &hints, &res) == 0 && res) {
        memcpy(ip, &((struct sockaddr_in *)res->ai_addr)->sin_addr, 4);
        found = true;
    }
    if (res) {
        freeaddrinfo(res);
    }

    memcpy(out, q, end);
    out[2] = q[2] | 0x80;            /* QR, keep the query's RD */
    out[3] = found ? (q[3] | 0x80) : 0x83; /* RA, or NXDOMAIN */
    out[6] = 0; out[7] = found ? 1 : 0;  /* ANCOUNT */
    out[8] = 0; out[9] = 0;              /* NSCOUNT */
    out[10] = 0; out[11] = 0;            /* ARCOUNT */
    len = end;

    if (found) {
        static const uint8_t answer[12] = {
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
        };

        memcpy(out + len, answer, sizeof(answer));
        memcpy(out + len + sizeof(answer), ip, 4);
        len += sizeof(answer) + 4;
    }

    info_report("ps3-ppu: net: resolved %s -> %u.%u.%u.%u", name, ip[0],
                ip[1], ip[2], ip[3]);
    return len;
}

static bool ps3_net_dns(PS3BootROMState *s, int ni, const uint8_t *buf,
                        unsigned len, const struct sockaddr_in *dst)
{
    uint8_t reply[512];
    unsigned n;

    if (ntohs(dst->sin_port) != 53 ||
        memcmp(&dst->sin_addr, PS3_NET_DNS_IP, 4)) {
        return false;
    }

    n = ps3_dns_reply(buf, len, reply, sizeof(reply));
    if (!n) {
        return false;
    }

    g_free(s->net_pending[ni]);
    s->net_pending[ni] = g_malloc(n);
    memcpy(s->net_pending[ni], reply, n);
    s->net_pending_len[ni] = n;
    return true;
}

/*
 * The wired interface's own address, as NetBSD ioctls report it.  ioctl is
 * request-encoded: the group is 'i' and the low byte names the request, so the
 * size bits a caller may or may not set do not matter here.  The interface is
 * the console's Ethernet, with the address block this model gives it.
 */
#define PS3_NET_IP      ((const uint8_t [4]){ 10, 0, 2, 15 })
#define PS3_NET_MASK    ((const uint8_t [4]){ 255, 255, 255, 0 })
#define PS3_NET_BCAST   ((const uint8_t [4]){ 10, 0, 2, 255 })
#define PS3_NET_GW      ((const uint8_t [4]){ 10, 0, 2, 2 })

static void ps3_net_ifreq_addr(uint8_t *ram, uint32_t req, const uint8_t ip[4])
{
    ram[req + 16] = 16;         /* sockaddr length */
    ram[req + 17] = 2;          /* AF_INET */
    ram[req + 18] = 0;
    ram[req + 19] = 0;
    memcpy(ram + req + 20, ip, 4);
    memset(ram + req + 24, 0, 8);
}

static bool ps3_net_ioctl(uint8_t *ram, uint64_t ram_size, uint32_t request,
                          uint32_t arg, int32_t *ret)
{
    unsigned group = (request >> 8) & 0xFF;
    unsigned num = request & 0xFF;
    const uint8_t *ip;

    if (group != 'i' || !arg || (uint64_t)arg + 32 > ram_size) {
        return false;
    }

    switch (num) {
    case 36: {                  /* SIOCGIFCONF */
        uint32_t len = ps3_be32(ram + arg);
        uint32_t buf = ps3_be32(ram + arg + 4);

        if (buf && len >= 32 && (uint64_t)buf + 32 <= ram_size) {
            memset(ram + buf, 0, 32);
            memcpy(ram + buf, "eth0", 4);
            ps3_net_ifreq_addr(ram, buf, PS3_NET_IP);
            ps3_put_be32(ram + arg, 32);
        } else {
            ps3_put_be32(ram + arg, 0);
        }
        *ret = 0;
        return true;
    }
    case 33:                    /* SIOCGIFADDR */
        ip = PS3_NET_IP;
        break;
    case 37:                    /* SIOCGIFNETMASK */
        ip = PS3_NET_MASK;
        break;
    case 35:                    /* SIOCGIFBRDADDR */
        ip = PS3_NET_BCAST;
        break;
    case 34:                    /* SIOCGIFDSTADDR */
        ip = PS3_NET_GW;
        break;
    case 17:                    /* SIOCGIFFLAGS */
        memset(ram + arg + 16, 0, 16);
        ram[arg + 16] = 0x43;   /* UP | BROADCAST | RUNNING */
        ram[arg + 17] = 0x80;   /* MULTICAST */
        *ret = 0;
        return true;
    case 51:                    /* SIOCGIFMTU */
        ps3_put_be32(ram + arg + 16, 1500);
        *ret = 0;
        return true;
    default:
        return false;
    }

    ps3_net_ifreq_addr(ram, arg, ip);
    *ret = 0;
    return true;
}

static bool ps3_lv2_net(PS3BootROMState *s, uint8_t *ram, uint64_t ram_size,
                        uint32_t nr, uint32_t a0, uint32_t a1, uint32_t a2,
                        uint32_t a3, uint32_t a4, uint32_t a5, int32_t *ret)
{
    struct sockaddr_in sin, peer;
    socklen_t slen = sizeof(peer);
    int ni;
    int fd;

    switch (nr) {
    case 0x2C9:                 /* socket(family, type, protocol) */
        if (a0 != 2 || (a1 != 1 && a1 != 2)) {
            *ret = -EAFNOSUPPORT;
            break;
        }
        fd = qemu_socket(AF_INET, a1 == 1 ? SOCK_STREAM : SOCK_DGRAM, 0);
        if (fd < 0) {
            *ret = -errno;
            break;
        }
        ps3_net_set_nonblock(fd);
        *ret = ps3_net_alloc(s, fd);
        info_report("ps3-ppu: net: socket(%s) = 0x%X",
                    a1 == 1 ? "stream" : "dgram", *ret);
        break;
    case 0x2CA:                 /* close(fd) */
        ni = ps3_net_index(s, a0);
        if (ni < 0) {
            *ret = -EBADF;
            break;
        }
        ps3_net_close_fd(s->net_fd[ni]);
        s->net_used[ni] = false;
        g_free(s->net_pending[ni]);
        s->net_pending[ni] = NULL;
        s->net_pending_len[ni] = 0;
        *ret = 0;
        break;
    case 0x2BD:                 /* bind(fd, addr, len) */
        ni = ps3_net_index(s, a0);
        if (ni < 0 || !ps3_net_decode_addr(ram + a1, a2, &sin)) {
            *ret = -EINVAL;
            break;
        }
        *ret = bind(s->net_fd[ni], (struct sockaddr *)&sin, sizeof(sin)) < 0 ?
               -errno : 0;
        break;
    case 0x2BE:                 /* connect(fd, addr, len) */
        ni = ps3_net_index(s, a0);
        if (ni < 0 || !ps3_net_decode_addr(ram + a1, a2, &sin)) {
            *ret = -EINVAL;
            break;
        }
        if (connect(s->net_fd[ni], (struct sockaddr *)&sin, sizeof(sin)) < 0 &&
            errno != EINPROGRESS && errno != EWOULDBLOCK) {
            *ret = -errno;
            break;
        }
        *ret = 0;
        break;
    case 0x2C2:                 /* listen(fd, backlog) */
        ni = ps3_net_index(s, a0);
        *ret = ni < 0 ? -EBADF :
               (listen(s->net_fd[ni], a1) < 0 ? -errno : 0);
        break;
    case 0x2BC:                 /* accept(fd, addr*, len*) */
        ni = ps3_net_index(s, a0);
        if (ni < 0) {
            *ret = -EBADF;
            break;
        }
        fd = qemu_accept(s->net_fd[ni], (struct sockaddr *)&peer, &slen);
        if (fd < 0) {
            *ret = -errno;
            break;
        }
        ps3_net_set_nonblock(fd);
        if (a1 && (uint64_t)a1 + 16 <= ram_size) {
            ps3_net_encode_addr(ram + a1, &peer);
        }
        if (a2 && (uint64_t)a2 + 4 <= ram_size) {
            ps3_put_be32(ram + a2, 16);
        }
        *ret = ps3_net_alloc(s, fd);
        break;
    case 0x2C6: {               /* sendto(fd, buf, len, flags, addr, alen) */
        ssize_t sent;

        ni = ps3_net_index(s, a0);
        if (ni < 0 || !a1 || (uint64_t)a1 + a2 > ram_size) {
            *ret = -EINVAL;
            break;
        }
        if (a4 && ps3_net_decode_addr(ram + a4, a5, &sin) &&
            ps3_net_dns(s, ni, ram + a1, a2, &sin)) {
            sent = a2;          /* answered locally, as the nameserver */
        } else if (a4 && ps3_net_decode_addr(ram + a4, a5, &sin)) {
            sent = sendto(s->net_fd[ni], (const void *)(ram + a1), a2, 0,
                          (struct sockaddr *)&sin, sizeof(sin));
        } else if (getpeername(s->net_fd[ni], (struct sockaddr *)&sin,
                               &slen) == 0 &&
                   ps3_net_dns(s, ni, ram + a1, a2, &sin)) {
            sent = a2;
        } else {
            sent = send(s->net_fd[ni], (const void *)(ram + a1), a2, 0);
        }
        *ret = sent < 0 ? -errno : (int32_t)sent;
        break;
    }
    case 0x2C3: {              /* recvfrom(fd, buf, len, flags, addr, len*) */
        ssize_t got;

        ni = ps3_net_index(s, a0);
        if (ni < 0 || !a1 || (uint64_t)a1 + a2 > ram_size) {
            *ret = -EINVAL;
            break;
        }
        if (s->net_pending[ni]) {
            unsigned n = MIN(a2, s->net_pending_len[ni]);

            memcpy(ram + a1, s->net_pending[ni], n);
            g_free(s->net_pending[ni]);
            s->net_pending[ni] = NULL;
            s->net_pending_len[ni] = 0;
            if (a4 && (uint64_t)a4 + 16 <= ram_size) {
                memset(ram + a4, 0, 16);
                ram[a4] = 16;
                ram[a4 + 1] = 2;
                ram[a4 + 2] = 0;
                ram[a4 + 3] = 53;
                memcpy(ram + a4 + 4, PS3_NET_DNS_IP, 4);
                if (a5 && (uint64_t)a5 + 4 <= ram_size) {
                    ps3_put_be32(ram + a5, 16);
                }
            }
            *ret = (int32_t)n;
            break;
        }

        memset(&peer, 0, sizeof(peer));
        slen = sizeof(peer);
        if (a4) {
            got = recvfrom(s->net_fd[ni], (void *)(ram + a1), a2, 0,
                           (struct sockaddr *)&peer, &slen);
        } else {
            got = recv(s->net_fd[ni], (void *)(ram + a1), a2, 0);
        }
        if (got < 0) {
            *ret = -errno;
            break;
        }
        if (a4 && slen >= 16 && (uint64_t)a4 + 16 <= ram_size) {
            ps3_net_encode_addr(ram + a4, &peer);
            if (a5 && (uint64_t)a5 + 4 <= ram_size) {
                ps3_put_be32(ram + a5, 16);
            }
        }
        *ret = (int32_t)got;
        break;
    }
    case 0x2C0:                 /* getsockname(fd, addr*, len*) */
    case 0x2BF: {               /* getpeername(fd, addr*, len*) */
        ni = ps3_net_index(s, a0);
        if (ni < 0) {
            *ret = -EBADF;
            break;
        }
        memset(&peer, 0, sizeof(peer));
        slen = sizeof(peer);
        if (nr == 0x2C0) {
            getsockname(s->net_fd[ni], (struct sockaddr *)&peer, &slen);
        } else {
            getpeername(s->net_fd[ni], (struct sockaddr *)&peer, &slen);
        }
        if (a1 && (uint64_t)a1 + 16 <= ram_size) {
            ps3_net_encode_addr(ram + a1, &peer);
        }
        if (a2 && (uint64_t)a2 + 4 <= ram_size) {
            ps3_put_be32(ram + a2, 16);
        }
        *ret = 0;
        break;
    }
    case 0x2C7:                 /* setsockopt: accepted, no tuning */
        *ret = 0;
        break;
    case 0x2C1: {               /* getsockopt(fd, lvl, opt, val, len*) */
        uint32_t optlen = 0;

        if (a4 && (uint64_t)a4 + 4 <= ram_size) {
            optlen = ps3_be32(ram + a4);
        }
        if (a3 && optlen && (uint64_t)a3 + optlen <= ram_size) {
            memset(ram + a3, 0, optlen);
        }
        *ret = 0;
        break;
    }
    case 0x2C8:                 /* shutdown(fd, how) */
        ni = ps3_net_index(s, a0);
        *ret = ni < 0 ? -EBADF :
               (shutdown(s->net_fd[ni], a1) < 0 ? -errno : 0);
        break;
    case 0x2D2:                 /* infoctl(cmd, arg) */
        if (a0 == 9 && a1 && (uint64_t)a1 + 8 <= ram_size) {
            /* {u32 zero; u32 name*} - the resolver's nameserver line. */
            uint32_t name = ps3_be32(ram + a1 + 4);
            static const char ns[] = "nameserver 10.0.2.3";

            ps3_put_be32(ram + a1, 0);
            if (name && (uint64_t)name + sizeof(ns) <= ram_size) {
                memcpy(ram + name, ns, sizeof(ns));
            }
        }
        *ret = 0;
        break;
    case 0x2D3:                 /* control: interface commands succeed */
        *ret = 0;
        break;
    case 0x2D4:                 /* bnet_ioctl(fd, request, arg) */
        if (!ps3_net_ioctl(ram, ram_size, a1, a2, ret)) {
            *ret = 0;           /* other requests are accepted */
        } else if (!s->net_iface_reported) {
            s->net_iface_reported = true;
            info_report("ps3-ppu: net: wired interface eth0 10.0.2.15/24, "
                        "gateway 10.0.2.2, DNS 10.0.2.3");
        }
        break;
    default:
        return false;
    }

    return true;
}

/*
 * The host's keyboard, delivered as the pad buttons the recovery menu and the
 * VSH already read: arrows are the d-pad, Enter is cross, Escape is circle,
 * Backspace is square, Space is start and Tab is select.  QEMU hands the events
 * to us whenever the machine's display has focus.
 */
static void ps3_input_kick(PS3BootROMState *s)
{
    if (s->idle_timer && s->idle_off_seconds) {
        timer_mod(s->idle_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                  (int64_t)s->idle_off_seconds * 1000000000LL);
    }
}

static void ps3_idle_off(void *opaque)
{
    PS3BootROMState *s = opaque;

    if (!s->idle_off_reported) {
        s->idle_off_reported = true;
        info_report("ps3: no input for %u seconds: the console's auto-off "
                    "powers it down", s->idle_off_seconds);
    }
    qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
}

static void ps3_kbd_event(DeviceState *dev, QemuConsole *src,
                          QemuInputEvent *evt)
{
    PS3BootROMState *s = PS3_BOOT_ROM(dev);
    uint16_t *word = NULL;
    uint16_t bit = 0;

    ps3_input_kick(s);

    if (evt->type != INPUT_EVENT_KIND_KEY) {
        return;
    }

    switch (qemu_input_linux_to_qcode(evt->key.key)) {
    case Q_KEY_CODE_UP:       word = &s->kbd_d1; bit = 0x0010; break;
    case Q_KEY_CODE_RIGHT:    word = &s->kbd_d1; bit = 0x0020; break;
    case Q_KEY_CODE_DOWN:     word = &s->kbd_d1; bit = 0x0040; break;
    case Q_KEY_CODE_LEFT:     word = &s->kbd_d1; bit = 0x0080; break;
    case Q_KEY_CODE_RET:      word = &s->kbd_d2; bit = 0x0040; break;  /* cross */
    case Q_KEY_CODE_ESC:      word = &s->kbd_d2; bit = 0x0020; break;  /* circle */
    case Q_KEY_CODE_BACKSPACE: word = &s->kbd_d2; bit = 0x0080; break; /* square */
    case Q_KEY_CODE_SPC:      word = &s->kbd_d1; bit = 0x0008; break;  /* start */
    case Q_KEY_CODE_TAB:      word = &s->kbd_d1; bit = 0x0001; break;  /* select */
    default:
        return;
    }

    if (evt->key.down) {
        *word |= bit;
        if (!s->kbd_reported) {
            s->kbd_reported = true;
            info_report("ps3-ppu: keyboard: host keys drive the pad "
                        "(arrows, Enter cross, Escape circle, Backspace "
                        "square, Space start, Tab select)");
        }
    } else {
        *word &= ~bit;
    }
}

/*
 * The host's controller, as SDL publishes it: the whole state after every
 * change, so this replaces what it had and a controller that is unplugged
 * leaves both sticks centred.  Whatever the pad's product, the controller's
 * inputs land in the same two digital words the keyboard uses.
 */
static void ps3_gamepad_event(void *opaque, const QemuGamepadState *state)
{
    PS3BootROMState *s = opaque;

    bool connected = qemu_gamepad_connected();

    s->host_buttons = state->buttons;
    s->host_lx = state->lx;
    s->host_ly = state->ly;
    s->host_rx = state->rx;
    s->host_ry = state->ry;
    ps3_input_kick(s);

    /*
     * The display also publishes a state when it loses the controller (zeroed,
     * so the guest sees the release), which is how the detach is seen at all.
     */
    if (connected != s->host_pad_connected) {
        s->host_pad_connected = connected;
        if (connected) {
            info_report("ps3-ppu: gamepad: the host's controller drives port 0 "
                        "(sticks, d-pad, face and shoulder buttons)");
        } else {
            info_report("ps3-ppu: gamepad: the host's controller is gone; "
                        "port 0 sits at rest");
        }
    }
}

/*
 * SDL's -32768..32767 axis to libpad's 0..255, where 0 is up or left.  The
 * half step of rounding matters: without it a centred stick reads 127 and a
 * game takes that for a small push.
 */
static uint16_t ps3_pad_axis(int v)
{
    return (uint16_t)CLAMP(((v + 0x8000) * 255 + 0x7FFF) / 0xFFFF, 0, 255);
}

/* What the guest sees: the keyboard's word, with the controller's ORed in. */
static void ps3_pad_host_words(const PS3BootROMState *s, uint16_t *d1,
                               uint16_t *d2)
{
    const uint32_t b = s->host_buttons;

    *d1 = s->kbd_d1;
    *d2 = s->kbd_d2;

    if (b & QEMU_GAMEPAD_SELECT)     *d1 |= 0x0001;
    if (b & QEMU_GAMEPAD_THUMBL)     *d1 |= 0x0002;
    if (b & QEMU_GAMEPAD_THUMBR)     *d1 |= 0x0004;
    if (b & QEMU_GAMEPAD_START)      *d1 |= 0x0008;
    if (b & QEMU_GAMEPAD_DPAD_UP)    *d1 |= 0x0010;
    if (b & QEMU_GAMEPAD_DPAD_RIGHT) *d1 |= 0x0020;
    if (b & QEMU_GAMEPAD_DPAD_DOWN)  *d1 |= 0x0040;
    if (b & QEMU_GAMEPAD_DPAD_LEFT)  *d1 |= 0x0080;
    if (b & QEMU_GAMEPAD_MODE)       *d1 |= 0x0100;

    if (b & QEMU_GAMEPAD_TL2)        *d2 |= 0x0001;
    if (b & QEMU_GAMEPAD_TR2)        *d2 |= 0x0002;
    if (b & QEMU_GAMEPAD_TL)         *d2 |= 0x0004;
    if (b & QEMU_GAMEPAD_TR)         *d2 |= 0x0008;
    if (b & QEMU_GAMEPAD_NORTH)      *d2 |= 0x0010;
    if (b & QEMU_GAMEPAD_EAST)       *d2 |= 0x0020;
    if (b & QEMU_GAMEPAD_SOUTH)      *d2 |= 0x0040;
    if (b & QEMU_GAMEPAD_WEST)       *d2 |= 0x0080;
}

static const QemuInputHandler ps3_kbd_handler = {
    .name = "ps3 keyboard",
    .mask = INPUT_EVENT_MASK_KEY,
    .event = ps3_kbd_event,
};

static void ps3_pad_put_word(uint8_t *p, unsigned word, uint16_t v)
{
    p[4 + 2 * word] = v >> 8;
    p[5 + 2 * word] = v;
}

/*
 * One port's CellPadData.  Port 0 carries what the host presses; every other
 * port has nothing pressed, its sticks in the middle.  A sensor-mode pad
 * reports the DS3's rest orientation, and a peripheral reports the neutral
 * value of the controls its profile has.  The length says
 * how much of it is valid - 8 bytes, 20 with pressures, 24 with sensors - the
 * way a real pad does, and `len' 0 is never returned because this model has no
 * input to lose.
 */
static void ps3_pad_data(const PS3BootROMState *s, unsigned port, uint8_t *d,
                         bool periph)
{
    const PS3PadProduct *p = ps3_pad_product(s, port);
    uint32_t setting = s->pad_setting[port];
    uint16_t d1, d2;
    unsigned len = 8;

    if (setting & PS3_PAD_SETTING_SENSOR_ON) {
        len = 24;
    } else if (setting & PS3_PAD_SETTING_PRESS_ON) {
        len = 20;
    }

    memset(d, 0, PS3_PAD_DATA_SIZE);

    ps3_put_be32(d, len);
    /* Word 0 is reserved; word 1 holds the length in halfwords. */
    ps3_pad_put_word(d, 1, (0x7 << 4) | MIN(len / 2, 15));

    /* The host keyboard and controller press these, port 0 only. */
    ps3_pad_host_words(s, &d1, &d2);
    if (port != 0) {
        d1 = d2 = 0;
    }
    ps3_pad_put_word(d, PS3_PAD_W_DIGITAL1, d1);
    ps3_pad_put_word(d, PS3_PAD_W_DIGITAL2, d2);

    /*
     * The sticks read from the controller, or sit centred when there is none:
     * SDL's axes are 0 at rest, so a missing pad and a pad at rest agree.
     */
    ps3_pad_put_word(d, PS3_PAD_W_ANALOG_RX,
                     port == 0 ? ps3_pad_axis(s->host_rx) : 128);
    ps3_pad_put_word(d, PS3_PAD_W_ANALOG_RY,
                     port == 0 ? ps3_pad_axis(s->host_ry) : 128);
    ps3_pad_put_word(d, PS3_PAD_W_ANALOG_LX,
                     port == 0 ? ps3_pad_axis(s->host_lx) : 128);
    ps3_pad_put_word(d, PS3_PAD_W_ANALOG_LY,
                     port == 0 ? ps3_pad_axis(s->host_ly) : 128);

    /*
     * Press mode: a pressed button reports full travel.  The two triggers are
     * digital here too - SDL gives their axes, and the UI turns a pull past a
     * quarter into the L2/R2 bit.
     */
    if (len >= 20) {
        ps3_pad_put_word(d, 8,  (d1 & 0x0020) ? 255 : 0);  /* right */
        ps3_pad_put_word(d, 9,  (d1 & 0x0080) ? 255 : 0);  /* left */
        ps3_pad_put_word(d, 10, (d1 & 0x0010) ? 255 : 0);  /* up */
        ps3_pad_put_word(d, 11, (d1 & 0x0040) ? 255 : 0);  /* down */
        ps3_pad_put_word(d, 12, (d2 & 0x0010) ? 255 : 0);  /* triangle */
        ps3_pad_put_word(d, 13, (d2 & 0x0020) ? 255 : 0);  /* circle */
        ps3_pad_put_word(d, 14, (d2 & 0x0040) ? 255 : 0);  /* cross */
        ps3_pad_put_word(d, 15, (d2 & 0x0080) ? 255 : 0);  /* square */
        ps3_pad_put_word(d, 16, (d2 & 0x0004) ? 255 : 0);  /* L1 */
        ps3_pad_put_word(d, 17, (d2 & 0x0008) ? 255 : 0);  /* R1 */
        ps3_pad_put_word(d, 18, (d2 & 0x0001) ? 255 : 0);  /* L2 */
        ps3_pad_put_word(d, 19, (d2 & 0x0002) ? 255 : 0);  /* R2 */
    }

    if (len == 24) {
        ps3_pad_put_word(d, PS3_PAD_W_SENSOR_X, 512);
        ps3_pad_put_word(d, PS3_PAD_W_SENSOR_X + 1, 399); /* 512 - 1 G */
        ps3_pad_put_word(d, PS3_PAD_W_SENSOR_X + 2, 512);
        ps3_pad_put_word(d, PS3_PAD_W_SENSOR_X + 3, 512);
    }

    if (!periph) {
        return;
    }

    switch (p->pclass) {
    case 0x0001:                /* guitar: whammy and the 5-way switch */
        ps3_pad_put_word(d, PS3_PAD_W_GUITAR_WHAMMY, 0x80);
        ps3_pad_put_word(d, PS3_PAD_W_GUITAR_5WAY, 0x19);
        break;
    case 0x0003:                /* turntable: both platters at rest */
        ps3_pad_put_word(d, PS3_PAD_W_DJ_DECK1_PLATTER, 0x80);
        ps3_pad_put_word(d, PS3_PAD_W_DJ_DECK2_PLATTER, 0x80);
        break;
    default:
        break;
    }
}

static void ps3_pad_info(const PS3BootROMState *s, uint8_t *info);

/*
 * The pad selftest: one controller state through the same handler the display
 * feeds, then the guest's CellPadData read back and checked.  It is what says
 * the mapping is right without a controller in hand - a stick on the wrong
 * side or a face button in the wrong word would only look like a broken game.
 * The product the port describes is checked with it, so `pad-types=dualsense'
 * is known to reach `cellPadGetInfo' as the ids it stands for.
 */
static bool ps3_pad_selftest(PS3BootROMState *s, char *why, size_t why_len)
{
    const PS3PadProduct *p = ps3_pad_product(s, 0);
    QemuGamepadState gp;
    uint8_t info[PS3_PAD_INFO_SIZE];
    uint8_t d[PS3_PAD_DATA_SIZE];
    unsigned max_connect;
    uint32_t setting = s->pad_setting[0];
    uint16_t d1, d2, lx, ly, rx, ry, press_cross;

    /* The display owns the connected flag; here the selftest stands in for it. */
    qemu_gamepad_set_connected(true);

    memset(&gp, 0, sizeof(gp));
    gp.buttons = QEMU_GAMEPAD_SOUTH | QEMU_GAMEPAD_DPAD_LEFT;
    gp.lx = -0x8000;                    /* hard left */
    gp.ly = -0x8000;                    /* hard up */
    gp.rx = 0x7FFF;                     /* hard right */
    gp.ry = 0x7FFF;                     /* hard down */

    ps3_gamepad_event(s, &gp);
    s->pad_setting[0] = PS3_PAD_SETTING_PRESS_ON;
    ps3_pad_data(s, 0, d, false);

    d1 = (d[4 + 2 * 2] << 8) | d[5 + 2 * 2];
    d2 = (d[4 + 2 * 3] << 8) | d[5 + 2 * 3];
    rx = (d[4 + 2 * 4] << 8) | d[5 + 2 * 4];
    ry = (d[4 + 2 * 5] << 8) | d[5 + 2 * 5];
    lx = (d[4 + 2 * 6] << 8) | d[5 + 2 * 6];
    ly = (d[4 + 2 * 7] << 8) | d[5 + 2 * 7];
    press_cross = (d[4 + 2 * 14] << 8) | d[5 + 2 * 14];

    s->pad_setting[0] = setting;

    if (ps3_be32(d) != 20) {
        snprintf(why, why_len, "press mode gave a %u-byte report, not 20",
                 ps3_be32(d));
        return false;
    }
    if (d1 != 0x0080) {
        snprintf(why, why_len, "the d-pad left is 0x%04X in digital1, not "
                 "0x0080", d1);
        return false;
    }
    if (d2 != 0x0040) {
        snprintf(why, why_len, "cross is 0x%04X in digital2, not 0x0040", d2);
        return false;
    }
    if (lx != 0 || ly != 0 || rx != 255 || ry != 255) {
        snprintf(why, why_len, "the sticks read L %u,%u R %u,%u, not L 0,0 "
                 "R 255,255", lx, ly, rx, ry);
        return false;
    }
    if (press_cross != 255) {
        snprintf(why, why_len, "cross pressure is %u, not 255", press_cross);
        return false;
    }

    /*
     * And released: the sticks recentre and nothing stays pressed, which is
     * what an unplugged controller has to look like.
     */
    memset(&gp, 0, sizeof(gp));
    qemu_gamepad_set_connected(false);
    ps3_gamepad_event(s, &gp);
    ps3_pad_data(s, 0, d, false);

    lx = (d[4 + 2 * 6] << 8) | d[5 + 2 * 6];
    ly = (d[4 + 2 * 7] << 8) | d[5 + 2 * 7];
    d1 = (d[4 + 2 * 2] << 8) | d[5 + 2 * 2];
    d2 = (d[4 + 2 * 3] << 8) | d[5 + 2 * 3];
    if (ps3_be32(d) != 8 || lx != 128 || ly != 128 || d1 || d2) {
        snprintf(why, why_len, "released reads %u bytes, L %u,%u, digital "
                 "0x%04X 0x%04X", ps3_be32(d), lx, ly, d1, d2);
        return false;
    }

    /*
     * The guest's cellPadInit is what makes the ports connected; the selftest
     * stands in for that call, then puts the machine back as it found it.
     */
    max_connect = s->pad_max_connect;
    s->pad_max_connect = PS3_PAD_PORT_MAX;
    ps3_pad_info(s, info);
    s->pad_max_connect = max_connect;

    if (info[12] != (p->vendor >> 8) || info[13] != (uint8_t)p->vendor ||
        info[12 + 2 * 127] != (p->product >> 8) ||
        info[12 + 2 * 127 + 1] != (uint8_t)p->product) {
        snprintf(why, why_len, "cellPadGetInfo does not describe port 0 as "
                 "%04X:%04X", p->vendor, p->product);
        return false;
    }

    info_report("ps3-ppu: pad selftest ok: port 0 is a %s (%04X:%04X) and "
                "the controller's d-pad, cross, sticks and pressures land in "
                "the guest's CellPadData", p->name, p->vendor, p->product);

    return true;
}

static void ps3_pad_info(const PS3BootROMState *s, uint8_t *info)
{
    unsigned connected = ps3_pad_connect(s);
    unsigned i;

    memset(info, 0, PS3_PAD_INFO_SIZE);
    ps3_put_be32(info, s->pad_max_connect);
    ps3_put_be32(info + 4, connected);

    for (i = 0; i < connected; i++) {
        const PS3PadProduct *p = ps3_pad_product(s, i);

        info[12 + 2 * i] = p->vendor >> 8;
        info[12 + 2 * i + 1] = p->vendor;
        info[12 + 2 * 127 + 2 * i] = p->product >> 8;
        info[12 + 2 * 127 + 2 * i + 1] = p->product;
        info[12 + 4 * 127 + i] = PS3_PAD_STATUS_CONNECTED;
    }
}

static void ps3_pad_info2(const PS3BootROMState *s, uint8_t *info)
{
    unsigned connected = ps3_pad_connect(s);
    unsigned i;

    memset(info, 0, PS3_PAD_INFO2_SIZE);
    ps3_put_be32(info, MIN(s->pad_max_connect, PS3_PAD_PORT_MAX));
    ps3_put_be32(info + 4, connected);

    for (i = 0; i < connected; i++) {
        const PS3PadProduct *p = ps3_pad_product(s, i);
        unsigned at = 12 + 4 * i;

        ps3_put_be32(info + at, PS3_PAD_STATUS_CONNECTED);
        ps3_put_be32(info + at + 4 * PS3_PAD_PORT_MAX, s->pad_setting[i]);
        ps3_put_be32(info + at + 8 * PS3_PAD_PORT_MAX, p->capability);
        ps3_put_be32(info + at + 12 * PS3_PAD_PORT_MAX, 0); /* standard */
    }
}

static void ps3_pad_periph_info(const PS3BootROMState *s, uint8_t *info)
{
    unsigned connected = ps3_pad_connect(s);
    unsigned i;

    memset(info, 0, PS3_PAD_PERIPH_INFO_SIZE);
    ps3_put_be32(info, s->pad_max_connect);
    ps3_put_be32(info + 4, connected);

    for (i = 0; i < connected; i++) {
        const PS3PadProduct *p = ps3_pad_product(s, i);
        unsigned at = 12 + 4 * i;

        ps3_put_be32(info + at, PS3_PAD_STATUS_CONNECTED);
        ps3_put_be32(info + at + 4 * PS3_PAD_PORT_MAX, s->pad_setting[i]);
        ps3_put_be32(info + at + 8 * PS3_PAD_PORT_MAX, p->capability);
        ps3_put_be32(info + at + 12 * PS3_PAD_PORT_MAX, 0); /* standard */
        ps3_put_be32(info + at + 16 * PS3_PAD_PORT_MAX, p->pclass);
        ps3_put_be32(info + at + 20 * PS3_PAD_PORT_MAX, p->profile);
    }
}

static void ps3_thread_save(PS3Thread *t, CPUPPCState *env)
{
    memcpy(t->gpr, env->gpr, sizeof(t->gpr));
    t->lr = env->lr;
    t->ctr = env->ctr;
    t->xer = env->xer;
    t->srr0 = env->spr[SPR_SRR0];
    t->srr1 = env->spr[SPR_SRR1];
    memcpy(t->crf, env->crf, sizeof(t->crf));
    t->msr = env->msr;
    t->nip = env->nip;
}

static void ps3_thread_restore(const PS3Thread *t, CPUPPCState *env)
{
    memcpy(env->gpr, t->gpr, sizeof(t->gpr));
    env->lr = t->lr;
    env->ctr = t->ctr;
    env->xer = t->xer;
    /*
     * SRR0/SRR1 belong to the thread too.  A thread can be switched out in
     * the trampoline's own epilogue - between the restores and the `rfid` -
     * and that `rfid` loads SRR0/SRR1: leaving them to the thread that ran in
     * between would return this one through another thread's exception.
     */
    env->spr[SPR_SRR0] = t->srr0;
    env->spr[SPR_SRR1] = t->srr1;
    memcpy(env->crf, t->crf, sizeof(t->crf));
    /*
     * Through ppc_store_msr, not a plain assignment: the core caches the MSR
     * in env->hflags and every translation block is keyed by that cache, so a
     * raw write leaves the next block running with the previous thread's FP,
     * PR and relocation bits - a restored thread then took an FP-unavailable
     * exception on its first floating-point instruction.
     */
    ppc_store_msr(env, t->msr);
    env->nip = t->nip;
}

/*
 * The lv2 event service.  Queues are keyed by the handle lv2 handed out, so a
 * send can find the queue a port is wired to and the scheduler can find the
 * thread waiting on one.
 */
static int ps3_mio2_service(PS3BootROMState *s)
{
    unsigned i;

    for (i = 0; i < PS3_EQ_MAX; i++) {
        if (s->eq[i].used && s->eq[i].model) {
            return i;
        }
    }
    return -1;
}

static int ps3_eq_index(PS3BootROMState *s, uint32_t id)
{
    unsigned i;

    for (i = 0; i < PS3_EQ_MAX; i++) {
        if (s->eq[i].used && s->eq[i].id == id) {
            return i;
        }
    }
    return -1;
}

/* cellMic names a queue by the key it was created with, not by its handle. */
static int ps3_eq_index_key(const PS3BootROMState *s, uint64_t key)
{
    unsigned i;

    if (!key) {
        return -1;
    }
    for (i = 0; i < PS3_EQ_MAX; i++) {
        if (s->eq[i].used && s->eq[i].key == key) {
            return i;
        }
    }
    return -1;
}

static void ps3_eq_push(PS3EventQueue *q, const PS3Event *ev)
{
    if (q->count == PS3_EQ_DEPTH) {
        return;                         /* full: the oldest stays queued */
    }
    q->event[(q->head + q->count) % PS3_EQ_DEPTH] = *ev;
    q->count++;
}

static bool ps3_eq_pop(PS3EventQueue *q, PS3Event *ev)
{
    if (!q->count) {
        return false;
    }
    *ev = q->event[q->head];
    q->head = (q->head + 1) % PS3_EQ_DEPTH;
    q->count--;
    return true;
}

static void ps3_event_store(uint8_t *ram, uint64_t ram_size, uint32_t ea,
                            const PS3Event *ev)
{
    if (!ea || (uint64_t)ea + PS3_EQ_EVENT_SIZE > ram_size) {
        return;
    }
    ps3_put_be64(ram + ea, ev->source);
    ps3_put_be64(ram + ea + 8, ev->data1);
    ps3_put_be64(ram + ea + 16, ev->data2);
    ps3_put_be64(ram + ea + 24, ev->data3);
}

/*
 * Finish a call a parked thread was left inside.
 *
 * A receive that had to wait did not return through the trampoline: its exit
 * flag parked the thread at the halt loop.  The caller's context is still in
 * the trampoline's frame - r0, CR and r12 - and in SRR0/SRR1 as they were at
 * the `sc`, which is exactly what ps3_sched_apply reconstructs for a call it
 * completes in place; this is the same epilogue on a saved context.
 */
static void ps3_thread_finish_call(PS3BootROMState *s, PS3Thread *t,
                                   uint8_t *ram, uint64_t ram_size,
                                   uint32_t ret)
{
    uint32_t sp = (uint32_t)t->gpr[1];
    unsigned i;

    t->gpr[3] = ret;
    if (!t->call_collected && (uint64_t)sp + 0x20 <= ram_size) {
        t->call_collected = true;
        uint32_t cr = ps3_be32(ram + sp + 0x0C);

        t->gpr[12] = ps3_be32(ram + sp + 0x10);
        for (i = 0; i < 8; i++) {
            t->crf[i] = (cr >> (28 - 4 * i)) & 0xF;
        }
        t->gpr[0] = ps3_be32(ram + sp + 0x08);
        t->gpr[1] = sp + 0x20;
        if (s->ppu_trace) {
            info_report("ps3-ppu: fold: thread 0x%X wake: sp 0x%X -> 0x%X "
                        "nip 0x%" PRIX64 " srr0 0x%X ret 0x%X", t->id, sp,
                        (uint32_t)t->gpr[1], t->nip, (uint32_t)t->srr0, ret);
        }
    } else if (s->ppu_trace) {
        info_report("ps3-ppu: fold: thread 0x%X wake: sp 0x%X already "
                    "collected, ret 0x%X", t->id, sp, ret);
    }
    if (t->srr0) {
        t->nip = t->srr0;
    }
    /* Through the cached MSR, as a switch does: the next block is keyed on it. */
    t->msr = t->srr1;
    t->blocked = false;
    t->parked = false;
    t->wait_eq = -1;
    t->wait_ticks = -1;
    t->wait_mutex_id = 0;
    t->wait_cond_id = 0;
    t->wait_sem_id = 0;
    t->wait_rwlock_id = 0;
    t->wait_rwlock_write = false;
    /*
     * A lightweight-mutex wait that ended here (a timeout, or a wake that
     * handed the lock on) stops counting as a waiter; the scan is inline
     * because this runs before ps3_lwmutex_index is defined.
     */
    if (t->wait_lwmutex_id) {
        unsigned k;

        for (k = 0; k < PS3_LWMUTEX_MAX; k++) {
            if (s->lwm[k].used && s->lwm[k].id == t->wait_lwmutex_id) {
                if (s->lwm[k].parked) {
                    s->lwm[k].parked--;
                }
                break;
            }
        }
        t->wait_lwmutex_id = 0;
    }
}

/*
 * Hand an event to the first thread waiting on that queue.  Called on the
 * thread that owns the CPU, so the parked context can be written directly.
 */
static bool ps3_eq_wake(PS3BootROMState *s, uint8_t *ram, uint64_t ram_size,
                        int idx)
{
    unsigned i;

    for (i = 0; i < PS3_THREAD_MAX; i++) {
        PS3Thread *t = &s->thr[i];
        PS3Event ev;

        if (!t->used || !t->parked || t->wait_eq != idx) {
            continue;
        }
        if (!ps3_eq_pop(&s->eq[idx], &ev)) {
            return false;
        }
        if (s->ppu_trace) {
            info_report("ps3-ppu: sched: event 0x%" PRIX64 " (0x%" PRIX64
                        ", 0x%" PRIX64 ", 0x%" PRIX64 ") wakes thread "
                        "0x%X on queue 0x%X", ev.source, ev.data1, ev.data2,
                        ev.data3, t->id, s->eq[idx].id);
        }
        ps3_event_store(ram, ram_size, t->wait_ea, &ev);
        /* lv2 returns the same four words in r4..r7 as in the struct. */
        t->gpr[4] = ev.source;
        t->gpr[5] = ev.data1;
        t->gpr[6] = ev.data2;
        t->gpr[7] = ev.data3;
        ps3_thread_finish_call(s, t, ram, ram_size, 0);
        return true;
    }
    return false;
}

/*
 * The queue the MIO2 service answers into.
 *
 * A request names the slot of the caller's own ring the answer must go into,
 * and the caller creates one queue per slot at key + slot: the first client
 * here makes slot 1's queue (key + 1) and sends every request in slot 1, so
 * the two agree.  The lowest queue that exists is the fallback, because a
 * client that names a slot before making its queue is still waiting in the
 * one it has.
 */
static int ps3_mio2_caller(PS3BootROMState *s, uint32_t slot)
{
    unsigned i, k;

    if (slot >= 1 && slot <= PS3_MIO2_REPLIES) {
        for (i = 0; i < PS3_EQ_MAX; i++) {
            if (s->eq[i].used && !s->eq[i].model &&
                s->eq[i].key == PS3_MIO2_KEY + slot) {
                return i;
            }
        }
    }
    for (k = 1; k <= PS3_MIO2_REPLIES; k++) {
        for (i = 0; i < PS3_EQ_MAX; i++) {
            if (s->eq[i].used && !s->eq[i].model &&
                s->eq[i].key == PS3_MIO2_KEY + k) {
                return i;
            }
        }
    }
    return -1;
}

/* Open the service's queue: the peer a connect to its key is looking for. */
static int ps3_mio2_open(PS3BootROMState *s)
{
    int idx = ps3_mio2_service(s);
    unsigned j;

    if (idx >= 0) {
        return idx;
    }
    for (j = 0; j < PS3_EQ_MAX; j++) {
        if (!s->eq[j].used) {
            break;
        }
    }
    if (j == PS3_EQ_MAX) {
        return -1;
    }
    memset(&s->eq[j], 0, sizeof(s->eq[j]));
    s->eq[j].used = true;
    s->eq[j].model = true;
    s->eq[j].id = ++s->lv2_next_id;
    s->eq[j].key = PS3_MIO2_KEY;
    s->eq[j].size = PS3_MIO2_EQ_SIZE;
    info_report("ps3-ppu: lv2: MIO2 service queue 0x%X created for key "
                "0x%" PRIX64 " (the audio device's peer)", s->eq[j].id,
                (uint64_t)PS3_MIO2_KEY);
    return (int)j;
}

/*
 * One request from a client of the service.
 *
 * The device the model speaks for is present and idle, so the commands that
 * bring the audio path up are answered the way the hardware answers them: a
 * result of zero, the caller's correlation word back, and - where a command
 * asks for the device's own numbers - the stereo 48 kHz output this machine
 * has.  A command with no answer here leaves its data alone and is named in
 * the trace, which is where the next thing to model shows up.
 */
static void ps3_mio2_request(PS3BootROMState *s, uint8_t *ram,
                             uint64_t ram_size, int p, uint64_t d1,
                             uint64_t d2, uint64_t d3)
{
    uint32_t cmd = (uint32_t)(d1 >> 53);
    uint32_t slot = (uint32_t)((d1 >> 44) & 0x1F);
    uint32_t arg = (uint32_t)d1;
    /* Each command the model has no meaning for is named once in the trace. */
    static uint32_t unanswered[16];
    static unsigned unanswered_n;
    unsigned i;
    int32_t result = 0;
    PS3Event ev;
    int q;

    if (s->ppu_trace) {
        info_report("ps3-ppu: lv2: MIO2 request: command %u, slot %u, "
                    "arg 0x%X (port 0x%X, d2=0x%" PRIX64 ", d3=0x%" PRIX64
                    ")", cmd, slot, arg, s->ep[p].id, d2, d3);
    }

    ev.source = s->ep[p].id;
    ev.data2 = d2;
    ev.data3 = d3;
    switch (cmd) {
    case 1:
        /*
         * Open.  The caller names its pid in the argument word and checks
         * that the answer carries it back before it trusts the device, so
         * the answer repeats it.
         */
        ev.data2 = ((uint64_t)(uint32_t)(d2 >> 32) << 32) | (uint64_t)arg;
        break;
    case 5:
        /*
         * The device's own numbers.  Two words come back, and for an audio
         * device that can only be what the client's wrappers report on: the
         * output rate and the channel count it mixes.
         */
        ev.data2 = PS3_MIO2_RATE;
        ev.data3 = PS3_MIO2_CHANNELS;
        break;
    default:
        /*
         * A command this model has no meaning for is still answered - a
         * client that gets no result waits for one that never comes - and
         * named once, because the module's answer for it is what the next
         * piece of the device gets written from.
         */
        for (i = 0; i < unanswered_n; i++) {
            if (unanswered[i] == cmd) {
                break;
            }
        }
        if (i == unanswered_n) {
            if (unanswered_n < ARRAY_SIZE(unanswered)) {
                unanswered[unanswered_n++] = cmd;
            }
            info_report("ps3-ppu: lv2: MIO2: command %u has no meaning in "
                        "the model; answering result 0 with the caller's own "
                        "words", cmd);
        }
        break;
    }
    /*
     * The answer names the caller's ring slot: the high half of data1 is the
     * slot and the command, and the low half is this command's result.
     */
    ev.data1 = (d1 & 0xFFFFFFFF00000000ULL) | (uint32_t)result;

    q = ps3_mio2_caller(s, slot);
    if (q < 0) {
        info_report("ps3-ppu: lv2: MIO2: command %u has no queue of the "
                    "caller's to answer into", cmd);
        return;
    }
    ps3_eq_push(&s->eq[q], &ev);
    if (!ps3_eq_wake(s, ram, ram_size, q) && s->ppu_trace) {
        info_report("ps3-ppu: lv2: MIO2: answer to command %u queued on "
                    "0x%X (the client is not waiting yet)", cmd,
                    s->eq[q].id);
    }
}

/*
 * The microphone's sample ring.  One frame is two samples whatever the device
 * was opened with, because the DSP stream the VSH reads is stereo: a mono
 * capture is duplicated rather than handed out with a shifting frame size.
 */
static void ps3_mic_push(PS3BootROMState *s, const int16_t *pcm,
                         unsigned frames, unsigned channels)
{
    unsigned i, ch;

    for (i = 0; i < frames; i++) {
        unsigned slot;

        if (s->mic_used == PS3_MIC_RING_FRAMES) {
            s->mic_head = (s->mic_head + 1) % PS3_MIC_RING_FRAMES;
            s->mic_used--;
        }
        slot = (s->mic_head + s->mic_used) % PS3_MIC_RING_FRAMES;
        for (ch = 0; ch < 2; ch++) {
            s->mic_ring[slot * 2 + ch] =
                pcm[i * channels + (channels == 1 ? 0 : ch)];
        }
        s->mic_used++;
    }
}

static unsigned ps3_mic_take(PS3BootROMState *s, int16_t *dst,
                             unsigned max_frames)
{
    unsigned n = MIN(max_frames, s->mic_used), i;

    for (i = 0; i < n; i++) {
        unsigned slot = (s->mic_head + i) % PS3_MIC_RING_FRAMES;

        dst[i * 2] = s->mic_ring[slot * 2];
        dst[i * 2 + 1] = s->mic_ring[slot * 2 + 1];
    }
    s->mic_head = (s->mic_head + n) % PS3_MIC_RING_FRAMES;
    s->mic_used -= n;

    return n;
}

/* The level cellMicGetSignalState reports, on RPCS3's cellMic scale. */
static void ps3_mic_measure(PS3BootROMState *s, const int16_t *pcm,
                            unsigned frames)
{
    const unsigned n = frames * 2;
    double sum = 0.0;
    float rms, db;
    unsigned i;

    for (i = 0; i < n; i++) {
        double v = pcm[i] / 32767.0;

        sum += v * v;
    }
    rms = n ? sqrt(sum / n) : 0.0;
    db = 90.0f + 20.0f * log10f(MAX(rms, 0.00001f)) * 0.5f;
    s->mic_energy_db = CLAMP(db, 40.0f, 90.0f);
}

/* Pull what the host captured into the ring; a short read is normal. */
static void ps3_mic_pump(PS3BootROMState *s)
{
    int16_t pcm[PS3_MIC_BLOCK_FRAMES * 2];
    size_t bytes, frame_bytes;

    if (!s->mic_opened || !s->mic_started || !ps3_audio_mic_active(s->audio)) {
        return;
    }

    frame_bytes = sizeof(int16_t) * s->mic_channels;
    bytes = ps3_audio_mic_read(s->audio, pcm,
                               frame_bytes * PS3_MIC_BLOCK_FRAMES);
    if (bytes < frame_bytes) {
        return;                     /* the input has no full frame yet */
    }

    ps3_mic_push(s, pcm, bytes / frame_bytes, s->mic_channels);
}

/*
 * The notify half of the microphone, on the vCPU thread: the guest waits in
 * sys_event_queue_receive for CELLMIC_DATA, so the samples have to arrive as
 * an event before it ever calls cellMicRead.
 */
static void ps3_mic_apply(CPUState *cs, run_on_cpu_data data)
{
    PS3BootROMState *s = data.host_ptr;
    uint8_t *ram = memory_region_get_ram_ptr(s->ram);
    uint64_t ram_size = memory_region_size(s->ram);
    int q;

    s->mic_queued = false;
    ps3_mic_pump(s);

    if (!s->mic_used || !s->mic_eq_key) {
        return;
    }
    q = ps3_eq_index_key(s, s->mic_eq_key);
    if (q < 0) {
        return;
    }

    {
        PS3Event ev = {
            .source = s->mic_eq_source,
            .data1 = 5,             /* CELLMIC_DATA */
            .data2 = 0,             /* device 0 */
            .data3 = 0,
        };

        ps3_eq_push(&s->eq[q], &ev);
        ps3_eq_wake(s, ram, ram_size, q);
    }
}

static int ps3_ep_index(PS3BootROMState *s, uint32_t id)
{
    unsigned i;

    for (i = 0; i < PS3_EP_MAX; i++) {
        if (s->ep[i].used && s->ep[i].id == id) {
            return i;
        }
    }
    return -1;
}

/*
 * A receive with nothing queued: lv2 blocks the caller.  The trampoline's
 * exit flag parks it at its halt loop, and the call is finished from the
 * saved frame - by a send, or by the timeout running out.
 */
static void ps3_eq_park(PS3BootROMState *s, int idx, uint32_t event_ea,
                        uint64_t timeout_us)
{
    PS3Thread *t;
    int64_t ticks;

    if (s->thr_cur < 0 || !s->thr[s->thr_cur].used) {
        return;
    }
    t = &s->thr[s->thr_cur];
    /* A sleep always ends; a receive with a zero timeout never does. */
    ticks = (idx < 0 || timeout_us) ? (int64_t)(timeout_us / 1000) : -1;
    if (ticks > PS3_EQ_TIMEOUT_MAX_TICKS) {
        ticks = PS3_EQ_TIMEOUT_MAX_TICKS;
    }
    t->parked = true;
    t->blocked = true;
    t->wait_eq = idx;
    t->wait_ea = event_ea;
    t->wait_ticks = (int32_t)ticks;
    s->lv2_park = true;
    s->sched_pending = true;
}

static int ps3_mutex_index(PS3BootROMState *s, uint32_t id)
{
    unsigned i;

    for (i = 0; i < PS3_MUTEX_MAX; i++) {
        if (s->mtx[i].used && s->mtx[i].id == id) {
            return i;
        }
    }
    return -1;
}

static int ps3_rwlock_index(PS3BootROMState *s, uint32_t id)
{
    unsigned i;

    for (i = 0; i < PS3_RWLOCK_MAX; i++) {
        if (s->rw[i].used && s->rw[i].id == id) {
            return i;
        }
    }
    return -1;
}

static int ps3_sem_index(PS3BootROMState *s, uint32_t id)
{
    unsigned i;

    for (i = 0; i < PS3_SEM_MAX; i++) {
        if (s->sem[i].used && s->sem[i].id == id) {
            return i;
        }
    }
    return -1;
}

static int ps3_cond_index(PS3BootROMState *s, uint32_t id)
{
    unsigned i;

    for (i = 0; i < PS3_COND_MAX; i++) {
        if (s->cond[i].used && s->cond[i].id == id) {
            return i;
        }
    }
    return -1;
}

static int ps3_lwmutex_index(PS3BootROMState *s, uint32_t id)
{
    unsigned i;

    for (i = 0; i < PS3_LWMUTEX_MAX; i++) {
        if (s->lwm[i].used && s->lwm[i].id == id) {
            return i;
        }
    }
    return -1;
}

/*
 * Publish the lock into the guest's own `sys_lwmutex_t`.  The library locks
 * that block with lwarx/stwcx before it calls lv2, so an acquire or a release
 * that only updated the model would leave the library believing the lock is
 * still held (or not its own), and its 100 us retry loop would never end.
 * `owner' is the word the library compares against its own thread id.
 */
static void ps3_lwmutex_sync(PS3BootROMState *s, uint8_t *ram,
                             uint64_t ram_size, int m)
{
    uint32_t at = s->lwm[m].control;

    if (!at || (uint64_t)at + 0x14 > ram_size) {
        return;
    }
    ps3_put_be32(ram + at, s->lwm[m].owner ? s->lwm[m].owner
                                           : PS3_LWMUTEX_FREE);
    ps3_put_be32(ram + at + 4, s->lwm[m].parked ? 1 : 0);
    ps3_put_be32(ram + at + 0x10, s->lwm[m].id);
}

/*
 * A release the library did in its own fast path leaves `owner' free in guest
 * memory without telling lv2, so the block is the authority: if it says the
 * lock is free, the model's owner is stale and its waiters have to be served.
 */
static void ps3_lwmutex_reconcile(PS3BootROMState *s, uint8_t *ram,
                                  uint64_t ram_size, int m)
{
    uint32_t at = s->lwm[m].control;

    if (!at || (uint64_t)at + 4 > ram_size) {
        return;
    }
    if (s->lwm[m].owner && ps3_be32(ram + at) == PS3_LWMUTEX_FREE) {
        s->lwm[m].owner = 0;
    }
}

/*
 * Hand a released lightweight mutex to the first thread parked on it: the new
 * owner goes into the guest block before the waiter is woken, so the woken
 * thread finds the lock already its own and does not queue behind itself.
 */
static void ps3_lwmutex_handoff(PS3BootROMState *s, uint8_t *ram,
                                uint64_t ram_size, int m)
{
    unsigned i;

    if (s->lwm[m].owner) {
        return;
    }
    for (i = 0; i < PS3_THREAD_MAX; i++) {
        PS3Thread *t = &s->thr[i];

        if (!t->used || !t->parked || t->dead ||
            t->wait_lwmutex_id != s->lwm[m].id) {
            continue;
        }
        s->lwm[m].owner = t->id;
        if (s->lwm[m].parked) {
            s->lwm[m].parked--;
        }
        t->wait_lwmutex_id = 0;
        ps3_lwmutex_sync(s, ram, ram_size, m);
        ps3_thread_finish_call(s, t, ram, ram_size, 0);
        return;
    }
    ps3_lwmutex_sync(s, ram, ram_size, m);
}

/* Park the current thread in a blocking synchronization call. */
static void ps3_sync_park(PS3BootROMState *s, uint64_t timeout_us)
{
    PS3Thread *t;
    int64_t ticks;

    if (s->thr_cur < 0 || !s->thr[s->thr_cur].used) {
        return;
    }
    t = &s->thr[s->thr_cur];
    ticks = timeout_us ? (int64_t)(timeout_us / 1000) : -1;
    if (ticks > PS3_EQ_TIMEOUT_MAX_TICKS) {
        ticks = PS3_EQ_TIMEOUT_MAX_TICKS;
    }
    t->parked = true;
    t->blocked = true;
    t->wait_eq = -2;                /* a lock wait, not a queue */
    t->wait_ea = 0;
    t->wait_ticks = (int32_t)ticks;
    s->lv2_park = true;
    s->sched_pending = true;
}

/* Give a posted semaphore to the first thread waiting for it. */
static void ps3_sem_handoff(PS3BootROMState *s, uint8_t *ram,
                            uint64_t ram_size, int m)
{
    unsigned i;

    if (s->sem[m].count <= 0) {
        return;
    }
    for (i = 0; i < PS3_THREAD_MAX; i++) {
        PS3Thread *t = &s->thr[i];

        if (!t->used || !t->parked || t->wait_sem_id != s->sem[m].id) {
            continue;
        }
        s->sem[m].count--;
        t->wait_sem_id = 0;
        ps3_thread_finish_call(s, t, ram, ram_size, 0);
        return;
    }
}

/* Give the mutex to the first thread waiting for it, when it is free. */
/*
 * Hand a free read/write lock on: a queued writer first (it was queued before
 * any reader that arrives now), and only when no writer is queued do the
 * readers get it, all of them in one pass.
 */
static void ps3_rwlock_handoff(PS3BootROMState *s, uint8_t *ram,
                               uint64_t ram_size, int r)
{
    unsigned i;

    if (s->rw[r].writer || s->rw[r].readers) {
        return;
    }
    if (s->rw[r].wait_writers) {
        for (i = 0; i < PS3_THREAD_MAX; i++) {
            PS3Thread *t = &s->thr[i];

            if (!t->used || !t->parked || !t->wait_rwlock_write ||
                t->wait_rwlock_id != s->rw[r].id) {
                continue;
            }
            s->rw[r].writer = t->id;
            s->rw[r].wait_writers--;
            t->wait_rwlock_id = 0;
            t->wait_rwlock_write = false;
            ps3_thread_finish_call(s, t, ram, ram_size, 0);
            return;
        }
    }
    for (i = 0; i < PS3_THREAD_MAX; i++) {
        PS3Thread *t = &s->thr[i];

        if (!t->used || !t->parked || t->wait_rwlock_write ||
            t->wait_rwlock_id != s->rw[r].id) {
            continue;
        }
        s->rw[r].readers++;
        t->wait_rwlock_id = 0;
        ps3_thread_finish_call(s, t, ram, ram_size, 0);
    }
}

static void ps3_mutex_handoff(PS3BootROMState *s, uint8_t *ram,
                              uint64_t ram_size, int m)
{
    unsigned i;

    if (s->mtx[m].owner) {
        return;
    }
    for (i = 0; i < PS3_THREAD_MAX; i++) {
        PS3Thread *t = &s->thr[i];

        if (!t->used || !t->parked ||
            t->wait_mutex_id != s->mtx[m].id) {
            continue;
        }
        s->mtx[m].owner = t->id;
        t->wait_mutex_id = 0;
        ps3_thread_finish_call(s, t, ram, ram_size, 0);
        return;
    }
}

/*
 * Wake the waiters of a condition.  lv2's cond_wait releases the mutex it is
 * given and takes it again before it returns, so a thread only completes when
 * the mutex is free; otherwise it stays parked and queues for the lock.
 */
static void ps3_cond_wake(PS3BootROMState *s, uint8_t *ram,
                          uint64_t ram_size, int c, bool all)
{
    unsigned i;

    for (i = 0; i < PS3_THREAD_MAX; i++) {
        PS3Thread *t = &s->thr[i];
        int m;

        if (!t->used || !t->parked ||
            t->wait_cond_id != s->cond[c].id) {
            continue;
        }
        t->wait_cond_id = 0;
        m = ps3_mutex_index(s, s->cond[c].mutex);
        if (m >= 0 && !s->mtx[m].owner) {
            s->mtx[m].owner = t->id;
            ps3_thread_finish_call(s, t, ram, ram_size, 0);
        } else if (m >= 0) {
            t->wait_mutex_id = s->mtx[m].id;
        }
        if (!all) {
            return;
        }
    }
}

/*
 * The parked calls whose time is up.  Runs right after the outgoing thread
 * has been saved, so every context it touches is a saved one.
 */
static void ps3_eq_expire(PS3BootROMState *s, uint8_t *ram, uint64_t ram_size)
{
    unsigned i;

    for (i = 0; i < PS3_THREAD_MAX; i++) {
        PS3Thread *t = &s->thr[i];

        if (!t->used || !t->parked || t->wait_ticks < 0) {
            continue;
        }
        if (t->wait_ticks > 0) {
            t->wait_ticks--;
            continue;
        }
        if (s->ppu_trace) {
            info_report("ps3-ppu: sched: thread 0x%X timed out%s", t->id,
                        t->wait_eq >= 0 ? " on its queue" : " sleeping");
        }
        t->gpr[4] = t->gpr[5] = t->gpr[6] = t->gpr[7] = 0;
        /* A sleep ends normally; every other wait reports the timeout. */
        ps3_thread_finish_call(s, t, ram, ram_size,
                               t->wait_eq == -1 ? 0 : PS3_LV2_ETIMEDOUT);
    }
}

static void ps3_sched_switch(PS3BootROMState *s, CPUPPCState *env)
{
    int start = s->thr_cur;
    int next = -1;
    int i;

    if (start >= 0 && s->thr[start].used) {
        ps3_thread_save(&s->thr[start], env);
        if (s->ppu_trace) {
            info_report("ps3-ppu: sched: thread 0x%X yields at 0x%" PRIX64
                        " (lr=0x%" PRIX64 ", sp=0x%X, srr0=0x%" PRIX64 ")",
                        s->thr[start].id, s->thr[start].nip,
                        s->thr[start].lr, (uint32_t)s->thr[start].gpr[1],
                        s->thr[start].srr0);
        }
    }

    /* Every context is saved by now, so an expired wait is safe to finish. */
    ps3_eq_expire(s, memory_region_get_ram_ptr(s->ram),
                  memory_region_size(s->ram));

    for (i = 1; i <= PS3_THREAD_MAX; i++) {
        int idx = (start + i + PS3_THREAD_MAX) % PS3_THREAD_MAX;

        if (s->thr[idx].used && !s->thr[idx].dead && !s->thr[idx].blocked) {
            next = idx;
            break;
        }
    }

    if (next < 0 && start >= 0 && s->thr[start].used &&
        !s->thr[start].dead && !s->thr[start].blocked) {
        next = start;
    }
    if (next < 0) {
        /*
         * Nothing to run: every thread is parked.  Say who waits on what once,
         * because an all-parked machine makes no further log line and the
         * reason it stopped is then only visible in its contexts.
         */
        if (!s->all_parked_reported) {
            s->all_parked_reported = true;
            for (i = 0; i < PS3_THREAD_MAX; i++) {
                if (!s->thr[i].used) {
                    continue;
                }
                info_report("ps3-ppu: sched: all parked: thread 0x%X%s at 0x%"
                            PRIX64 " eq=%d mutex=0x%X cond=0x%X sem=0x%X ticks=%d%s",
                            s->thr[i].id, s->thr[i].dead ? " (dead)" : "",
                            s->thr[i].nip, s->thr[i].wait_eq,
                            s->thr[i].wait_mutex_id, s->thr[i].wait_cond_id,
                            s->thr[i].wait_sem_id, s->thr[i].wait_ticks,
                            s->thr[i].parked ? " parked" : "");
            }
        }
        return;
    }
    s->all_parked_reported = false;

    s->thr_cur = next;
    s->thr_slice = 0;
    s->thr[next].last_run = s->sched_ticks;
    s->thr[next].stall_reported = false;
    ps3_thread_restore(&s->thr[next], env);
    if (s->ppu_trace) {
        info_report("ps3-ppu: sched: -> thread 0x%X at 0x%" PRIX64
                    " (msr=0x%" PRIX64 ")", s->thr[next].id,
                    s->thr[next].nip, s->thr[next].msr);
    }
}

/*
 * The switch, on the thread that owns the CPU.
 *
 * A thread between its `sc` and the trampoline's `rfid` cannot be resumed at
 * that point, so the trampoline is finished here instead: its frame holds the
 * caller's r12, CR and r0, and SRR0/SRR1 are what the `rfid` would return to.
 * That is the same epilogue the guest's own code runs at 0xC40..0xC54, so the
 * saved context is an ordinary one.  This matters for a worker that calls lv2
 * in a loop - the tick almost always lands inside the trampoline for it, and
 * deferring the switch would starve every other thread.
 */
static void ps3_sched_apply(CPUState *cs, run_on_cpu_data data)
{
    PS3BootROMState *s = data.host_ptr;
    CPUPPCState *env = &POWERPC_CPU(cs)->env;

    s->sched_queued = false;
    if (!s->sched_pending || s->thr_cur < 0) {
        return;
    }

    if (env->nip >= 0xC00 && env->nip < 0xC60) {
        uint8_t *ram = memory_region_get_ram_ptr(s->ram);
        uint64_t ram_size = memory_region_size(s->ram);
        uint32_t sp = env->gpr[1];
        uint64_t from = env->nip;
        uint32_t cr;
        unsigned i;

        if (env->nip < 0xC28 || (uint64_t)sp + 0x14 > ram_size) {
            return;                     /* the call is still in flight */
        }
        /*
         * 0xC28..0xC3C are the trampoline's collection of the result; from
         * 0xC40 on it has started restoring the caller, `addi r1' included.
         * Folding a frame the trampoline has already restored steps r1 past
         * the caller's own frame, whose epilogue then reads a local as the
         * saved LR and returns into the stack - the null-LR fault.  The
         * epilogue is safe to preempt in now that SRR0/SRR1 travel with the
         * thread: resuming at 0xC50 finishes the `addi' and the `rfid'.
         */
        if (env->nip >= 0xC40) {
            s->sched_pending = false;
            ps3_sched_switch(s, env);
            return;
        }

        /*
         * The collection itself: r3 comes from the scratch block and the exit
         * flag from the word after it.  Skipping it left the caller's r3 (a
         * pointer) as the call's return value, which read as an error - the
         * stdio lock initialiser called abort() over a sys_lwmutex_create
         * that had in fact succeeded.
         */
        env->gpr[3] = ps3_be32(ram + PS3_LV2_SCRATCH);
        if (s->thr_cur >= 0 && s->thr[s->thr_cur].used &&
            s->thr[s->thr_cur].call_collected) {
            /*
             * The wake path already folded this call up (it finishes a parked
             * thread itself); collecting it again would step r1 past the
             * trampoline twice.
             */
            s->sched_pending = false;
            ps3_sched_switch(s, env);
            return;
        }
        if (ps3_be32(ram + PS3_LV2_SCRATCH + 4)) {
            /*
             * Parked, not finished: the wake path owns the frame, so the
             * collected flag stays clear for it or the +0x20 that steps r1 out
             * of the trampoline would never happen.
             */
            env->nip = 0xC58;           /* the trampoline's halt loop */
            /*
             * A blocking call: the thread is parked here until the service
             * completes it.  Its frame and SRR0/SRR1 are exactly what the
             * completion needs, and the switch saves them, so this is a
             * safe point to let another thread run - which is what makes a
             * worker waiting on its queue stop occupying the core.
             */
            if (s->thr_cur >= 0 && s->thr[s->thr_cur].used &&
                s->thr[s->thr_cur].parked) {
                s->sched_pending = false;
                ps3_sched_switch(s, env);
            }
            return;
        }
        env->gpr[12] = ps3_be32(ram + sp + 0x10);
        cr = ps3_be32(ram + sp + 0x0C);
        for (i = 0; i < 8; i++) {
            env->crf[i] = (cr >> (28 - 4 * i)) & 0xF;
        }
        env->gpr[0] = ps3_be32(ram + sp + 0x08);
        env->gpr[1] = sp + 0x20;
        /*
         * A return address that is not in the image cannot be executed: the
         * thread would fetch address 0 and die on the 0x700 vector, which says
         * nothing about why.  Park it on the trampoline's halt loop and name
         * the call it was returning from instead.
         */
        if (!env->spr[SPR_SRR0] || env->spr[SPR_SRR0] >= ram_size) {
            if (!s->thr[s->thr_cur].fault_reported) {
                s->thr[s->thr_cur].fault_reported = true;
                info_report("ps3-ppu: sched: thread 0x%X returns to 0x%"
                            PRIX64 " from lv2 call 0x%llX (sp 0x%X, "
                            "lr 0x%" PRIX64 "): parked on the trampoline",
                            s->thr[s->thr_cur].id,
                            (uint64_t)env->spr[SPR_SRR0],
                            (unsigned long long)env->gpr[11],
                            (uint32_t)env->gpr[1], (uint64_t)env->lr);
            }
            env->nip = 0xC58;
            ppc_store_msr(env, env->spr[SPR_SRR1]);
            s->sched_pending = false;
            ps3_sched_switch(s, env);
            return;
        }
        env->nip = env->spr[SPR_SRR0];
        s->thr[s->thr_cur].call_collected = true;
        s->thr[s->thr_cur].call_folded_srr0 = env->spr[SPR_SRR0];
        if (s->ppu_trace) {
            info_report("ps3-ppu: fold: thread 0x%X apply at 0x%" PRIX64
                        ": sp 0x%X -> 0x%X nip 0x%" PRIX64,
                        s->thr[s->thr_cur].id, from,
                        sp, (uint32_t)env->gpr[1], (uint64_t)env->nip);
        }
        /* The MSR the trampoline's rfid would load, through the same path. */
        ppc_store_msr(env, env->spr[SPR_SRR1]);
    }

    s->sched_pending = false;
    ps3_sched_switch(s, env);
}

/*
 * A thread that has not had the CPU for a long time is either parked in an lv2
 * call or starved by the threads that are polling.  Say which, once per stall:
 * a machine that stops making progress otherwise only shows its idle loops, and
 * the wait the block is on is then invisible.
 */
static void ps3_sched_stall_report(PS3BootROMState *s)
{
    unsigned i;

    for (i = 0; i < PS3_THREAD_MAX; i++) {
        PS3Thread *t = &s->thr[i];

        if (!t->used || t->dead || t->stall_reported) {
            continue;
        }
        if (s->sched_ticks - t->last_run < 512) {
            continue;
        }
        t->stall_reported = true;
        info_report("ps3-ppu: sched: thread 0x%X stalled %" PRIu64
                    " ticks at 0x%" PRIX64 " (blocked=%d parked=%d eq=%d "
                    "mutex=0x%X cond=0x%X sem=0x%X ticks=%d)",
                    t->id, s->sched_ticks - t->last_run, t->nip,
                    t->blocked, t->parked, t->wait_eq, t->wait_mutex_id,
                    t->wait_cond_id, t->wait_sem_id, t->wait_ticks);

        /*
         * A thread queued for a lock names the lock; who holds it is the
         * other half of the answer, and without it a stall reads as if the
         * waiter were at fault.  Report the owner and where it is, so a lock
         * held by a thread that is itself blocked is visible as the deadlock
         * it is.
         */
        if (t->wait_mutex_id) {
            int m = ps3_mutex_index(s, t->wait_mutex_id);
            unsigned o;
            PS3Thread *owner = NULL;

            for (o = 0; m >= 0 && o < PS3_THREAD_MAX; o++) {
                if (s->thr[o].used && s->thr[o].id == s->mtx[m].owner) {
                    owner = &s->thr[o];
                    break;
                }
            }
            if (!owner) {
                info_report("ps3-ppu: sched:   its lock 0x%X has no owner",
                            t->wait_mutex_id);
            } else {
                info_report("ps3-ppu: sched:   its lock 0x%X is held by "
                            "thread 0x%X at 0x%" PRIX64 " (blocked=%d "
                            "parked=%d dead=%d eq=%d mutex=0x%X)",
                            t->wait_mutex_id, owner->id, owner->nip,
                            owner->blocked, owner->parked, owner->dead,
                            owner->wait_eq, owner->wait_mutex_id);
            }
        }
    }
}

/*
 * A thread that keeps coming back to the same page is not making progress, and
 * the page alone does not say why: its caller is what says which wait it is in.
 * Walk the ABI backchain out of its stack so the report names the call chain
 * rather than one address inside it.
 */
static void ps3_sched_spin_report(PS3BootROMState *s, PS3Thread *t,
                                  CPUPPCState *env)
{
    uint64_t ram_size = memory_region_size(s->ram);
    uint8_t *ram = memory_region_get_ram_ptr(s->ram);
    uint64_t r1 = env->gpr[1];
    unsigned i;

    info_report("ps3-ppu: sched: thread 0x%X spinning in the 0x%" PRIX64
                " page at 0x%" PRIX64 " (lr=0x%" PRIX64 ", sp=0x%" PRIX64
                ")", t->id, t->spin_page, (uint64_t)env->nip,
                (uint64_t)env->lr, r1);
    /*
     * A jump to address 0 is a call through a descriptor that was never
     * filled, and which descriptor it was is in the registers the call used:
     * the callee's code and TOC words, and the entry the caller loaded them
     * from.  `ctr` is what the call actually branched to, so a zero there and
     * a zero at [r9] name the same broken entry.
     */
    info_report("ps3-ppu: sched:   ctr=0x%" PRIX64 " r0=0x%" PRIX64
                " r2=0x%" PRIX64 " r3=0x%" PRIX64 " r9=0x%" PRIX64
                " r11=0x%" PRIX64 " r31=0x%" PRIX64,
                (uint64_t)env->ctr, (uint64_t)env->gpr[0],
                (uint64_t)env->gpr[2], (uint64_t)env->gpr[3],
                (uint64_t)env->gpr[9], (uint64_t)env->gpr[11],
                (uint64_t)env->gpr[31]);
    {
        unsigned k, n = s->call_ring_pos < PS3_CALL_RING ?
                        s->call_ring_pos : PS3_CALL_RING;

        for (k = 0; k < n && k < 8; k++) {
            PS3Call *c = &s->call_ring[(s->call_ring_pos - n + k) %
                                       PS3_CALL_RING];

            info_report("ps3-ppu: sched:   call 0x%X from lr=0x%" PRIX64
                        " sp=0x%" PRIX64 " tid=%d", c->nr, c->lr, c->sp,
                        c->tid);
        }
    }

    for (i = 0; i < 12 && r1 && r1 + 0x18 <= ram_size; i++) {
        uint64_t next = ps3_be64(ram + r1);
        uint64_t ret = ps3_be64(ram + r1 + 0x10);

        info_report("ps3-ppu: sched:   frame %u: sp 0x%" PRIX64
                    " return 0x%" PRIX64, i, r1, ret);
        if (next <= r1) {
            break;
        }
        r1 = next;
    }
}

static void ps3_sched_tick(void *opaque)
{
    PS3BootROMState *s = opaque;
    CPUState *cs = qemu_get_cpu(0);

    s->sched_ticks++;
    if (!(s->sched_ticks & 0x3F)) {
        ps3_sched_stall_report(s);
    }

    /*
     * Sample the running thread's code page on every tick.  A thread that
     * stays on one page for hundreds of slices is looping there, and the
     * stack says what it is looping over.
     */
    if (cs && s->thr_cur >= 0 && s->thr[s->thr_cur].used &&
        !s->thr[s->thr_cur].parked) {
        PS3Thread *t = &s->thr[s->thr_cur];
        CPUPPCState *env = cpu_env(cs);
        uint64_t page = env->nip & ~0xFFFULL;

        if (page == t->spin_page) {
            if (++t->spin_ticks == 512 && !t->spin_reported) {
                t->spin_reported = true;
                ps3_sched_spin_report(s, t, env);
            }
        } else {
            t->spin_page = page;
            t->spin_ticks = 1;
            t->spin_reported = false;
        }
    }

    /*
     * A thread that called sys_ppu_thread_exit is parked on its trampoline's
     * `b .`; lv2 switches away from it at the next tick.  Set the yield here
     * too, or the run idles on a dead thread when its exit did not ask for a
     * switch itself.
     */
    if (cs && s->thr_cur >= 0 && s->thr[s->thr_cur].used &&
        s->thr[s->thr_cur].dead) {
        s->sched_pending = true;
    }

    /*
     * Timeslice preemption.  A worker polling a flag spends its whole slice in
     * guest code and never reaches lv2, so nothing else would ever run: the
     * VSH's main thread blocks on what those workers publish.  When the slice
     * is up, ask for the switch the same way a blocking call does.
     */
    if (cs && s->thr_cur >= 0 && s->thr[s->thr_cur].used &&
        !s->sched_pending && ++s->thr_slice >= PS3_SCHED_SLICE_TICKS) {
        s->sched_pending = true;
        if (s->ppu_trace) {
            info_report("ps3-ppu: sched: thread 0x%X slice up at 0x%" PRIX64,
                        s->thr[s->thr_cur].id, s->thr[s->thr_cur].nip);
        }
    }

    /*
     * The microphone.  Its samples arrive from the host between ticks, and the
     * guest has to be told from the vCPU thread - the event path finishes a
     * parked receive and writes the guest's memory - so the pump is queued
     * like a thread switch, on the same timer.
     */
    if (s->mic_started && ++s->mic_tick >= PS3_MIC_PERIOD_TICKS) {
        s->mic_tick = 0;
        if (cs && !s->mic_queued) {
            s->mic_queued = true;
            run_on_cpu(cs, ps3_mic_apply, RUN_ON_CPU_HOST_PTR(s));
        }
    }

    /*
     * The switch itself runs on the vCPU thread (ps3_sched_apply): this timer
     * fires on the I/O thread while the guest is executing without the BQL, so
     * writing the CPU state from here would race the translation block that is
     * running.  QEMU restores the guest PC from that block when it stops
     * (`synchronize_from_tb`), which overwrote the restored context and left
     * every thread frozen at the instruction it was switched out on.
     */
    if (cs && s->sched_pending && !s->sched_queued) {
        s->sched_queued = true;
        run_on_cpu(cs, ps3_sched_apply, RUN_ON_CPU_HOST_PTR(s));
    }

    /*
     * Heartbeat.  A guest that spins in its own code produces no lv2 line at
     * all, and then the run looks identical to one that is idle: say once every
     * ten seconds which thread holds the CPU and where it is.
     */
    if (cs && s->thr_cur >= 0 && s->thr[s->thr_cur].used &&
        ++s->hb_tick >= 10000) {
        s->hb_tick = 0;
        info_report("ps3-ppu: sched: heartbeat: thread 0x%X at 0x%" PRIX64
                    " (lr=0x%" PRIX64 ", sp=0x%X)",
                    s->thr[s->thr_cur].id, s->thr[s->thr_cur].nip,
                    s->thr[s->thr_cur].lr,
                    (uint32_t)s->thr[s->thr_cur].gpr[1]);
    }

    if (s->sched_timer) {
        timer_mod(s->sched_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                  1000000);
    }
}

/*
 * A thread the guest asked lv2 to create.  It gets a stack and an entry
 * context now, and the tick timer starts running it once the creating thread
 * blocks or sleeps.
 */
static uint32_t ps3_lv2_thread_created(PS3BootROMState *s, uint8_t *ram,
                                       uint64_t ram_size, CPUPPCState *env,
                                       uint32_t entry, uint32_t tls,
                                       uint32_t arg, uint32_t stack,
                                       int32_t prio, uint32_t name)
{
    char text[32];
    PS3Thread *t = NULL;
    uint32_t code, toc, stub, base, size, top;
    unsigned i;

    for (i = 0; i < PS3_THREAD_MAX; i++) {
        if (!s->thr[i].used) {
            t = &s->thr[i];
            break;
        }
    }
    if (!t || !entry) {
        return 0;
    }

    if (!s->threads_enabled) {
        /* Default: report the thread without running its body. */
        uint32_t id = ++s->lv2_next_id;

        g_strlcpy(text, "?", sizeof(text));
        if (name && !ps3_lv2_guest_string(ram, ram_size, name, text,
                                          sizeof(text))) {
            g_strlcpy(text, "?", sizeof(text));
        }
        info_report("ps3-ppu: lv2: thread \"%s\" created (id 0x%X) but not "
                    "scheduled (threads=off)", text, id);
        return id;
    }

    size = stack ? (stack & ~0x0000000Fu) : 0x10000;
    size = CLAMP(size, 0x4000, 0x200000);
    base = (s->lv2_heap + 0xF) & ~0x0000000Fu;
    stub = (base + size + 0xF) & ~0x0000000Fu;
    if ((uint64_t)stub + 0x10 > ram_size ||
        (uint64_t)base + size > stub) {
        return 0;
    }
    top = base + size - 0x100;
    ps3_put_be64(ram + top, 0);  /* the outermost frame's back chain */
    s->lv2_heap = stub + 0x10;
    ps3_put_be32(ram + PS3_LV2_HEAP, s->lv2_heap);

    /* Returning from the entry ends at sys_ppu_thread_exit(0). */
    ps3_put_be32(ram + stub, 0x39600029u);       /* li r11, 0x29 */
    ps3_put_be32(ram + stub + 4, 0x44000002u);   /* sc */
    ps3_put_be32(ram + stub + 8, 0x48000000u);   /* b . */

    /*
     * The entry is a function descriptor, which lv2 writes as a packed
     * 8-byte pair: the code address then the module's TOC.  The 16-byte
     * word-pair layout appears in a few process entries, so fall back to it
     * when the packed half is not usable.
     */
    code = 0;
    toc = 0;
    if ((uint64_t)entry + 8 <= ram_size) {
        code = ps3_be32(ram + entry);
        toc = ps3_be32(ram + entry + 4);
    }
    if ((!code || code >= ram_size || !toc || toc >= ram_size) &&
        (uint64_t)entry + 16 <= ram_size) {
        code = ps3_be64(ram + entry);
        toc = ps3_be64(ram + entry + 8);
    }
    if (!toc || toc >= ram_size) {
        toc = env->gpr[2];
    }
    if (!code || code >= ram_size) {
        return 0;
    }

    g_strlcpy(text, "?", sizeof(text));
    if (name &&
        !ps3_lv2_guest_string(ram, ram_size, name, text, sizeof(text))) {
        g_strlcpy(text, "?", sizeof(text));
    }

    memset(t, 0, sizeof(*t));
    t->used = true;
    t->id = ++s->lv2_next_id;
    t->prio = (int32_t)prio;
    t->stack_base = base;
    t->stack_size = size;
    /*
     * lv2 starts a user thread with a clean register file: r3 is the
     * argument, r13 the thread's TLS base, r2 the entry's TOC.  Inheriting
     * the creator's registers would leak its syscall result (r3/r31) and
     * scratch values into the thread body.
     */
    memset(t->gpr, 0, sizeof(t->gpr));
    t->gpr[1] = top;
    t->gpr[2] = toc;
    t->gpr[3] = arg;
    t->gpr[13] = (tls && tls < ram_size) ? tls : env->gpr[13];
    if (t->gpr[13] >= ram_size) {
        t->gpr[13] = 0;
    }
    t->exit_stub = stub;
    t->lr = stub;
    t->nip = code;
    /*
     * The thread runs in the same state as the process's main one: PR clear,
     * so the 970's real-mode mapping stays in force and every fetch of the
     * process image resolves the way the main thread's does.  With PR set the
     * core takes the user-process path instead, where a fetch has to find an
     * SLB entry - and this model has none, so the first instruction after a
     * worker's `sc` would take an instruction segment exception (0x480) and
     * every thread would park on the 0x700 vector.  A `sc` with PR clear still
     * enters the lv2 trampoline at 0xC00, which is also where the `rfid` that
     * returns from it needs supervisor state.  lv2 enables FP and VR too.
     */
    t->msr = env->msr | (1ULL << MSR_FP) | (1ULL << MSR_VR);

    if (s->thr_cur < 0) {
        /* Register the thread that is running now as the process's main one. */
        for (i = 0; i < PS3_THREAD_MAX; i++) {
            if (&s->thr[i] != t && !s->thr[i].used) {
                s->thr[i].used = true;
                s->thr[i].main = true;
                s->thr[i].id = 0;
                /* Its context is saved by the first switch, not here. */
                s->thr_cur = i;
                break;
            }
        }
    }

    if (!s->sched_timer) {
        s->sched_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ps3_sched_tick, s);
    }
    s->sched_pending = true;
    timer_mod(s->sched_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000000);

    info_report("ps3-ppu: lv2: thread \"%s\" created (id 0x%X), entry "
                "0x%X, toc 0x%X, arg 0x%X, stack 0x%X-0x%X (from lr "
                "0x%" PRIX64 ")", text, t->id, code, toc, arg, base, top,
                (uint64_t)env->lr);
    return t->id;
}

/*
 * sys_io's exports, answered from the port table above.
 *
 * The VSH reaches cellPad through libpad, which reaches this library directly;
 * libpadconfig also uses the sys_config services to be told when a pad is
 * plugged in.  Nothing here blocks and nothing is asynchronous: the ports are
 * always in the state the properties described, so a port is either there with
 * a product or absent, and the services say which.
 *
 * Returns true when the NID is one of ours, with the result in *ret.
 */
/*
 * cellVideoOut: the VSH's AV layer reads the sink, picks a mode and configures
 * it.  The NIDs are lv2's name-hash values, so imports of this library land
 * here instead of on a placeholder stub.  ps3-vga is the sink: it answers with
 * the HDMI EDID and its 720p/1080p modes, and takes the selected mode.
 */
#define PS3_NID_VIDEO_OUT_GET_NUM_DEVICES   0x75BBB672u
#define PS3_NID_VIDEO_OUT_GET_STATE         0x887572D5u
#define PS3_NID_VIDEO_OUT_GET_RESOLUTION    0xE558748Du
#define PS3_NID_VIDEO_OUT_RES_AVAILABILITY  0xA322DB75u
#define PS3_NID_VIDEO_OUT_GET_DEVICE_INFO   0x1E930EEFu
#define PS3_NID_VIDEO_OUT_CONFIGURE         0x0BAE8772u
#define PS3_NID_VIDEO_OUT_GET_CONFIG        0x15B0B0CDu
#define PS3_NID_VIDEO_OUT_SET_CONVERT_MODE  0xE8AB2C69u
#define PS3_NID_VIDEO_OUT_GET_CONVERT_MODE  0x7C4B0260u

#define PS3_VIDEO_OUT_DEVICE_INFO_SIZE      456

static const char *ps3_video_out_name(uint32_t nid)
{
    switch (nid) {
    case PS3_NID_VIDEO_OUT_GET_NUM_DEVICES:  return "cellVideoOutGetNumberOfDevice";
    case PS3_NID_VIDEO_OUT_GET_STATE:        return "cellVideoOutGetState";
    case PS3_NID_VIDEO_OUT_GET_RESOLUTION:   return "cellVideoOutGetResolution";
    case PS3_NID_VIDEO_OUT_RES_AVAILABILITY: return "cellVideoOutGetResolutionAvailability";
    case PS3_NID_VIDEO_OUT_GET_DEVICE_INFO:  return "cellVideoOutGetDeviceInfo";
    case PS3_NID_VIDEO_OUT_CONFIGURE:        return "cellVideoOutConfigure";
    case PS3_NID_VIDEO_OUT_GET_CONFIG:       return "cellVideoOutGetConfiguration";
    case PS3_NID_VIDEO_OUT_SET_CONVERT_MODE: return "cellVideoOutSetConvertMode";
    case PS3_NID_VIDEO_OUT_GET_CONVERT_MODE: return "cellVideoOutGetConvertMode";
    default:                                 return NULL;
    }
}

/* resolutionId 1 is 1080, 2 is 720 - the two modes the sink offers. */
static bool ps3_video_out_resolution(uint8_t id, uint32_t *w, uint32_t *h)
{
    switch (id) {
    case 0x01: *w = 1920; *h = 1080; return true;   /* CELL_..._1080 */
    case 0x02: *w = 1280; *h = 720;  return true;   /* CELL_..._720 */
    case 0x04: *w = 720;  *h = 480;  return true;
    case 0x05: *w = 720;  *h = 576;  return true;
    default:   return false;
    }
}

/*
 * The context the library appends its commands through.  A CellGcmContextData
 * is {begin, end, current, callback}, and every inlined cellGcmSet* expander
 * loads the address of the current one from a process-global before it emits
 * anything; a slot that still holds zero turns the first call into `bctrl` to
 * address 0 and the process parks on the 0x700 vector.
 *
 * On hardware the library's own _cellGcmInitBody lays the context down at the
 * address sys_rsx_device_map returned and publishes it - the handshake RPCS3
 * models with `gcm_info.context_addr = device_addr` followed by
 * `context->set(context_addr)`.  The 4.93 vsh.self in this tree has no writer
 * for the slot at all (nothing in its 7 MiB image stores to it), so its init
 * asks lv2 for a context that never appears.  lv2 owns the RSX window and the
 * tail of the DMA region, so it publishes the context exactly where and how
 * the library would have.
 */
#define PS3_GCM_CTX_SLOT             0x70938Cu  /* CellGcmContextData *gGcmCtx */
#define PS3_GCM_CTX_SIZE             0x10

static void ps3_rsx_publish_context(PS3BootROMState *s, uint8_t *ram,
                                    uint64_t ram_size)
{
    uint32_t ctx = s->rsx_device;
    uint32_t begin, end;

    if (!ctx || !s->rsx_dma || (uint64_t)ctx + PS3_GCM_CTX_SIZE > ram_size ||
        (uint64_t)PS3_GCM_CTX_SLOT + 4 > ram_size) {
        return;
    }

    /* The command buffer sits past the DMA control block, as the library
     * places it past the io address it is handed, and is large enough that the
     * bring-up commands never ask for a flush. */
    begin = s->rsx_dma + 0x1000;
    end = s->rsx_dma + 0x8000;

    ps3_put_be32(ram + ctx + 0x0, begin);       /* begin */
    ps3_put_be32(ram + ctx + 0x4, end);         /* end */
    ps3_put_be32(ram + ctx + 0x8, begin);       /* current */
    ps3_put_be32(ram + ctx + 0xC, 0);           /* callback, unused until full */
    ps3_put_be32(ram + PS3_GCM_CTX_SLOT, ctx);

    info_report("ps3-rsx: gcm context 0x%X: 0x%X..0x%X, published at 0x%X",
                ctx, begin, end, PS3_GCM_CTX_SLOT);
}

/* cellGcmSys: the display half of the RSX library (NIDs from vsh_exports). */
#define PS3_NID_GCM_INIT             0xB477F06Au
#define PS3_NID_GCM_GET_CONFIG       0xE315A0B2u
#define PS3_NID_GCM_SET_DISPLAY_BUF  0xA53D12AEu
#define PS3_NID_GCM_SET_FLIP         0xDC09357Eu
#define PS3_NID_AIM_GET_DEVICE_TYPE  0x8F71C2DFu

static bool ps3_lv2_gcm(PS3BootROMState *s, CPUPPCState *env,
                        uint8_t *ram, uint64_t ram_size,
                        uint32_t nid, int32_t *ret)
{
    uint32_t a0 = env->gpr[3];
    uint32_t a1 = env->gpr[4];
    uint32_t a2 = env->gpr[5];
    uint32_t a3 = env->gpr[6];
    uint32_t a4 = env->gpr[7];

    switch (nid) {
    case PS3_NID_GCM_INIT: {        /* context*, cmdSize, ioAddress */
        if (!a0 || (uint64_t)a0 + 16 > ram_size) {
            *ret = PS3_LV2_EFAULT;
            break;
        }
        /* CellGcmContextData: begin, end, current, callback. */
        ps3_put_be32(ram + a0 + 0x0, a2);
        ps3_put_be32(ram + a0 + 0x4, a2 + a1);
        ps3_put_be32(ram + a0 + 0x8, a2);
        ps3_put_be32(ram + a0 + 0xC, 0);
        /*
         * The inlined cellGcmSet* expanders do not use this context: they
         * load the library's "current context" word, which expects the one
         * lv2 keeps in the RSX window (see ps3_rsx_publish_context).
         */
        ps3_rsx_publish_context(s, ram, ram_size);
        info_report("ps3-ppu: cellGcmInit: context 0x%X, 0x%X-byte command "
                    "buffer at 0x%X", a0, a1, a2);
        ps3_vga_printf("GCM: COMMAND BUFFER 0x%X BYTES", a1);
        *ret = 0;
        break;
    }
    case PS3_NID_GCM_GET_CONFIG: {  /* CellGcmConfig* */
        if (!a0 || (uint64_t)a0 + 24 > ram_size) {
            *ret = PS3_LV2_EFAULT;
            break;
        }
        /*
         * The console's RSX has 256 MiB of local memory and the XDR is 256
         * MiB; the library asks for both before it sizes its command buffer,
         * and a zero answer is what made emer_init print "Gcm Init Memory
         * Shortage".  The reserved part is not given out, as on hardware.
         */
        ps3_put_be32(ram + a0 + 0x00, 0x00000000);   /* localAddress */
        ps3_put_be32(ram + a0 + 0x04, 0x00000000);   /* ioAddress */
        ps3_put_be32(ram + a0 + 0x08, 0x0F000000);   /* localSize 240 MiB */
        ps3_put_be32(ram + a0 + 0x0C, 0x0F000000);   /* ioSize 240 MiB */
        ps3_put_be32(ram + a0 + 0x10, 0x26BE3680);   /* memory frequency */
        ps3_put_be32(ram + a0 + 0x14, 0x1F78A400);   /* core frequency */
        *ret = 0;
        break;
    }
    case PS3_NID_GCM_SET_DISPLAY_BUF: { /* id, offset, pitch, width, height */
        if (a0 < ARRAY_SIZE(s->gcm_display)) {
            s->gcm_display[a0].offset = a1;
            s->gcm_display[a0].pitch = a2;
            s->gcm_display[a0].width = a3;
            s->gcm_display[a0].height = a4;
            s->gcm_display[a0].set = true;
            info_report("ps3-ppu: cellGcmSetDisplayBuffer(%u): 0x%X, pitch "
                        "0x%X, %ux%u", a0, a1, a2, a3, a4);
        }
        *ret = 0;
        break;
    }
    case PS3_NID_GCM_SET_FLIP: {    /* context, id */
        uint32_t id = a1;

        if (id >= ARRAY_SIZE(s->gcm_display) || !s->gcm_display[id].set) {
            *ret = 0;
            break;
        }

        s->gcm_display[id].set = false;
        ps3_vga_guest_scanout(s->gcm_display[id].offset,
                              s->gcm_display[id].width,
                              s->gcm_display[id].height,
                              s->gcm_display[id].pitch);
        info_report("ps3-ppu: cellGcmSetFlip(%u): scanout 0x%X, %ux%u, "
                    "pitch 0x%X", id, s->gcm_display[id].offset,
                    s->gcm_display[id].width, s->gcm_display[id].height,
                    s->gcm_display[id].pitch);
        ps3_vga_printf("GCM: FLIP %u AT 0x%X", id,
                       s->gcm_display[id].offset);
        *ret = 0;
        break;
    }
    case PS3_NID_AIM_GET_DEVICE_TYPE: { /* u32 *type */
        /*
         * cellSsAimGetDeviceType: the AIM block reports what the AV port is
         * wired to.  This machine is a TV on HDMI, which is what the
         * cellVideoOut EDID already says.
         */
        if (a0 && (uint64_t)a0 + 4 <= ram_size) {
            ps3_put_be32(ram + a0, 1);      /* CELL_SS_AIM_DEVICE_TYPE_TV */
        }
        info_report("ps3-ppu: cellSsAimGetDeviceType: TV (HDMI)");
        *ret = 0;
        break;
    }
    default:
        return false;
    }

    return true;
}

/*
 * cellMic: the console's microphone.
 *
 * The library is a front end over a USB audio class device: open it, start it,
 * read its samples.  Under LLE the samples belong to sys_audio's mic thread,
 * which is why the notify queue matters as much as the reads - the thread
 * sleeps on CELLMIC_DATA and only calls cellMicRead when one arrives.  Here the
 * device is QEMU's capture input and the samples are the host's microphone.
 *
 * NIDs are lv2's name hashes, the same generator that names cellVideoOut's
 * imports, so a guest's cellMic stubs land here rather than on a placeholder.
 */
#define PS3_NID_MIC_INIT                0x8325E02Du
#define PS3_NID_MIC_END                 0xC6328CAAu
#define PS3_NID_MIC_OPEN                0xDD1B59F0u
#define PS3_NID_MIC_OPEN_EX             0x05709BBFu
#define PS3_NID_MIC_OPEN_RAW            0xA42AC07Au
#define PS3_NID_MIC_CLOSE               0x8D229F8Eu
#define PS3_NID_MIC_START               0xDD724314u
#define PS3_NID_MIC_START_EX            0xDDD19A89u
#define PS3_NID_MIC_STOP                0xFCFAF246u
#define PS3_NID_MIC_READ                0x07E1B12Cu
#define PS3_NID_MIC_READ_RAW            0x72165A7Fu
#define PS3_NID_MIC_READ_DSP            0xC414FAA5u
#define PS3_NID_MIC_READ_AUX            0x3ACC118Eu
#define PS3_NID_MIC_GET_FORMAT          0x48108A23u
#define PS3_NID_MIC_GET_FORMAT_EX       0xAD049ECFu
#define PS3_NID_MIC_GET_FORMAT_RAW      0x4E0B69EEu
#define PS3_NID_MIC_GET_FORMAT_AUX      0xFDA12276u
#define PS3_NID_MIC_GET_FORMAT_DSP      0x87A08D29u
#define PS3_NID_MIC_IS_OPEN             0x186CB1FBu
#define PS3_NID_MIC_IS_ATTACHED         0x1B42101Bu
#define PS3_NID_MIC_GET_TYPE            0xA52D2AE4u
#define PS3_NID_MIC_GET_STATUS          0x25C5723Fu
#define PS3_NID_MIC_GET_SIGNAL_STATE    0xB30780EBu
#define PS3_NID_MIC_SET_SIGNAL_ATTR     0x323DEB41u
#define PS3_NID_MIC_GET_SIGNAL_ATTR     0xAC5BA03Au
#define PS3_NID_MIC_SET_DEVICE_ATTR     0xB2C16321u
#define PS3_NID_MIC_GET_DEVICE_ATTR     0x6A024AA0u
#define PS3_NID_MIC_SET_EQ              0x7903400Eu
#define PS3_NID_MIC_SET_EQ2             0x6CC7AE00u
#define PS3_NID_MIC_REMOVE_EQ           0x65336418u
#define PS3_NID_MIC_RESET               0x6BC46AABu
#define PS3_NID_MIC_GET_GUID            0x017024A8u
#define PS3_NID_MIC_GET_IDENTIFIER      0xFDBBE469u
#define PS3_NID_MIC_STOP_EX             0xE839380Fu
#define PS3_NID_MIC_SYS_SHARE_INIT      0xD127CD3Eu
#define PS3_NID_MIC_SYS_SHARE_END       0xF82BBF7Cu
#define PS3_NID_MIC_SYS_SHARE_OPEN      0xC3610DBDu
#define PS3_NID_MIC_SYS_SHARE_CLOSE     0x3ACE58F3u
#define PS3_NID_MIC_SYS_SHARE_START     0xCAC7E7D7u
#define PS3_NID_MIC_SYS_SHARE_STOP      0xBDFD51E2u
#define PS3_NID_MIC_COMMAND             0xC461563Cu
#define PS3_NID_MIC_SET_MULTI_EQ        0x891C6291u

/* cellMic's own error codes, not lv2's. */
#define CELL_MICIN_ERROR_ALREADY_INIT        ((int32_t)0x80140101)
#define CELL_MICIN_ERROR_NOT_INIT            ((int32_t)0x80140103)
#define CELL_MICIN_ERROR_PARAM               ((int32_t)0x80140104)
#define CELL_MICIN_ERROR_ALREADY_OPEN        ((int32_t)0x80140106)
#define CELL_MICIN_ERROR_NOT_OPEN            ((int32_t)0x80140107)
#define CELL_MICIN_ERROR_EVENT_QUEUE         ((int32_t)0x8014010D)
#define CELL_MICIN_ERROR_DEVICE_NOT_FOUND    ((int32_t)0x8014010E)
#define CELL_MICIN_ERROR_DEVICE_NOT_SUPPORT  ((int32_t)0x80140110)

/* Device attributes and signal states, as cellMic.h numbers them. */
#define CELLMIC_DEVATTR_LED       9
#define CELLMIC_DEVATTR_GAIN      10
#define CELLMIC_DEVATTR_VOLUME    201
#define CELLMIC_DEVATTR_AGC       202
#define CELLMIC_DEVATTR_CHANVOL   301
#define CELLMIC_DEVATTR_DSPTYPE   302

#define CELLMIC_SIGSTATE_LOCTALK  0
#define CELLMIC_SIGSTATE_FARTALK  1
#define CELLMIC_SIGSTATE_NSR      3
#define CELLMIC_SIGSTATE_AGC      4
#define CELLMIC_SIGSTATE_MICENG   5
#define CELLMIC_SIGSTATE_SPKENG   6

#define CELLMIC_SIGTYPE_DSP       0x01
#define CELLMIC_SIGTYPE_AUX       0x02
#define CELLMIC_SIGTYPE_RAW       0x04

#define CELLMIC_TYPE_USBAUDIO     3
#define CELLMIC_CMD_ATTACH        2

static const char *ps3_cellmic_name(uint32_t nid)
{
    switch (nid) {
    case PS3_NID_MIC_INIT:              return "cellMicInit";
    case PS3_NID_MIC_END:               return "cellMicEnd";
    case PS3_NID_MIC_OPEN:              return "cellMicOpen";
    case PS3_NID_MIC_OPEN_EX:           return "cellMicOpenEx";
    case PS3_NID_MIC_OPEN_RAW:          return "cellMicOpenRaw";
    case PS3_NID_MIC_CLOSE:             return "cellMicClose";
    case PS3_NID_MIC_START:             return "cellMicStart";
    case PS3_NID_MIC_START_EX:          return "cellMicStartEx";
    case PS3_NID_MIC_STOP:              return "cellMicStop";
    case PS3_NID_MIC_READ:              return "cellMicRead";
    case PS3_NID_MIC_READ_RAW:          return "cellMicReadRaw";
    case PS3_NID_MIC_READ_DSP:          return "cellMicReadDsp";
    case PS3_NID_MIC_READ_AUX:          return "cellMicReadAux";
    case PS3_NID_MIC_GET_FORMAT:        return "cellMicGetFormat";
    case PS3_NID_MIC_GET_FORMAT_EX:     return "cellMicGetFormatEx";
    case PS3_NID_MIC_GET_FORMAT_RAW:    return "cellMicGetFormatRaw";
    case PS3_NID_MIC_GET_FORMAT_AUX:    return "cellMicGetFormatAux";
    case PS3_NID_MIC_GET_FORMAT_DSP:    return "cellMicGetFormatDsp";
    case PS3_NID_MIC_IS_OPEN:           return "cellMicIsOpen";
    case PS3_NID_MIC_IS_ATTACHED:       return "cellMicIsAttached";
    case PS3_NID_MIC_GET_TYPE:          return "cellMicGetType";
    case PS3_NID_MIC_GET_STATUS:        return "cellMicGetStatus";
    case PS3_NID_MIC_GET_SIGNAL_STATE:  return "cellMicGetSignalState";
    case PS3_NID_MIC_SET_SIGNAL_ATTR:   return "cellMicSetSignalAttr";
    case PS3_NID_MIC_GET_SIGNAL_ATTR:   return "cellMicGetSignalAttr";
    case PS3_NID_MIC_SET_DEVICE_ATTR:   return "cellMicSetDeviceAttr";
    case PS3_NID_MIC_GET_DEVICE_ATTR:   return "cellMicGetDeviceAttr";
    case PS3_NID_MIC_SET_EQ:            return "cellMicSetNotifyEventQueue";
    case PS3_NID_MIC_SET_EQ2:           return "cellMicSetNotifyEventQueue2";
    case PS3_NID_MIC_REMOVE_EQ:         return "cellMicRemoveNotifyEventQueue";
    case PS3_NID_MIC_RESET:             return "cellMicReset";
    case PS3_NID_MIC_GET_GUID:          return "cellMicGetDeviceGUID";
    case PS3_NID_MIC_GET_IDENTIFIER:    return "cellMicGetDeviceIdentifier";
    case PS3_NID_MIC_STOP_EX:           return "cellMicStopEx";
    case PS3_NID_MIC_SYS_SHARE_INIT:    return "cellMicSysShareInit";
    case PS3_NID_MIC_SYS_SHARE_END:     return "cellMicSysShareEnd";
    case PS3_NID_MIC_SYS_SHARE_OPEN:    return "cellMicSysShareOpen";
    case PS3_NID_MIC_SYS_SHARE_CLOSE:   return "cellMicSysShareClose";
    case PS3_NID_MIC_SYS_SHARE_START:   return "cellMicSysShareStart";
    case PS3_NID_MIC_SYS_SHARE_STOP:    return "cellMicSysShareStop";
    case PS3_NID_MIC_COMMAND:           return "cellMicCommand";
    case PS3_NID_MIC_SET_MULTI_EQ:      return "cellMicSetMultiMicNotifyEventQueue";
    default:                            return NULL;
    }
}

static void ps3_put_be_f32(uint8_t *p, float f)
{
    union {
        float f;
        uint32_t u;
    } v;

    v.f = f;
    ps3_put_be32(p, v.u);
}

/*
 * Open device 0.  The rate the voice accepts is what the guest is then told it
 * has, so a backend that cannot run at the requested rate still gives the
 * guest a stream whose timing is right.
 */
static int32_t ps3_cellmic_open(PS3BootROMState *s, uint32_t dev, uint32_t raw_rate,
                            uint32_t channels, uint32_t dsp_rate,
                            uint32_t sig_type)
{
    Error *err = NULL;

    if (!s->mic_init) {
        return CELL_MICIN_ERROR_NOT_INIT;
    }
    if (dev >= PS3_MIC_DEVICES) {
        return CELL_MICIN_ERROR_DEVICE_NOT_FOUND;
    }
    if (s->mic_opened) {
        return CELL_MICIN_ERROR_ALREADY_OPEN;
    }
    if (!sig_type || (sig_type & ~(CELLMIC_SIGTYPE_DSP | CELLMIC_SIGTYPE_AUX |
                                   CELLMIC_SIGTYPE_RAW))) {
        return CELL_MICIN_ERROR_PARAM;
    }

    if (!channels) {
        channels = 1;
    }
    if (channels > 2) {
        channels = 2;               /* the ring and the DSP stream are stereo */
    }
    if (!raw_rate) {
        raw_rate = PS3_MIC_DEFAULT_RATE;
    }

    if (!ps3_audio_mic_open(s->audio, raw_rate, channels, &err)) {
        info_report("ps3-ppu: cellMicOpenEx: %s", error_get_pretty(err));
        error_free(err);
        return CELL_MICIN_ERROR_DEVICE_NOT_SUPPORT;
    }

    s->mic_opened = true;
    s->mic_started = false;
    s->mic_channels = channels;
    s->mic_sig_type = sig_type;
    s->mic_rate = ps3_audio_mic_rate(s->audio);
    s->mic_dsp_rate = dsp_rate ? dsp_rate : s->mic_rate;
    s->mic_head = 0;
    s->mic_used = 0;
    s->mic_tick = 0;

    info_report("ps3-ppu: cellMicOpenEx(dev %u): %u Hz, %u channel(s), "
                "signal 0x%X", dev, s->mic_rate, channels, sig_type);

    return 0;
}

/*
 * Copy the ring out in the format the caller asked for.  RAW is big-endian
 * signed 16-bit; DSP is the same samples as big-endian floats in [-1, 1],
 * unless the guest set DSPTYPE to 1, which makes the DSP stream the raw one
 * (the library does the same on hardware).  A null buffer is not an error: the
 * caller is asking how much is waiting.
 */
static int32_t ps3_cellmic_read(PS3BootROMState *s, uint8_t *ram,
                            uint64_t ram_size, uint32_t dev, uint32_t ea,
                            uint32_t max_bytes, uint32_t type)
{
    int16_t pcm[PS3_MIC_CHUNK_FRAMES * 2];
    unsigned frame_bytes, frames, done = 0, n, i, ch;
    bool dsp;

    if (!s->mic_init) {
        return CELL_MICIN_ERROR_NOT_INIT;
    }
    if (dev >= PS3_MIC_DEVICES) {
        return CELL_MICIN_ERROR_DEVICE_NOT_FOUND;
    }
    if (!s->mic_opened || !(s->mic_sig_type & type)) {
        return CELL_MICIN_ERROR_NOT_OPEN;
    }
    if (type == CELLMIC_SIGTYPE_AUX) {
        return 0;                   /* no auxiliary stream on this device */
    }
    if (!ea) {
        return 0;
    }
    if (!type || (uint64_t)ea + max_bytes > ram_size) {
        return CELL_MICIN_ERROR_PARAM;
    }

    dsp = type == CELLMIC_SIGTYPE_DSP && s->mic_attr_dsptype != 1;
    frame_bytes = (dsp ? 4 : 2) * s->mic_channels;
    frames = MIN(s->mic_used, max_bytes / frame_bytes);

    while (frames) {
        unsigned block = MIN(frames, PS3_MIC_CHUNK_FRAMES);
        uint8_t *dst = ram + ea + done * frame_bytes;

        n = ps3_mic_take(s, pcm, block);
        if (!n) {
            break;
        }
        ps3_mic_measure(s, pcm, n);

        for (i = 0; i < n; i++) {
            for (ch = 0; ch < s->mic_channels; ch++) {
                int16_t v = pcm[i * s->mic_channels + ch];

                if (dsp) {
                    ps3_put_be_f32(dst, v / 32767.0f);
                    dst += 4;
                } else {
                    *dst++ = (uint8_t)(v >> 8);
                    *dst++ = (uint8_t)v;
                }
            }
        }
        done += n;
        frames -= n;
    }

    return done * frame_bytes;
}

static bool ps3_lv2_mic(PS3BootROMState *s, CPUPPCState *env,
                        uint8_t *ram, uint64_t ram_size,
                        uint32_t nid, int32_t *ret)
{
    uint32_t a0 = env->gpr[3];
    uint32_t a1 = env->gpr[4];
    uint32_t a2 = env->gpr[5];
    uint32_t a3 = env->gpr[6];

    switch (nid) {
    case PS3_NID_MIC_INIT:
        if (s->mic_init) {
            *ret = CELL_MICIN_ERROR_ALREADY_INIT;
            break;
        }
        s->mic_init = true;
        s->mic_opened = false;
        s->mic_started = false;
        s->mic_channels = 2;
        s->mic_sig_type = 0;
        s->mic_rate = PS3_MIC_DEFAULT_RATE;
        s->mic_dsp_rate = PS3_MIC_DEFAULT_RATE;
        s->mic_attr_gain = 3;
        s->mic_attr_volume = 145;
        s->mic_attr_agc = 0;
        s->mic_attr_led = 0;
        s->mic_attr_dsptype = 0;
        s->mic_chanvol[0] = 100;
        s->mic_chanvol[1] = 100;
        s->mic_eq_key = 0;
        s->mic_eq_source = 0;
        s->mic_head = 0;
        s->mic_used = 0;
        s->mic_tick = 0;
        s->mic_energy_db = 40.0f;
        info_report("ps3-ppu: cellMicInit: device 0 is the host's capture "
                    "input");
        *ret = 0;
        break;
    case PS3_NID_MIC_END:
        if (!s->mic_init) {
            *ret = CELL_MICIN_ERROR_NOT_INIT;
            break;
        }
        ps3_audio_mic_close(s->audio);
        s->mic_init = false;
        s->mic_opened = false;
        s->mic_started = false;
        s->mic_eq_key = 0;
        s->mic_eq_source = 0;
        s->mic_used = 0;
        *ret = 0;
        break;
    case PS3_NID_MIC_OPEN:          /* dev, sampleRate */
        *ret = ps3_cellmic_open(s, a0, a1, 1, a1, CELLMIC_SIGTYPE_DSP);
        break;
    case PS3_NID_MIC_OPEN_RAW:      /* dev, sampleRate, maxChannels */
        *ret = ps3_cellmic_open(s, a0, a1, a2, a1, CELLMIC_SIGTYPE_RAW);
        break;
    case PS3_NID_MIC_OPEN_EX:       /* dev, rawRate, rawChannels, dspRate,
                                     * bufferMs, signalType */
        *ret = ps3_cellmic_open(s, a0, a1, a2, a3, env->gpr[8]);
        break;
    case PS3_NID_MIC_CLOSE:
        if (!s->mic_init) {
            *ret = CELL_MICIN_ERROR_NOT_INIT;
            break;
        }
        if (a0 >= PS3_MIC_DEVICES) {
            *ret = CELL_MICIN_ERROR_DEVICE_NOT_FOUND;
            break;
        }
        if (!s->mic_opened) {
            *ret = CELL_MICIN_ERROR_NOT_OPEN;
            break;
        }
        ps3_audio_mic_close(s->audio);
        s->mic_opened = false;
        s->mic_started = false;
        s->mic_used = 0;
        info_report("ps3-ppu: cellMicClose(dev %u)", a0);
        *ret = 0;
        break;
    case PS3_NID_MIC_START:
    case PS3_NID_MIC_START_EX: {
        if (!s->mic_init) {
            *ret = CELL_MICIN_ERROR_NOT_INIT;
            break;
        }
        if (nid == PS3_NID_MIC_START_EX && (a1 & ~0x3u)) {
            *ret = CELL_MICIN_ERROR_PARAM;
            break;
        }
        if (a0 >= PS3_MIC_DEVICES) {
            *ret = CELL_MICIN_ERROR_DEVICE_NOT_FOUND;
            break;
        }
        if (!s->mic_opened) {
            *ret = CELL_MICIN_ERROR_NOT_OPEN;
            break;
        }
        if (!s->mic_started) {
            s->mic_started = true;
            s->mic_tick = 0;
            ps3_audio_mic_start(s->audio, true);
            info_report("ps3-ppu: cellMicStart: capturing %u Hz, %u "
                        "channel(s)%s", s->mic_rate, s->mic_channels,
                        ps3_audio_mic_active(s->audio) ? "" :
                        " (no capture voice)");
        }
        *ret = 0;
        break;
    }
    case PS3_NID_MIC_STOP:
        if (!s->mic_init) {
            *ret = CELL_MICIN_ERROR_NOT_INIT;
            break;
        }
        if (a0 >= PS3_MIC_DEVICES) {
            *ret = CELL_MICIN_ERROR_DEVICE_NOT_FOUND;
            break;
        }
        if (!s->mic_opened) {
            *ret = CELL_MICIN_ERROR_NOT_OPEN;
            break;
        }
        s->mic_started = false;
        *ret = 0;
        break;
    case PS3_NID_MIC_READ:
    case PS3_NID_MIC_READ_DSP:
        *ret = ps3_cellmic_read(s, ram, ram_size, a0, a1, a2,
                            CELLMIC_SIGTYPE_DSP);
        break;
    case PS3_NID_MIC_READ_RAW:
        *ret = ps3_cellmic_read(s, ram, ram_size, a0, a1, a2,
                            CELLMIC_SIGTYPE_RAW);
        break;
    case PS3_NID_MIC_READ_AUX:
        *ret = ps3_cellmic_read(s, ram, ram_size, a0, a1, a2,
                            CELLMIC_SIGTYPE_AUX);
        break;
    case PS3_NID_MIC_GET_FORMAT:
    case PS3_NID_MIC_GET_FORMAT_EX:
    case PS3_NID_MIC_GET_FORMAT_RAW:
    case PS3_NID_MIC_GET_FORMAT_AUX:
    case PS3_NID_MIC_GET_FORMAT_DSP: {
        uint32_t type = nid == PS3_NID_MIC_GET_FORMAT_EX ? a2 :
                        nid == PS3_NID_MIC_GET_FORMAT_RAW ? CELLMIC_SIGTYPE_RAW :
                        CELLMIC_SIGTYPE_DSP;
        bool dsp;
        uint8_t *p;

        if (!s->mic_init) {
            *ret = CELL_MICIN_ERROR_NOT_INIT;
            break;
        }
        if (a0 >= PS3_MIC_DEVICES) {
            *ret = CELL_MICIN_ERROR_DEVICE_NOT_FOUND;
            break;
        }
        if (!a1 || (uint64_t)a1 + 8 > ram_size) {
            *ret = CELL_MICIN_ERROR_PARAM;
            break;
        }
        if (!s->mic_opened) {
            *ret = CELL_MICIN_ERROR_NOT_OPEN;
            break;
        }

        dsp = type == CELLMIC_SIGTYPE_DSP && s->mic_attr_dsptype != 1;
        p = ram + a1;
        p[0] = (uint8_t)s->mic_channels;    /* channelNum */
        p[1] = dsp ? 4 : 2;                 /* subframeSize */
        p[2] = dsp ? 32 : 16;               /* bitResolution */
        p[3] = 1;                           /* dataType: big-endian */
        ps3_put_be32(p + 4, s->mic_rate);
        *ret = 0;
        break;
    }
    case PS3_NID_MIC_IS_OPEN:
        *ret = s->mic_init && a0 < PS3_MIC_DEVICES && s->mic_opened ? 1 : 0;
        break;
    case PS3_NID_MIC_IS_ATTACHED:
        *ret = 1;
        break;
    case PS3_NID_MIC_GET_TYPE: {    /* dev, s32 *type */
        if (!s->mic_init) {
            *ret = CELL_MICIN_ERROR_NOT_INIT;
            break;
        }
        if (!a1 || (uint64_t)a1 + 4 > ram_size) {
            *ret = CELL_MICIN_ERROR_PARAM;
            break;
        }
        ps3_put_be32(ram + a1, a0 < PS3_MIC_DEVICES ? CELLMIC_TYPE_USBAUDIO
                                                    : (uint32_t)-1);
        *ret = 0;
        break;
    }
    case PS3_NID_MIC_GET_STATUS: {  /* dev, CellMicStatus *status */
        if (!s->mic_init) {
            *ret = CELL_MICIN_ERROR_NOT_INIT;
            break;
        }
        if (!a1 || (uint64_t)a1 + 0x24 > ram_size) {
            *ret = CELL_MICIN_ERROR_PARAM;
            break;
        }

        ps3_put_be32(ram + a1 + 0x00, s->mic_rate);
        ps3_put_be32(ram + a1 + 0x04, s->mic_dsp_rate);
        ps3_put_be32(ram + a1 + 0x08, 5);            /* dsp_volume, 0..5 */
        ps3_put_be32(ram + a1 + 0x0C, s->mic_started);
        ps3_put_be32(ram + a1 + 0x10, s->mic_opened);
        ps3_put_be32(ram + a1 + 0x14, 10);           /* local voice, 0..10 */
        ps3_put_be32(ram + a1 + 0x18, 0);            /* remote voice */
        ps3_put_be_f32(ram + a1 + 0x1C, s->mic_energy_db);
        ps3_put_be_f32(ram + a1 + 0x20, 60.0f);      /* speaker level, dB */
        *ret = 0;
        break;
    }
    case PS3_NID_MIC_GET_SIGNAL_STATE: {    /* dev, state, void *value */
        uint8_t *p;

        if (!s->mic_init) {
            *ret = CELL_MICIN_ERROR_NOT_INIT;
            break;
        }
        if (!a2 || (uint64_t)a2 + 4 > ram_size) {
            *ret = CELL_MICIN_ERROR_PARAM;
            break;
        }
        if (a0 >= PS3_MIC_DEVICES) {
            *ret = CELL_MICIN_ERROR_DEVICE_NOT_FOUND;
            break;
        }
        if (!s->mic_opened) {
            *ret = CELL_MICIN_ERROR_NOT_OPEN;
            break;
        }

        p = ram + a2;
        switch (a1) {
        case CELLMIC_SIGSTATE_LOCTALK:
            ps3_put_be32(p, 9);     /* someone is probably talking */
            break;
        case CELLMIC_SIGSTATE_FARTALK:
            ps3_put_be32(p, 1);
            break;
        case CELLMIC_SIGSTATE_NSR:
            ps3_put_be_f32(p, 0.0f);    /* no noise reduction */
            break;
        case CELLMIC_SIGSTATE_AGC:
            ps3_put_be_f32(p, 1.0f);    /* no gain applied */
            break;
        case CELLMIC_SIGSTATE_MICENG:
            ps3_put_be_f32(p, s->mic_energy_db);
            break;
        case CELLMIC_SIGSTATE_SPKENG:
            ps3_put_be_f32(p, 10.0f);
            break;
        default:
            *ret = CELL_MICIN_ERROR_PARAM;
            return true;
        }
        *ret = 0;
        break;
    }
    case PS3_NID_MIC_SET_DEVICE_ATTR: {     /* dev, attr, arg1, arg2 */
        if (!s->mic_init) {
            *ret = CELL_MICIN_ERROR_NOT_INIT;
            break;
        }
        if (a0 >= PS3_MIC_DEVICES) {
            *ret = CELL_MICIN_ERROR_DEVICE_NOT_FOUND;
            break;
        }

        switch (a1) {
        case CELLMIC_DEVATTR_CHANVOL:
            if (a2 > 2) {
                *ret = CELL_MICIN_ERROR_PARAM;
                return true;
            }
            if (a2 == 0) {
                s->mic_chanvol[0] = a3;
                s->mic_chanvol[1] = a3;
            } else {
                s->mic_chanvol[a2 - 1] = a3;
            }
            break;
        case CELLMIC_DEVATTR_LED:     s->mic_attr_led = a2;      break;
        case CELLMIC_DEVATTR_GAIN:    s->mic_attr_gain = a2;     break;
        case CELLMIC_DEVATTR_VOLUME:  s->mic_attr_volume = a2;   break;
        case CELLMIC_DEVATTR_AGC:     s->mic_attr_agc = a2;      break;
        case CELLMIC_DEVATTR_DSPTYPE: s->mic_attr_dsptype = a2;  break;
        default:
            *ret = CELL_MICIN_ERROR_PARAM;
            return true;
        }
        *ret = 0;
        break;
    }
    case PS3_NID_MIC_GET_DEVICE_ATTR: {     /* dev, attr, s32 *arg1, s32 *arg2 */
        if (!s->mic_init) {
            *ret = CELL_MICIN_ERROR_NOT_INIT;
            break;
        }
        if (a0 >= PS3_MIC_DEVICES) {
            *ret = CELL_MICIN_ERROR_DEVICE_NOT_FOUND;
            break;
        }

        switch (a1) {
        case CELLMIC_DEVATTR_CHANVOL:
            if (!a2 || (uint64_t)a2 + 4 > ram_size) {
                *ret = CELL_MICIN_ERROR_PARAM;
                break;
            }
            if (!a3 || (uint64_t)a3 + 4 > ram_size) {
                *ret = CELL_MICIN_ERROR_PARAM;
                break;
            }
            {
                uint32_t ch = ps3_be32(ram + a2);

                if (ch > 2) {
                    *ret = CELL_MICIN_ERROR_PARAM;
                    break;
                }
                ps3_put_be32(ram + a3, ch == 0 ?
                             (s->mic_chanvol[0] + s->mic_chanvol[1]) / 2 :
                             s->mic_chanvol[ch - 1]);
            }
            break;
        case CELLMIC_DEVATTR_LED:
        case CELLMIC_DEVATTR_GAIN:
        case CELLMIC_DEVATTR_VOLUME:
        case CELLMIC_DEVATTR_AGC:
        case CELLMIC_DEVATTR_DSPTYPE: {
            uint32_t v = a1 == CELLMIC_DEVATTR_LED ? s->mic_attr_led :
                         a1 == CELLMIC_DEVATTR_GAIN ? s->mic_attr_gain :
                         a1 == CELLMIC_DEVATTR_VOLUME ? s->mic_attr_volume :
                         a1 == CELLMIC_DEVATTR_AGC ? s->mic_attr_agc :
                         s->mic_attr_dsptype;

            if (!a2 || (uint64_t)a2 + 4 > ram_size) {
                *ret = CELL_MICIN_ERROR_PARAM;
                break;
            }
            ps3_put_be32(ram + a2, v);
            break;
        }
        default:
            *ret = CELL_MICIN_ERROR_PARAM;
            return true;
        }
        *ret = 0;
        break;
    }
    case PS3_NID_MIC_SET_SIGNAL_ATTR:       /* dev, attr, void *value */
    case PS3_NID_MIC_GET_SIGNAL_ATTR:
        if (!s->mic_init) {
            *ret = CELL_MICIN_ERROR_NOT_INIT;
            break;
        }
        if (a0 >= PS3_MIC_DEVICES) {
            *ret = CELL_MICIN_ERROR_DEVICE_NOT_FOUND;
            break;
        }
        if (!a2) {
            *ret = CELL_MICIN_ERROR_PARAM;
            break;
        }
        *ret = 0;
        break;
    case PS3_NID_MIC_SET_EQ:        /* u64 key */
    case PS3_NID_MIC_SET_EQ2: {     /* u64 key, u64 source, u64 flag */
        uint64_t key = env->gpr[3];
        int q;

        if (!s->mic_init) {
            *ret = CELL_MICIN_ERROR_NOT_INIT;
            break;
        }
        q = ps3_eq_index_key(s, key);
        if (q < 0) {
            *ret = CELL_MICIN_ERROR_EVENT_QUEUE;
            break;
        }

        s->mic_eq_key = key;
        s->mic_eq_source = nid == PS3_NID_MIC_SET_EQ2 ? env->gpr[4] : 0;

        /* The device is there, which is what the library announces first. */
        {
            PS3Event ev = {
                .source = s->mic_eq_source,
                .data1 = CELLMIC_CMD_ATTACH,
                .data2 = 0,
                .data3 = 0,
            };

            ps3_eq_push(&s->eq[q], &ev);
            ps3_eq_wake(s, ram, ram_size, q);
        }
        info_report("ps3-ppu: cellMicSetNotifyEventQueue: key 0x%" PRIX64
                    " (source 0x%" PRIX64 ")", key, s->mic_eq_source);
        *ret = 0;
        break;
    }
    case PS3_NID_MIC_REMOVE_EQ:
        if (!s->mic_init) {
            *ret = CELL_MICIN_ERROR_NOT_INIT;
            break;
        }
        s->mic_eq_key = 0;
        s->mic_eq_source = 0;
        *ret = 0;
        break;
    case PS3_NID_MIC_GET_GUID:      /* dev, u32 *guid */
    case PS3_NID_MIC_GET_IDENTIFIER:        /* dev, u32 *id */
        if (!s->mic_init) {
            *ret = CELL_MICIN_ERROR_NOT_INIT;
            break;
        }
        if (!a1 || (uint64_t)a1 + 4 > ram_size) {
            *ret = CELL_MICIN_ERROR_PARAM;
            break;
        }
        ps3_put_be32(ram + a1, nid == PS3_NID_MIC_GET_GUID ?
                     0xFFFFFFFFu : 0);
        *ret = 0;
        break;
    case PS3_NID_MIC_RESET:
        if (!s->mic_init) {
            *ret = CELL_MICIN_ERROR_NOT_INIT;
            break;
        }
        if (a0 >= PS3_MIC_DEVICES) {
            *ret = CELL_MICIN_ERROR_DEVICE_NOT_FOUND;
            break;
        }
        if (!s->mic_opened) {
            *ret = CELL_MICIN_ERROR_NOT_OPEN;
            break;
        }
        s->mic_head = 0;
        s->mic_used = 0;
        *ret = 0;
        break;
    case PS3_NID_MIC_STOP_EX:
    case PS3_NID_MIC_SYS_SHARE_INIT:
    case PS3_NID_MIC_SYS_SHARE_END:
    case PS3_NID_MIC_SYS_SHARE_OPEN:
    case PS3_NID_MIC_SYS_SHARE_CLOSE:
    case PS3_NID_MIC_SYS_SHARE_START:
    case PS3_NID_MIC_SYS_SHARE_STOP:
    case PS3_NID_MIC_COMMAND:
    case PS3_NID_MIC_SET_MULTI_EQ:
        /*
         * The system-side sharing entry points.  The VSH never calls them on
         * its own microphone; a guest that does gets the library's success
         * answer rather than -1, which its caller would treat as a pointer.
         */
        *ret = 0;
        break;
    default:
        return false;
    }

    return true;
}

/*
 * The microphone's selftest, in the spirit of the AES one.
 *
 * The guest's cellMic calls are answered from a capture voice and a ring, and
 * a byte-order or ring mistake would only show up as noise the guest cannot
 * explain.  This drives the handler the way the library does - init, open,
 * start, read, format, level, close - and names what failed.  With no host
 * input the open must be refused the library's way, which is itself the check.
 */
/*
 * What the host actually captured during the selftest's wait.  A voice the
 * backend accepts but never fills would pass every other check, so the count
 * is reported: zero frames means the input is silent or absent, which is a
 * fact about the host, not a failure of the model.
 */
static void ps3_mic_capture_done(void *opaque)
{
    PS3BootROMState *s = opaque;
    unsigned before, i;
    int peak = 0;

    s->mic_capture_timer = NULL;
    for (i = 0; i < 16; i++) {
        before = s->mic_used;
        ps3_mic_pump(s);
        if (s->mic_used == before) {
            break;
        }
    }

    /* The peak says whether a device is really there or only a silent one. */
    for (i = 0; i < s->mic_used * 2; i++) {
        peak = MAX(peak, abs((int)s->mic_ring[i]));
    }

    info_report("ps3-ppu: microphone capture test: the host delivered %u "
                "frame(s) in 300 ms, peak %d/32767%s", s->mic_used, peak,
                s->mic_used ? "" : " (silence, or no input device)");

    s->mic_used = 0;
    if (!s->mic_init) {
        /* A guest that started using the device in the meantime keeps it. */
        s->mic_started = false;
        s->mic_opened = false;
        ps3_audio_mic_close(s->audio);
    }
}

/*
 * The capture voice has to be opened while the VM is running: a backend only
 * starts its input when it is told to, and before the run state reaches
 * running the audio core leaves the hardware off.  So the selftest's real
 * capture starts one timer after the machine does.
 */
static void ps3_mic_capture_open(void *opaque)
{
    PS3BootROMState *s = opaque;
    Error *err = NULL;

    if (!ps3_audio_mic_open(s->audio, PS3_MIC_DEFAULT_RATE, 2, &err)) {
        info_report("ps3-ppu: microphone selftest: %s",
                    error_get_pretty(err));
        error_free(err);
        return;
    }

    s->mic_opened = true;
    s->mic_started = true;
    s->mic_channels = 2;
    s->mic_rate = ps3_audio_mic_rate(s->audio);
    s->mic_used = 0;

    s->mic_capture_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                       ps3_mic_capture_done, s);
    timer_mod(s->mic_capture_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 300000000);
}

static bool ps3_mic_selftest(PS3BootROMState *s, char *why, size_t why_len)
{
    uint8_t *ram = memory_region_get_ram_ptr(s->ram);
    uint64_t ram_size = memory_region_size(s->ram);
    const uint32_t ea = PS3_MIC_SELFTEST_EA;
    CPUPPCState env;
    int16_t block[64];
    int32_t ret;
    unsigned i;
    union {
        uint32_t u;
        float f;
    } level;

    if (!ram || ea + 0x100 > ram_size) {
        snprintf(why, why_len, "no scratch RAM for the selftest");
        return false;
    }

    memset(&env, 0, sizeof(env));
    memset(ram + ea, 0, 0x100);
    s->mic_init = false;
    s->mic_opened = false;
    s->mic_started = false;

    env.gpr[3] = 0;
    if (!ps3_lv2_mic(s, &env, ram, ram_size, PS3_NID_MIC_INIT, &ret) || ret) {
        snprintf(why, why_len, "cellMicInit answered 0x%X", (uint32_t)ret);
        return false;
    }

    /* The second init is the library's ALREADY_INIT, not a silent success. */
    if (!ps3_lv2_mic(s, &env, ram, ram_size, PS3_NID_MIC_INIT, &ret) ||
        ret != CELL_MICIN_ERROR_ALREADY_INIT) {
        snprintf(why, why_len, "a second cellMicInit answered 0x%X, not "
                 "ALREADY_INIT", (uint32_t)ret);
        return false;
    }

    env.gpr[3] = 0;                     /* dev 0 */
    env.gpr[4] = 48000;                 /* raw rate */
    env.gpr[5] = 2;                     /* channels */
    env.gpr[6] = 48000;                 /* DSP rate */
    env.gpr[7] = 0x80;                  /* bufferSizeMS */
    env.gpr[8] = CELLMIC_SIGTYPE_DSP | CELLMIC_SIGTYPE_RAW;
    ps3_lv2_mic(s, &env, ram, ram_size, PS3_NID_MIC_OPEN_EX, &ret);

    if (ret == CELL_MICIN_ERROR_DEVICE_NOT_SUPPORT) {
        /* No input on this host: the open has to be refused, not faked. */
        info_report("ps3-ppu: microphone selftest: no host capture device, "
                    "cellMicOpenEx answered DEVICE_NOT_SUPPORT");
        s->mic_init = false;
        return true;
    }
    if (ret) {
        snprintf(why, why_len, "cellMicOpenEx answered 0x%X", (uint32_t)ret);
        return false;
    }

    env.gpr[3] = 0;
    if (!ps3_lv2_mic(s, &env, ram, ram_size, PS3_NID_MIC_START, &ret) || ret) {
        snprintf(why, why_len, "cellMicStart answered 0x%X", (uint32_t)ret);
        return false;
    }

    /*
     * A ramp of 32 stereo frames, pushed the way the capture tick pushes
     * them, so both the channel order and the big-endian conversion are
     * visible in what the guest reads back.
     */
    for (i = 0; i < 64; i++) {
        block[i] = (int16_t)(i * 512 - 16384);
    }
    ps3_mic_push(s, block, 32, 2);

    env.gpr[3] = 0;
    env.gpr[4] = ea;
    env.gpr[5] = 0x100;
    ps3_lv2_mic(s, &env, ram, ram_size, PS3_NID_MIC_READ_RAW, &ret);
    if (ret != 32 * 4) {
        snprintf(why, why_len, "cellMicReadRaw answered 0x%X, not %u",
                 (uint32_t)ret, 32 * 4);
        return false;
    }
    if (ram[ea] != (uint8_t)(block[0] >> 8) ||
        ram[ea + 1] != (uint8_t)block[0] ||
        ram[ea + 2] != (uint8_t)(block[1] >> 8) ||
        ram[ea + 3] != (uint8_t)block[1]) {
        snprintf(why, why_len, "the raw read gave %02X %02X %02X %02X, not "
                 "the big-endian ramp", ram[ea], ram[ea + 1], ram[ea + 2],
                 ram[ea + 3]);
        return false;
    }

    /* The ring is drained: a second read has nothing to give. */
    if (!ps3_lv2_mic(s, &env, ram, ram_size, PS3_NID_MIC_READ_RAW, &ret) ||
        ret != 0) {
        snprintf(why, why_len, "an empty ring answered 0x%X", (uint32_t)ret);
        return false;
    }

    env.gpr[3] = 0;
    env.gpr[4] = ea + 0x40;
    if (!ps3_lv2_mic(s, &env, ram, ram_size, PS3_NID_MIC_GET_FORMAT_RAW,
                     &ret) || ret) {
        snprintf(why, why_len, "cellMicGetFormatRaw answered 0x%X",
                 (uint32_t)ret);
        return false;
    }
    if (ram[ea + 0x40] != 2 || ram[ea + 0x41] != 2 || ram[ea + 0x42] != 16 ||
        ram[ea + 0x43] != 1 || ps3_be32(ram + ea + 0x44) != s->mic_rate) {
        snprintf(why, why_len, "the raw format is %u ch/%u B/%u bit/%u BE/%u "
                 "Hz, not 2/2/16/1/%u", ram[ea + 0x40], ram[ea + 0x41],
                 ram[ea + 0x42], ram[ea + 0x43], ps3_be32(ram + ea + 0x44),
                 s->mic_rate);
        return false;
    }

    env.gpr[3] = 0;
    env.gpr[4] = CELLMIC_SIGSTATE_MICENG;
    env.gpr[5] = ea + 0x60;
    if (!ps3_lv2_mic(s, &env, ram, ram_size, PS3_NID_MIC_GET_SIGNAL_STATE,
                     &ret) || ret) {
        snprintf(why, why_len, "cellMicGetSignalState answered 0x%X",
                 (uint32_t)ret);
        return false;
    }
    level.u = ps3_be32(ram + ea + 0x60);
    if (!(level.f >= 40.0f && level.f <= 90.0f)) {
        snprintf(why, why_len, "the microphone level is %f dB, outside "
                 "40..90", level.f);
        return false;
    }

    /* A read after the close is the library's NOT_OPEN. */
    env.gpr[3] = 0;
    if (!ps3_lv2_mic(s, &env, ram, ram_size, PS3_NID_MIC_CLOSE, &ret) || ret) {
        snprintf(why, why_len, "cellMicClose answered 0x%X", (uint32_t)ret);
        return false;
    }
    env.gpr[4] = ea;
    env.gpr[5] = 0x40;
    if (!ps3_lv2_mic(s, &env, ram, ram_size, PS3_NID_MIC_READ_RAW, &ret) ||
        ret != CELL_MICIN_ERROR_NOT_OPEN) {
        snprintf(why, why_len, "a read after close answered 0x%X, not "
                 "NOT_OPEN", (uint32_t)ret);
        return false;
    }

    env.gpr[3] = 0;
    if (!ps3_lv2_mic(s, &env, ram, ram_size, PS3_NID_MIC_END, &ret) || ret) {
        snprintf(why, why_len, "cellMicEnd answered 0x%X", (uint32_t)ret);
        return false;
    }

    memset(ram + ea, 0, 0x100);
    s->mic_init = false;
    s->mic_used = 0;

    info_report("ps3-ppu: microphone selftest ok: init/open/start/read/format/"
                "level/close on a %u Hz stereo ring", s->mic_rate);

    /*
     * And once with the real input, so "the voice opened" is not mistaken for
     * "samples arrive".  It opens once the machine is running, then the tick
     * pulls from it for 300 ms and the callback reports the count.
     */
    s->mic_capture_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                       ps3_mic_capture_open, s);
    timer_mod(s->mic_capture_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 100000000);

    return true;
}

static bool ps3_lv2_video_out(PS3BootROMState *s, CPUPPCState *env,
                              uint8_t *ram, uint64_t ram_size,
                              uint32_t nid, int32_t *ret)
{
    uint32_t a0 = env->gpr[3];
    uint32_t a1 = env->gpr[4];
    uint32_t a2 = env->gpr[5];
    uint32_t w, h;
    const char *name = ps3_video_out_name(nid);

    if (!name) {
        return false;
    }

    if (s->ppu_trace) {
        info_report("ps3-ppu: cellVideoOut: %s(0x%X, 0x%X, 0x%X)",
                    name, a0, a1, a2);
    }

    switch (nid) {
    case PS3_NID_VIDEO_OUT_GET_NUM_DEVICES:
        *ret = 1;
        break;
    case PS3_NID_VIDEO_OUT_GET_STATE: {   /* videoOut, device, state* */
        uint8_t *p;

        if ((uint64_t)a2 + 16 > ram_size) {
            *ret = PS3_LV2_EFAULT;
            break;
        }
        p = ram + a2;
        memset(p, 0, 16);
        p[0] = 1;                     /* CELL_VIDEO_OUT_OUTPUT_STATE_ENABLED */
        p[1] = 1;                     /* RGB */
        p[8] = 1;                     /* resolutionId: 1080 */
        p[9] = 0;                     /* scanMode */
        p[10] = 0;                    /* conversion */
        p[11] = 0;                    /* aspect: 16:9 */
        p[15] = 1;                    /* refreshRates: 60 Hz */
        *ret = 0;
        break;
    }
    case PS3_NID_VIDEO_OUT_GET_RESOLUTION: /* resolutionId, resolution* */
        if (!ps3_video_out_resolution((uint8_t)a0, &w, &h)) {
            *ret = PS3_LV2_EINVAL;
            break;
        }
        if ((uint64_t)a1 + 4 > ram_size) {
            *ret = PS3_LV2_EFAULT;
            break;
        }
        ps3_put_be32(ram + a1, (w << 16) | h);
        *ret = 0;
        break;
    case PS3_NID_VIDEO_OUT_RES_AVAILABILITY: /* videoOut, id, aspect, opt */
        *ret = ps3_video_out_resolution((uint8_t)a1, &w, &h) ? 1 : 0;
        break;
    case PS3_NID_VIDEO_OUT_GET_DEVICE_INFO: { /* videoOut, device, info* */
        uint8_t *p;

        if (!a2 || (uint64_t)a2 + PS3_VIDEO_OUT_DEVICE_INFO_SIZE > ram_size) {
            *ret = PS3_LV2_EFAULT;
            break;
        }
        p = ram + a2;
        memset(p, 0, PS3_VIDEO_OUT_DEVICE_INFO_SIZE);
        p[0] = 1;                     /* portType: HDMI */
        p[1] = 1;                     /* colorSpace: RGB */
        p[4] = 2;                     /* availableModeCount */
        p[5] = 1;                     /* state: enabled */
        p[6] = 1;                     /* rgbOutputRange: full */
        /* availableModes start at 32; each is 8 bytes. */
        p[32] = 0x01; p[39] = 1;      /* 1080, 60 Hz */
        p[40] = 0x02; p[47] = 1;      /* 720, 60 Hz */
        if (!s->lv2_video_reported) {
            s->lv2_video_reported = true;
            info_report("ps3-ppu: cellVideoOut: device info: HDMI sink, "
                        "modes 1080 and 720 available");
        }
        *ret = 0;
        break;
    }
    case PS3_NID_VIDEO_OUT_CONFIGURE: {  /* videoOut, config*, option*, wait */
        uint8_t id, aspect;

        if (!a1 || (uint64_t)a1 + 16 > ram_size) {
            *ret = PS3_LV2_EFAULT;
            break;
        }
        id = ram[a1];
        aspect = ram[a1 + 2];
        if (!ps3_video_out_resolution(id, &w, &h)) {
            *ret = PS3_LV2_EINVAL;
            break;
        }
        s->lv2_video_res = id;
        ps3_vga_set_mode(w, h);
        if (!s->lv2_video_reported) {
            s->lv2_video_reported = true;
            info_report("ps3-ppu: cellVideoOut: configured %ux%u "
                        "(aspect %u, pitch 0x%X)", w, h, aspect,
                        ps3_be32(ram + a1 + 12));
        }
        *ret = 0;
        break;
    }
    case PS3_NID_VIDEO_OUT_GET_CONFIG: { /* videoOut, config*, option* */
        if (!a1 || (uint64_t)a1 + 16 > ram_size) {
            *ret = PS3_LV2_EFAULT;
            break;
        }
        memset(ram + a1, 0, 16);
        ram[a1] = s->lv2_video_res ?: 1;
        *ret = 0;
        break;
    }
    case PS3_NID_VIDEO_OUT_SET_CONVERT_MODE:
        *ret = 0;
        break;
    case PS3_NID_VIDEO_OUT_GET_CONVERT_MODE:
        if (a1 && (uint64_t)a1 + 4 <= ram_size) {
            ps3_put_be32(ram + a1, 0);
        }
        *ret = 0;
        break;
    }

    return true;
}

static bool ps3_lv2_sys_io(PS3BootROMState *s, CPUPPCState *env, uint8_t *ram,
                           uint64_t ram_size, uint32_t nid, int32_t *ret)
{
    uint32_t a0 = env->gpr[3];
    uint32_t a1 = env->gpr[4];
    uint32_t a2 = env->gpr[5];
    uint32_t a4 = env->gpr[7];
    uint32_t a5 = env->gpr[8];
    uint32_t a6 = env->gpr[9];
    unsigned connected = ps3_pad_connect(s);
    unsigned port;
    int32_t r = 0;

    if (!ps3_sys_io_name(nid)) {
        return false;
    }

    switch (nid) {
    case PS3_NID_SYS_CONFIG_START:
        info_report("ps3-ppu: sys_io: sys_config_start()");
        break;
    case PS3_NID_SYS_CONFIG_ADD_LISTENER:       /* cfg, service, verbosity,
                                                 * in, size, type, out* */
        if (!a6 || (uint64_t)a6 + 4 > ram_size) {
            r = PS3_LV2_EFAULT;
            break;
        }
        ps3_put_be32(ram + a6, ++s->lv2_next_id);
        info_report("ps3-ppu: sys_io: sys_config_add_service_listener"
                    "(service 0x%X, verbosity %u, type %u)", a1, a2, a5);
        break;
    case PS3_NID_SYS_CONFIG_REGISTER_SERVICE:   /* cfg, service, user,
                                                 * verbosity, data, size,
                                                 * out* */
        if (!a6 || (uint64_t)a6 + 4 > ram_size) {
            r = PS3_LV2_EFAULT;
            break;
        }
        ps3_put_be32(ram + a6, ++s->lv2_next_id);
        info_report("ps3-ppu: sys_io: sys_config_register_service"
                    "(service 0x%X, user %u, %u byte(s))", a1, a2, a5);
        break;
    case PS3_NID_SYS_CONFIG_REMOVE_LISTENER:
    case PS3_NID_SYS_CONFIG_UNREGISTER_SRV:
        break;
    case PS3_NID_CELLPAD_INIT:                  /* max_connect */
        if (!a0) {
            r = PS3_PAD_E_INVALID_PARAMETER;
        } else if (s->pad_max_connect) {
            r = PS3_PAD_E_ALREADY_INITIALIZED;
        } else {
            s->pad_max_connect = a0;
            info_report("ps3-ppu: sys_io: cellPadInit(%u): %u port(s), "
                        "port 0 is a %s", a0, s->pad_ports,
                        ps3_pad_product(s, 0)->name);
        }
        break;
    case PS3_NID_CELLPAD_END:
        if (!s->pad_max_connect) {
            r = PS3_PAD_E_UNINITIALIZED;
            break;
        }
        s->pad_max_connect = 0;
        for (port = 0; port < PS3_PAD_PORT_MAX; port++) {
            s->pad_setting[port] = 0;
        }
        break;
    case PS3_NID_CELLPAD_GET_INFO:              /* info* */
        if (!s->pad_max_connect) {
            r = PS3_PAD_E_UNINITIALIZED;
        } else if (!a0 || (uint64_t)a0 + PS3_PAD_INFO_SIZE > ram_size) {
            r = PS3_PAD_E_INVALID_PARAMETER;
        } else {
            ps3_pad_info(s, ram + a0);
        }
        break;
    case PS3_NID_CELLPAD_GET_INFO2:             /* info* */
        if (!s->pad_max_connect) {
            r = PS3_PAD_E_UNINITIALIZED;
        } else if (!a0 || (uint64_t)a0 + PS3_PAD_INFO2_SIZE > ram_size) {
            r = PS3_PAD_E_INVALID_PARAMETER;
        } else {
            ps3_pad_info2(s, ram + a0);
        }
        break;
    case PS3_NID_CELLPAD_PERIPH_GET_INFO:       /* info* */
        if (!s->pad_max_connect) {
            r = PS3_PAD_E_UNINITIALIZED;
        } else if (!a0 ||
                   (uint64_t)a0 + PS3_PAD_PERIPH_INFO_SIZE > ram_size) {
            r = PS3_PAD_E_INVALID_PARAMETER;
        } else {
            ps3_pad_periph_info(s, ram + a0);
        }
        break;
    case PS3_NID_CELLPAD_GET_DATA:              /* port, data* */
    case PS3_NID_CELLPAD_GET_RAW_DATA:
        if (!s->pad_max_connect) {
            r = PS3_PAD_E_UNINITIALIZED;
        } else if (a0 >= PS3_PAD_CONNECT_MAX || !a1 ||
                   (uint64_t)a1 + PS3_PAD_DATA_SIZE > ram_size) {
            r = PS3_PAD_E_INVALID_PARAMETER;
        } else if (a0 >= s->pad_max_connect) {
            r = PS3_PAD_E_NO_DEVICE;
        } else if (a0 >= connected) {
            r = PS3_PAD_E_NO_DEVICE;    /* described, but not plugged in */
        } else if (nid == PS3_NID_CELLPAD_GET_RAW_DATA) {
            ps3_pad_data(s, a0, ram + a1, false);
        } else {
            ps3_pad_data(s, a0, ram + a1, false);
        }
        break;
    case PS3_NID_CELLPAD_GET_DATA_EXTRA:        /* port, device_type*, data* */
        if (!s->pad_max_connect) {
            r = PS3_PAD_E_UNINITIALIZED;
            break;
        }
        if (a0 >= s->pad_max_connect || a0 >= connected) {
            r = PS3_PAD_E_NO_DEVICE;
            break;
        }
        if (!a2 || (uint64_t)a2 + PS3_PAD_DATA_SIZE > ram_size) {
            r = PS3_PAD_E_INVALID_PARAMETER;
            break;
        }
        ps3_pad_data(s, a0, ram + a2, false);
        if (a1 && (uint64_t)a1 + 4 <= ram_size) {
            ps3_put_be32(ram + a1, 0);  /* CELL_PAD_DEV_TYPE_STANDARD */
        }
        break;
    case PS3_NID_CELLPAD_PERIPH_GET_DATA:       /* port, data* */
        if (!s->pad_max_connect) {
            r = PS3_PAD_E_UNINITIALIZED;
        } else if (a0 >= PS3_PAD_PORT_MAX || !a1 ||
                   (uint64_t)a1 + PS3_PAD_PERIPH_DATA_SIZE > ram_size) {
            r = PS3_PAD_E_INVALID_PARAMETER;
        } else if (a0 >= s->pad_max_connect || a0 >= connected) {
            r = PS3_PAD_E_NO_DEVICE;
        } else {
            const PS3PadProduct *p = ps3_pad_product(s, a0);

            ps3_put_be32(ram + a1, p->pclass);
            ps3_put_be32(ram + a1 + 4, p->profile);
            ps3_pad_data(s, a0, ram + a1 + 8, true);
        }
        break;
    case PS3_NID_CELLPAD_GET_CAPABILITY:        /* port, info* */
        if (!s->pad_max_connect) {
            r = PS3_PAD_E_UNINITIALIZED;
        } else if (a0 >= PS3_PAD_CONNECT_MAX || !a1 ||
                   (uint64_t)a1 + PS3_PAD_CAPABILITY_SIZE > ram_size) {
            r = PS3_PAD_E_INVALID_PARAMETER;
        } else if (a0 >= s->pad_max_connect || a0 >= connected) {
            r = PS3_PAD_E_NO_DEVICE;
        } else {
            memset(ram + a1, 0, PS3_PAD_CAPABILITY_SIZE);
            ps3_put_be32(ram + a1, ps3_pad_product(s, a0)->capability);
        }
        break;
    case PS3_NID_CELLPAD_SET_ACT_DIRECT:        /* port, param* */
        if (!s->pad_max_connect) {
            r = PS3_PAD_E_UNINITIALIZED;
            break;
        }
        if (a0 >= PS3_PAD_CONNECT_MAX || !a1 || (uint64_t)a1 + 8 > ram_size) {
            r = PS3_PAD_E_INVALID_PARAMETER;
            break;
        }
        if (a0 >= s->pad_max_connect || a0 >= connected) {
            r = PS3_PAD_E_NO_DEVICE;
            break;
        }
        if (!(ps3_pad_product(s, a0)->capability & PS3_PAD_CAP_ACTUATOR)) {
            r = PS3_PAD_E_UNSUPPORTED_GAMEPAD;
            break;
        }
        /* There is nothing to shake: remember the motors and carry on. */
        s->pad_motor[a0][0] = ram[a1];
        s->pad_motor[a0][1] = ram[a1 + 1];
        break;
    case PS3_NID_CELLPAD_SET_PORT_SETTING:      /* port, setting */
        if (!s->pad_max_connect) {
            r = PS3_PAD_E_UNINITIALIZED;
        } else if (a0 >= PS3_PAD_CONNECT_MAX) {
            r = PS3_PAD_E_INVALID_PARAMETER;
        } else if (a0 < PS3_PAD_PORT_MAX) {
            if (a1 & PS3_PAD_SETTING_PRESS_ON) {
                s->pad_setting[a0] |= PS3_PAD_SETTING_PRESS_ON;
            } else {
                s->pad_setting[a0] &= ~PS3_PAD_SETTING_PRESS_ON;
            }
            if (a1 & PS3_PAD_SETTING_SENSOR_ON) {
                s->pad_setting[a0] |= PS3_PAD_SETTING_SENSOR_ON;
            } else {
                s->pad_setting[a0] &= ~PS3_PAD_SETTING_SENSOR_ON;
            }
        }
        break;
    case PS3_NID_CELLPAD_SET_PRESS_MODE:        /* port, mode */
    case PS3_NID_CELLPAD_SET_SENSOR_MODE:
        if (!s->pad_max_connect) {
            r = PS3_PAD_E_UNINITIALIZED;
            break;
        }
        if (a0 >= PS3_PAD_CONNECT_MAX || a1 > 1) {
            r = PS3_PAD_E_INVALID_PARAMETER;
            break;
        }
        if (a0 >= PS3_PAD_PORT_MAX) {
            break;
        }
        if (nid == PS3_NID_CELLPAD_SET_PRESS_MODE) {
            if (!(ps3_pad_product(s, a0)->capability & PS3_PAD_CAP_PRESS_MODE)) {
                r = PS3_PAD_E_UNSUPPORTED_GAMEPAD;
                break;
            }
            if (a1) {
                s->pad_setting[a0] |= PS3_PAD_SETTING_PRESS_ON;
            } else {
                s->pad_setting[a0] &= ~PS3_PAD_SETTING_PRESS_ON;
            }
        } else {
            if (!(ps3_pad_product(s, a0)->capability &
                  PS3_PAD_CAP_SENSOR_MODE)) {
                r = PS3_PAD_E_UNSUPPORTED_GAMEPAD;
                break;
            }
            if (a1) {
                s->pad_setting[a0] |= PS3_PAD_SETTING_SENSOR_ON;
            } else {
                s->pad_setting[a0] &= ~PS3_PAD_SETTING_SENSOR_ON;
            }
        }
        break;
    case PS3_NID_CELLPAD_INFO_PRESS_MODE:       /* port */
    case PS3_NID_CELLPAD_INFO_SENSOR_MODE:
        if (!s->pad_max_connect) {
            r = PS3_PAD_E_UNINITIALIZED;
            break;
        }
        if (a0 >= PS3_PAD_CONNECT_MAX) {
            r = PS3_PAD_E_INVALID_PARAMETER;
            break;
        }
        if (a0 >= s->pad_max_connect || a0 >= connected) {
            r = PS3_PAD_E_NO_DEVICE;
            break;
        }
        {
            uint32_t want = nid == PS3_NID_CELLPAD_INFO_PRESS_MODE ?
                PS3_PAD_CAP_PRESS_MODE : PS3_PAD_CAP_SENSOR_MODE;

            r = !!(ps3_pad_product(s, a0)->capability & want);
        }
        break;
    case PS3_NID_CELLPAD_CLEAR_BUF:             /* port */
        if (!s->pad_max_connect) {
            r = PS3_PAD_E_UNINITIALIZED;
        } else if (a0 >= PS3_PAD_CONNECT_MAX) {
            r = PS3_PAD_E_INVALID_PARAMETER;
        } else if (a0 >= s->pad_max_connect || a0 >= connected) {
            r = PS3_PAD_E_NO_DEVICE;
        }
        break;
    case PS3_NID_CELLPAD_LDD_REGISTER:          /* no LDD pad */
        if (!s->pad_max_connect) {
            r = PS3_PAD_E_UNINITIALIZED;
        } else {
            r = PS3_PAD_E_TOO_MANY_DEVICES;
        }
        break;
    case PS3_NID_CELLPAD_LDD_GET_PORT:          /* handle */
        r = PS3_PAD_E_INVALID_PARAMETER;
        break;
    case PS3_NID_CELLPAD_LDD_INSERT:            /* handle, data* */
        if (!s->pad_max_connect) {
            r = PS3_PAD_E_UNINITIALIZED;
        } else if (!a1 || (uint64_t)a1 + PS3_PAD_DATA_SIZE > ram_size) {
            r = PS3_PAD_E_INVALID_PARAMETER;
        } else {
            r = PS3_PAD_E_NO_DEVICE;    /* no handle was ever registered */
        }
        break;
    case PS3_NID_CELLPAD_LDD_UNREGISTER:        /* handle */
        if (!s->pad_max_connect) {
            r = PS3_PAD_E_UNINITIALIZED;
        } else {
            r = PS3_PAD_E_NO_DEVICE;
        }
        break;
    case PS3_NID_SYS_MEMSET:                    /* ptr, byte, size */
        if ((uint64_t)a0 + a2 > ram_size) {
            r = -1;
            break;
        }
        memset(ram + a0, a1 & 0xFF, a2);
        r = (int32_t)a0;
        break;
    case PS3_NID_SYS_PPU_THREAD_CREATE:         /* id*, entry, arg, prio,
                                                 * stack, flags, name* */
        if (!a0 || (uint64_t)a0 + 4 > ram_size) {
            r = PS3_LV2_EFAULT;
            break;
        }
        {
            uint32_t tid = ps3_lv2_thread_created(s, ram, ram_size, env,
                                                  a1, env->gpr[13], a2,
                                                  a4, (int32_t)env->gpr[6], a6);

            if (!tid) {
                r = -EAGAIN;
                break;
            }
            ps3_put_be32(ram + a0, tid);
        }
        break;
    default:
        return false;
    }

    *ret = r;
    return true;
}

/*
 * The console's front LED.
 *
 * sys_sm_control_led is the only path the guest has to the front panel, and a
 * virtual console has no lamp: the state is kept and published to the display
 * frontends, whose window title shows it (`green on', `red blink', ...).  led 0
 * is the power LED, 1 the standby one and 2 the blue disc LED of the later
 * revisions; action 0 is off, 1 on and anything else the blink the boot code
 * asks for while the system is coming up.
 */
static void ps3_console_led(PS3BootROMState *s, uint32_t led, uint32_t action)
{
    const char *colour = led == 0 ? "green" : led == 1 ? "red" :
                         led == 2 ? "blue" : "aux";
    const char *state = action == 0 ? "off" : action == 1 ? "on" : "blink";

    if (led < ARRAY_SIZE(s->led_action)) {
        s->led_action[led] = action;
    }

    snprintf(s->led_text, sizeof(s->led_text), "%s %s", colour, state);
    qemu_console_set_status_led(s->led_text);
    info_report("ps3-ppu: lv2: front LED: %s %s", colour, state);
}

/*
 * Read the pad properties.  `pad-count' is how many of the seven ports exist,
 * and `pad-types' names the product in each of them, comma separated; a single
 * name applies to every port.  The names are the ones in ps3_pad_products.
 */
static bool ps3_pad_defaults(PS3BootROMState *s, Error **errp)
{
    gchar **names = s->pad_types_prop ?
        g_strsplit(s->pad_types_prop, ",", -1) : NULL;
    unsigned count = names ? g_strv_length(names) : 0;
    unsigned port, i;

    if (s->pad_ports < 1) {
        s->pad_ports = 1;
    } else if (s->pad_ports > PS3_PAD_PORT_MAX) {
        s->pad_ports = PS3_PAD_PORT_MAX;
    }

    for (port = 0; port < s->pad_ports; port++) {
        const char *want = count ? names[MIN(port, count - 1)] : "standard";

        for (i = 0; i < ARRAY_SIZE(ps3_pad_products); i++) {
            if (!g_strcmp0(ps3_pad_products[i].name, want)) {
                break;
            }
        }
        if (i == ARRAY_SIZE(ps3_pad_products)) {
            error_setg(errp, "ps3-boot-rom: unknown pad type '%s' (try "
                       "\"standard\", \"guitar\", \"guitar-rb\", "
                       "\"drums\", \"drums-rb\", \"drums-rb3\", "
                       "\"drums-rr\", \"dj\", \"dancemat\", "
                       "\"navigation\", \"move\" or \"skateboard\")", want);
            g_strfreev(names);
            return false;
        }
        s->pad_types[port] = i;
    }

    g_strfreev(names);
    return true;
}

/* ---------------------------------------------------------------------- */
/* lv2's file services: the VSH keeps its own files under /dev_flash2 and   */
/* /dev_hdd0, and without sys_fs it cannot even create a directory.  A guest */
/* path is mapped onto the host firmware tree (or the HDD image) and the   */
/* call runs against the host, so the guest sees the same tree it would on  */
/* the console.                                                            */

/* ---------------------------------------------------------------------- */
/* sysPrxForUser: the helpers lv2's own libraries and the VSH's libc are    */
/* built on.  The light-weight mutex and condition are the primitives lv2    */
/* itself builds the heavier sync objects from, and _sys_printf is how the   */
/* VSH writes to its debug console - the text goes through the same UART    */
/* sys_tty_write feeds, so it lands in the log and on the screen.           */
/*                                                                          */
/* The printf family reads its arguments over the guest's calling           */
/* convention: the first eight integers are in r3..r10, the rest in the      */
/* caller's parameter area at 0x20(r1), and doubles take f1..f13.  Every     */
/* conversion consumes one argument of its own class, exactly as the         */
/* console's own libc would, so a format string means the same thing here.   */
/* ---------------------------------------------------------------------- */

#define PS3_NID_SYS_PRINTF           0x9F04F7AFu
#define PS3_NID_SYS_SNPRINTF         0x06574237u
#define PS3_NID_SYS_SPRINTF          0xA1F9EAFEu
#define PS3_NID_SYS_VSNPRINTF        0x0618936Bu
#define PS3_NID_SYS_VSPRINTF         0x791B9219u
#define PS3_NID_SYS_VPRINTF          0xFA7F693Du
#define PS3_NID_SYS_LWMUTEX_CREATE   0x2F85C0EFu
#define PS3_NID_SYS_LWMUTEX_DESTROY  0xC3476D0Cu
#define PS3_NID_SYS_LWMUTEX_LOCK     0x1573DC3Fu
#define PS3_NID_SYS_LWMUTEX_UNLOCK   0x1BC200F4u
#define PS3_NID_SYS_LWMUTEX_TRYLOCK  0xAEB78725u
#define PS3_NID_SYS_LWCOND_CREATE    0xDA0EB71Au
#define PS3_NID_SYS_LWCOND_DESTROY   0x1C9A942Cu
#define PS3_NID_SYS_LWCOND_WAIT      0x2A6D9D51u
#define PS3_NID_SYS_LWCOND_SIGNAL    0xEF87A695u
#define PS3_NID_SYS_LWCOND_SIGNAL_ALL 0xE9A1BD84u
#define PS3_NID_SYS_LWCOND_SIGNAL_TO 0x52AADADFu
#define PS3_NID_SYS_GET_PARAMSFO     0xE75C40F2u

typedef struct PS3Printf {
    CPUPPCState *env;
    uint8_t *ram;
    uint64_t ram_size;
    unsigned gpr;                   /* register mode: r3 is slot 0 */
    unsigned fpr;
    bool va;                        /* the arguments come from a va_list */
    uint32_t tag;                   /* and this is where that tag lives */
} PS3Printf;

/*
 * The next integer argument, in either calling convention.
 *
 * A PPC64 va_list is the ELFv1 `__va_list_tag`: the byte offset of the next
 * integer argument in the register save area, the same for the float argument
 * area, then the address of the caller's parameter area and the save area
 * itself.  Arguments beyond the eight register slots come from the parameter
 * area, one 8-byte slot at a time, which is what the guest's own libc does.
 */
static uint64_t ps3_printf_word(PS3Printf *p)
{
    if (p->va) {
        uint8_t *tag = p->ram + p->tag;
        uint64_t save, spill, value;
        unsigned off;

        if ((uint64_t)p->tag + 0x18 > p->ram_size) {
            return 0;
        }
        off = tag[0];
        save = ps3_be64(tag + 8);
        spill = ps3_be64(tag + 16);

        if (off < 8 * 8) {
            tag[0] = off + 8;
            if (save + off + 8 > p->ram_size) {
                return 0;
            }
            return ps3_be64(p->ram + save + off);
        }
        if (spill + 8 > p->ram_size) {
            return 0;
        }
        value = ps3_be64(p->ram + spill);
        ps3_put_be64(tag + 16, spill + 8);
        return value;
    }

    {
        unsigned slot = p->gpr++;
        uint64_t at;

        if (slot < 8) {
            return p->env->gpr[3 + slot];
        }
        at = (uint64_t)(uint32_t)p->env->gpr[1] + 0x20 +
             (uint64_t)(slot - 8) * 8;
        if (at + 8 > p->ram_size) {
            return 0;
        }
        return ps3_be64(p->ram + at);
    }
}

static double ps3_printf_double(PS3Printf *p)
{
    union {
        uint64_t u;
        double d;
    } bits;

    if (p->va) {
        uint8_t *tag = p->ram + p->tag;
        uint64_t save;
        unsigned off;

        if ((uint64_t)p->tag + 0x18 > p->ram_size) {
            return 0;
        }
        off = tag[1];
        save = ps3_be64(tag + 8);
        tag[1] = off + 8;
        /* f1..f13 are saved after the eight integer registers. */
        if (save + 0x40 + off + 8 > p->ram_size) {
            return 0;
        }
        bits.u = ps3_be64(p->ram + save + 0x40 + off);
        return bits.d;
    }

    if (p->fpr >= 13) {
        return 0;
    }
    /* The FPRs are the low double of the first 32 VSRs. */
    bits.u = p->env->vsr[p->fpr++].VsrD(0);
    return bits.d;
}

/* One number, with the sign, prefix, width, precision and fill it asked for. */
static void ps3_printf_number(GString *out, uint64_t value, bool negative,
                              unsigned base, bool upper, int width,
                              int precision, bool left, bool zero,
                              const char *prefix)
{
    char digits[32], body[96];
    const char *set = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    unsigned n = 0, len = 0, zeros = 0, pad, i;

    do {
        digits[n++] = set[value % base];
        value /= base;
    } while (value);

    if (negative) {
        body[len++] = '-';
    }
    while (prefix && *prefix) {
        body[len++] = *prefix++;
    }
    if (precision > (int)n) {
        zeros = (unsigned)precision - n;
    }
    if (zero && !left && precision < 0) {
        pad = width > (int)(len + n) ? (unsigned)width - len - n : 0;
        zeros = MAX(zeros, pad);
    }
    for (i = 0; i < zeros; i++) {
        body[len++] = '0';
    }
    for (i = 0; i < n; i++) {
        body[len++] = digits[n - 1 - i];
    }
    body[len] = 0;

    pad = width > (int)len ? (unsigned)width - len : 0;
    if (!left) {
        for (i = 0; i < pad; i++) {
            g_string_append_c(out, ' ');
        }
    }
    g_string_append(out, body);
    if (left) {
        for (i = 0; i < pad; i++) {
            g_string_append_c(out, ' ');
        }
    }
}

static void ps3_printf_text(GString *out, const char *text, int width,
                            int precision, bool left)
{
    size_t len = strlen(text), pad, i;

    if (precision >= 0 && (size_t)precision < len) {
        len = (size_t)precision;
    }
    pad = width > (int)len ? (size_t)width - len : 0;
    if (!left) {
        for (i = 0; i < pad; i++) {
            g_string_append_c(out, ' ');
        }
    }
    g_string_append_len(out, text, len);
    if (left) {
        for (i = 0; i < pad; i++) {
            g_string_append_c(out, ' ');
        }
    }
}

/* %ls: the console's wchar_t is a 32-bit code point, stored big-endian. */
static void ps3_printf_wide(GString *out, uint64_t addr, uint64_t ram_size,
                            const uint8_t *ram)
{
    while (addr && addr + 4 <= ram_size) {
        uint32_t ch = ps3_be32(ram + addr);

        if (!ch) {
            break;
        }
        if (ch < 0x80) {
            g_string_append_c(out, (char)ch);
        } else {
            char utf8[8];
            int len = g_unichar_to_utf8(g_unichar_validate(ch) ? ch : '?',
                                        utf8);

            g_string_append_len(out, utf8, len);
        }
        addr += 4;
    }
}

/* The format string, expanded into `out'. */
static void ps3_printf_format(PS3Printf *p, uint32_t fmt, GString *out)
{
    char text[1024];
    unsigned i;

    if (!ps3_lv2_guest_string(p->ram, p->ram_size, fmt, text, sizeof(text))) {
        return;
    }

    for (i = 0; text[i]; i++) {
        const char *q;
        bool left = false, plus = false, space = false, alt = false;
        bool zero = false;
        int width = 0, precision = -1, length = 0;
        char conv;

        if (text[i] != '%') {
            g_string_append_c(out, text[i]);
            continue;
        }
        q = text + i + 1;
        if (*q == '%') {
            g_string_append_c(out, '%');
            i = q - text;
            continue;
        }
        for (;; q++) {
            if (*q == '-') {
                left = true;
            } else if (*q == '+') {
                plus = true;
            } else if (*q == ' ') {
                space = true;
            } else if (*q == '#') {
                alt = true;
            } else if (*q == '0') {
                zero = true;
            } else {
                break;
            }
        }
        if (*q == '*') {
            width = (int)(int32_t)ps3_printf_word(p);
            if (width < 0) {
                left = true;
                width = -width;
            }
            q++;
        } else {
            while (g_ascii_isdigit(*q)) {
                width = width * 10 + (*q++ - '0');
            }
        }
        if (*q == '.') {
            q++;
            precision = 0;
            if (*q == '*') {
                precision = (int)(int32_t)ps3_printf_word(p);
                q++;
            } else {
                while (g_ascii_isdigit(*q)) {
                    precision = precision * 10 + (*q++ - '0');
                }
            }
        }
        if (*q == 'h') {
            q++;
            length = *q == 'h' ? (q++, -2) : -1;
        } else if (*q == 'l') {
            q++;
            length = *q == 'l' ? (q++, 2) : 1;
        } else if (*q == 'z' || *q == 'j' || *q == 't') {
            length = 3;
            q++;
        } else if (*q == 'L') {
            q++;
        }
        conv = *q;
        i = q - text;

        switch (conv) {
        case 'd': case 'i': {
            int64_t v = (int64_t)ps3_printf_word(p);

            switch (length) {
            case -2:
                v = (int8_t)v;
                break;
            case -1:
                v = (int16_t)v;
                break;
            case 0:
            case 3:
                v = (int32_t)v;
                break;
            default:
                break;      /* long and long long are 64 bits here */
            }
            ps3_printf_number(out, v < 0 ? (uint64_t)-v : (uint64_t)v,
                              v < 0, 10, false, width, precision, left, zero,
                              v < 0 ? NULL : plus ? "+" : space ? " " : NULL);
            break;
        }
        case 'u': case 'o': case 'x': case 'X': {
            uint64_t v = ps3_printf_word(p);

            switch (length) {
            case -2:
                v = (uint8_t)v;
                break;
            case -1:
                v = (uint16_t)v;
                break;
            case 0:
            case 3:
                v = (uint32_t)v;
                break;
            default:
                break;
            }
            ps3_printf_number(out, v, false,
                              conv == 'o' ? 8 : conv == 'u' ? 10 : 16,
                              conv == 'X', width, precision, left, zero,
                              alt && v ? (conv == 'o' ? "0" :
                                          conv == 'X' ? "0X" : "0x") : NULL);
            break;
        }
        case 'c': {
            char one[2] = { (char)(ps3_printf_word(p) & 0xFF), 0 };

            ps3_printf_text(out, one, width, precision, left);
            break;
        }
        case 's': {
            uint64_t addr = ps3_printf_word(p);

            if (!addr) {
                ps3_printf_text(out, "(null)", width, precision, left);
            } else if (length == 1) {
                g_autoptr(GString) wide = g_string_new(NULL);

                ps3_printf_wide(wide, addr, p->ram_size, p->ram);
                ps3_printf_text(out, wide->str, width, precision, left);
            } else {
                char str[512];

                if (!ps3_lv2_guest_string(p->ram, p->ram_size, (uint32_t)addr,
                                          str, sizeof(str))) {
                    str[0] = 0;
                }
                ps3_printf_text(out, str, width, precision, left);
            }
            break;
        }
        case 'p':
            ps3_printf_number(out, ps3_printf_word(p), false, 16, false,
                              width, precision, left, zero, "0x");
            break;
        case 'f': case 'F': case 'e': case 'E': case 'g': case 'G': {
            char spec[16];
            g_autofree gchar *text_out = NULL;

            g_snprintf(spec, sizeof(spec), "%%%s*.*%c", left ? "-" : "",
                       conv == 'F' ? 'f' : g_ascii_tolower(conv));
            text_out = g_strdup_printf(spec, width,
                                       precision < 0 ? 6 : precision,
                                       ps3_printf_double(p));
            g_string_append(out, text_out);
            break;
        }
        case 'n': {
            uint64_t where = ps3_printf_word(p);

            if (where && where + 4 <= p->ram_size) {
                ps3_put_be32(p->ram + where, (uint32_t)out->len);
            }
            break;
        }
        case '\0':
            return;
        default:
            g_string_append_c(out, '%');
            g_string_append_c(out, conv);
            break;
        }
    }
}

/* Put `text' at a guest address, NUL-terminated, never longer than `room'. */
static uint32_t ps3_lv2_put_string(uint8_t *ram, uint64_t ram_size,
                                   uint32_t addr, const char *text,
                                   uint64_t room, bool *ok)
{
    uint64_t len;

    *ok = false;
    if (!addr || addr >= ram_size || !room) {
        return 0;
    }
    room = MIN(room, ram_size - addr);
    len = MIN(strlen(text), room - 1);
    memcpy(ram + addr, text, len);
    ram[addr + len] = 0;
    *ok = true;
    return len;
}

/*
 * The process's parameter block, as much of it as anything reads: a valid
 * SFO header with no entries.  lv2's own call and sysPrxForUser's copy of it
 * answer the same thing, because they are the same call to the guest.
 */
static void ps3_process_sfo_put(uint8_t *ram, uint64_t ram_size, uint32_t ea)
{
    if (!ea || (uint64_t)ea + 0x40 > ram_size) {
        return;
    }
    memset(ram + ea, 0, 0x40);
    ps3_put_be32(ram + ea, 0x00505346);
    ps3_put_be32(ram + ea + 0x04, 0x00000101);
    ps3_put_be32(ram + ea + 0x08, 0x00000014);
    ps3_put_be32(ram + ea + 0x0C, 0x00000014);
}

static bool ps3_lv2_prx_user(PS3BootROMState *s, CPUPPCState *env, uint8_t *ram,
                             uint64_t ram_size, uint32_t nid, int32_t *ret)
{
    uint32_t a0 = env->gpr[3];
    uint32_t a1 = env->gpr[4];
    uint32_t a2 = env->gpr[5];
    uint32_t a3 = env->gpr[6];
    int32_t r = 0;

    switch (nid) {
    case PS3_NID_SYS_PRINTF: {          /* (fmt, ...) */
        PS3Printf p = { env, ram, ram_size, 1, 0, false, 0 };
        g_autoptr(GString) text = g_string_new(NULL);
        size_t i;

        ps3_printf_format(&p, a0, text);
        for (i = 0; i < text->len; i++) {
            ps3_uart_putc(s, text->str[i]);
        }
        break;
    }
    case PS3_NID_SYS_SNPRINTF:          /* (dst, count, fmt, ...) */
    case PS3_NID_SYS_SPRINTF:           /* (dst, fmt, ...) */
    case PS3_NID_SYS_VSNPRINTF:         /* (dst, count, fmt, va_list) */
    case PS3_NID_SYS_VSPRINTF:          /* (dst, fmt, va_list) */
    case PS3_NID_SYS_VPRINTF: {         /* (fmt, va_list) */
        bool to_console = nid == PS3_NID_SYS_VPRINTF;
        bool va = nid == PS3_NID_SYS_VSNPRINTF ||
                  nid == PS3_NID_SYS_VSPRINTF ||
                  nid == PS3_NID_SYS_VPRINTF;
        uint32_t dst = to_console ? 0 : a0;
        uint64_t room = ram_size;
        uint32_t fmt, tag = 0;
        unsigned named;
        PS3Printf p = { env, ram, ram_size, 0, 0, va, 0 };
        g_autoptr(GString) text = g_string_new(NULL);
        bool ok;
        uint32_t len;

        switch (nid) {
        case PS3_NID_SYS_SNPRINTF:
            fmt = a2;
            room = a1;
            named = 3;
            break;
        case PS3_NID_SYS_SPRINTF:
            fmt = a1;
            named = 2;
            break;
        case PS3_NID_SYS_VSNPRINTF:
            fmt = a2;
            room = a1;
            tag = a3;
            named = 0;
            break;
        case PS3_NID_SYS_VSPRINTF:
            fmt = a1;
            tag = a2;
            named = 0;
            break;
        default:                /* _sys_vprintf */
            fmt = a0;
            tag = a1;
            named = 0;
            break;
        }
        if (va) {
            p.tag = tag;
        } else {
            p.gpr = named;
        }
        ps3_printf_format(&p, fmt, text);

        if (to_console) {
            size_t i;

            for (i = 0; i < text->len; i++) {
                ps3_uart_putc(s, text->str[i]);
            }
            break;
        }

        len = ps3_lv2_put_string(ram, ram_size, dst, text->str, room, &ok);
        r = ok ? (int32_t)len : PS3_LV2_EFAULT;
        break;
    }
    case PS3_NID_SYS_GET_PARAMSFO:      /* (u32 *params) */
        /*
         * sys_audio asks for the process's parameters while it brings the
         * audio device up, and it treats a failure as fatal to that path.
         */
        if (!a0 || (uint64_t)a0 + 0x40 > ram_size) {
            r = PS3_LV2_EFAULT;
            break;
        }
        ps3_process_sfo_put(ram, ram_size, a0);
        break;
    case PS3_NID_SYS_LWMUTEX_CREATE:    /* (u32 *id, attribute *) */
    case PS3_NID_SYS_LWCOND_CREATE:     /* (u32 *id, attribute *, lwmutex) */
        if (!a0 || (uint64_t)a0 + 4 > ram_size) {
            r = PS3_LV2_EFAULT;
            break;
        }
        ps3_put_be32(ram + a0, ++s->lv2_next_id);
        break;
    case PS3_NID_SYS_LWMUTEX_LOCK:      /* (id, timeout) */
    case PS3_NID_SYS_LWMUTEX_TRYLOCK:   /* (id) */
    case PS3_NID_SYS_LWMUTEX_UNLOCK:    /* (id) */
    case PS3_NID_SYS_LWMUTEX_DESTROY:   /* (id) */
    case PS3_NID_SYS_LWCOND_WAIT:       /* (id, lwmutex, timeout) */
    case PS3_NID_SYS_LWCOND_SIGNAL:     /* (id) */
    case PS3_NID_SYS_LWCOND_SIGNAL_ALL:
    case PS3_NID_SYS_LWCOND_SIGNAL_TO:
    case PS3_NID_SYS_LWCOND_DESTROY:
        /*
         * The scheduler runs one guest thread at a time, so no thread can
         * hold a light-weight lock against another: a lock is always granted,
         * a wait is a wake-up that has already happened, and the ids are kept
         * so the callers' bookkeeping stays consistent.
         */
        break;
    default:
        return false;
    }

    *ret = r;
    return true;
}

static int32_t ps3_lv2_fs_error(int err)
{
    switch (err) {
    case 0:
        return 0;
    case ENOENT:
        return PS3_LV2_ENOENT;
    case EEXIST:
        return PS3_LV2_EEXIST;
    case EISDIR:
        return PS3_LV2_EISDIR;
    case ENOTDIR:
        return PS3_LV2_ENOTDIR;
    case EACCES:
    case EPERM:
        return PS3_LV2_EACCES;
    default:
        return PS3_LV2_EIO;
    }
}

/* Read a guest path and map it onto the firmware tree; NULL when unmapped. */
static gchar *ps3_lv2_path(PS3BootROMState *s, uint8_t *ram,
                           uint64_t ram_size, uint32_t addr)
{
    char guest[512];

    if (!addr ||
        !ps3_lv2_guest_string(ram, ram_size, addr, guest, sizeof(guest))) {
        return NULL;
    }

    return ps3_lv2_host_path(s, guest);
}

static int ps3_lv2_fd_alloc(PS3BootROMState *s, int host)
{
    unsigned i;

    for (i = 0; i < PS3_LV2_FD_MAX; i++) {
        if (!s->lv2_fd_open[i]) {
            s->lv2_fd_open[i] = true;
            s->lv2_fd[i] = host;
            return (int)i + 3;
        }
    }

    return -1;
}

static int ps3_lv2_fd_host(PS3BootROMState *s, uint32_t guest)
{
    unsigned i;

    if (guest < 3) {
        return -1;
    }

    i = guest - 3;
    if (i >= PS3_LV2_FD_MAX || !s->lv2_fd_open[i]) {
        return -1;
    }

    return s->lv2_fd[i];
}

/* CellFsStat is 0x34 bytes: mode/uid/gid, then 8-byte times and sizes. */
static void ps3_lv2_stat(uint8_t *out, bool is_dir, int64_t atime,
                         int64_t mtime, int64_t ctime, int64_t size)
{
    ps3_put_be32(out + 0x00, is_dir ? 0040755 : 0100644);
    ps3_put_be32(out + 0x04, 0);
    ps3_put_be32(out + 0x08, 0);
    ps3_put_be64(out + 0x0C, atime);
    ps3_put_be64(out + 0x14, mtime);
    ps3_put_be64(out + 0x1C, ctime);
    ps3_put_be64(out + 0x24, size);
    ps3_put_be64(out + 0x2C, 4096);
}

/*
 * The directory side of sys_fs.
 *
 * A listing on a console starts with "." and "..", and both the readdir
 * shape (a CellFsDirent per call) and the packed shape (CellFsDirectoryEntry:
 * the stat, then the name) are used by the VSH's own file library.  The two
 * dot entries are synthesised because a host directory does not carry them.
 */
#define PS3_FS_TYPE_UNKNOWN     0
#define PS3_FS_TYPE_DIRECTORY   1
#define PS3_FS_TYPE_REGULAR     2
#define PS3_FS_DIRENT_SIZE      0x102u   /* type, namlen, name[256] */
#define PS3_FS_DIRENTRY_SIZE    0x138u   /* stat 0x34, then the dirent */

static int ps3_lv2_dir_alloc(PS3BootROMState *s, GDir *dir, const gchar *path)
{
    unsigned i;

    for (i = 0; i < PS3_LV2_FD_MAX; i++) {
        if (!s->lv2_fd_open[i]) {
            s->lv2_fd_open[i] = true;
            s->lv2_fd[i] = -1;
            s->lv2_dir[i] = dir;
            s->lv2_dir_path[i] = g_strdup(path);
            s->lv2_dir_step[i] = 0;
            return (int)i + 3;
        }
    }

    return -1;
}

static GDir *ps3_lv2_dir_host(PS3BootROMState *s, uint32_t guest, int *index)
{
    unsigned i;

    if (guest < 3) {
        return NULL;
    }
    i = guest - 3;
    if (i >= PS3_LV2_FD_MAX || !s->lv2_fd_open[i] || !s->lv2_dir[i]) {
        return NULL;
    }
    if (index) {
        *index = (int)i;
    }
    return s->lv2_dir[i];
}

/* The next entry of a listing, with its host stat when there is one. */
static bool ps3_lv2_dir_entry(PS3BootROMState *s, int i, char *name,
                              size_t len, bool *is_dir, GStatBuf *st,
                              bool *have_st)
{
    unsigned step = s->lv2_dir_step[i]++;
    const char *entry;

    *have_st = false;
    if (step == 0) {
        g_strlcpy(name, ".", len);
        *is_dir = true;
        if (s->lv2_dir_path[i] &&
            g_stat(s->lv2_dir_path[i], st) == 0) {
            *have_st = true;
        }
        return true;
    }
    if (step == 1) {
        g_autofree gchar *parent = s->lv2_dir_path[i] ?
            g_path_get_dirname(s->lv2_dir_path[i]) : NULL;

        g_strlcpy(name, "..", len);
        *is_dir = true;
        if (parent && g_stat(parent, st) == 0) {
            *have_st = true;
        }
        return true;
    }

    entry = g_dir_read_name(s->lv2_dir[i]);
    if (!entry) {
        return false;
    }
    g_strlcpy(name, entry, len);
    *is_dir = false;
    if (s->lv2_dir_path[i]) {
        g_autofree gchar *child =
            g_build_filename(s->lv2_dir_path[i], entry, NULL);

        if (g_stat(child, st) == 0) {
            *have_st = true;
            *is_dir = S_ISDIR(st->st_mode);
        }
    }
    return true;
}

static void ps3_lv2_dirent(uint8_t *out, const char *name, bool is_dir)
{
    size_t len = MIN(strlen(name), (size_t)255);

    out[0] = is_dir ? PS3_FS_TYPE_DIRECTORY : PS3_FS_TYPE_REGULAR;
    out[1] = (uint8_t)len;
    memcpy(out + 2, name, len);
    memset(out + 2 + len, 0, 256 - len);
}

static int32_t ps3_lv2_fs_opendir(PS3BootROMState *s, uint8_t *ram,
                                  uint64_t ram_size, uint32_t path,
                                  uint32_t out)
{
    g_autofree gchar *host = ps3_lv2_path(s, ram, ram_size, path);
    GDir *dir;
    int fd;

    if (s->ppu_trace) {
        char guest[512];

        if (ps3_lv2_guest_string(ram, ram_size, path, guest, sizeof(guest))) {
            info_report("ps3-ppu: lv2: opendir(%s) -> %s", guest,
                        host ? host : "unmapped");
        }
    }
    if (!host) {
        return PS3_LV2_ENOENT;
    }
    if (!out || (uint64_t)out + 4 > ram_size) {
        return PS3_LV2_EFAULT;
    }
    if (g_file_test(host, G_FILE_TEST_IS_REGULAR)) {
        return PS3_LV2_ENOTDIR;
    }
    dir = g_dir_open(host, 0, NULL);
    if (!dir) {
        return g_file_test(host, G_FILE_TEST_IS_DIR) ?
            PS3_LV2_EACCES : PS3_LV2_ENOENT;
    }
    fd = ps3_lv2_dir_alloc(s, dir, host);
    if (fd < 0) {
        g_dir_close(dir);
        return PS3_LV2_EIO;
    }

    ps3_put_be32(ram + out, fd);
    if (s->ppu_trace) {
        info_report("ps3-ppu: lv2: opendir %s -> fd %d", host, fd);
    }
    return 0;
}

static int32_t ps3_lv2_fs_readdir(PS3BootROMState *s, uint8_t *ram,
                                  uint64_t ram_size, uint32_t guest,
                                  uint32_t dirent, uint32_t nread)
{
    char name[256];
    GStatBuf st;
    bool is_dir = false, have_st = false;
    int i = 0;

    if (!ps3_lv2_dir_host(s, guest, &i)) {
        return PS3_LV2_EBADF;
    }
    if (!dirent || (uint64_t)dirent + PS3_FS_DIRENT_SIZE > ram_size ||
        !nread || (uint64_t)nread + 8 > ram_size) {
        return PS3_LV2_EFAULT;
    }

    if (ps3_lv2_dir_entry(s, i, name, sizeof(name), &is_dir, &st, &have_st)) {
        ps3_lv2_dirent(ram + dirent, name, is_dir);
        ps3_put_be64(ram + nread, PS3_FS_DIRENT_SIZE);
        if (s->ppu_trace) {
            info_report("ps3-ppu: lv2: readdir fd %u -> %s%s", guest, name,
                        is_dir ? "/" : "");
        }
    } else {
        /* The end of a listing is an empty entry, not an error. */
        memset(ram + dirent, 0, PS3_FS_DIRENT_SIZE);
        ps3_put_be64(ram + nread, 0);
    }

    return 0;
}

static int32_t ps3_lv2_fs_closedir(PS3BootROMState *s, uint32_t guest)
{
    int i = 0;

    if (!ps3_lv2_dir_host(s, guest, &i)) {
        return PS3_LV2_EBADF;
    }

    if (s->ppu_trace) {
        info_report("ps3-ppu: lv2: closedir fd %u", guest);
    }
    g_dir_close(s->lv2_dir[i]);
    g_free(s->lv2_dir_path[i]);
    s->lv2_dir[i] = NULL;
    s->lv2_dir_path[i] = NULL;
    s->lv2_fd_open[i] = false;
    return 0;
}

/* The sys_fs library exports the VSH's file layer imports by name. */
#define PS3_NID_FS_OPENDIR       0x3F61245Cu
#define PS3_NID_FS_READDIR       0x5C74903Du
#define PS3_NID_FS_CLOSEDIR      0xFF42DCC3u
#define PS3_NID_FS_GET_ENTRIES   0x9B882495u

static bool ps3_lv2_fs_lib(PS3BootROMState *s, CPUPPCState *env, uint8_t *ram,
                           uint64_t ram_size, uint32_t nid, int32_t *ret)
{
    uint32_t a0 = env->gpr[3];
    uint32_t a1 = env->gpr[4];
    uint32_t a2 = env->gpr[5];
    uint32_t a3 = env->gpr[6];

    switch (nid) {
    case PS3_NID_FS_OPENDIR:
        *ret = ps3_lv2_fs_opendir(s, ram, ram_size, a0, a1);
        return true;
    case PS3_NID_FS_READDIR:
        *ret = ps3_lv2_fs_readdir(s, ram, ram_size, a0, a1, a2);
        return true;
    case PS3_NID_FS_CLOSEDIR:
        *ret = ps3_lv2_fs_closedir(s, a0);
        return true;
    case PS3_NID_FS_GET_ENTRIES: {
        char name[256];
        GStatBuf st;
        bool is_dir = false, have_st = false;
        uint32_t room, count = 0;
        int i = 0;

        if (!ps3_lv2_dir_host(s, a0, &i)) {
            *ret = PS3_LV2_EBADF;
            return true;
        }
        if (!a1 || !a3 || (uint64_t)a3 + 4 > ram_size ||
            (uint64_t)a1 + a2 > ram_size) {
            *ret = PS3_LV2_EFAULT;
            return true;
        }
        room = a2 / PS3_FS_DIRENTRY_SIZE;
        while (count < room &&
               ps3_lv2_dir_entry(s, i, name, sizeof(name), &is_dir, &st,
                                 &have_st)) {
            uint8_t *at = ram + a1 + (uint64_t)count * PS3_FS_DIRENTRY_SIZE;

            if (have_st) {
                ps3_lv2_stat(at, is_dir, st.st_atime, st.st_mtime,
                             st.st_ctime, st.st_size);
            } else {
                ps3_lv2_stat(at, is_dir, 0, 0, 0, 0);
            }
            ps3_lv2_dirent(at + 0x34, name, is_dir);
            count++;
        }
        ps3_put_be32(ram + a3, count);
        *ret = 0;
        return true;
    }
    default:
        return false;
    }
}


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
/*
 * The sound driver's DMA side.
 *
 * sys_rsxaudio gives the guest a page of ring buffers: the serial ring is the
 * stereo mix that goes to HDMI and the AV multi out, and two S/PDIF rings sit
 * beside it.  Every entry names a 256-byte block (32 stereo frames of
 * big-endian floats) plus a timestamp; the hardware pulls entries while
 * read_idx trails write_idx and clears `valid` as it goes.  This is that pull:
 * it runs on a 5 ms timer, turns each block into S16 for the host backend and
 * publishes its progress back into the guest's page.
 */
#define PS3_RSXAUDIO_RING_STRIDE  0x230
#define PS3_RSXAUDIO_ENTRY_BASE   0x30
#define PS3_RSXAUDIO_ENTRY_STRIDE 0x20
#define PS3_RSXAUDIO_ENTRIES      16
#define PS3_RSXAUDIO_BLOCK_BYTES  256
#define PS3_RSXAUDIO_RING_ACTIVE  0x00
#define PS3_RSXAUDIO_RING_READ    0x08
#define PS3_RSXAUDIO_RING_WRITE   0x0C
#define PS3_RSXAUDIO_RING_NEXT    0x28
#define PS3_RSXAUDIO_ENTRY_VALID  0x00
#define PS3_RSXAUDIO_ENTRY_BUF    0x18

static void ps3_rsxaudio_tick(void *opaque);

static void ps3_rsxaudio_kick(PS3BootROMState *s)
{
    if (!s->rsxaudio_timer) {
        s->rsxaudio_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                         ps3_rsxaudio_tick, s);
    }
    timer_mod(s->rsxaudio_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 5000000);
}

static void ps3_rsxaudio_tick(void *opaque)
{
    PS3BootROMState *s = opaque;
    uint8_t *ram = memory_region_get_ram_ptr(s->ram);
    uint64_t ram_size = memory_region_size(s->ram);
    uint32_t ring = s->rsxaudio_shmem;
    unsigned taken = 0;

    if (s->rsxaudio_running && ring && (uint64_t)ring + 0x1000 <= ram_size &&
        ps3_be32(ram + ring + PS3_RSXAUDIO_RING_ACTIVE)) {
        while (taken < 8) {
            uint32_t rd = ps3_be32(ram + ring + PS3_RSXAUDIO_RING_READ);
            uint32_t wr = ps3_be32(ram + ring + PS3_RSXAUDIO_RING_WRITE);
            uint32_t entry, valid, buf;

            if (rd == wr) {
                break;
            }

            entry = ring + PS3_RSXAUDIO_ENTRY_BASE +
                    (rd % PS3_RSXAUDIO_ENTRIES) * PS3_RSXAUDIO_ENTRY_STRIDE;
            valid = ps3_be32(ram + entry + PS3_RSXAUDIO_ENTRY_VALID);
            buf = ps3_be32(ram + entry + PS3_RSXAUDIO_ENTRY_BUF);

            if (valid && buf &&
                (uint64_t)buf + PS3_RSXAUDIO_BLOCK_BYTES <= ram_size) {
                ps3_audio_play_f32be(s->audio, ram + buf);
                s->rsxaudio_blocks++;
            }

            /* The block is consumed whether or not it held audio. */
            ps3_put_be32(ram + entry + PS3_RSXAUDIO_ENTRY_VALID, 0);
            ps3_put_be64(ram + ring + PS3_RSXAUDIO_RING_NEXT,
                         (uint64_t)rd + 1);
            ps3_put_be32(ram + ring + PS3_RSXAUDIO_RING_READ, rd + 1);
            taken++;
        }
    }

    if (s->rsxaudio_running) {
        ps3_rsxaudio_kick(s);
    }
}

/*
 * The syscon EEPROM.  RPCS3's ps3_syscon is the reference for the layout: only
 * the recover byte has meaning, everything else reads 0xFF until the guest
 * writes it, and 0x48C07 is the state of the machine rather than a stored byte.
 * emer_init reads it through sys_ss_update_manager(0x600B).
 */
#define PS3_SYSCON_RECOVER_OFFSET   0x48C07u

static uint8_t ps3_syscon_read(PS3BootROMState *s, uint32_t off)
{
    int i;

    if (off == PS3_SYSCON_RECOVER_OFFSET) {
        return s->syscon_recover ? 0x00 : 0xFF;
    }
    for (i = 0; i < s->syscon_ee_n; i++) {
        if (s->syscon_ee[i].off == off) {
            return s->syscon_ee[i].val;
        }
    }
    return 0xFF;
}

static void ps3_syscon_write(PS3BootROMState *s, uint32_t off, uint8_t val)
{
    int i;

    if (off == PS3_SYSCON_RECOVER_OFFSET) {
        s->syscon_recover = val != 0xFF;
        return;
    }
    for (i = 0; i < s->syscon_ee_n; i++) {
        if (s->syscon_ee[i].off == off) {
            s->syscon_ee[i].val = val;
            return;
        }
    }
    if (s->syscon_ee_n < ARRAY_SIZE(s->syscon_ee)) {
        s->syscon_ee[s->syscon_ee_n].off = off;
        s->syscon_ee[s->syscon_ee_n].val = val;
        s->syscon_ee_n++;
    }
}

/*
 * The RSX front end.
 *
 * This is lv2's sys_rsx, not a modelled graphics library: cellGcmSys.sprx is
 * real guest code and reaches the GPU through these calls alone.  Their
 * semantics follow RPCS3's sys_rsx, which is the only public description of
 * them, so a library that works there sees the same answers here:
 *
 *   device open/close      0x29A 0x29B   the device is always present
 *   memory allocate/free   0x29C 0x29D   local memory, handle 0x5A5A5A5B
 *   context allocate/free  0x29E 0x29F   DMA, driver info and report areas
 *   iomap/iounmap          0x2A0 0x2A1   the io window the FIFO lives in
 *   context attribute      0x2A2         FIFO, display, tiles, zcull, events
 *   device map/unmap       0x2A3 0x2A4   the register window
 *   attribute              0x2A5         accepted
 *
 * The FIFO is a packet ring in main memory.  The graphics library writes
 * packets, publishes put in the DMA control block and calls attribute 0x001:
 * that call is the doorbell.  This handler then consumes packets from get to
 * put - following jump, call and return packets - dispatching each method to
 * the display-side handler and writing get back, so the RSX runs entirely off
 * the guest's own calls.  Nothing here needs a tick.
 *
 * Local memory is a real 256 MiB RAM region at PS3_RSX_LOCAL_BASE, so the
 * display buffers cellGcmSetDisplayBuffer names are readable by the scanout.
 * The method handler executes the surface, clear and synchronisation methods
 * that decide what a flip shows; the shader pipeline and the copy engine are
 * what this front end still does not have.
 */
#define PS3_RSX_LV1_ILLEGAL_PARAM (-17)

static uint64_t ps3_rsx_timebase(void)
{
    /* The console's timebase runs at 79.8 MHz, as the CPU's does. */
    return (qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) * 798ull) / 10000ull;
}

/* An io offset through the context's map; 0xFFFFFFFF when it is not mapped. */
static uint32_t ps3_rsx_io_ea(PS3BootROMState *s, uint32_t io)
{
    uint32_t page = io >> 20;

    if (page >= PS3_RSX_IO_PAGES || !s->rsx_iomap_used[page]) {
        return 0xFFFFFFFFu;
    }
    return s->rsx_iomap_ea[page] | (io & 0xFFFFFu);
}

/*
 * The current render target.
 *
 * NV4097_SET_SURFACE_FORMAT packs the render target's log2 width and height
 * (bits 16..23 and 24..31) with its colour format, and the pitch and offset
 * registers say where the pixels live.  A surface offset below the local
 * memory size names local memory; any other is an io offset and is resolved
 * through the context map.  Both paths are bounds checked against the region
 * they name before a single word is written.
 *
 * The five-bit colour format decides the channel order of a pixel word.  The
 * A8R8G8B8 family stores alpha, red, green, blue from the most significant
 * byte; the A8B8G8R8 family stores alpha, blue, green, red.  Formats 12 and 13
 * are the 32-bit float targets, which a clear can fill with the guest's word
 * but which the rasterizer does not blend into.
 */
typedef struct PS3RsxSurface {
    uint8_t *base;
    unsigned width, height, pitch;
    uint64_t limit;
    unsigned format;
    bool bgr;                   /* the format stores blue in bits 16..23 */
    bool colour32;              /* the target holds 8-bit RGBA channels */
    int x0, y0, x1, y1;         /* the scissor, inclusive, window coordinates */
} PS3RsxSurface;

static bool ps3_rsx_surface(PS3BootROMState *s, uint8_t *ram,
                            uint64_t ram_size, PS3RsxSurface *out)
{
    uint32_t fmt = s->rsx_surface_format;
    unsigned lw = (fmt >> 16) & 0xFF, lh = (fmt >> 24) & 0xFF;
    unsigned width, height, pitch, off;
    uint8_t *base;
    uint64_t limit;

    if (!fmt || lw > 12 || lh > 12) {
        return false;
    }

    switch (fmt & 0x1F) {
    case 4:                     /* X8R8G8B8_Z8R8G8B8 */
    case 5:                     /* X8R8G8B8_O8R8G8B8 */
    case 8:                     /* A8R8G8B8 */
    case 12:                    /* F_W32Z32Y32X32 */
    case 13:                    /* F_X32 */
    case 14:                    /* X8B8G8R8_Z8B8G8R8 */
    case 15:                    /* X8B8G8R8_O8B8G8R8 */
    case 16:                    /* A8B8G8R8 */
        break;
    default:
        return false;
    }

    width = 1u << lw;
    height = 1u << lh;
    pitch = s->rsx_surface_pitch ? s->rsx_surface_pitch : width * 4;
    off = s->rsx_surface_offset & ~3u;

    if (pitch < width * 4) {
        return false;
    }

    if (off < s->rsx_local_size) {
        base = memory_region_get_ram_ptr(&s->rsx_local) + off;
        limit = s->rsx_local_size - off;
    } else {
        uint32_t ea = ps3_rsx_io_ea(s, off);

        if (ea == 0xFFFFFFFFu || (uint64_t)ea + 4 > ram_size) {
            return false;
        }
        base = ram + ea;
        limit = ram_size - ea;
    }

    if ((uint64_t)pitch * height > limit) {
        return false;
    }

    out->base = base;
    out->width = width;
    out->height = height;
    out->pitch = pitch;
    out->limit = limit;
    out->format = fmt & 0x1F;
    out->bgr = (fmt & 0x1F) >= 14;
    out->colour32 = (fmt & 0x1F) != 12 && (fmt & 0x1F) != 13;

    return true;
}

/*
 * Colour target clear.  Only surface A is filled: it is the target a single
 * render target uses, and every other target is reported rather than guessed
 * at.
 */
static void ps3_rsx_clear(PS3BootROMState *s, uint8_t *ram, uint64_t ram_size,
                          uint32_t target, uint32_t color)
{
    PS3RsxSurface surf;
    unsigned y;

    if (!(target & 1)) {
        return;
    }

    if (!ps3_rsx_surface(s, ram, ram_size, &surf)) {
        if (s->ppu_trace) {
            info_report("ps3-rsx: clear: surface 0x%08X (format 0x%X, "
                        "pitch 0x%X, offset 0x%X) is not a clearable target",
                        s->rsx_surface_format, s->rsx_surface_format & 0x1F,
                        s->rsx_surface_pitch, s->rsx_surface_offset);
        }
        return;
    }

    for (y = 0; y < surf.height; y++) {
        uint32_t x;
        uint8_t *row = surf.base + (uint64_t)y * surf.pitch;

        for (x = 0; x < surf.width; x++) {
            ps3_put_be32(row + 4 * x, color);
        }
    }

    s->rsx_draws++;
    if (s->ppu_trace) {
        info_report("ps3-rsx: clear 0x%08X: %ux%u at 0x%X, pitch 0x%X",
                    color, surf.width, surf.height, s->rsx_surface_offset,
                    surf.pitch);
    }
}

/*
 * The vertex pipeline.
 *
 * cellGcmSys has no fixed-function state of its own: it writes the same NV4097
 * methods a game does, so the vertex arrays, the viewport, the scissor and the
 * blend state arrive here as register values.  Two things the hardware does
 * that this front end does not are the vertex program and the texture unit.
 * The RSX runs a vp40 shader that turns the attribute registers into clip-space
 * positions and colours; without it the model takes the position attribute as
 * the primitive's coordinates - through the viewport when the values look like
 * clip space, directly when they are already window coordinates, which is what
 * the 2D interface path feeds - and interpolates the colour attribute across
 * the primitive.  Everything else (how draws accumulate into one primitive, the
 * index fetch, the base-index addition, the scissor and the blending) follows
 * RPCS3's nv4097 handlers.
 */

/* A half float, as the sf vertex attribute type stores it. */
static float ps3_rsx_half(uint16_t h)
{
    unsigned sign = h >> 15, exp = (h >> 10) & 0x1F, man = h & 0x3FF;
    float v;

    if (!exp) {
        v = ldexpf(man, -24);
    } else if (exp == 0x1F) {
        v = man ? NAN : INFINITY;
    } else {
        v = ldexpf(1024 + man, (int)exp - 25);
    }

    return sign ? -v : v;
}

/* Bytes one component of a vertex attribute type occupies. */
static unsigned ps3_rsx_type_size(unsigned type)
{
    switch (type) {
    case 0:                     /* s1, signed short normalized */
    case 2:                     /* sf, half float */
    case 4:                     /* s32k, signed short */
    case 5:                     /* cmp, packed 16-bit */
        return 2;
    case 1:                     /* f, float */
        return 4;
    case 3:                     /* ub, unsigned byte normalized */
    case 6:                     /* ub256, unsigned byte */
        return 1;
    default:
        return 0;
    }
}

/* One component of an attribute, from its guest-order bytes. */
static float ps3_rsx_component(const uint8_t *p, unsigned type)
{
    switch (type) {
    case 0:
        return MAX((int16_t)((p[0] << 8) | p[1]) / 32767.0f, -1.0f);
    case 1: {
        uint32_t w = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                     ((uint32_t)p[2] << 8) | p[3];
        float f;

        memcpy(&f, &w, sizeof(f));
        return f;
    }
    case 2:
        return ps3_rsx_half((p[0] << 8) | p[1]);
    case 3:
        return p[0] / 255.0f;
    case 4:
        return (int16_t)((p[0] << 8) | p[1]);
    case 5:
        return (float)((p[0] << 8) | p[1]);
    case 6:
        return p[0];
    default:
        return 0.0f;
    }
}

/*
 * The attribute the colour comes from.
 *
 * The console's shaders name their own attribute registers, so without running
 * the vertex program the model picks the register that carries a colour: the
 * first 3- or 4-component attribute in the usual diffuse slots.  When none is
 * enabled the primitive is white.
 */
static int ps3_rsx_colour_attr(PS3BootROMState *s)
{
    static const unsigned order[] = { 1, 3, 2, 4 };
    unsigned k;

    for (k = 0; k < ARRAY_SIZE(order); k++) {
        unsigned fmt = s->rsx_vtx_fmt[order[k]];

        if (((fmt >> 4) & 0xF) >= 3 && ps3_rsx_type_size(fmt & 7)) {
            return order[k];
        }
    }

    return -1;
}

/*
 * Read one attribute of one vertex out of its array.
 *
 * The offset register's top bit says which memory the array lives in - set is
 * main memory, clear is local - and the rest is the offset, which the hardware
 * adds to the vertex base offset and masks to 28 bits (RPCS3's
 * get_vertex_offset_from_base).  An array whose vertex stride is zero is
 * packed: the components follow each other.
 */
static bool ps3_rsx_read_array(PS3BootROMState *s, uint8_t *ram,
                               uint64_t ram_size, unsigned attr,
                               uint32_t vertex, float out[4])
{
    uint32_t fmt = s->rsx_vtx_fmt[attr];
    unsigned size = (fmt >> 4) & 0xF, type = fmt & 7;
    unsigned tsize = ps3_rsx_type_size(type);
    unsigned stride = (fmt >> 8) & 0xFF, i;
    uint32_t raw = s->rsx_vtx_off[attr];
    bool main_mem = !!(raw & 0x80000000u);
    uint32_t off = ((raw & 0x7FFFFFFFu) + s->rsx_vtx_base) & 0x0FFFFFFFu;
    uint64_t addr, span;
    const uint8_t *p;

    if (!size || size > 4 || !tsize) {
        return false;
    }

    span = (uint64_t)size * tsize;
    if (!stride) {
        stride = span;
    }
    addr = (uint64_t)off + (uint64_t)vertex * stride;

    if (main_mem) {
        uint32_t ea = ps3_rsx_io_ea(s, (uint32_t)addr);

        /* An attribute that crosses the page was not mapped as one page. */
        if (ea == 0xFFFFFFFFu || ((uint32_t)addr & 0xFFFFF) + span > 0x100000 ||
            (uint64_t)ea + span > ram_size) {
            return false;
        }
        p = ram + ea;
    } else {
        if (addr + span > s->rsx_local_size) {
            return false;
        }
        p = memory_region_get_ram_ptr(&s->rsx_local) + addr;
    }

    for (i = 0; i < 4; i++) {
        out[i] = i == 3 ? 1.0f : 0.0f;
    }
    for (i = 0; i < size; i++) {
        out[i] = ps3_rsx_component(p + (uint64_t)i * tsize, type);
    }

    return true;
}

/* Bytes one inline (push buffer) vertex occupies. */
static unsigned ps3_rsx_inline_stride(PS3BootROMState *s)
{
    unsigned i, total = 0;

    for (i = 0; i < PS3_RSX_ATTRS; i++) {
        unsigned fmt = s->rsx_vtx_fmt[i];
        unsigned size = (fmt >> 4) & 0xF;
        unsigned tsize = ps3_rsx_type_size(fmt & 7);

        if (size && size <= 4) {
            total += size * tsize;
        }
    }

    return total;
}

/* Read one attribute of one vertex out of the inline word stream. */
static bool ps3_rsx_read_inline(PS3BootROMState *s, unsigned attr,
                                uint32_t vertex, float out[4])
{
    uint32_t fmt = s->rsx_vtx_fmt[attr];
    unsigned size = (fmt >> 4) & 0xF, type = fmt & 7;
    unsigned tsize = ps3_rsx_type_size(type);
    unsigned stride = ps3_rsx_inline_stride(s);
    unsigned prefix = 0, i;
    uint64_t base;
    const uint8_t *p;

    if (!size || size > 4 || !tsize || !stride) {
        return false;
    }

    for (i = 0; i < attr; i++) {
        unsigned f = s->rsx_vtx_fmt[i];
        unsigned sz = (f >> 4) & 0xF;

        if (sz && sz <= 4) {
            prefix += sz * ps3_rsx_type_size(f & 7);
        }
    }

    base = (uint64_t)vertex * stride + prefix;
    if (base + (uint64_t)size * tsize > (uint64_t)s->rsx_inline_words * 4) {
        return false;
    }

    p = s->rsx_inline + base;
    for (i = 0; i < 4; i++) {
        out[i] = i == 3 ? 1.0f : 0.0f;
    }
    for (i = 0; i < size; i++) {
        out[i] = ps3_rsx_component(p + (uint64_t)i * tsize, type);
    }

    return true;
}

/*
 * The vertex program.
 *
 * The RSX runs a vp40 shader: four 32-bit words per instruction, an input
 * register file of sixteen vec4 attributes, sixteen temporaries, an address
 * register and a bank of vec4 constants.  The encoding is RPCS3's
 * RSXVertexProgram.h (D0..D3 plus the three 17-bit source fields), and the
 * execution below follows its CgBinaryVertexProgram operand handling: a source
 * selects a temporary, an input attribute or a constant, applies a swizzle,
 * an optional absolute value and a negation; the vector opcode produces a
 * vec4 that the write mask commits, optionally saturated.
 *
 * Output register 0 is the clip-space position (the hardware requires it) and
 * the first further output the program writes supplies the colour, which is
 * where a fragment program's colour input would come from.  The scalar opcodes
 * and the branch family are not executed: a program that uses one is refused,
 * and the caller falls back to the attribute path (reported once).
 */
typedef struct PS3RsxVpInst {
    uint32_t src[3];
    unsigned input_src, const_src;
    unsigned vec_op, sca_op;
    unsigned dst, dst_tmp, mask;
    unsigned index_const;
    bool end, staturate;
} PS3RsxVpInst;

static void ps3_rsx_vp_parse(const uint32_t w[4], PS3RsxVpInst *in)
{
    unsigned mw = (w[3] >> 13) & 1, mz = (w[3] >> 14) & 1;
    unsigned my = (w[3] >> 15) & 1, mx = (w[3] >> 16) & 1;

    in->src[0] = ((w[2] >> 23) & 0x1FF) | ((w[1] & 0xFF) << 9);
    in->src[1] = (w[2] >> 6) & 0x1FFFF;
    in->src[2] = ((w[3] >> 21) & 0x7FF) | ((w[2] & 0x3F) << 11);
    in->input_src = (w[1] >> 8) & 0xF;
    in->const_src = (w[1] >> 12) & 0x3FF;
    in->vec_op = (w[1] >> 22) & 0x1F;
    in->sca_op = (w[1] >> 27) & 0x1F;
    in->dst_tmp = (w[0] >> 13) & 0x3F;
    in->staturate = (w[0] >> 24) & 1;
    in->dst = (w[3] >> 2) & 0x1F;
    in->mask = mx | (my << 1) | (mz << 2) | (mw << 3);
    in->end = w[3] & 1;
    in->index_const = (w[3] >> 1) & 1;
}

/* One source operand: register selection, swizzle, absolute value, negation. */
static bool ps3_rsx_vp_src(PS3BootROMState *s, const PS3RsxVpInst *in,
                           const float vin[PS3_RSX_ATTRS][4],
                           const float r[16][4], float a0, unsigned n,
                           bool abs_value, float out[4])
{
    uint32_t src = in->src[n];
    unsigned tmp = src & 0x3F;
    unsigned swz = (src >> 6) & 0xFF;
    bool neg = (src >> 14) & 1;
    unsigned type = (src >> 15) & 3;
    float v[4], w[4];
    unsigned i;

    switch (type) {
    case 1:                             /* temporary register */
        if (tmp >= 16) {
            return false;
        }
        memcpy(v, r[tmp], sizeof(v));
        break;
    case 2:                             /* input attribute */
        memcpy(v, vin[in->input_src & (PS3_RSX_ATTRS - 1)], sizeof(v));
        break;
    case 3: {                           /* constant bank */
        unsigned idx = in->const_src;

        if (in->index_const) {
            /* The address register shifts the bank; A0 is a float. */
            idx = (idx + (unsigned)(int)floorf(a0)) & 0xFF;
        }
        idx &= PS3_RSX_VCONST - 1;
        for (i = 0; i < 4; i++) {
            uint32_t word = s->rsx_vconst[idx][i];

            memcpy(&v[i], &word, sizeof(v[i]));
        }
        break;
    }
    default:
        return false;
    }

    for (i = 0; i < 4; i++) {
        w[i] = v[(swz >> (2 * i)) & 3];
    }
    if (abs_value) {
        for (i = 0; i < 4; i++) {
            w[i] = fabsf(w[i]);
        }
    }
    for (i = 0; i < 4; i++) {
        out[i] = neg ? -w[i] : w[i];
    }

    return true;
}

/* The vector opcodes: the NV40 forms RPCS3's enum names. */
static bool ps3_rsx_vp_vec(unsigned op, const float a[4], const float b[4],
                           const float c[4], float out[4])
{
    unsigned i;
    float d;

    switch (op) {
    case 0:                             /* NOP */
        memcpy(out, a, 16);
        return true;
    case 1:                             /* MOV */
        memcpy(out, a, 16);
        return true;
    case 2:                             /* MUL */
        for (i = 0; i < 4; i++) out[i] = a[i] * b[i];
        return true;
    case 3:                             /* ADD */
        for (i = 0; i < 4; i++) out[i] = a[i] + b[i];
        return true;
    case 4:                             /* MAD */
        for (i = 0; i < 4; i++) out[i] = a[i] * b[i] + c[i];
        return true;
    case 5:                             /* DP3 */
        d = a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
        for (i = 0; i < 4; i++) out[i] = d;
        return true;
    case 6:                             /* DPH */
        d = a[0] * b[0] + a[1] * b[1] + a[2] * b[2] + b[3];
        for (i = 0; i < 4; i++) out[i] = d;
        return true;
    case 7:                             /* DP4 */
        d = a[0] * b[0] + a[1] * b[1] + a[2] * b[2] + a[3] * b[3];
        for (i = 0; i < 4; i++) out[i] = d;
        return true;
    case 8:                             /* DST */
        out[0] = 1.0f;
        out[1] = a[1] * b[1];
        out[2] = a[2];
        out[3] = b[3];
        return true;
    case 9:                             /* MIN */
        for (i = 0; i < 4; i++) out[i] = MIN(a[i], b[i]);
        return true;
    case 10:                            /* MAX */
        for (i = 0; i < 4; i++) out[i] = MAX(a[i], b[i]);
        return true;
    case 11:                            /* SLT */
        for (i = 0; i < 4; i++) out[i] = a[i] < b[i] ? 1.0f : 0.0f;
        return true;
    case 12:                            /* SGE */
        for (i = 0; i < 4; i++) out[i] = a[i] >= b[i] ? 1.0f : 0.0f;
        return true;
    case 13:                            /* ARL: the address register */
        return false;                   /* handled separately */
    case 14:                            /* FRC */
        for (i = 0; i < 4; i++) out[i] = a[i] - floorf(a[i]);
        return true;
    case 15:                            /* FLR */
        for (i = 0; i < 4; i++) out[i] = floorf(a[i]);
        return true;
    case 16:                            /* SEQ */
        for (i = 0; i < 4; i++) out[i] = a[i] == b[i] ? 1.0f : 0.0f;
        return true;
    case 17:                            /* SFL */
        for (i = 0; i < 4; i++) out[i] = 0.0f;
        return true;
    case 18:                            /* SGT */
        for (i = 0; i < 4; i++) out[i] = a[i] > b[i] ? 1.0f : 0.0f;
        return true;
    case 19:                            /* SLE */
        for (i = 0; i < 4; i++) out[i] = a[i] <= b[i] ? 1.0f : 0.0f;
        return true;
    case 20:                            /* SNE */
        for (i = 0; i < 4; i++) out[i] = a[i] != b[i] ? 1.0f : 0.0f;
        return true;
    case 21:                            /* STR */
        for (i = 0; i < 4; i++) out[i] = 1.0f;
        return true;
    case 22:                            /* SSG */
        for (i = 0; i < 4; i++) {
            out[i] = a[i] > 0.0f ? 1.0f : (a[i] < 0.0f ? -1.0f : 0.0f);
        }
        return true;
    default:
        return false;
    }
}

/*
 * Run the loaded program for one vertex.  Returns false when there is no
 * program, when it uses an instruction this interpreter does not have, or when
 * it never writes output 0.  The sixteen outputs are what the fragment stage
 * sees as its varying inputs.
 */
static bool ps3_rsx_vprog_run(PS3BootROMState *s,
                              const float vin[PS3_RSX_ATTRS][4],
                              float out[16][4])
{
    float r[16][4] = { { 0 } }, o[16][4] = { { 0 } };
    bool wrote[16] = { false };
    bool abs_mask[3];
    float a0 = 0.0f;
    unsigned pc, steps, i;

    if (!s->rsx_vprog_ready) {
        return false;
    }

    pc = s->rsx_vprog_start & (PS3_RSX_VPROG_INST - 1);

    for (steps = 0; steps < PS3_RSX_VPROG_INST; steps++) {
        const uint32_t *w = &s->rsx_vprog[(pc & (PS3_RSX_VPROG_INST - 1)) * 4];
        PS3RsxVpInst in;
        float a[4], b[4], c[4], res[4];
        float *dstp = NULL;
        bool ok;

        if (!w[0] && !w[1] && !w[2] && !w[3]) {
            break;                      /* the program ends at a zero slot */
        }

        ps3_rsx_vp_parse(w, &in);

        if (in.sca_op) {
            return false;               /* scalar/branch family is not run */
        }

        abs_mask[0] = (w[0] >> 19) & 1;
        abs_mask[1] = (w[0] >> 20) & 1;
        abs_mask[2] = (w[0] >> 21) & 1;

        ok = ps3_rsx_vp_src(s, &in, vin, r, a0, 0, abs_mask[0], a);
        ok = ok && ps3_rsx_vp_src(s, &in, vin, r, a0, 1, abs_mask[1], b);
        ok = ok && ps3_rsx_vp_src(s, &in, vin, r, a0, 2, abs_mask[2], c);
        if (!ok) {
            return false;
        }

        if (in.vec_op == 13) {          /* ARL: round down into A0 */
            a0 = floorf(a[0]);
        } else if (!ps3_rsx_vp_vec(in.vec_op, a, b, c, res)) {
            return false;
        } else {
            if (in.staturate) {
                for (i = 0; i < 4; i++) {
                    res[i] = MIN(MAX(res[i], 0.0f), 1.0f);
                }
            }
        }

        if (in.vec_op != 13 && in.mask) {
            if (in.dst < 16) {
                dstp = o[in.dst];
                wrote[in.dst] = true;
            } else if (in.dst == 0x1F && in.dst_tmp < 16) {
                dstp = r[in.dst_tmp];
            }
            if (dstp) {
                for (i = 0; i < 4; i++) {
                    if (in.mask & (1u << i)) {
                        dstp[i] = res[i];
                    }
                }
            }
            /* The double destination vp40 supports: output plus temporary. */
            if (in.dst < 16 && in.dst_tmp != 0x3F && in.dst_tmp < 16) {
                for (i = 0; i < 4; i++) {
                    if (in.mask & (1u << i)) {
                        r[in.dst_tmp][i] = res[i];
                    }
                }
            }
        }

        if (in.end) {
            break;
        }
        pc++;
    }

    if (!wrote[0]) {
        return false;
    }

    for (i = 0; i < 16; i++) {
        if (wrote[i]) {
            memcpy(out[i], o[i], sizeof(o[i]));
        } else {
            out[i][0] = 0.0f;
            out[i][1] = 0.0f;
            out[i][2] = 0.0f;
            out[i][3] = 1.0f;
        }
    }

    return true;
}

/*
 * The fragment program.
 *
 * The graphics library uploads an fp40 shader with SET_SHADER_PROGRAM: the
 * program sits in local (or main) memory behind a small header, and the first
 * instruction is the first 16-byte slot whose opcode field is not zero.  Each
 * instruction is four big-endian words - the destination and three sources -
 * and RPCS3's RSXFragmentProgram.h is the encoding this follows: a source
 * selects a temporary, an input attribute or a constant (which occupies the
 * sixteen bytes after the instruction), applies a swizzle, an optional
 * absolute value and negation, and the opcode produces the vec4 that the
 * destination mask commits.
 *
 * Textures are sampled through the eight registers per unit at
 * SET_TEXTURE_OFFSET: the format register says where the pixels live and what
 * they are, the image rectangle gives the size, and the filter register picks
 * nearest or linear.  Both swizzled and linear textures are read, in the
 * formats the VSH uses: A8R8G8B8, B8, R5G6B5, A1R5G5B5, A4R4G4B4, G8B8 and
 * the three DXT variants.
 */

/* The program's words are big-endian, and the fields are byte-swapped inside
 * each 16-bit half, which is what RPCS3's from_be32 does. */
static uint32_t ps3_rsx_fp_word(const uint8_t *p)
{
    uint32_t be = ps3_be32(p);

    return ((be & 0x00FF00FFu) << 8) | ((be & 0xFF00FF00u) >> 8);
}

/* A host pointer for a span in the RSX's local or main memory, or NULL. */
static const uint8_t *ps3_rsx_mem(PS3BootROMState *s, uint8_t *ram,
                                  uint64_t ram_size, bool main_mem,
                                  uint32_t addr, uint32_t span)
{
    if (main_mem) {
        uint32_t ea = ps3_rsx_io_ea(s, addr & 0x0FFFFFFFu);

        if (ea == 0xFFFFFFFFu || (uint64_t)ea + span > ram_size) {
            return NULL;
        }
        return ram + ea;
    }

    if ((uint64_t)addr + span > s->rsx_local_size) {
        return NULL;
    }
    return memory_region_get_ram_ptr(&s->rsx_local) + addr;
}

/* One address mode, as the texture address register names it. */
static int ps3_rsx_wrap(int c, unsigned n, unsigned mode)
{
    int period;

    if (!n) {
        return 0;
    }

    switch (mode) {
    case 1:                             /* repeat */
        c %= (int)n;
        return c < 0 ? c + (int)n : c;
    case 2:                             /* mirrored repeat */
        period = 2 * (int)n;
        c %= period;
        if (c < 0) {
            c += period;
        }
        return c >= (int)n ? period - 1 - c : c;
    default:                            /* clamp to edge */
        return MIN(MAX(c, 0), (int)n - 1);
    }
}

/* One DXT colour palette: four BGRA-ish colours in float form. */
static void ps3_rsx_dxt_palette(uint16_t c0, uint16_t c1, bool opaque,
                                float pal[4][4])
{
    unsigned i;
    unsigned v[2] = { c0, c1 };

    for (i = 0; i < 2; i++) {
        pal[i][0] = ((v[i] >> 11) & 0x1F) / 31.0f;
        pal[i][1] = ((v[i] >> 5) & 0x3F) / 63.0f;
        pal[i][2] = (v[i] & 0x1F) / 31.0f;
        pal[i][3] = 1.0f;
    }

    if (opaque || c0 > c1) {
        for (i = 0; i < 3; i++) {
            pal[2][i] = (2.0f * pal[0][i] + pal[1][i]) / 3.0f;
            pal[3][i] = (pal[0][i] + 2.0f * pal[1][i]) / 3.0f;
        }
        pal[2][3] = pal[3][3] = 1.0f;
    } else {
        for (i = 0; i < 3; i++) {
            pal[2][i] = (pal[0][i] + pal[1][i]) * 0.5f;
            pal[3][i] = 0.0f;
        }
        pal[2][3] = 1.0f;
        pal[3][3] = 0.0f;
    }
}

/* One texel of a texture through its registers. */
static bool ps3_rsx_tex_texel(PS3BootROMState *s, uint8_t *ram,
                              uint64_t ram_size, unsigned unit,
                              int x, int y, float out[4])
{
    PS3RsxTexture *t = &s->rsx_tex[unit];
    unsigned fmt = (t->format >> 8) & 0xFF;
    unsigned width = (t->image_rect >> 16) & 0xFFFF;
    unsigned height = t->image_rect & 0xFFFF;
    bool main_mem = (t->format & 3) == 3;
    bool linear = !!(fmt & 0x20);
    unsigned base_fmt = fmt & ~0x20u;
    unsigned bpp, tile_w = 8, tile_h = 8;
    unsigned pitch, off, bx, by, i;
    const uint8_t *p;

    if (!width || !height) {
        return false;
    }
    x = ps3_rsx_wrap(x, width, t->address & 0xF);
    y = ps3_rsx_wrap(y, height, (t->address >> 4) & 0xF);

    switch (base_fmt) {
    case 0x86:                          /* DXT1 */
    case 0x87:                          /* DXT2/3 */
    case 0x88:                          /* DXT4/5 */
        bx = (unsigned)x >> 2;
        by = (unsigned)y >> 2;
        pitch = (((width + 3) >> 2)) * (base_fmt == 0x86 ? 8u : 16u);
        off = by * pitch + bx * (base_fmt == 0x86 ? 8u : 16u);
        p = ps3_rsx_mem(s, ram, ram_size, main_mem, t->offset + off,
                        base_fmt == 0x86 ? 8 : 16);
        if (!p) {
            return false;
        }
        {
            float pal[4][4];
            unsigned idx, row, col;
            uint16_t c0 = (p[0] << 8) | p[1];
            uint16_t c1 = (p[2] << 8) | p[3];
            uint32_t bits = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                            ((uint32_t)p[6] << 8) | p[7];

            ps3_rsx_dxt_palette(c0, c1, base_fmt != 0x86, pal);
            idx = (bits >> (2 * (((unsigned)y & 3) * 4 + ((unsigned)x & 3)))) & 3;
            for (i = 0; i < 4; i++) {
                out[i] = pal[idx][i];
            }
            if (base_fmt != 0x86) {
                /* The DXT3/5 alpha block: eight explicit values, 4 bits each
                 * for DXT3 and the two-colour ramp for DXT5. */
                const uint8_t *a = p + 8;
                unsigned ax = (unsigned)x & 3, ay = (unsigned)y & 3;

                if (base_fmt == 0x87) {
                    unsigned nib = (a[(ay * 4 + ax) >> 1] >>
                                    (((ay * 4 + ax) & 1) ? 4 : 0)) & 0xF;
                    out[3] = nib / 15.0f;
                } else {
                    unsigned a0 = a[0], a1 = a[1];
                    unsigned bits2 = a[2] | (a[3] << 8) | (a[4] << 16) |
                                     (a[5] << 24);
                    unsigned idx2 = (bits2 >> (3 * (ay * 4 + ax))) & 7;
                    float av[8];
                    unsigned k;

                    av[0] = a0 / 255.0f;
                    av[1] = a1 / 255.0f;
                    if (a0 > a1) {
                        for (k = 0; k < 6; k++) {
                            av[2 + k] = ((6 - k) * a0 + (1 + k) * a1) / (7.0f * 255.0f);
                        }
                    } else {
                        for (k = 0; k < 4; k++) {
                            av[2 + k] = ((4 - k) * a0 + (1 + k) * a1) / (5.0f * 255.0f);
                        }
                        av[6] = 0.0f;
                        av[7] = 1.0f;
                    }
                    out[3] = av[idx2];
                }
            }
            return true;
        }
    case 0x85:                          /* A8R8G8B8 */
    case 0x9E:                          /* D8R8G8B8 */
        bpp = 4;
        break;
    case 0x82:                          /* A1R5G5B5 */
    case 0x83:                          /* A4R4G4B4 */
    case 0x84:                          /* R5G6B5 */
    case 0x8F:                          /* R6G5B5 */
    case 0x94:                          /* X16 */
    case 0x95:                          /* Y16_X16 */
    case 0x97:                          /* R5G5B5A1 */
    case 0x9D:                          /* D1R5G5B5 */
        bpp = 2;
        tile_w = 16;
        break;
    case 0x81:                          /* B8 */
    case 0x8B:                          /* G8B8 */
        bpp = base_fmt == 0x81 ? 1 : 2;
        tile_w = base_fmt == 0x81 ? 32 : 16;
        break;
    default:
        return false;
    }

    pitch = width * bpp;
    if (linear) {
        off = (unsigned)y * pitch + (unsigned)x * bpp;
    } else {
        unsigned tx = (unsigned)x / tile_w, ty = (unsigned)y / tile_h;
        unsigned lx = (unsigned)x % tile_w, ly = (unsigned)y % tile_h;
        unsigned tile = (lx & 1) | ((ly & 1) << 1) | (((lx >> 1) & 1) << 2) |
                        (((ly >> 1) & 1) << 3) | (((lx >> 2) & 1) << 4) |
                        (((ly >> 2) & 1) << 5) | (((lx >> 3) & 1) << 6) |
                        (((ly >> 3) & 1) << 7);
        unsigned across = (width + tile_w - 1) / tile_w;

        off = (ty * across + tx) * 256 + tile * bpp;
    }

    p = ps3_rsx_mem(s, ram, ram_size, main_mem, t->offset + off, bpp);
    if (!p) {
        return false;
    }

    out[3] = 1.0f;
    switch (base_fmt) {
    case 0x85:                          /* B, G, R, A in memory */
    case 0x9E:
        out[0] = p[2] / 255.0f;
        out[1] = p[1] / 255.0f;
        out[2] = p[0] / 255.0f;
        out[3] = p[3] / 255.0f;
        break;
    case 0x82:                          /* A1R5G5B5 */
    case 0x9D: {                        /* D1R5G5B5 */
        unsigned v = (p[0] << 8) | p[1];

        out[3] = base_fmt == 0x82 ? ((v >> 15) & 1) : 1.0f;
        out[0] = ((v >> 10) & 0x1F) / 31.0f;
        out[1] = ((v >> 5) & 0x1F) / 31.0f;
        out[2] = (v & 0x1F) / 31.0f;
        break;
    }
    case 0x83: {                        /* A4R4G4B4 */
        unsigned v = (p[0] << 8) | p[1];

        out[3] = ((v >> 12) & 0xF) / 15.0f;
        out[0] = ((v >> 8) & 0xF) / 15.0f;
        out[1] = ((v >> 4) & 0xF) / 15.0f;
        out[2] = (v & 0xF) / 15.0f;
        break;
    }
    case 0x84: {                        /* R5G6B5 */
        unsigned v = (p[0] << 8) | p[1];

        out[0] = ((v >> 11) & 0x1F) / 31.0f;
        out[1] = ((v >> 5) & 0x3F) / 63.0f;
        out[2] = (v & 0x1F) / 31.0f;
        break;
    }
    case 0x8F: {                        /* R6G5B5 */
        unsigned v = (p[0] << 8) | p[1];

        out[0] = ((v >> 10) & 0x3F) / 63.0f;
        out[1] = ((v >> 5) & 0x1F) / 31.0f;
        out[2] = (v & 0x1F) / 31.0f;
        break;
    }
    case 0x97: {                        /* R5G5B5A1 */
        unsigned v = (p[0] << 8) | p[1];

        out[0] = ((v >> 11) & 0x1F) / 31.0f;
        out[1] = ((v >> 6) & 0x1F) / 31.0f;
        out[2] = ((v >> 1) & 0x1F) / 31.0f;
        out[3] = (v & 1) ? 1.0f : 0.0f;
        break;
    }
    case 0x8B:                          /* G8B8: green and blue */
        out[0] = out[2] = p[0] / 255.0f;
        out[1] = p[1] / 255.0f;
        break;
    case 0x81:                          /* B8: luminance */
        out[0] = out[1] = out[2] = p[0] / 255.0f;
        break;
    case 0x94:                          /* X16 */
    case 0x95:                          /* Y16_X16 */
    {
        unsigned v = (p[0] << 8) | p[1];

        out[0] = v / 65535.0f;
        out[1] = out[2] = out[0];
        if (base_fmt == 0x95) {
            out[1] = p[3] / 255.0f;
        }
        break;
    }
    default:
        break;
    }

    return true;
}

/* One texture lookup through a unit's filter register. */
static void ps3_rsx_tex_sample(PS3BootROMState *s, uint8_t *ram,
                               uint64_t ram_size, unsigned unit,
                               float u, float v, float out[4])
{
    PS3RsxTexture *t = &s->rsx_tex[unit];
    unsigned width = (t->image_rect >> 16) & 0xFFFF;
    unsigned height = t->image_rect & 0xFFFF;
    bool linear = ((t->filter >> 16) & 0xFFFF) == 2;
    float texel[4];

    out[0] = out[1] = out[2] = out[3] = 0.0f;
    if (!width || !height || !(t->control0 & 0x80000000u)) {
        out[3] = 1.0f;
        return;
    }

    if (!linear) {
        int x = (int)floorf(u * width), y = (int)floorf(v * height);

        if (ps3_rsx_tex_texel(s, ram, ram_size, unit, x, y, texel)) {
            memcpy(out, texel, sizeof(texel));
        }
        return;
    }

    {
        float fx = u * width - 0.5f, fy = v * height - 0.5f;
        int x0 = (int)floorf(fx), y0 = (int)floorf(fy);
        float ax = fx - x0, ay = fy - y0;
        float c[4][4];
        unsigned i, k;

        for (k = 0; k < 4; k++) {
            int xx = x0 + (k & 1), yy = y0 + (k >> 1);

            if (!ps3_rsx_tex_texel(s, ram, ram_size, unit, xx, yy, c[k])) {
                return;
            }
        }
        for (i = 0; i < 4; i++) {
            float top = c[0][i] * (1.0f - ax) + c[1][i] * ax;
            float bottom = c[2][i] * (1.0f - ax) + c[3][i] * ax;

            out[i] = top * (1.0f - ay) + bottom * ay;
        }
    }
}

/* One fp40 instruction, decoded. */
typedef struct PS3RsxFpInst {
    uint32_t src0, src1, src2;
    unsigned opcode, mask, dst, attr, tex, scale, prec;
    bool end, saturate, fp16, no_dest;
} PS3RsxFpInst;

static void ps3_rsx_fp_parse(const uint8_t *p, PS3RsxFpInst *in)
{
    uint32_t d0 = ps3_rsx_fp_word(p);

    in->src0 = ps3_rsx_fp_word(p + 4);
    in->src1 = ps3_rsx_fp_word(p + 8);
    in->src2 = ps3_rsx_fp_word(p + 12);
    in->end = d0 & 1;
    in->dst = (d0 >> 1) & 0x3F;
    in->fp16 = (d0 >> 7) & 1;
    in->mask = (d0 >> 9) & 0xF;
    in->attr = (d0 >> 13) & 0xF;
    in->tex = (d0 >> 17) & 0xF;
    in->prec = (d0 >> 22) & 3;
    in->opcode = ((d0 >> 24) & 0x3F) | (((in->src1 >> 31) & 1) << 6);
    in->no_dest = (d0 >> 30) & 1;
    in->saturate = (d0 >> 31) & 1;
    in->scale = (in->src1 >> 28) & 7;
}

/* One source operand. */
static bool ps3_rsx_fp_src(PS3BootROMState *s, const uint8_t *prog,
                           unsigned len, unsigned inst_off,
                           const PS3RsxFpInst *in, uint32_t src, bool is_src0,
                           const float vin[16][4], const float r[16][4],
                           float out[4])
{
    unsigned reg = src & 3, tmp = (src >> 2) & 0x3F;
    unsigned swz = (src >> 9) & 0xFF;
    bool neg = (src >> 17) & 1;
    bool absv = is_src0 ? !!((src >> 29) & 1) : !!((src >> 18) & 1);
    float v[4], w[4];
    unsigned i;

    switch (reg) {
    case 0:                             /* temporary register */
        if (tmp >= PS3_RSX_FP_TEMP) {
            return false;
        }
        memcpy(v, r[tmp], sizeof(v));
        break;
    case 1: {                           /* input attribute */
        unsigned idx = in->attr;

        if ((in->src2 >> 30) & 1) {
            idx = ((in->src2 >> 19) & 0x7FF) + 4;
        }
        if (idx >= PS3_RSX_FP_INPUTS) {
            return false;
        }
        memcpy(v, vin[idx], sizeof(v));
        break;
    }
    case 2: {                           /* constant, in the slot after */
        const uint8_t *cp = prog + inst_off + 16;

        if (inst_off + 32 > len) {
            return false;
        }
        for (i = 0; i < 4; i++) {
            uint32_t word = ps3_rsx_fp_word(cp + 4 * i);

            memcpy(&v[i], &word, sizeof(v[i]));
        }
        break;
    }
    default:
        return false;
    }

    for (i = 0; i < 4; i++) {
        w[i] = v[(swz >> (2 * i)) & 3];
    }
    if (absv) {
        for (i = 0; i < 4; i++) {
            w[i] = fabsf(w[i]);
        }
    }
    if (neg) {
        for (i = 0; i < 4; i++) {
            w[i] = -w[i];
        }
    }
    if (is_src0) {
        switch (in->scale) {
        case 1: for (i = 0; i < 4; i++) w[i] *= 2.0f; break;
        case 2: for (i = 0; i < 4; i++) w[i] *= 4.0f; break;
        case 3: for (i = 0; i < 4; i++) w[i] *= 8.0f; break;
        case 5: for (i = 0; i < 4; i++) w[i] *= 0.5f; break;
        case 6: for (i = 0; i < 4; i++) w[i] *= 0.25f; break;
        case 7: for (i = 0; i < 4; i++) w[i] *= 0.125f; break;
        default: break;
        }
    }

    memcpy(out, w, sizeof(w));
    return true;
}

static bool ps3_rsx_fp_uses_const(const PS3RsxFpInst *in)
{
    return (in->src0 & 3) == 2 || (in->src1 & 3) == 2 ||
           (in->src2 & 3) == 2;
}

/*
 * Run the loaded fragment program for one pixel.  The sixteen input registers
 * are the fragment stage's varyings; the result is register 0.  A KIL whose
 * operand is negative discards the pixel, which is reported as a failure so
 * the rasterizer writes nothing.
 */
static bool ps3_rsx_fprog_run(PS3BootROMState *s, uint8_t *ram,
                              uint64_t ram_size, const float vin[16][4],
                              float out[4])
{
    const uint8_t *prog = s->rsx_fprog;
    unsigned len = s->rsx_fprog_len;
    float r[PS3_RSX_FP_TEMP][4] = { { 0 } };
    unsigned pc, steps;
    bool wrote0 = false;

    if (!s->rsx_fprog_ready || len < 32) {
        return false;
    }

    /* The header ends at the first slot that holds an instruction. */
    pc = 0;
    while (pc + 16 <= len) {
        uint32_t d0 = ps3_rsx_fp_word(prog + pc);

        if (((d0 >> 24) & 0x3F) || ((d0 >> 8) & 1)) {
            break;
        }
        pc += 16;
    }

    for (steps = 0; steps < 1024 && pc + 16 <= len; steps++) {
        PS3RsxFpInst in;
        float a[4], b[4], c[4], res[4];
        bool const_slot;
        unsigned i;

        ps3_rsx_fp_parse(prog + pc, &in);
        const_slot = ps3_rsx_fp_uses_const(&in);

        if (!ps3_rsx_fp_src(s, prog, len, pc, &in, in.src0, true, vin, r, a)) {
            return false;
        }

        switch (in.opcode) {
        case 0:                                 /* NOP */
            memcpy(res, a, sizeof(a));
            break;
        case 1:                                 /* MOV */
            memcpy(res, a, sizeof(a));
            break;
        case 2:                                 /* MUL */
        case 3:                                 /* ADD */
        case 4:                                 /* MAD */
        case 5:                                 /* DP3 */
        case 6:                                 /* DP4 */
        case 7:                                 /* DST */
        case 8:                                 /* MIN */
        case 9:                                 /* MAX */
        case 10:                                /* SLT */
        case 11:                                /* SGE */
        case 12:                                /* SLE */
        case 13:                                /* SGT */
        case 14:                                /* SNE */
        case 15:                                /* SEQ */
        case 16:                                /* FRC */
        case 17:                                /* FLR */
        case 26:                                /* RCP */
        case 27:                                /* RSQ */
        case 28:                                /* EX2 */
        case 29:                                /* LG2 */
        case 30:                                /* LIT */
        case 31:                                /* LRP */
        case 32:                                /* STR */
        case 33:                                /* SFL */
        case 34:                                /* COS */
        case 35:                                /* SIN */
        case 38:                                /* POW */
        case 46:                                /* DP2A */
        case 54:                                /* REFL */
        case 56:                                /* DP2 */
        case 57:                                /* NRM */
        case 58:                                /* DIV */
        case 59:                                /* DIVSQ */
            if (!ps3_rsx_fp_src(s, prog, len, pc, &in, in.src1, false,
                                vin, r, b)) {
                return false;
            }
            if (!ps3_rsx_fp_src(s, prog, len, pc, &in, in.src2, false,
                                vin, r, c)) {
                return false;
            }
            switch (in.opcode) {
            case 2: for (i = 0; i < 4; i++) res[i] = a[i] * b[i]; break;
            case 3: for (i = 0; i < 4; i++) res[i] = a[i] + b[i]; break;
            case 4: for (i = 0; i < 4; i++) res[i] = a[i] * b[i] + c[i]; break;
            case 5: {
                float d = a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
                for (i = 0; i < 4; i++) res[i] = d;
                break;
            }
            case 6: {
                float d = a[0] * b[0] + a[1] * b[1] + a[2] * b[2] + a[3] * b[3];
                for (i = 0; i < 4; i++) res[i] = d;
                break;
            }
            case 7:                             /* DST */
                res[0] = 1.0f;
                res[1] = a[1] * b[1];
                res[2] = a[2];
                res[3] = b[3];
                break;
            case 8: for (i = 0; i < 4; i++) res[i] = MIN(a[i], b[i]); break;
            case 9: for (i = 0; i < 4; i++) res[i] = MAX(a[i], b[i]); break;
            case 10: for (i = 0; i < 4; i++) res[i] = a[i] < b[i] ? 1.0f : 0.0f; break;
            case 11: for (i = 0; i < 4; i++) res[i] = a[i] >= b[i] ? 1.0f : 0.0f; break;
            case 12: for (i = 0; i < 4; i++) res[i] = a[i] <= b[i] ? 1.0f : 0.0f; break;
            case 13: for (i = 0; i < 4; i++) res[i] = a[i] > b[i] ? 1.0f : 0.0f; break;
            case 14: for (i = 0; i < 4; i++) res[i] = a[i] != b[i] ? 1.0f : 0.0f; break;
            case 15: for (i = 0; i < 4; i++) res[i] = a[i] == b[i] ? 1.0f : 0.0f; break;
            case 16: for (i = 0; i < 4; i++) res[i] = a[i] - floorf(a[i]); break;
            case 17: for (i = 0; i < 4; i++) res[i] = floorf(a[i]); break;
            case 26: res[0] = res[1] = res[2] = res[3] = 1.0f / a[0]; break;
            case 27: res[0] = res[1] = res[2] = res[3] = 1.0f / sqrtf(fabsf(a[0])); break;
            case 28: res[0] = res[1] = res[2] = res[3] = exp2f(a[0]); break;
            case 29: res[0] = res[1] = res[2] = res[3] = log2f(fabsf(a[0])); break;
            case 30:                            /* LIT */
                res[0] = 1.0f;
                res[1] = MAX(a[0], 0.0f);
                res[2] = MAX(a[1], 0.0f);
                res[3] = powf(MAX(a[3], 0.0f), MIN(MAX(a[1], -128.0f), 128.0f));
                break;
            case 31:                            /* LRP: a*b + (1-a)*c */
                for (i = 0; i < 4; i++) res[i] = a[i] * b[i] + (1.0f - a[i]) * c[i];
                break;
            case 32: for (i = 0; i < 4; i++) res[i] = 1.0f; break;
            case 33: for (i = 0; i < 4; i++) res[i] = 0.0f; break;
            case 34: res[0] = res[1] = res[2] = res[3] = cosf(a[0]); break;
            case 35: res[0] = res[1] = res[2] = res[3] = sinf(a[0]); break;
            case 38:                            /* POW */
                res[0] = res[1] = res[2] = res[3] = powf(fabsf(a[0]), b[0]);
                break;
            case 46:                            /* DP2A */
                res[0] = res[1] = res[2] = res[3] =
                    a[0] * b[0] + a[1] * b[1];
                break;
            case 54:                            /* REFL */
                for (i = 0; i < 4; i++) {
                    res[i] = a[i] - 2.0f * b[i] *
                             (a[0] * b[0] + a[1] * b[1] + a[2] * b[2]);
                }
                break;
            case 56:                            /* DP2 */
                res[0] = res[1] = res[2] = res[3] = a[0] * b[0] + a[1] * b[1];
                break;
            case 57: {                          /* NRM */
                float mag = sqrtf(a[0] * a[0] + a[1] * a[1] + a[2] * a[2]);

                for (i = 0; i < 4; i++) res[i] = mag ? a[i] / mag : 0.0f;
                break;
            }
            case 58:                            /* DIV */
                for (i = 0; i < 4; i++) res[i] = b[i] ? a[i] / b[i] : a[i];
                break;
            case 59:                            /* DIVSQ */
                for (i = 0; i < 4; i++) {
                    res[i] = b[i] ? a[i] / (b[i] * b[i]) : a[i];
                }
                break;
            default:
                break;
            }
            break;
        case 18:                                /* KIL */
            if (a[0] < 0.0f) {
                return false;
            }
            memcpy(res, a, sizeof(a));
            break;
        case 23:                                /* TEX */
        case 24:                                /* TXP */
        case 25:                                /* TXD */
        case 47:                                /* TXL */
        case 49:                                /* TXB */
        {
            float u = a[0], v = a[1], one = 1.0f;

            if (in.opcode == 24 && a[3] != 0.0f) {
                u /= a[3];
                v /= a[3];
            }
            (void)one;
            ps3_rsx_tex_sample(s, ram, ram_size, in.tex & (PS3_RSX_TEX_MAX - 1),
                               u, v, res);
            break;
        }
        default:
            return false;               /* an opcode this interpreter lacks */
        }

        if (in.saturate) {
            for (i = 0; i < 4; i++) {
                res[i] = MIN(MAX(res[i], 0.0f), 1.0f);
            }
        }

        if (!in.no_dest && in.mask) {
            unsigned d = in.dst < PS3_RSX_FP_TEMP ? in.dst : 0;

            for (i = 0; i < 4; i++) {
                if (in.mask & (1u << i)) {
                    r[d][i] = res[i];
                }
            }
            if (d == 0) {
                wrote0 = true;
            }
        }

        pc += 16;
        if (const_slot) {
            pc += 16;
        }
        if (in.end) {
            break;
        }
    }

    if (!wrote0) {
        return false;
    }

    memcpy(out, r[0], sizeof(r[0]));
    return true;
}

/* Every attribute of one vertex, the way the program's input file sees them. */
static bool ps3_rsx_all_attrs(PS3BootROMState *s, uint8_t *ram,
                              uint64_t ram_size, uint32_t index,
                              bool inlined, float out[PS3_RSX_ATTRS][4])
{
    unsigned i;

    for (i = 0; i < PS3_RSX_ATTRS; i++) {
        float *v = out[i];

        v[0] = 0.0f;
        v[1] = 0.0f;
        v[2] = 0.0f;
        v[3] = 1.0f;

        if (!((s->rsx_vtx_fmt[i] >> 4) & 0xF)) {
            continue;                   /* a disabled attribute's default */
        }
        if (inlined) {
            if (!ps3_rsx_read_inline(s, i, index, v)) {
                return false;
            }
        } else if (!ps3_rsx_read_array(s, ram, ram_size, i, index, v)) {
            return false;
        }
    }

    return true;
}

/* Position and colour of one vertex. */
static bool ps3_rsx_vertex(PS3BootROMState *s, uint8_t *ram, uint64_t ram_size,
                           uint32_t index, bool inlined, PS3RsxVertex *v,
                           bool *shaded)
{
    float p[4], c[4] = { 1.0f, 1.0f, 1.0f, 1.0f };
    int ci = ps3_rsx_colour_attr(s);
    bool ok;
    unsigned k;

    if (shaded) {
        *shaded = false;
    }

    for (k = 0; k < 16; k++) {
        v->var[k][0] = 0.0f;
        v->var[k][1] = 0.0f;
        v->var[k][2] = 0.0f;
        v->var[k][3] = 1.0f;
    }

    if (s->rsx_vprog_ready) {
        float vin[PS3_RSX_ATTRS][4];

        if (ps3_rsx_all_attrs(s, ram, ram_size, index, inlined, vin) &&
            ps3_rsx_vprog_run(s, vin, v->var)) {
            v->x = v->var[0][0];
            v->y = v->var[0][1];
            v->z = v->var[0][2];
            v->w = v->var[0][3];
            /* Output 1 is the diffuse colour the fragment stage reads. */
            v->r = MIN(MAX(v->var[1][0], 0.0f), 1.0f);
            v->g = MIN(MAX(v->var[1][1], 0.0f), 1.0f);
            v->b = MIN(MAX(v->var[1][2], 0.0f), 1.0f);
            v->a = MIN(MAX(v->var[1][3], 0.0f), 1.0f);
            if (shaded) {
                *shaded = true;
            }
            return true;
        }

        if (!s->rsx_vprog_fallback_reported) {
            s->rsx_vprog_fallback_reported = true;
            info_report("ps3-rsx: vertex program at 0x%X is not executable "
                        "by this model (scalar opcode or unsupported op); "
                        "falling back to the attribute path",
                        s->rsx_vprog_start);
        }
    }

    if (inlined) {
        ok = ps3_rsx_read_inline(s, 0, index, p);
        if (ok && ci >= 0 && !ps3_rsx_read_inline(s, ci, index, c)) {
            ci = -1;
        }
    } else {
        ok = ps3_rsx_read_array(s, ram, ram_size, 0, index, p);
        if (ok && ci >= 0 &&
            !ps3_rsx_read_array(s, ram, ram_size, ci, index, c)) {
            ci = -1;
        }
    }

    if (!ok) {
        return false;
    }

    v->x = p[0];
    v->y = p[1];
    v->z = p[2];
    v->w = p[3];
    if (ci < 0) {
        c[0] = c[1] = c[2] = c[3] = 1.0f;
    }
    v->r = MIN(MAX(c[0], 0.0f), 1.0f);
    v->g = MIN(MAX(c[1], 0.0f), 1.0f);
    v->b = MIN(MAX(c[2], 0.0f), 1.0f);
    v->a = MIN(MAX(c[3], 0.0f), 1.0f);

    return true;
}

/* One blend factor, as NV4097's factor enum names it. */
static unsigned ps3_rsx_blend_factor(unsigned f, unsigned sc, unsigned dc,
                                     unsigned sa, unsigned da)
{
    switch (f) {
    case 0:  return 0;                   /* ZERO */
    case 1:  return 255;                 /* ONE */
    case 2:  return sc;                  /* SRC_COLOR */
    case 3:  return 255 - sc;            /* ONE_MINUS_SRC_COLOR */
    case 4:  return sa;                  /* SRC_ALPHA */
    case 5:  return 255 - sa;            /* ONE_MINUS_SRC_ALPHA */
    case 6:  return da;                  /* DST_ALPHA */
    case 7:  return 255 - da;            /* ONE_MINUS_DST_ALPHA */
    case 8:  return dc;                  /* DST_COLOR */
    case 9:  return 255 - dc;            /* ONE_MINUS_DST_COLOR */
    default: return 255;
    }
}

/* One blended channel of a blend equation. */
static unsigned ps3_rsx_blend_channel(PS3BootROMState *s, unsigned sc,
                                      unsigned dc, unsigned sa, unsigned da)
{
    unsigned sf = ps3_rsx_blend_factor(s->rsx_blend_s, sc, dc, sa, da);
    unsigned df = ps3_rsx_blend_factor(s->rsx_blend_d, sc, dc, sa, da);
    long v;

    switch (s->rsx_blend_eq) {
    case 1:                             /* MIN */
        return MIN(sc, dc);
    case 2:                             /* MAX */
        return MAX(sc, dc);
    case 3:                             /* SUBTRACT */
        v = (long)sc * sf - (long)dc * df;
        return MIN(MAX(v / 255, 0L), 255L);
    case 4:                             /* REVERSE_SUBTRACT */
        v = (long)dc * df - (long)sc * sf;
        return MIN(MAX(v / 255, 0L), 255L);
    default:                            /* ADD */
        return MIN(((long)sc * sf + (long)dc * df + 127) / 255, 255L);
    }
}

/* One fragment: colour, blend, colour mask, into the surface. */
static void ps3_rsx_pixel(PS3BootROMState *s, const PS3RsxSurface *surf,
                          int x, int y, float r, float g, float b, float a)
{
    uint8_t *p = surf->base + (uint64_t)y * surf->pitch + 4u * x;
    uint32_t dst = ps3_be32(p);

    unsigned sr = (unsigned)(MIN(MAX(r, 0.0f), 1.0f) * 255.0f + 0.5f);
    unsigned sg = (unsigned)(MIN(MAX(g, 0.0f), 1.0f) * 255.0f + 0.5f);
    unsigned sb = (unsigned)(MIN(MAX(b, 0.0f), 1.0f) * 255.0f + 0.5f);
    unsigned sa = (unsigned)(MIN(MAX(a, 0.0f), 1.0f) * 255.0f + 0.5f);
    unsigned out[4];
    uint32_t mask = s->rsx_color_mask ? s->rsx_color_mask : 0xFFFFFFFFu;

    out[0] = sr;
    out[1] = sg;
    out[2] = sb;
    out[3] = sa;

    if (s->rsx_blend) {
        unsigned dc[4];

        if (surf->bgr) {
            dc[0] = dst & 0xFF;
            dc[1] = (dst >> 8) & 0xFF;
            dc[2] = (dst >> 16) & 0xFF;
        } else {
            dc[2] = dst & 0xFF;
            dc[1] = (dst >> 8) & 0xFF;
            dc[0] = (dst >> 16) & 0xFF;
        }
        dc[3] = dst >> 24;

        out[0] = ps3_rsx_blend_channel(s, sr, dc[0], sa, dc[3]);
        out[1] = ps3_rsx_blend_channel(s, sg, dc[1], sa, dc[3]);
        out[2] = ps3_rsx_blend_channel(s, sb, dc[2], sa, dc[3]);
        out[3] = ps3_rsx_blend_channel(s, sa, dc[3], sa, dc[3]);
    }

    {
        unsigned keep[4];

        if (surf->bgr) {
            keep[0] = dst & 0xFF;
            keep[1] = (dst >> 8) & 0xFF;
            keep[2] = (dst >> 16) & 0xFF;
        } else {
            keep[2] = dst & 0xFF;
            keep[1] = (dst >> 8) & 0xFF;
            keep[0] = (dst >> 16) & 0xFF;
        }
        keep[3] = dst >> 24;

        if (!(mask & 0x000000FFu)) {
            out[2] = keep[2];
        }
        if (!(mask & 0x0000FF00u)) {
            out[1] = keep[1];
        }
        if (!(mask & 0x00FF0000u)) {
            out[0] = keep[0];
        }
        if (!(mask & 0xFF000000u)) {
            out[3] = keep[3];
        }
    }

    if (surf->bgr) {
        ps3_put_be32(p, (out[3] << 24) | (out[2] << 16) | (out[1] << 8) |
                        out[0]);
    } else {
        ps3_put_be32(p, (out[3] << 24) | (out[0] << 16) | (out[1] << 8) |
                        out[2]);
    }

    s->rsx_pixels++;
}

/*
 * One fragment.
 *
 * When the graphics library has loaded an fp40 the fragment stage runs it
 * with the interpolated varyings - WPOS, the two colours, the fog and the ten
 * texture coordinates - and its register 0 is the colour.  Otherwise the
 * model shades with the vertex colour it interpolated, which is what the 2D
 * interface path that carries no programs uses.
 */
static void ps3_rsx_shade(PS3BootROMState *s, const PS3RsxSurface *surf,
                          uint8_t *ram, uint64_t ram_size,
                          int x, int y, double w0, double w1, double w2,
                          double sum, const PS3RsxVertex *v0,
                          const PS3RsxVertex *v1, const PS3RsxVertex *v2)
{
    if (s->rsx_fprog_ready) {
        float in[16][4], out[4];
        float wsum = (float)((w0 * v0->w + w1 * v1->w + w2 * v2->w) / sum);
        float invw = fabsf(wsum) > 1e-9f ? 1.0f / wsum : 1.0f;
        unsigned k, c;

        for (k = 0; k < 16; k++) {
            for (c = 0; c < 4; c++) {
                in[k][c] = (float)((w0 * v0->var[k][c] +
                                    w1 * v1->var[k][c] +
                                    w2 * v2->var[k][c]) / sum);
            }
        }

        in[0][0] = x + 0.5f;
        in[0][1] = y + 0.5f;
        in[0][2] = 0.5f * in[0][2] * invw + 0.5f;    /* clip z to window z */
        in[0][3] = invw;
        for (c = 0; c < 4; c++) {                   /* COL0/COL1 are clamped */
            in[1][c] = MIN(MAX(in[1][c], 0.0f), 1.0f);
            in[2][c] = MIN(MAX(in[2][c], 0.0f), 1.0f);
        }
        in[14][0] = 1.0f;                           /* SSA: front facing */
        in[14][1] = 0.0f;
        in[14][2] = 0.0f;
        in[14][3] = 1.0f;

        if (ps3_rsx_fprog_run(s, ram, ram_size, in, out)) {
            ps3_rsx_pixel(s, surf, x, y, out[0], out[1], out[2], out[3]);
            s->rsx_shaded++;
        }
        return;
    }

    ps3_rsx_pixel(s, surf, x, y,
                  (float)((w0 * v0->r + w1 * v1->r + w2 * v2->r) / sum),
                  (float)((w0 * v0->g + w1 * v1->g + w2 * v2->g) / sum),
                  (float)((w0 * v0->b + w1 * v1->b + w2 * v2->b) / sum),
                  (float)((w0 * v0->a + w1 * v1->a + w2 * v2->a) / sum));
}

/*
 * A triangle.
 *
 * The edge functions are evaluated incrementally along each row, so a span
 * costs three adds per pixel.  Both windings are filled, since the model does
 * not cull; interpolation is linear in window space, which is what a
 * non-perspective-corrected fill does.
 */
static void ps3_rsx_tri(PS3BootROMState *s, const PS3RsxSurface *surf,
                        uint8_t *ram, uint64_t ram_size,
                        const PS3RsxVertex *v0, const PS3RsxVertex *v1,
                        const PS3RsxVertex *v2)
{
    double area = ((double)v1->x - v0->x) * ((double)v2->y - v0->y) -
                  ((double)v1->y - v0->y) * ((double)v2->x - v0->x);
    double sign, sum, dx0, dx1, dx2;
    int x0, x1, y0, y1, x, y;

    if (!isfinite(area) || fabs(area) < 1e-9) {
        return;
    }

    sign = area < 0 ? -1.0 : 1.0;
    sum = fabs(area);

    x0 = (int)floor(MIN(MIN(v0->x, v1->x), v2->x) + 0.5);
    x1 = (int)floor(MAX(MAX(v0->x, v1->x), v2->x) + 0.5);
    y0 = (int)floor(MIN(MIN(v0->y, v1->y), v2->y) + 0.5);
    y1 = (int)floor(MAX(MAX(v0->y, v1->y), v2->y) + 0.5);

    x0 = MAX(x0, surf->x0);
    x1 = MIN(x1, surf->x1);
    y0 = MAX(y0, surf->y0);
    y1 = MIN(y1, surf->y1);
    if (x0 > x1 || y0 > y1) {
        return;
    }

    dx0 = sign * ((double)v1->y - v2->y);
    dx1 = sign * ((double)v2->y - v0->y);
    dx2 = sign * ((double)v0->y - v1->y);

    s->rsx_prims++;

    for (y = y0; y <= y1; y++) {
        double py = y + 0.5;
        double px = x0 + 0.5;
        double w0 = sign * ((v1->x - px) * (v2->y - py) -
                            (v1->y - py) * (v2->x - px));
        double w1 = sign * ((v2->x - px) * (v0->y - py) -
                            (v2->y - py) * (v0->x - px));
        double w2 = sign * ((v0->x - px) * (v1->y - py) -
                            (v0->y - py) * (v1->x - px));

        for (x = x0; x <= x1; x++, w0 += dx0, w1 += dx1, w2 += dx2) {
            if (w0 < 0 || w1 < 0 || w2 < 0) {
                continue;
            }
            ps3_rsx_shade(s, surf, ram, ram_size, x, y, w0, w1, w2, sum,
                          v0, v1, v2);
        }
    }
}

/* A line segment, as a run of pixels from one end to the other. */
static void ps3_rsx_line(PS3BootROMState *s, const PS3RsxSurface *surf,
                         uint8_t *ram, uint64_t ram_size,
                         const PS3RsxVertex *a, const PS3RsxVertex *b)
{
    double dx = (double)b->x - a->x, dy = (double)b->y - a->y;
    double len = MAX(fabs(dx), fabs(dy));
    unsigned i, steps;

    if (!isfinite(len) || len < 1.0) {
        steps = 1;
    } else {
        steps = (unsigned)len;
    }
    if (steps > 8192) {
        steps = 8192;
    }

    s->rsx_prims++;
    for (i = 0; i <= steps; i++) {
        double t = (double)i / steps;
        int x = (int)floor(a->x + dx * t + 0.5);
        int y = (int)floor(a->y + dy * t + 0.5);

        if (x < surf->x0 || x > surf->x1 || y < surf->y0 || y > surf->y1) {
            continue;
        }
        ps3_rsx_shade(s, surf, ram, ram_size, x, y, 1.0 - t, t, 0.0, 1.0,
                      a, b, a);
    }
}

/* A point: one pixel. */
static void ps3_rsx_point(PS3BootROMState *s, const PS3RsxSurface *surf,
                          uint8_t *ram, uint64_t ram_size,
                          const PS3RsxVertex *v)
{
    int x = (int)floor(v->x + 0.5), y = (int)floor(v->y + 0.5);

    if (x < surf->x0 || x > surf->x1 || y < surf->y0 || y > surf->y1) {
        return;
    }

    s->rsx_prims++;
    ps3_rsx_shade(s, surf, ram, ram_size, x, y, 1.0, 0.0, 0.0, 1.0,
                  v, v, v);
}

/* One index of the index array DRAW_INDEX_ARRAY reads. */
static bool ps3_rsx_index(PS3BootROMState *s, uint8_t *ram, uint64_t ram_size,
                          uint32_t slot, uint32_t *out)
{
    bool main_mem = (s->rsx_index_dma & 0xF) == 1;
    bool type16 = ((s->rsx_index_dma >> 4) & 0xF) == 1;
    unsigned width = type16 ? 2 : 4;
    uint64_t addr = (uint64_t)(s->rsx_index_addr & 0xFFFFFFFCu) +
                    (uint64_t)slot * width;
    const uint8_t *p;

    if (main_mem) {
        uint32_t ea = ps3_rsx_io_ea(s, (uint32_t)addr);

        if (ea == 0xFFFFFFFFu || ((uint32_t)addr & 0xFFFFF) + width > 0x100000 ||
            (uint64_t)ea + width > ram_size) {
            return false;
        }
        p = ram + ea;
    } else {
        if (addr + width > s->rsx_local_size) {
            return false;
        }
        p = memory_region_get_ram_ptr(&s->rsx_local) + addr;
    }

    *out = type16 ? ((p[0] << 8) | p[1]) :
                    (((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                     ((uint32_t)p[2] << 8) | p[3]);
    return true;
}

/*
 * The closed draw clause: fetch its vertices, map them onto the surface and
 * walk the primitive the clause was opened with.
 */
static void ps3_rsx_rasterize(PS3BootROMState *s, uint8_t *ram,
                              uint64_t ram_size)
{
    PS3RsxSurface surf;
    PS3RsxVertex *vtx = NULL;
    uint32_t *idx = NULL;
    uint64_t total = 0, n = 0, i;
    unsigned r, clip_like = 0, checked = 0;
    bool inlined = s->rsx_clause_indexed == 2;
    bool clip = false, shaded_all = true;
    float vp_x = 0, vp_y = 0, vp_w, vp_h;
    uint64_t prims0 = s->rsx_prims, pixels0 = s->rsx_pixels;
    uint64_t shaded0 = s->rsx_shaded;

    if (!s->rsx_prim) {
        return;
    }

    if (!ps3_rsx_surface(s, ram, ram_size, &surf)) {
        if (s->ppu_trace && !s->rsx_draw_reported) {
            s->rsx_draw_reported = true;
            info_report("ps3-rsx: draw: surface 0x%08X is not renderable",
                        s->rsx_surface_format);
        }
        return;
    }

    if (!surf.colour32) {
        if (s->ppu_trace && !s->rsx_draw_reported) {
            s->rsx_draw_reported = true;
            info_report("ps3-rsx: draw: colour format 0x%X is not an 8-bit "
                        "target, not rasterized", surf.format);
        }
        return;
    }

    if (!s->rsx_vtx_fmt[0] || !((s->rsx_vtx_fmt[0] >> 4) & 0xF)) {
        if (!s->rsx_noattr_reported) {
            s->rsx_noattr_reported = true;
            info_report("ps3-rsx: draw: primitive 0x%X with no position "
                        "attribute, ignored", s->rsx_prim);
        }
        return;
    }

    /* The viewport: x and y in the low half, width and height above it. */
    vp_x = (s->rsx_viewport_h & 0xFFFF);
    vp_y = (s->rsx_viewport_v & 0xFFFF);
    vp_w = (s->rsx_viewport_h >> 16) & 0xFFFF;
    vp_h = (s->rsx_viewport_v >> 16) & 0xFFFF;
    if (!vp_w || !vp_h) {
        vp_x = vp_y = 0;
        vp_w = surf.width;
        vp_h = surf.height;
    }

    /* The scissor, defaulting to the whole surface. */
    surf.x0 = 0;
    surf.y0 = 0;
    surf.x1 = surf.width - 1;
    surf.y1 = surf.height - 1;
    if ((s->rsx_scissor_h >> 16) & 0xFFFF) {
        int sx0 = s->rsx_scissor_h & 0xFFFF;
        int sw = (s->rsx_scissor_h >> 16) & 0xFFFF;
        int sy0 = s->rsx_scissor_v & 0xFFFF;
        int sh = (s->rsx_scissor_v >> 16) & 0xFFFF;

        surf.x0 = MAX(sx0, 0);
        surf.x1 = MIN(sx0 + sw - 1, (int)surf.width - 1);
        surf.y0 = MAX(sy0, 0);
        surf.y1 = MIN(sy0 + sh - 1, (int)surf.height - 1);
        if (surf.x0 > surf.x1 || surf.y0 > surf.y1) {
            return;
        }
    }

    if (inlined) {
        unsigned stride = ps3_rsx_inline_stride(s);

        if (!stride) {
            return;
        }
        total = (uint64_t)s->rsx_inline_words * 4 / stride;
    } else {
        for (r = 0; r < s->rsx_clause_n; r++) {
            total += s->rsx_clause[r].count;
        }
        if (total > (1u << 20)) {
            total = 1u << 20;
        }
        idx = g_new0(uint32_t, total ? total : 1);
        for (r = 0; r < s->rsx_clause_n && n < total; r++) {
            uint32_t j;

            for (j = 0; j < s->rsx_clause[r].count && n < total; j++) {
                uint32_t slot = s->rsx_clause[r].start + j;
                uint32_t v;

                if (s->rsx_clause_indexed) {
                    if (!ps3_rsx_index(s, ram, ram_size, slot, &v)) {
                        info_report("ps3-rsx: draw: index %u of the index "
                                    "array is not mapped", slot);
                        g_free(idx);
                        return;
                    }
                } else {
                    v = slot;
                }
                idx[n++] = (v + s->rsx_vtx_index_base) & 0xFFFFF;
            }
        }
    }

    if (!n) {
        g_free(idx);
        return;
    }

    vtx = g_new0(PS3RsxVertex, n);
    for (i = 0; i < n; i++) {
        uint32_t vi = inlined ? (uint32_t)i : idx[i];
        bool shaded;

        if (!ps3_rsx_vertex(s, ram, ram_size, vi, inlined, &vtx[i], &shaded)) {
            info_report("ps3-rsx: draw: vertex %" PRIu64 " (attribute 0 at "
                        "0x%X, format 0x%X) is not mapped", i,
                        s->rsx_vtx_off[0], s->rsx_vtx_fmt[0]);
            g_free(vtx);
            g_free(idx);
            return;
        }

        if (!shaded) {
            shaded_all = false;
        }
    }

    /*
     * Clip space or window space.  A vertex program writes clip space by
     * definition, so its output always goes through the viewport.  Without one
     * the values themselves have to say: a primitive whose positions sit
     * inside the normalised cube is treated as clip space, one whose positions
     * are pixel-sized is 2D interface geometry and is used as is.
     */
    if (shaded_all) {
        clip = true;
    } else {
        for (i = 0; i < n && checked < 64; i++, checked++) {
            if (isfinite(vtx[i].x) && isfinite(vtx[i].y) &&
                fabs(vtx[i].x) <= 1.5f && fabs(vtx[i].y) <= 1.5f &&
                vtx[i].w > 0.0f && vtx[i].w <= 2.0f) {
                clip_like++;
            }
        }
        clip = checked && clip_like * 2 > checked;
    }

    if (clip) {
        for (i = 0; i < n; i++) {
            float iw = vtx[i].w;

            if (!(iw > 0.0f) || !isfinite(iw)) {
                /* Behind the eye: the primitive that uses it is dropped. */
                vtx[i].x = NAN;
                vtx[i].y = NAN;
                continue;
            }
            vtx[i].x = vp_x + (vtx[i].x / iw + 1.0f) * 0.5f * vp_w;
            vtx[i].y = vp_y + (1.0f - vtx[i].y / iw) * 0.5f * vp_h;
        }
    }

    if (s->ppu_trace && s->rsx_methods_logged < 24) {
        s->rsx_methods_logged++;
        info_report("ps3-rsx: draw %" PRIu64 " vertices as primitive 0x%X "
                    "(%s space), first vertex %.1f,%.1f colour %.2f,%.2f,%.2f",
                    n, s->rsx_prim, clip ? "clip" : "window",
                    vtx[0].x, vtx[0].y, vtx[0].r, vtx[0].g, vtx[0].b);
    }

#define RSX_VALID(a) (isfinite(vtx[a].x) && isfinite(vtx[a].y))
#define RSX_TRI(a, b, c)                                                  \
    do {                                                                  \
        if (RSX_VALID(a) && RSX_VALID(b) && RSX_VALID(c)) {               \
            ps3_rsx_tri(s, &surf, ram, ram_size, &vtx[a], &vtx[b],         \
                        &vtx[c]);                                         \
        }                                                                 \
    } while (0)
#define RSX_LINE(a, b)                                                    \
    do {                                                                  \
        if (RSX_VALID(a) && RSX_VALID(b)) {                               \
            ps3_rsx_line(s, &surf, ram, ram_size, &vtx[a], &vtx[b]);      \
        }                                                                 \
    } while (0)

    switch (s->rsx_prim) {
    case 1:                             /* points */
        for (i = 0; i < n; i++) {
            if (RSX_VALID(i)) {
                ps3_rsx_point(s, &surf, ram, ram_size, &vtx[i]);
            }
        }
        break;
    case 2:                             /* lines */
        for (i = 0; i + 1 < n; i += 2) {
            RSX_LINE(i, i + 1);
        }
        break;
    case 3:                             /* line loop */
        for (i = 0; i + 1 < n; i++) {
            RSX_LINE(i, i + 1);
        }
        if (n > 2) {
            RSX_LINE(n - 1, 0);
        }
        break;
    case 4:                             /* line strip */
        for (i = 0; i + 1 < n; i++) {
            RSX_LINE(i, i + 1);
        }
        break;
    case 5:                             /* triangles */
        for (i = 0; i + 2 < n; i += 3) {
            RSX_TRI(i, i + 1, i + 2);
        }
        break;
    case 6:                             /* triangle strip */
        for (i = 0; i + 2 < n; i++) {
            if (i & 1) {
                RSX_TRI(i + 1, i, i + 2);
            } else {
                RSX_TRI(i, i + 1, i + 2);
            }
        }
        break;
    case 7:                             /* triangle fan */
        for (i = 1; i + 1 < n; i++) {
            RSX_TRI(0, i, i + 1);
        }
        break;
    case 8:                             /* quads */
        for (i = 0; i + 3 < n; i += 4) {
            RSX_TRI(i, i + 1, i + 2);
            RSX_TRI(i, i + 2, i + 3);
        }
        break;
    case 9:                             /* quad strip */
        for (i = 0; i + 3 < n; i += 2) {
            RSX_TRI(i, i + 1, i + 2);
            RSX_TRI(i + 1, i + 3, i + 2);
        }
        break;
    case 10:                            /* polygon: a fan about its first vertex */
        for (i = 1; i + 1 < n; i++) {
            RSX_TRI(0, i, i + 1);
        }
        break;
    default:
        if (s->ppu_trace) {
            info_report("ps3-rsx: draw: primitive 0x%X is not a primitive "
                        "type", s->rsx_prim);
        }
        break;
    }

#undef RSX_TRI
#undef RSX_LINE
#undef RSX_VALID

    s->rsx_draws++;
    if (s->ppu_trace) {
        info_report("ps3-rsx: draw done: %" PRIu64 " primitive(s), %" PRIu64
                    " pixel(s), %" PRIu64 " shaded by the fp40",
                    s->rsx_prims - prims0, s->rsx_pixels - pixels0,
                    s->rsx_shaded - shaded0);
    }
    g_free(vtx);
    g_free(idx);
}

/*
 * One graphics method.
 *
 * The register number is the FIFO's method field shifted down; the arguments
 * arrive in order.  The dispatch is RPCS3's nv4097 table reduced to the
 * entries the front end implements: the render target, the vertex arrays and
 * their formats, the index array, the viewport and scissor, the blend and
 * colour-mask state, and the three draw calls.  Draw calls do not rasterize on
 * their own - they append vertex ranges to the open draw clause, and the
 * closing SET_BEGIN_END(0) walks them, which is how one primitive can span
 * several draw calls.  Everything else is counted and the first few are named
 * under ppu-trace; there is still no shader, texture unit or copy engine.
 */
static void ps3_rsx_method(PS3BootROMState *s, uint8_t *ram, uint64_t ram_size,
                           uint32_t reg, uint32_t value)
{
    uint32_t method = reg >> 2;

    s->rsx_methods++;

    if (method >= PS3_RSX_SET_VTX_OFF &&
        method < PS3_RSX_SET_VTX_OFF + PS3_RSX_ATTRS) {
        s->rsx_vtx_off[method - PS3_RSX_SET_VTX_OFF] = value;
        return;
    }
    if (method >= PS3_RSX_SET_VTX_FMT &&
        method < PS3_RSX_SET_VTX_FMT + PS3_RSX_ATTRS) {
        s->rsx_vtx_fmt[method - PS3_RSX_SET_VTX_FMT] = value;
        return;
    }

    /*
     * The vertex program's words arrive through the 32 methods at
     * SET_TRANSFORM_PROGRAM; the load register names the instruction the
     * first four words of the range belong to, so each dword's slot follows
     * RPCS3's set_transform_program: load * 4 + index % 4.
     */
    if (method >= PS3_RSX_SET_TRANSFORM_PROGRAM &&
        method < PS3_RSX_SET_TRANSFORM_PROGRAM + 32) {
        unsigned index = method - PS3_RSX_SET_TRANSFORM_PROGRAM;
        unsigned slot = s->rsx_vprog_load * 4 + (index % 4);

        if (slot < PS3_RSX_VPROG_WORDS) {
            s->rsx_vprog[slot] = value;
        }
        s->rsx_vprog_word = index;
        s->rsx_vprog_ready = true;
        return;
    }
    if (method >= PS3_RSX_SET_TRANSFORM_CONSTANT &&
        method < PS3_RSX_SET_TRANSFORM_CONSTANT + 32) {
        unsigned index = method - PS3_RSX_SET_TRANSFORM_CONSTANT;
        unsigned slot = s->rsx_vconst_load * 4 + index;

        if (slot < PS3_RSX_VCONST * 4) {
            s->rsx_vconst[slot / 4][slot % 4] = value;
        }
        s->rsx_vconst_word = index;
        return;
    }

    /*
     * The fragment stage's registers.  Each texture unit owns eight methods at
     * SET_TEXTURE_OFFSET (offset, format, address, control0, control1, filter,
     * image rectangle, border colour), which is RPCS3's stride.
     */
    if (method >= PS3_RSX_SET_TEXTURE &&
        method < PS3_RSX_SET_TEXTURE + PS3_RSX_TEX_MAX * 8) {
        unsigned n = (method - PS3_RSX_SET_TEXTURE) / 8;
        PS3RsxTexture *t = &s->rsx_tex[n];

        switch ((method - PS3_RSX_SET_TEXTURE) % 8) {
        case 0: t->offset = value; return;
        case 1: t->format = value; return;
        case 2: t->address = value; return;
        case 3: t->control0 = value; return;
        case 4: t->control1 = value; return;
        case 5: t->filter = value; return;
        case 6: t->image_rect = value; return;
        default: t->border = value; return;
        }
    }

    switch (method) {
    case PS3_RSX_SET_FORMAT:            /* NV4097_SET_SURFACE_FORMAT */
        s->rsx_surface_format = value;
        return;
    case PS3_RSX_SET_PITCH_A:           /* NV4097_SET_SURFACE_PITCH_A */
        s->rsx_surface_pitch = value;
        return;
    case PS3_RSX_SET_OFFSET_A:          /* NV4097_SET_SURFACE_COLOR_AOFFSET */
        s->rsx_surface_offset = value;
        return;
    case PS3_RSX_SET_TARGET:            /* NV4097_SET_SURFACE_COLOR_TARGET */
        s->rsx_surface_target = value;
        return;
    case PS3_RSX_SET_CLEAR:             /* NV4097_SET_COLOR_CLEAR_VALUE */
        s->rsx_clear_color = value;
        return;
    case PS3_RSX_SET_BLEND:             /* NV4097_SET_BLEND_ENABLE */
        s->rsx_blend = value & 1;
        return;
    case PS3_RSX_SET_BLEND_S:           /* NV4097_SET_BLEND_FUNC_SFACTOR */
        s->rsx_blend_s = value & 0xF;
        return;
    case PS3_RSX_SET_BLEND_D:           /* NV4097_SET_BLEND_FUNC_DFACTOR */
        s->rsx_blend_d = value & 0xF;
        return;
    case PS3_RSX_SET_BLEND_EQ:          /* NV4097_SET_BLEND_EQUATION */
        s->rsx_blend_eq = value & 0xF;
        return;
    case PS3_RSX_SET_COLORMASK:         /* NV4097_SET_COLOR_MASK */
        s->rsx_color_mask = (value & 0xFEFEFEFEu) ? value : 0xFFFFFFFFu;
        return;
    case PS3_RSX_SET_SCISSOR_H:         /* NV4097_SET_SCISSOR_HORIZONTAL */
        s->rsx_scissor_h = value;
        return;
    case PS3_RSX_SET_SCISSOR_V:         /* NV4097_SET_SCISSOR_VERTICAL */
        s->rsx_scissor_v = value;
        return;
    case PS3_RSX_SET_VIEWPORT_H:        /* NV4097_SET_VIEWPORT_HORIZONTAL */
        s->rsx_viewport_h = value;
        return;
    case PS3_RSX_SET_VIEWPORT_V:        /* NV4097_SET_VIEWPORT_VERTICAL */
        s->rsx_viewport_v = value;
        return;
    case PS3_RSX_SET_DEPTHTEST:         /* NV4097_SET_DEPTH_TEST_ENABLE */
        s->rsx_depth_test = value & 1;
        return;
    case PS3_RSX_SET_CULL:              /* NV4097_SET_CULL_FACE_ENABLE */
        s->rsx_cull = value & 1;
        return;
    case PS3_RSX_SET_VTX_BASE:          /* NV4097_SET_VERTEX_DATA_BASE_OFFSET */
        s->rsx_vtx_base = value;
        return;
    case PS3_RSX_SET_VTX_INDEX:         /* NV4097_SET_VERTEX_DATA_BASE_INDEX */
        s->rsx_vtx_index_base = value & 0xFFFFF;
        return;
    case PS3_RSX_SET_TRANSFORM_PROGRAM_LOAD:
        s->rsx_vprog_load = value & (PS3_RSX_VPROG_INST - 1);
        return;
    case PS3_RSX_SET_TRANSFORM_PROGRAM_START:
        s->rsx_vprog_start = value & (PS3_RSX_VPROG_INST - 1);
        return;
    case PS3_RSX_SET_TRANSFORM_CONST_LOAD:
        s->rsx_vconst_load = value & (PS3_RSX_VCONST - 1);
        return;
    case PS3_RSX_SET_SHADER_CONTROL:
        s->rsx_shader_control = value;
        return;
    case PS3_RSX_SET_SHADER_PROGRAM: {
        /*
         * The address names the program's header: bits 0..1 select the memory
         * (2 local, 3 main) and the rest is its offset.  Copy the program and
         * the constants it carries inline so a draw reads them from here.
         */
        unsigned loc = value & 3;
        uint32_t addr = value & ~3u;
        unsigned want = PS3_RSX_FPROG_BYTES;
        const uint8_t *p;

        s->rsx_fprog_addr = addr;
        s->rsx_fprog_ready = false;
        s->rsx_fprog_len = 0;

        if (loc != 2 && loc != 3) {
            return;                     /* not a location a program can live in */
        }
        if (loc == 2 && (uint64_t)addr + 16 <= s->rsx_local_size) {
            want = MIN(want, s->rsx_local_size - addr);
        } else if (loc == 3) {
            want = MIN(want, 4096u);
        } else {
            return;
        }

        p = ps3_rsx_mem(s, ram, ram_size, loc == 3, addr, want);
        if (!p) {
            if (!s->rsx_fprog_reported) {
                s->rsx_fprog_reported = true;
                info_report("ps3-rsx: fragment program at 0x%X is not mapped",
                            addr);
            }
            return;
        }

        memcpy(s->rsx_fprog, p, want);
        s->rsx_fprog_len = want;
        s->rsx_fprog_ready = true;
        if (!s->rsx_fprog_reported) {
            s->rsx_fprog_reported = true;
            info_report("ps3-rsx: fragment program at 0x%X (%u bytes, %s)",
                        addr, want, loc == 2 ? "local" : "main");
        }
        return;
    }
    case PS3_RSX_SET_INDEX_ADDR:        /* NV4097_SET_INDEX_ARRAY_ADDRESS */
        s->rsx_index_addr = value & 0x1FFFFFFCu;
        return;
    case PS3_RSX_SET_INDEX_DMA:         /* NV4097_SET_INDEX_ARRAY_DMA */
        /* Location in bits 0..3, the index width in bits 4..7. */
        if (value & ~0x1Fu) {
            return;                     /* RPCS3 rolls an invalid value back */
        }
        s->rsx_index_dma = value;
        return;
    case PS3_RSX_SET_BEGIN_END:         /* NV4097_SET_BEGIN_END */
        if (value) {
            /* A new primitive closes the clause that was still open. */
            if (s->rsx_prim && (s->rsx_clause_n || s->rsx_inline_words)) {
                ps3_rsx_rasterize(s, ram, ram_size);
            }
            s->rsx_prim = value & 0xFF;
            s->rsx_clause_n = 0;
            s->rsx_inline_words = 0;
            s->rsx_clause_indexed = 0;
            s->rsx_begin_end = value;
        } else {
            ps3_rsx_rasterize(s, ram, ram_size);
            s->rsx_begin_end = 0;
            s->rsx_prim = 0;
            s->rsx_clause_n = 0;
            s->rsx_inline_words = 0;
            s->rsx_clause_indexed = 0;
        }
        return;
    case PS3_RSX_DRAW_ARRAYS:           /* NV4097_DRAW_ARRAYS */
    case PS3_RSX_DRAW_INDEXED:          /* NV4097_DRAW_INDEX_ARRAY */
        if (!s->rsx_prim) {
            return;                     /* outside a primitive, ignored */
        }
        if (s->rsx_clause_n == PS3_RSX_CLAUSE_MAX) {
            if (s->ppu_trace) {
                info_report("ps3-rsx: draw clause is full, range dropped");
            }
            return;
        }
        s->rsx_clause[s->rsx_clause_n].start = value & 0xFFFFFFu;
        s->rsx_clause[s->rsx_clause_n].count = ((value >> 24) & 0xFF) + 1;
        s->rsx_clause_n++;
        s->rsx_clause_indexed = method == PS3_RSX_DRAW_INDEXED;
        return;
    case PS3_RSX_INLINE_ARRAY:          /* NV4097_INLINE_ARRAY */
        if (!s->rsx_prim || s->rsx_inline_words == PS3_RSX_INLINE_MAX) {
            return;
        }
        ps3_put_be32(s->rsx_inline + 4 * s->rsx_inline_words, value);
        s->rsx_inline_words++;
        s->rsx_clause_indexed = 2;
        return;
    case PS3_RSX_ARRAY_ELEM16:          /* NV4097_ARRAY_ELEMENT16 */
    case PS3_RSX_ARRAY_ELEM32:          /* NV4097_ARRAY_ELEMENT32 */
        if (!s->rsx_immediate_reported) {
            s->rsx_immediate_reported = true;
            info_report("ps3-rsx: immediate-mode vertex elements are not "
                        "drawn; cellGcmSys uses vertex arrays");
        }
        return;
    case PS3_RSX_CLEAR_SURFACE:         /* NV4097_CLEAR_SURFACE */
        if (value & 0xF0) {
            ps3_rsx_clear(s, ram, ram_size, s->rsx_surface_target & 0xF,
                          s->rsx_clear_color);
        }
        return;
    default:
        break;
    }

    if (s->ppu_trace && s->rsx_methods_logged < 24) {
        info_report("ps3-rsx: method 0x%X <- 0x%X", method, value);
        s->rsx_methods_logged++;
    }
}

/*
 * The FIFO consumer.
 *
 * get and put are io offsets, as the graphics library writes them into the
 * DMA control block.  Each word is translated through the context map before
 * it is read.  A method packet carries a count of arguments (a count of zero
 * is a NOP); jump, call and return packets move get without consuming
 * arguments.  A jump to get itself is the library's idle marker: the ring is
 * empty, so the consumer stops there until the next doorbell.
 */
static void ps3_rsx_fifo(PS3BootROMState *s, uint8_t *ram, uint64_t ram_size)
{
    uint32_t get, put, ret = PS3_RSX_CALL_EMPTY;
    unsigned steps = 0;

    if (!s->rsx_context) {
        return;
    }

    get = s->rsx_get;
    put = s->rsx_put;

    while (get != put && steps++ < 65536) {
        uint32_t ea = ps3_rsx_io_ea(s, get);
        uint32_t w;

        if (ea == 0xFFFFFFFFu || (uint64_t)ea + 4 > ram_size) {
            break;
        }
        w = ps3_be32(ram + ea);

        if ((w & 0xE0030003u) == 0) {                   /* method packet */
            unsigned count = (w >> 18) & 0x7FF;
            uint32_t method = w & 0xFFFCu;
            unsigned inc = (w & 0x40000000u) ? 0 : 4;
            unsigned i;

            if (!count) {                               /* NOP */
                get += 4;
                continue;
            }
            for (i = 0; i < count; i++) {
                uint32_t aea = ps3_rsx_io_ea(s, get + 4 + 4 * i);

                if (aea == 0xFFFFFFFFu || (uint64_t)aea + 4 > ram_size) {
                    break;
                }
                ps3_rsx_method(s, ram, ram_size, method + i * inc,
                               ps3_be32(ram + aea));
            }
            get += 4 + count * 4;
            continue;
        }

        if ((w & 0xE0000003u) == 0x00000001u) {         /* new-style jump */
            uint32_t to = w & 0xFFFFFFFCu;

            if (to == get) {
                break;
            }
            get = to;
            continue;
        }

        if ((w & 0xE0000003u) == 0x20000000u) {         /* old-style jump */
            get = w & 0x1FFFFFFCu;
            continue;
        }

        if ((w & 3u) == 2u) {                           /* call */
            ret = get + 4;
            get = w & 0x1FFFFFFCu;
            continue;
        }

        if ((w & 0xFFFF0003u) == 0x00020000u) {         /* return */
            if (ret == PS3_RSX_CALL_EMPTY) {
                break;
            }
            get = ret;
            ret = PS3_RSX_CALL_EMPTY;
            continue;
        }

        break;                                          /* malformed packet */
    }

    s->rsx_get = get;
    if (s->rsx_dma) {
        ps3_put_be32(ram + s->rsx_dma + PS3_RSX_DMA_GET, get);
    }
}

/*
 * One handler event.
 *
 * The driver info page carries the mask of handlers the library installed and
 * the id of the queue that owns them, so an event is only queued for a
 * handler that asked for it, exactly as RPCS3's send_event filters it.
 */
static void ps3_rsx_event(PS3BootROMState *s, uint8_t *ram, uint64_t ram_size,
                          uint64_t data1, uint64_t flags, uint64_t data3)
{
    uint32_t drv = s->rsx_driver;
    PS3Event ev;
    int q;

    if (!s->rsx_context || !drv || (uint64_t)drv + PS3_RSX_DI_SIZE > ram_size) {
        return;
    }

    flags &= ps3_be32(ram + drv + PS3_RSX_DI_HANDLERS) | (0xFFFFFFFFull << 32);
    if (!flags) {
        return;
    }

    q = ps3_eq_index(s, ps3_be32(ram + drv + PS3_RSX_DI_QUEUE));
    if (q < 0) {
        return;
    }

    ev.source = 0;
    ev.data1 = data1;
    ev.data2 = flags;
    ev.data3 = data3;
    ps3_eq_push(&s->eq[q], &ev);
    ps3_eq_wake(s, ram, ram_size, q);
}

/* The display circuit's vblank for one head. */
static void ps3_rsx_vblank(PS3BootROMState *s, uint8_t *ram, uint64_t ram_size,
                           unsigned head)
{
    uint32_t h = s->rsx_driver + PS3_RSX_DI_HEAD +
                 head * PS3_RSX_DI_HEAD_STRIDE;
    uint64_t tb = ps3_rsx_timebase();
    uint64_t flags = PS3_RSX_EVENT_VBLANK;

    ps3_put_be32(ram + h + PS3_RSX_HEAD_VTLOW, (uint32_t)tb);
    ps3_put_be32(ram + h + PS3_RSX_HEAD_VTHIGH, (uint32_t)(tb >> 32));
    ps3_put_be64(ram + h + PS3_RSX_HEAD_SECONDT,
                 ps3_be64(ram + h + PS3_RSX_HEAD_SECONDT) + 1);
    ps3_put_be64(ram + h + PS3_RSX_HEAD_VCOUNT,
                 ps3_be64(ram + h + PS3_RSX_HEAD_VCOUNT) + 1);

    if (s->rsx_second_vhandler) {
        flags |= PS3_RSX_EVENT_SECOND_BASE << head;
    }

    s->rsx_vblanks++;
    ps3_rsx_event(s, ram, ram_size, 0, flags, 0);
}

/*
 * The display's own clock: 59.94 Hz of virtual time, which is what carries
 * vblank to a guest waiting on the RSX queue.  It is display timing, not a
 * scheduler tick; the FIFO and the flips are driven by the guest's doorbell.
 */
static void ps3_rsx_vblank_tick(void *opaque)
{
    PS3BootROMState *s = opaque;
    uint8_t *ram = memory_region_get_ram_ptr(s->ram);
    uint64_t ram_size = memory_region_size(s->ram);

    if (!s->rsx_context) {
        return;
    }

    ps3_rsx_vblank(s, ram, ram_size, 0);
    ps3_rsx_vblank(s, ram, ram_size, 1);

    timer_mod(s->rsx_vblank_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + PS3_RSX_VBLANK_NS);
}

static void ps3_rsx_flip(PS3BootROMState *s, unsigned head, unsigned id)
{
    if (head > 1 || id >= ARRAY_SIZE(s->rsx_db_w) || !s->rsx_db_w[id]) {
        return;
    }

    s->rsx_flips++;
    info_report("ps3-rsx: flip head %u buffer %u: 0x%X, %ux%u, pitch 0x%X",
                head, id, s->rsx_db_offset[id], s->rsx_db_w[id],
                s->rsx_db_h[id], s->rsx_db_pitch[id]);
    ps3_vga_guest_scanout(PS3_RSX_LOCAL_BASE + s->rsx_db_offset[id],
                          s->rsx_db_w[id], s->rsx_db_h[id],
                          s->rsx_db_pitch[id]);
}

/*
 * sys_storage, the way lv2 presents the drives to the application layer.
 *
 * This is what the VSH's media manager uses, not the ATA command block: it
 * asks how many storages and devices there are, reports the device list, then
 * reads the device info of each one, opens the Blu-ray drive and reads
 * 2048-byte sectors.  Every one of those calls was unmodelled, so the whole
 * family answered 0 and the drive never "connected": the VSH printed
 * `BD Drive connect error', its x3 worker threads died, and its main thread
 * sat in the media list's mutex at 0x5390B8 waiting for a handshake that could
 * not happen.  With the layer here that handshake completes and the boot
 * carries on into cellGcmInit.
 */
static uint64_t ps3_stor_base(uint64_t device)
{
    return device & 0xFFFFF00FFFFFFFFULL;
}

static unsigned ps3_stor_num(uint64_t device)
{
    return (device >> 32) & 0xFF;
}

static int ps3_stor_index(PS3BootROMState *s, uint32_t fd)
{
    if (!fd || fd > PS3_STOR_MAX) {
        return -1;
    }
    return s->stor[fd - 1].used ? (int)(fd - 1) : -1;
}

static uint64_t ps3_stor_hdd_sectors(PS3BootROMState *s, unsigned num)
{
    uint64_t total = s->hdd_size ? s->hdd_size / PS3_LV2_SECTOR
                                 : 0x2542EAB0ULL;

    switch (num) {
    case 0:
        return total;
    case 1:
        return total > 0x483018 ? total - 0x483018 : total;
    default:
        return 0x3FFFF8;
    }
}

static const uint64_t ps3_stor_all[PS3_STOR_DEVICES] = {
    PS3_STOR_USB,
    PS3_STOR_NAND, PS3_STOR_NAND | (1ULL << 32), PS3_STOR_NAND | (2ULL << 32),
    PS3_STOR_NAND | (3ULL << 32), PS3_STOR_NAND | (4ULL << 32),
    PS3_STOR_NAND | (5ULL << 32), PS3_STOR_NAND | (6ULL << 32),
    PS3_STOR_ATA_HDD, PS3_STOR_ATA_HDD | (1ULL << 32),
    PS3_STOR_ATA_HDD | (2ULL << 32),
    PS3_STOR_BDVD,
    PS3_STOR_NOR, PS3_STOR_NOR | (1ULL << 32), PS3_STOR_NOR | (2ULL << 32),
    PS3_STOR_NOR | (3ULL << 32),
    PS3_STOR_NAND_UNK,
};

/* StorageDeviceInfo: name[0x20], 0x20, 0x24, count u64 at 0x28, sector size
 * u32 at 0x30, a constant 1 at 0x34 and eight flag bytes at 0x38. */
static int32_t ps3_stor_info(PS3BootROMState *s, uint8_t *ram,
                             uint64_t ram_size, uint64_t device, uint32_t ptr)
{
    uint8_t info[0x40];
    uint64_t sectors = 0;
    uint32_t size = PS3_LV2_SECTOR;
    uint8_t flags[8] = { 0, 0, 1, 0, 0, 0, 0, 1 };
    unsigned num = ps3_stor_num(device);

    if (!ptr || (uint64_t)ptr + sizeof(info) > ram_size) {
        return PS3_LV2_EFAULT;
    }

    switch (ps3_stor_base(device)) {
    case PS3_STOR_BDVD:
        if (num > 0) {
            return -5;              /* no such partition, as lv2 answers */
        }
        size = PS3_STOR_SECT_BD;
        /* An empty drawer really is empty: the media's size is the answer. */
        sectors = s->disc_size / PS3_STOR_SECT_BD;
        break;
    case PS3_STOR_ATA_HDD:
        if (num > 2) {
            return -5;
        }
        sectors = ps3_stor_hdd_sectors(s, num);
        flags[1] = 1;
        break;
    case PS3_STOR_NAND: {
        static const uint64_t nand[7] = { 0x80000, 0x75F8, 0x63E00, 0x8000,
                                          0x400, 0x2000, 0x200 };

        if (num > 6) {
            return -5;
        }
        sectors = nand[num];
        flags[1] = 1;
        break;
    }
    case PS3_STOR_NOR: {
        static const uint64_t nor[4] = { 0x8000, 0x77F8, 0x100, 0x400 };

        if (num > 3) {
            return -5;
        }
        sectors = nor[num];
        break;
    }
    case PS3_STOR_NAND_UNK:
        if (num > 1) {
            return -5;
        }
        size = PS3_STOR_SECT_BD;
        sectors = 0x7FFFFFFF;
        break;
    case PS3_STOR_USB:
        if (num > 0) {
            return -5;
        }
        /* A USB stick is a host directory here, so it has no geometry. */
        break;
    default:
        return PS3_LV2_ENOENT;
    }

    memset(info, 0, sizeof(info));
    memcpy(info, "unnamed", 7);
    ps3_put_be64(info + 0x28, sectors);
    ps3_put_be32(info + 0x30, size);
    ps3_put_be32(info + 0x34, 1);
    memcpy(info + 0x38, flags, 8);
    memcpy(ram + ptr, info, sizeof(info));

    return 0;
}

static bool ps3_lv2_storage(PS3BootROMState *s, CPUPPCState *env, uint8_t *ram,
                            uint64_t ram_size, uint32_t nr, int32_t *ret)
{
    uint64_t a0 = env->gpr[3];
    uint64_t a1 = env->gpr[4];
    uint64_t a2 = env->gpr[5];
    uint64_t a3 = env->gpr[6];
    uint64_t a4 = env->gpr[7];
    uint64_t a5 = env->gpr[8];
    uint64_t a6 = env->gpr[9];

    switch (nr) {
    case 0x258: {               /* sys_storage_open(device, mode, fd*,
                                 * flags) */
        unsigned n;

        if (a0 == 0) {
            *ret = PS3_LV2_ENOENT;
            return true;
        }
        if (!a2 || a2 + 4 > ram_size) {
            *ret = PS3_LV2_EFAULT;
            return true;
        }
        for (n = 0; n < PS3_STOR_MAX; n++) {
            if (!s->stor[n].used) {
                break;
            }
        }
        if (n == PS3_STOR_MAX) {
            *ret = PS3_LV2_EAGAIN;
            return true;
        }
        s->stor[n].used = true;
        s->stor[n].device = a0;
        ps3_put_be32(ram + a2, n + 1);
        if (s->ppu_trace) {
            info_report("ps3-ppu: lv2: sys_storage_open(0x%" PRIX64
                        ", mode 0x%" PRIX64 ") -> handle %u", a0, a1, n + 1);
        }
        *ret = 0;
        return true;
    }
    case 0x259: {               /* sys_storage_close(fd) */
        int i = ps3_stor_index(s, a0);

        if (i < 0) {
            *ret = PS3_LV2_ESRCH;
            return true;
        }
        memset(&s->stor[i], 0, sizeof(s->stor[i]));
        *ret = 0;
        return true;
    }
    case 0x25A:                 /* sys_storage_read(fd, mode, start, count,
                                 * buf, got*, flags) */
    case 0x25B: {               /* sys_storage_write(...) */
        int i = ps3_stor_index(s, a0);
        bool bd = i >= 0 && ps3_stor_base(s->stor[i].device) == PS3_STOR_BDVD;
        BlockBackend *blk = bd ? s->disc : s->hdd;
        uint32_t sect = bd ? PS3_STOR_SECT_BD : PS3_LV2_SECTOR;
        uint64_t bytes, off, media;
        uint32_t n;
        bool write = nr == 0x25B;

        if (i < 0) {
            *ret = PS3_LV2_ESRCH;
            return true;
        }
        if (!a4 || a4 + 8 > ram_size || !a5 || a5 + 4 > ram_size) {
            *ret = PS3_LV2_EFAULT;
            return true;
        }
        n = (uint32_t)a3;
        if (n > (ram_size - a4) / sect) {
            n = (ram_size - a4) / sect;
        }
        bytes = (uint64_t)n * sect;
        off = (uint64_t)(uint32_t)a2 * sect;
        media = bd ? s->disc_size : s->hdd_size;

        /* An empty drawer, a write to a read-only disc: nothing moves. */
        if (!blk || (write && bd) || off >= media) {
            ps3_put_be32(ram + a5, 0);
            *ret = 0;
            return true;
        }
        /* A read that runs past the media stops at its end. */
        if (!write && off + bytes > media) {
            n = (media - off) / sect;
            bytes = (uint64_t)n * sect;
        }
        if (write ? blk_pwrite(blk, off, bytes, ram + a4, 0) < 0
                  : blk_pread(blk, off, bytes, ram + a4, 0) < 0) {
            *ret = PS3_LV2_EIO;
            return true;
        }
        ps3_put_be32(ram + a5, n);
        if (s->ppu_trace) {
            info_report("ps3-ppu: lv2: storage %s sector 0x%X, %u sector(s)",
                        write ? "write" : "read", (uint32_t)a2, n);
        }
        *ret = 0;
        return true;
    }
    case 0x25C:                 /* sys_storage_send_device_command(handle, cmd,
                                 * in, inlen, out, outlen) */
    case 0x268: {               /* sys_storage_execute_device_command(...) */
        /* A SCSI pass-through.  lv2 forwards it to the drive and the drive's
         * own firmware answers; there is no firmware here, so the reply is
         * a zeroed buffer and success, which is what every caller that only
         * needs the drive to be present expects. */
        uint64_t out = nr == 0x25C ? a4 : a6;
        uint64_t outlen = nr == 0x25C ? a5 : a6;

        if (nr == 0x268) {
            out = a4;
            outlen = a5;
        }
        if (out && outlen && out + outlen <= ram_size) {
            memset(ram + out, 0, MIN(outlen, ram_size - out));
        }
        if (nr == 0x268 && a6 && a6 + 4 <= ram_size) {
            ps3_put_be32(ram + a6, 0);
        }
        *ret = 0;
        return true;
    }
    case 0x25D:                 /* sys_storage_async_configure(fd, io_buf,
                                 * eq, unk) */
    case 0x25E:                 /* sys_storage_async_read */
    case 0x25F:                 /* sys_storage_async_write */
    case 0x260:                 /* sys_storage_async_cancel */
    case 0x264:                 /* sys_storage_configure_medium_event */
    case 0x265:                 /* sys_storage_set_medium_polling_interval */
    case 0x266:                 /* sys_storage_create_region */
    case 0x267:                 /* sys_storage_delete_region */
    case 0x269:                 /* sys_storage_check_region_acl */
    case 0x26A:                 /* sys_storage_set_region_acl */
    case 0x26B:                 /* sys_storage_async_send_device_command */
    case 0x26E:                 /* sys_storage_get_region_offset */
    case 0x26F:                 /* sys_storage_set_emulated_speed */
    case 0x2BB:                 /* sys_bdemu_send_command */
        *ret = 0;
        return true;
    case 0x261:                 /* sys_storage_get_device_info(device, info*) */
        *ret = ps3_stor_info(s, ram, ram_size, a0, (uint32_t)a1);
        return true;
    case 0x262:                 /* sys_storage_get_device_config(storages*,
                                 * devices*) */
        if (!a0 || a0 + 4 > ram_size || !a1 || a1 + 4 > ram_size) {
            *ret = PS3_LV2_EFAULT;
            return true;
        }
        ps3_put_be32(ram + a0, 6);              /* storages lv2 reports */
        ps3_put_be32(ram + a1, PS3_STOR_DEVICES);
        if (!s->lv2_storage_reported) {
            s->lv2_storage_reported = true;
            info_report("ps3-ppu: lv2: sys_storage: 6 storage(s), %u device(s); "
                        "BD drive %s", PS3_STOR_DEVICES,
                        s->disc_size ? "has media" : "is empty");
        }
        *ret = 0;
        return true;
    case 0x263: {               /* sys_storage_report_devices(storages, start,
                                 * count, ids*) */
        uint32_t n;

        if (!a3 || a3 + 8 > ram_size) {
            *ret = PS3_LV2_EFAULT;
            return true;
        }
        if ((uint32_t)a1 >= PS3_STOR_DEVICES ||
            (uint32_t)a2 > PS3_STOR_DEVICES - (uint32_t)a1) {
            *ret = PS3_LV2_EINVAL;
            return true;
        }
        for (n = 0; n < (uint32_t)a2; n++) {
            ps3_put_be64(ram + a3 + 8 * (uint64_t)n,
                         ps3_stor_all[(uint32_t)a1 + n]);
        }
        *ret = 0;
        return true;
    }
    default:
        return false;
    }
}

/*
 * The three areas lv2 keeps for the context.  They come out of the same heap
 * as everything else lv2 allocates, one MiB apart as RPCS3 lays them out, and
 * their contents are what the library reads: the DMA control block, the
 * driver info page and the report table.
 */
static void ps3_rsx_init_driver(PS3BootROMState *s, uint8_t *ram,
                                uint32_t system_mode)
{
    uint32_t d = s->rsx_driver, r = s->rsx_reports, i;

    memset(ram + d, 0, PS3_RSX_DI_SIZE);
    ps3_put_be32(ram + d + PS3_RSX_DI_VERSION, 0x211);      /* driver 2.11 */
    ps3_put_be32(ram + d + PS3_RSX_DI_GPU, 0x5C);           /* RSX 0x5C */
    ps3_put_be32(ram + d + PS3_RSX_DI_MEM_SIZE, s->rsx_local_size);
    ps3_put_be32(ram + d + PS3_RSX_DI_CHANNEL, 1);
    ps3_put_be32(ram + d + PS3_RSX_DI_NVCORE, 500000000);
    ps3_put_be32(ram + d + PS3_RSX_DI_MEMFREQ, 650000000);
    ps3_put_be32(ram + d + PS3_RSX_DI_NOTIFY, PS3_RSX_NOTIFY_OFF);
    ps3_put_be32(ram + d + PS3_RSX_DI_REPORTS, 0);
    ps3_put_be32(ram + d + PS3_RSX_DI_REPTABLE, PS3_RSX_REPORT_OFF);
    ps3_put_be32(ram + d + PS3_RSX_DI_SYSMODE, system_mode);

    memset(ram + r, 0, PS3_RSX_REPORTS_SIZE);
    for (i = 0; i < 64; i++) {
        ps3_put_be64(ram + r + PS3_RSX_NOTIFY_OFF + 16 * i, ~0ull);
    }
    for (i = 0; i < 1024; i += 4) {
        ps3_put_be32(ram + r + 4 * (i + 0), 0x1337C0D3u);
        ps3_put_be32(ram + r + 4 * (i + 1), 0x1337BABEu);
        ps3_put_be32(ram + r + 4 * (i + 2), 0x1337BEEFu);
        ps3_put_be32(ram + r + 4 * (i + 3), 0x1337F001u);
    }
    for (i = 0; i < 2048; i++) {
        uint32_t p = r + PS3_RSX_REPORT_OFF + 16 * i;

        ps3_put_be64(ram + p, ~0ull);           /* timestamp */
        ps3_put_be32(ram + p + 8, 0);           /* value */
        ps3_put_be32(ram + p + 12, 0xFFFFFFFFu); /* pad */
    }

    ps3_put_be32(ram + s->rsx_dma + PS3_RSX_DMA_PUT, 0);
    ps3_put_be32(ram + s->rsx_dma + PS3_RSX_DMA_GET, 0);
    ps3_put_be32(ram + s->rsx_dma + PS3_RSX_DMA_REF, 0);
}

static bool ps3_lv2_rsx(PS3BootROMState *s, uint8_t *ram, uint64_t ram_size,
                        uint32_t nr, uint64_t a0, uint64_t a1, uint64_t a2,
                        uint64_t a3, uint64_t a4, uint64_t a5, int32_t *ret)
{
    switch (nr) {
    case 0x29A:                 /* sys_rsx_device_open */
    case 0x29B:                 /* sys_rsx_device_close */
        /* There is one RSX and it is always there. */
        *ret = 0;
        return true;

    case 0x29C: {               /* sys_rsx_memory_allocate(handle*, addr*,
                                 * size, flags, a5, a6, a7) */
        uint64_t size = a2;

        if ((uint64_t)a0 + 4 > ram_size || (uint64_t)a1 + 8 > ram_size) {
            *ret = PS3_LV2_EFAULT;
            return true;
        }
        if (!size || (size & 0xFFFFF) || size > PS3_RSX_LOCAL_SIZE) {
            *ret = PS3_RSX_LV1_ILLEGAL_PARAM;
            return true;
        }
        if (s->rsx_mem_allocated || s->rsx_context) {
            *ret = PS3_LV2_ENOMEM;
            return true;
        }

        s->rsx_mem_allocated = true;
        s->rsx_mem_handle = PS3_RSX_MEM_HANDLE;
        s->rsx_local_size = (uint32_t)size;
        ps3_put_be32(ram + a0, PS3_RSX_MEM_HANDLE);
        ps3_put_be64(ram + a1, PS3_RSX_LOCAL_BASE);
        info_report("ps3-rsx: local memory 0x%X bytes at 0x%X (handle 0x%X)",
                    (uint32_t)size, PS3_RSX_LOCAL_BASE, PS3_RSX_MEM_HANDLE);
        *ret = 0;
        return true;
    }

    case 0x29D:                 /* sys_rsx_memory_free(handle) */
        if (!s->rsx_mem_allocated || a0 != s->rsx_mem_handle ||
            s->rsx_context) {
            *ret = PS3_LV2_ENOMEM;
            return true;
        }
        s->rsx_mem_allocated = false;
        s->rsx_local_size = 0;
        *ret = 0;
        return true;

    case 0x29E: {               /* context_allocate(ctx*, dma*, driver*,
                                 * reports*, mem_ctx, system_mode) */
        uint32_t base, d, i;
        int qi = -1, pi = -1;

        if ((uint64_t)a0 + 4 > ram_size || (uint64_t)a1 + 8 > ram_size ||
            (uint64_t)a2 + 8 > ram_size || (uint64_t)a3 + 8 > ram_size) {
            *ret = PS3_LV2_EFAULT;
            return true;
        }
        if (!s->rsx_mem_allocated || a4 != PS3_RSX_MEM_HANDLE ||
            s->rsx_context) {
            *ret = PS3_LV2_EINVAL;
            return true;
        }
        for (i = 0; i < PS3_EQ_MAX; i++) {
            if (!s->eq[i].used) {
                qi = i;
                break;
            }
        }
        for (i = 0; i < PS3_EP_MAX; i++) {
            if (!s->ep[i].used) {
                pi = i;
                break;
            }
        }
        if (qi < 0 || pi < 0) {
            *ret = PS3_LV2_EAGAIN;
            return true;
        }

        base = (s->lv2_heap + 0xFFFFF) & ~0xFFFFFu;
        if ((uint64_t)base + 0x300000 > ram_size) {
            *ret = PS3_LV2_ENOMEM;
            return true;
        }
        s->lv2_heap = base + 0x300000;
        ps3_put_be32(ram + PS3_LV2_HEAP, s->lv2_heap);

        s->rsx_dma = base;
        s->rsx_driver = base + 0x100000;
        s->rsx_reports = base + 0x200000;
        d = s->rsx_driver;

        /* The context's handler queue, which the library receives from. */
        memset(&s->eq[qi], 0, sizeof(s->eq[qi]));
        s->eq[qi].used = true;
        s->eq[qi].id = ++s->lv2_next_id;
        s->eq[qi].size = 0x20;
        memset(&s->ep[pi], 0, sizeof(s->ep[pi]));
        s->ep[pi].used = true;
        s->ep[pi].id = ++s->lv2_next_id;
        s->ep[pi].type = 1;             /* SYS_EVENT_PORT_LOCAL */
        s->ep[pi].eq = qi;
        s->rsx_event_port = s->ep[pi].id;
        s->rsx_event_queue = s->eq[qi].id;

        ps3_rsx_init_driver(s, ram, (uint32_t)a5);
        ps3_put_be32(ram + d + PS3_RSX_DI_QUEUE, s->rsx_event_queue);

        s->rsx_context = PS3_RSX_CONTEXT_ID;
        s->rsx_get = 0;
        s->rsx_put = 0;
        ps3_put_be32(ram + a0, PS3_RSX_CONTEXT_ID);
        ps3_put_be64(ram + a1, s->rsx_dma);
        ps3_put_be64(ram + a2, s->rsx_driver);
        ps3_put_be64(ram + a3, s->rsx_reports);

        /*
         * The library's command context lives in the RSX window this call has
         * just been paired with; publish it before the guest can emit.
         */
        ps3_rsx_publish_context(s, ram, ram_size);

        if (!s->rsx_vblank_timer) {
            s->rsx_vblank_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                               ps3_rsx_vblank_tick, s);
        }
        timer_mod(s->rsx_vblank_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + PS3_RSX_VBLANK_NS);

        info_report("ps3-rsx: context 0x%X: dma 0x%X, driver info 0x%X, "
                    "reports 0x%X; handler queue 0x%X",
                    PS3_RSX_CONTEXT_ID, s->rsx_dma, s->rsx_driver,
                    s->rsx_reports, s->rsx_event_queue);
        *ret = 0;
        return true;
    }

    case 0x29F: {               /* sys_rsx_context_free(context) */
        int qi, pi;

        if (a0 != PS3_RSX_CONTEXT_ID || !s->rsx_context) {
            *ret = PS3_LV2_EINVAL;
            return true;
        }

        qi = ps3_eq_index(s, s->rsx_event_queue);
        pi = ps3_ep_index(s, s->rsx_event_port);
        if (qi >= 0) {
            memset(&s->eq[qi], 0, sizeof(s->eq[qi]));
        }
        if (pi >= 0) {
            memset(&s->ep[pi], 0, sizeof(s->ep[pi]));
        }

        if (s->rsx_vblank_timer) {
            timer_del(s->rsx_vblank_timer);
        }
        s->rsx_context = 0;
        s->rsx_event_port = 0;
        s->rsx_event_queue = 0;
        s->rsx_dma = 0;
        s->rsx_driver = 0;
        s->rsx_reports = 0;
        s->rsx_head_queued[0] = s->rsx_head_queued[1] = 0;
        s->rsx_head_flags[0] = s->rsx_head_flags[1] = 0;
        *ret = 0;
        return true;
    }

    case 0x2A0: {               /* context_iomap(ctx, io, ea, size, flags) */
        uint64_t io = a1, ea = a2, size = a3;
        uint32_t page, first;

        if (!size || (io & 0xFFFFF) || (size & 0xFFFFF) || (ea & 0xFFFFF) ||
            size > 0x20000000 || size > ~io || size > ~ea) {
            info_report("ps3-rsx: iomap refused: ctx 0x%X, io 0x%" PRIX64
                        ", ea 0x%" PRIX64 ", size 0x%" PRIX64
                        ": not a whole number of 1MB pages",
                        (uint32_t)a0, io, ea, size);
            *ret = PS3_LV2_EINVAL;
            return true;
        }
        if (a0 != PS3_RSX_CONTEXT_ID || PS3_RSX_MAIN_SIZE < io + size ||
            ea + size > ram_size) {
            info_report("ps3-rsx: iomap refused: ctx 0x%X, io 0x%" PRIX64
                        ", ea 0x%" PRIX64 ", size 0x%" PRIX64
                        ": outside the window or main memory",
                        (uint32_t)a0, io, ea, size);
            *ret = PS3_LV2_EINVAL;
            return true;
        }

        first = io >> 20;
        for (page = 0; page < (size >> 20); page++) {
            s->rsx_iomap_ea[first + page] = (uint32_t)(ea + ((uint64_t)page << 20));
            s->rsx_iomap_used[first + page] = 1;
        }
        info_report("ps3-rsx: iomap ctx 0x%X: io 0x%" PRIX64
                    " <- ea 0x%" PRIX64 ", 0x%" PRIX64 " bytes",
                    (uint32_t)a0, io, ea, size);
        *ret = 0;
        return true;
    }

    case 0x2A1: {               /* context_iounmap(ctx, io, size) */
        uint64_t io = a1, size = a2;
        uint32_t page, first;

        if (!size || (io & 0xFFFFF) || (size & 0xFFFFF) ||
            size > 0x20000000 || size > ~io) {
            *ret = PS3_LV2_EINVAL;
            return true;
        }
        if (a0 != PS3_RSX_CONTEXT_ID || PS3_RSX_MAIN_SIZE < io + size) {
            *ret = PS3_LV2_EINVAL;
            return true;
        }

        first = io >> 20;
        for (page = 0; page < (size >> 20); page++) {
            s->rsx_iomap_used[first + page] = 0;
            s->rsx_iomap_ea[first + page] = 0;
        }
        *ret = 0;
        return true;
    }

    case 0x2A2: {               /* context_attribute(ctx, package, a3..a6) */
        uint32_t drv, h;

        if (a0 != PS3_RSX_CONTEXT_ID || !s->rsx_context) {
            *ret = PS3_LV2_EINVAL;
            return true;
        }
        drv = s->rsx_driver;

        switch (a1) {
        case 0x001:             /* FIFO get/put: the doorbell */
            s->rsx_get = a2;
            s->rsx_put = a3;
            ps3_rsx_fifo(s, ram, ram_size);
            break;

        case 0x100:             /* display mode set */
            break;

        case 0x101:             /* display sync: 2 is vsync, 1 is hsync */
            s->rsx_vsync = (a3 == 2);
            break;

        case 0x102: {           /* display flip: head, buffer */
            uint32_t head = a2;
            unsigned id;

            if (head > 1) {
                *ret = PS3_LV2_EINVAL;
                return true;
            }
            if (a3 & 0x80000000u) {
                unsigned idx = a3 & 0xFu;

                id = idx > 7 ? s->rsx_head_queued[head] : idx;
                if (!(s->rsx_head_flags[head] & (1u << id)) ||
                    !(s->rsx_head_flags[head] & 0x40000000u)) {
                    info_report("ps3-rsx: flip of buffer %u, which was not "
                                "queued", id);
                }
            } else {
                unsigned i;

                id = s->rsx_head_queued[head];
                for (i = 0; i < s->rsx_db_count; i++) {
                    if (s->rsx_db_offset[i] == a3) {
                        id = i;
                        break;
                    }
                }
                if (i == s->rsx_db_count) {
                    info_report("ps3-rsx: flip: no display buffer at 0x%X, "
                                "flipping %u", (uint32_t)a3, id);
                }
            }
            if (s->ppu_trace) {
                info_report("ps3-rsx: flip head %u buffer 0x%X -> %u",
                            head, (uint32_t)a3, id);
            }
            ps3_rsx_flip(s, head, id);
            break;
        }

        case 0x103:             /* display queue: head, buffer */
            if (a2 > 1 || a3 > 31) {
                *ret = PS3_LV2_EINVAL;
                return true;
            }
            s->rsx_head_queued[a2] = a3;
            s->rsx_head_flags[a2] |= 0x40000000u | (1u << a3);
            h = drv + PS3_RSX_DI_HEAD + a2 * PS3_RSX_DI_HEAD_STRIDE;
            ps3_put_be32(ram + h + PS3_RSX_HEAD_QUEUED, a3);
            ps3_put_be32(ram + h + PS3_RSX_HEAD_FLAGS,
                         ps3_be32(ram + h + PS3_RSX_HEAD_FLAGS) |
                         0x40000000u | (1u << a3));
            ps3_rsx_event(s, ram, ram_size, 0,
                          PS3_RSX_EVENT_QUEUE_BASE << a2, 0);
            break;

        case 0x104: {           /* display buffer: id, h<<32|w, p<<32|off */
            unsigned id = a2 & 0xFFu;

            if (id > 7) {
                *ret = PS3_RSX_LV1_ILLEGAL_PARAM;
                return true;
            }
            s->rsx_db_w[id] = (a3 >> 32) & 0xFFFFFFFFu;
            s->rsx_db_h[id] = a3 & 0xFFFFFFFFu;
            s->rsx_db_pitch[id] = (a4 >> 32) & 0xFFFFFFFFu;
            s->rsx_db_offset[id] = a4 & 0xFFFFFFFFu;
            if (id + 1 > s->rsx_db_count) {
                s->rsx_db_count = id + 1;
            }
            info_report("ps3-rsx: display buffer %u: %ux%u, pitch 0x%X, "
                        "offset 0x%X", id, s->rsx_db_w[id], s->rsx_db_h[id],
                        s->rsx_db_pitch[id], s->rsx_db_offset[id]);
            break;
        }

        case 0x105:             /* destroy buffer */
        case 0x106:             /* cellGcmInitPerfMon */
            break;

        case 0x108:             /* vblank frequency */
            if (a4 == 1) {
                s->rsx_vsync = true;
            } else if (a4 == 2) {
                s->rsx_second_vhandler = (a3 != 4);
            }
            break;

        case 0x2:               /* FIFO control: (put, ref) of a new run */
            s->rsx_put = a2;
            break;

        case 0x40B:             /* host memory: a size query */
            *ret = 0;
            return true;

        case 0x10A:             /* flip status: (flags & a3) | a4 */
            if (a2 > 7) {
                *ret = PS3_RSX_LV1_ILLEGAL_PARAM;
                return true;
            }
            if (a2 > 1) {
                *ret = PS3_LV2_EINVAL;
                return true;
            }
            s->rsx_head_flags[a2] =
                (s->rsx_head_flags[a2] & a3) | a4;
            h = drv + PS3_RSX_DI_HEAD + a2 * PS3_RSX_DI_HEAD_STRIDE;
            ps3_put_be32(ram + h + PS3_RSX_HEAD_FLAGS, s->rsx_head_flags[a2]);
            break;

        case 0x10B:             /* cursor position or image */
        case 0x10C:             /* cursor enable/disable */
        case 0x10D:             /* cursor init */
            break;

        case 0x300: {           /* tiles */
            uint32_t id = a2;
            uint32_t location, offset, size, pitch, comp, base_;
            uint64_t lo = a3, hi = a4;
            bool bound = ((uint32_t)(lo >> 32) & 0x3) != 0;

            if (id >= PS3_RSX_TILES) {
                *ret = PS3_RSX_LV1_ILLEGAL_PARAM;
                return true;
            }

            location = ((uint32_t)(lo >> 32) & 0x3) - 1;
            offset = (((uint32_t)((lo >> 32) & 0x7FFFFFFF)) >> 16) * 0x10000;
            size = ((((uint32_t)(lo & 0x7FFFFFFF) >> 16) + 1) * 0x10000) -
                   offset;
            pitch = ((uint32_t)(hi >> 32) >> 8) * 0x100;
            comp = ((uint32_t)hi >> 26) & 0xF;
            base_ = (uint32_t)hi & 0x7FF;

            if (bound) {
                uint32_t limit;

                if (!size || !pitch || offset + size < offset) {
                    *ret = PS3_LV2_EINVAL;
                    return true;
                }
                if (location == 0) {
                    limit = PS3_RSX_MAIN_SIZE;
                } else if (location == 1) {
                    limit = s->rsx_local_size;
                } else {
                    *ret = PS3_LV2_EINVAL;
                    return true;
                }
                if (offset + size > limit) {
                    *ret = PS3_LV2_EINVAL;
                    return true;
                }
                if (!(hi & (1u << 30))) {
                    /* GCM hardcodes this bit; a clear without it is a bug. */
                    *ret = PS3_LV2_EINVAL;
                    return true;
                }
                if (location == 0) {
                    uint32_t page;

                    for (page = offset >> 20;
                         page <= (offset + size - 1) >> 20; page++) {
                        if (page >= PS3_RSX_IO_PAGES ||
                            !s->rsx_iomap_used[page]) {
                            *ret = PS3_LV2_EINVAL;
                            return true;
                        }
                    }
                }
            }

            s->rsx_tiles[id].bound = bound;
            s->rsx_tiles[id].location = location;
            s->rsx_tiles[id].offset = offset;
            s->rsx_tiles[id].size = size;
            s->rsx_tiles[id].pitch = pitch;
            s->rsx_tiles[id].comp = comp;
            s->rsx_tiles[id].base = base_;
            break;
        }

        case 0x301: {           /* depth buffer (zcull) */
            uint32_t id = a2;
            uint32_t width, height, cull_start, offset;
            bool bound = a5 != 0;

            if (id >= PS3_RSX_ZCULLS) {
                *ret = PS3_RSX_LV1_ILLEGAL_PARAM;
                return true;
            }

            width = ((a3 & 0xFFFFFFFFu) >> 22) << 6;
            height = ((a3 & 0xFFFFu) >> 6) << 6;
            cull_start = (uint32_t)(a4 >> 32) & ~0xFFFu;
            offset = (uint32_t)a4 & 0x0FFFFFFFu;

            if (bound) {
                if (!width || !height ||
                    (uint64_t)cull_start + (uint64_t)width * height > 3u << 20 ||
                    offset >= s->rsx_local_size) {
                    *ret = PS3_LV2_EINVAL;
                    return true;
                }
                if (!(a3 & (1ull << 32)) ||
                    (a5 & 0xFFFFFFFFu) != ((0x2000u << 0) | (0x20u << 16))) {
                    *ret = PS3_LV2_EINVAL;
                    return true;
                }
            }

            s->rsx_zculls[id].bound = bound;
            s->rsx_zculls[id].width = width;
            s->rsx_zculls[id].height = height;
            s->rsx_zculls[id].cull_start = cull_start;
            s->rsx_zculls[id].offset = offset;
            s->rsx_zculls[id].z_format = ((uint32_t)(a3 >> 32) >> 4) & 0xF;
            s->rsx_zculls[id].aa_format = ((uint32_t)(a3 >> 32) >> 8) & 0xF;
            s->rsx_zculls[id].dir = ((uint32_t)(a5 >> 32) >> 1) & 1;
            s->rsx_zculls[id].format = ((uint32_t)(a5 >> 32) >> 2) & 0x3FF;
            s->rsx_zculls[id].func = ((uint32_t)(a5 >> 32) >> 12) & 0xF;
            s->rsx_zculls[id].ref = ((uint32_t)(a5 >> 32) >> 16) & 0xFF;
            s->rsx_zculls[id].mask = ((uint32_t)(a5 >> 32) >> 24) & 0xFF;
            break;
        }

        case 0x302:             /* zcull state */
        case 0x600:             /* framebuffer setup */
        case 0x601:             /* framebuffer blit */
        case 0x602:             /* framebuffer blit sync */
        case 0x603:             /* framebuffer close */
            break;

        case 0xFEC:             /* flip event notification */
            h = drv + PS3_RSX_DI_HEAD + PS3_RSX_DI_HEAD_STRIDE;  /* head 1 */
            s->rsx_head_flags[1] |= 0x80000000u;
            ps3_put_be32(ram + h + PS3_RSX_HEAD_FLAGS, s->rsx_head_flags[1]);
            ps3_put_be64(ram + h + PS3_RSX_HEAD_FLIPTIME, ps3_rsx_timebase());
            ps3_put_be32(ram + h + PS3_RSX_HEAD_FLIPID, a2);
            /* cellGcmWaitLabel watches this semaphore: every flip clears it. */
            memset(ram + s->rsx_reports + 0x10, 0, 16);
            ps3_rsx_event(s, ram, ram_size, 0,
                          PS3_RSX_EVENT_FLIP_BASE << 1, 0);
            break;

        case 0xFED:             /* vblank: raised by the display, not by a PPU */
            *ret = PS3_LV2_EINVAL;
            return true;

        case 0xFEF:             /* user command */
            ps3_put_be32(ram + drv + PS3_RSX_DI_USERCMD, a3);
            ps3_rsx_event(s, ram, ram_size, 0, PS3_RSX_EVENT_USER_CMD, 0);
            break;

        default:
            info_report("ps3-rsx: attribute package 0x%X (0x%X, 0x%X, "
                        "0x%X, 0x%X) is not modelled", (uint32_t)a1,
                        (uint32_t)a2, (uint32_t)a3, (uint32_t)a4,
                        (uint32_t)a5);
            *ret = PS3_LV2_EINVAL;
            return true;
        }
        *ret = 0;
        return true;
    }

    case 0x2A3: {               /* device_map(dev_addr*, unused*, dev_id) */
        uint32_t base;

        if ((uint64_t)a0 + 8 > ram_size) {
            *ret = PS3_LV2_EFAULT;
            return true;
        }
        if (a2 != 8) {
            /* lv1 only hands out the RSX's own window for dev 8. */
            *ret = PS3_LV2_EINVAL;
            return true;
        }
        if (!s->rsx_device) {
            base = (s->lv2_heap + 0xFFFFFu) & ~0xFFFFFu;
            if ((uint64_t)base + 0x100000 > ram_size) {
                *ret = PS3_LV2_ENOMEM;
                return true;
            }
            s->lv2_heap = base + 0x100000;
            ps3_put_be32(ram + PS3_LV2_HEAP, s->lv2_heap);
            s->rsx_device = base;
            info_report("ps3-rsx: device window 0x%X", base);
        }
        ps3_put_be64(ram + a0, s->rsx_device);
        *ret = 0;
        return true;
    }

    case 0x2A4:                 /* device_unmap(dev_id) */
        *ret = 0;
        return true;

    case 0x2A5:                 /* attribute(package, a2..a5) */
        *ret = 0;
        return true;

    default:
        return false;
    }
}

/* ---- the SPE interface: lv2's sys_spu --------------------------------- */

static PS3SPUImage *ps3_spu_lv2_image(PS3BootROMState *s, uint32_t id)
{
    unsigned i;

    for (i = 0; i < PS3_SPU_IMAGES; i++) {
        if (s->spuimg[i].used && s->spuimg[i].id == id) {
            return &s->spuimg[i];
        }
    }

    return NULL;
}

static PS3SPULv2Group *ps3_spu_lv2_group(PS3BootROMState *s, uint32_t id)
{
    unsigned i;

    for (i = 0; i < PS3_SPU_LV2_GROUPS; i++) {
        if (s->spug[i].used && s->spug[i].id == id) {
            return &s->spug[i];
        }
    }

    return NULL;
}

static PS3SPU *ps3_spu_lv2_thread(PS3BootROMState *s, uint32_t id,
                                  PS3SPULv2Group **out)
{
    PS3SPULv2Group *g = ps3_spu_lv2_group(s, id & ~0xFFu);
    unsigned n = id & 0xFFu;

    if (!g || n >= g->count || !g->thread[n]) {
        return NULL;
    }
    if (out) {
        *out = g;
    }

    return ps3_spes_spu(g->spes, n);
}

/*
 * Parse an SPU ELF's program headers into the shape sys_spu_thread_initialize
 * deploys: a COPY of p_filesz bytes from the image, then a FILL for the rest of
 * p_memsz.  `src' is the effective address the ELF itself sits at, because a
 * copy segment names its bytes in guest memory, not a host pointer.
 */
static int ps3_spu_lv2_parse(PS3SPUImage *img, const uint8_t *elf, size_t len,
                             uint32_t src)
{
    uint32_t phoff, phentsize, phnum, entry, n = 0, i;

    if (len < 0x34 || memcmp(elf, "\x7f" "ELF", 4) ||
        elf[4] != 1 || elf[5] != 2 || elf[6] != 1) {
        return -1;              /* not a 32-bit big-endian ELF */
    }

    entry = ps3_be32(elf + 0x18) & (PS3_LS_SIZE - 1);
    phoff = ps3_be32(elf + 0x1C);
    phentsize = ((uint32_t)elf[0x2A] << 8) | elf[0x2B];
    phnum = ((uint32_t)elf[0x2C] << 8) | elf[0x2D];

    if (phentsize < 0x20 || phnum == 0 || phnum > 0x20 ||
        (uint64_t)phoff + (uint64_t)phnum * phentsize > len) {
        return -1;
    }

    for (i = 0; i < phnum; i++) {
        const uint8_t *ph = elf + phoff + i * phentsize;
        uint32_t type = ps3_be32(ph);
        uint32_t offset = ps3_be32(ph + 0x04);
        uint32_t vaddr = ps3_be32(ph + 0x08);
        uint32_t filesz = ps3_be32(ph + 0x10);
        uint32_t memsz = ps3_be32(ph + 0x14);

        if (type == 4) {                /* SYS_SPU_SEGMENT_TYPE_INFO */
            if (n < 0x20) {
                img->seg[n].type = 4;
                img->seg[n].ls = vaddr & (PS3_LS_SIZE - 1);
                img->seg[n].size = memsz;
                img->seg[n].addr = 0;
                n++;
            }
            continue;
        }
        if (type != 1 || !filesz) {     /* PT_LOAD */
            continue;
        }
        if ((uint64_t)offset + filesz > len || n >= 0x20) {
            return -1;
        }

        img->seg[n].type = 1;
        img->seg[n].ls = vaddr & (PS3_LS_SIZE - 1);
        img->seg[n].size = filesz;
        img->seg[n].addr = src + offset;
        n++;

        if (memsz > filesz && n < 0x20) {
            img->seg[n].type = 2;
            img->seg[n].ls = (vaddr + filesz) & (PS3_LS_SIZE - 1);
            img->seg[n].size = memsz - filesz;
            img->seg[n].addr = 0;
            n++;
        }
    }

    if (!n) {
        return -1;
    }

    img->entry = entry;
    img->nsegs = n;
    return 0;
}

static PS3SPUImage *ps3_spu_lv2_image_new(PS3BootROMState *s,
                                          const uint8_t *elf, size_t len,
                                          uint32_t src)
{
    unsigned i;

    for (i = 0; i < PS3_SPU_IMAGES; i++) {
        PS3SPUImage *img = &s->spuimg[i];

        if (img->used) {
            continue;
        }
        memset(img, 0, sizeof(*img));
        if (ps3_spu_lv2_parse(img, elf, len, src) != 0) {
            return NULL;
        }
        img->used = true;
        img->id = s->spu_next_id++;
        if (!img->id) {
            img->id = s->spu_next_id++;
        }
        return img;
    }

    return NULL;
}

/*
 * A kernel image is an id in the guest's sys_spu_image: the segments stay in
 * the model, exactly as lv2 keeps them in its own id table, so a title's
 * `segs' field is unused and `nsegs' reads back 0.
 */
static void ps3_spu_lv2_publish(uint8_t *ram, uint64_t ram_size, uint32_t ea,
                                const PS3SPUImage *img)
{
    if (!ea || (uint64_t)ea + 0x10 > ram_size) {
        return;
    }

    ps3_put_be32(ram + ea, 1);          /* SYS_SPU_IMAGE_TYPE_KERNEL */
    ps3_put_be32(ram + ea + 0x04, img->id);
    ps3_put_be32(ram + ea + 0x08, 0);
    ps3_put_be32(ram + ea + 0x0C, 0);
}

static bool ps3_spu_lv2_deploy(PS3SPU *spu, const PS3SPUImage *img,
                               uint8_t *ram, uint64_t ram_size)
{
    unsigned i;

    for (i = 0; i < img->nsegs; i++) {
        const PS3SPUImageSeg *seg = &img->seg[i];

        if (seg->type == 1) {
            if (!seg->addr || (uint64_t)seg->addr + seg->size > ram_size) {
                return false;
            }
            ps3_spu_load_ls(spu, seg->ls, ram + seg->addr, seg->size);
        } else if (seg->type == 2) {
            ps3_spu_fill_ls(spu, seg->ls, seg->size, seg->addr);
        }
    }

    ps3_spe_set_pc(spu, img->entry);
    return true;
}

static PS3SPULv2Group *ps3_spu_lv2_group_new(PS3BootROMState *s, uint8_t *ram,
                                             uint64_t ram_size, unsigned count,
                                             uint32_t *out_id)
{
    unsigned i;

    if (!count || count > PS3_SPE_MAX) {
        return NULL;
    }

    for (i = 0; i < PS3_SPU_LV2_GROUPS; i++) {
        PS3SPULv2Group *g = &s->spug[i];

        if (g->used) {
            continue;
        }

        memset(g, 0, sizeof(*g));
        g->ls = g_malloc0((size_t)count * PS3_LS_SIZE);
        g->spes = ps3_spes_new(count, g->ls, (size_t)count * PS3_LS_SIZE,
                               NULL, 0, PS3_SPES_LS_BASE);
        if (!g->spes) {
            g_free(g->ls);
            memset(g, 0, sizeof(*g));
            return NULL;
        }
        /* The SPEs DMA into guest RAM itself, not into a private copy. */
        ps3_spes_map_ext(g->spes, ram, ram_size);
        /* A distinct range from the PPU thread ids the model hands out. */
        g->id = 0x0A000000u + i * 0x100u;
        g->count = count;
        g->used = true;
        *out_id = g->id;
        return g;
    }

    return NULL;
}

static void ps3_spu_lv2_group_free(PS3SPULv2Group *g)
{
    if (!g || !g->used) {
        return;
    }

    ps3_spes_free(g->spes);
    g_free(g->ls);
    memset(g, 0, sizeof(*g));
}

/*
 * Run whatever SPEs are ready.  A group is only stepped when it has been
 * started, and the loop stops as soon as every SPE is halted or blocked on a
 * channel - there are no periodic ticks and no host threads, so a title's
 * `group_start' so consistently completes the SPE's work before the next call
 * looks at the result.
 */
static void ps3_spu_lv2_pump(PS3BootROMState *s, uint64_t budget)
{
    unsigned gi;

    for (gi = 0; gi < PS3_SPU_LV2_GROUPS; gi++) {
        PS3SPULv2Group *g = &s->spug[gi];
        uint64_t left = budget;
        char why[160];

        if (!g->used || !g->started || g->terminated) {
            continue;
        }

        while (left) {
            uint64_t slice = MIN(left, 1u << 14);
            uint64_t ran = 0;
            int st = ps3_spes_run_quantum(g->spes, slice, &ran, why, sizeof(why));

            left -= MIN(left, ran ? ran : slice);
            if (st == PS3_SPU_STOPPED) {
                g->exit_cause = 1;          /* group exit */
                g->started = false;
                info_report("ps3-ppu: spu group 0x%X: %s", g->id, why);
                if (s->ppu_trace) {
                    unsigned n;

                    for (n = 0; n < g->count; n++) {
                        PS3SPU *spu = ps3_spes_spu(g->spes, n);

                        if (!g->thread[n]) {
                            continue;
                        }
                        info_report("ps3-ppu: spu 0x%X: pc 0x%X, stop 0x%X, "
                                    "ls 0x%X 0x%X 0x%X 0x%X", g->id | n,
                                    ps3_spu_pc(spu), ps3_spu_stop_code(spu),
                                    ps3_spu_ls_read32(spu, 0x100),
                                    ps3_spu_ls_read32(spu, 0x104),
                                    ps3_spu_ls_read32(spu, 0x108),
                                    ps3_spu_ls_read32(spu, 0x10C));
                    }
                }
                break;
            }
            if (st == PS3_SPU_FAULT) {
                g->exit_cause = 2;          /* exception */
                g->started = false;
                info_report("ps3-ppu: spu group 0x%X faulted: %s", g->id, why);
                break;
            }
            if (st == PS3_SPU_BLOCKED) {
                break;                      /* waiting on a mailbox or event */
            }
        }
    }
}

/*
 * The AV channel: sys_uart is the VSH's link to the console's AV device.
 *
 * libavst owns the port.  Its receiver thread blocks in sys_uart_receive and
 * hands every packet it reads to the AV service thread, which talks to the
 * device: it sends AV_INIT, asks for the monitor information (the EDID-derived
 * mode table), sets the HDMI behaviour, sends the video and audio set-up as
 * one AVB_PARAM packet, and waits for the plugged and HDCP events.  A port
 * with nothing on the other end never completes any of that: the receiver
 * stays blocked, the service thread never gets its event, and vsh.self's main
 * thread - which joins the service - never reaches cellGcmInit.
 *
 * The device below is the one RPCS3 presents: the same packet layout, a reply
 * for each command (version, length, cid|reply bit, status), the same monitor
 * information, and the plug and HDCP events.  The modes it reports are the
 * ones the machine's display offers (ps3-vga, an HDMI sink with 720p/1080p).
 */
#define PS3_AV_WAIT              (-4)   /* wait_eq: a receive on the port */
#define PS3_AV_STATUS_SUCCESS    0x00
#define PS3_AV_STATUS_FAILURE    0x0B
#define PS3_AV_STATUS_INVALID_CMD 0x03
#define PS3_AV_STATUS_BAD_PORT   0x04
#define PS3_AV_STATUS_BAD_VIDEO  0x0E
#define PS3_AV_STATUS_NO_SEL     0x0F
#define PS3_AV_STATUS_BAD_AUDIO  0x11

static void ps3_av_reply(PS3BootROMState *s, uint32_t cid, uint32_t status,
                         const void *data, unsigned size)
{
    unsigned at = s->av_rx_len;
    unsigned total = 12 + size;

    if (at + total > PS3_AV_RX_SIZE) {
        return;                 /* the device's reply buffer is full */
    }

    ps3_put_be16(s->av_rx + at, PS3_AV_VERSION);
    ps3_put_be16(s->av_rx + at + 2, (uint16_t)(size + 8));
    ps3_put_be32(s->av_rx + at + 4, cid | PS3_AV_REPLY_BIT);
    ps3_put_be32(s->av_rx + at + 8, status);
    if (size) {
        memcpy(s->av_rx + at + 12, data, size);
    }
    s->av_rx_len += total;

    if (s->ppu_trace) {
        info_report("ps3-av: reply cid 0x%08X status 0x%02X (%u byte(s))",
                    cid, status, size);
    }
}

/* An event the device raises on its own: the reply bit stays clear. */
static void ps3_av_event(PS3BootROMState *s, uint32_t cid, const void *data,
                         unsigned size)
{
    unsigned at = s->av_rx_len;
    unsigned total = 8 + size;

    if (at + total > PS3_AV_RX_SIZE) {
        return;
    }

    ps3_put_be16(s->av_rx + at, s->av_version ? s->av_version
                                              : PS3_AV_VERSION);
    ps3_put_be16(s->av_rx + at + 2, (uint16_t)(size + 4));
    ps3_put_be32(s->av_rx + at + 4, cid);
    if (size) {
        memcpy(s->av_rx + at + 8, data, size);
    }
    s->av_rx_len += total;

    if (s->ppu_trace) {
        info_report("ps3-av: event 0x%08X (%u byte(s))", cid, size);
    }
}

/*
 * The monitor information: the modes and the audio formats the sink supports.
 * The native mode is the one the display is showing, so the VSH picks the
 * resolution the window is already in instead of asking for another one.
 */
static unsigned ps3_av_monitor_info(uint8_t *out, uint16_t avport)
{
    static const uint8_t mon_id[10] = {
        0x4A, 0x13, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15,
    };
    static const uint8_t audio[7][4] = {
        { 1, 8, 0x7F, 0x07 },   /* LPCM */
        { 2, 8, 0x7F, 0xFF },   /* AC-3 */
        { 6, 8, 0x7F, 0xFF },   /* AAC */
        { 7, 8, 0x7F, 0xFF },   /* DTS */
        { 10, 8, 0x7F, 0xFF },  /* Dolby Digital Plus */
        { 11, 8, 0x7F, 0xFF },  /* DTS-HD */
        { 12, 8, 0x7F, 0xFF },  /* Dolby TrueHD */
    };
    uint32_t w = 0, h = 0, native;
    unsigned i;

    memset(out, 0, 208);
    out[0] = avport;

    ps3_vga_mode(&w, &h);
    if (h >= 1080) {
        native = 0x4000;                /* 1920x1080p */
    } else if (h >= 720) {
        native = 0x0004;                /* 1280x720p */
    } else {
        native = 0x0003;                /* 720x480p / 720x576p */
    }

    if (avport == 0x10) {               /* AVMULTI_0, the analogue head */
        out[0x0B] = 3;                  /* PS3AV_MONITOR_TYPE_AVMULTI */
        for (i = 0; i < 3; i++) {
            ps3_put_be32(out + 0x1C + 8 * i, 0xFFFFFFFFu);
        }
        out[0x3C] = 1;
        out[0x3D] = 1;
        out[0x3E] = 1;
        out[0x55] = 1;                  /* one speaker */
        ps3_put_be16(out + 0x56, 1);
        out[0x58] = 1;                  /* LPCM */
        out[0x59] = 2;                  /* two channels */
        out[0x5A] = 127;                /* every sample rate */
        out[0x5B] = 7;                  /* up to 24-bit */
        return 208;
    }

    memcpy(out + 0x01, mon_id, sizeof(mon_id));
    out[0x0B] = 1;                      /* PS3AV_MONITOR_TYPE_HDMI */
    memcpy(out + 0x0C, "PlayStation 3", 13);

    ps3_put_be32(out + 0x1C, 0xFFFFFFFFu);  /* every 60 Hz mode */
    ps3_put_be32(out + 0x20, native);
    ps3_put_be32(out + 0x24, 0xFFFFFFFFu);  /* every 50 Hz mode */
    ps3_put_be32(out + 0x28, native);
    ps3_put_be32(out + 0x2C, 0xFFFFFFFFu);  /* other modes */
    ps3_put_be32(out + 0x30, native);
    ps3_put_be32(out + 0x34, 1);           /* VESA: one mode at a time */

    out[0x3C] = 0x19;   /* RGB, selectable range, 12-bit */
    out[0x3D] = 0x11;   /* YCbCr 4:4:4, 12-bit */
    out[0x3E] = 0x01;   /* YCbCr 4:2:2 */
    out[0x3F] = 0x73;   /* xvYCC 601/709, MD0..MD2 */

    ps3_put_be16(out + 0x40, 1023);     /* red */
    ps3_put_be16(out + 0x42, 0);
    ps3_put_be16(out + 0x44, 0);        /* green */
    ps3_put_be16(out + 0x46, 1023);
    ps3_put_be16(out + 0x4C, 341);      /* white, D65 */
    ps3_put_be16(out + 0x4E, 341);
    ps3_put_be32(out + 0x50, 100);      /* gamma */

    out[0x54] = 1;                      /* supported AI */
    out[0x55] = 0x4F;                   /* speaker mask */
    ps3_put_be16(out + 0x56, 7);
    memcpy(out + 0x58, audio, sizeof(audio));

    ps3_put_be16(out + 0x98, 60);       /* a 27-inch 16:9 panel */
    ps3_put_be16(out + 0x9A, 34);
    out[0x9C] = 0x0F;                   /* graphics, cinema, photo, game */

    for (i = 0; i < 5; i++) {
        ps3_put_be32(out + 0xA0 + 8 * i, 0xFFFFFFFFu);  /* the 3D modes */
    }

    return 208;
}

/* The sink came up: say so, if the guest asked to be told. */
static void ps3_av_hdmi_events(PS3BootROMState *s)
{
    uint8_t info[208];

    if (s->av_event_bits & 0x01) {          /* UNPLUGGED */
        ps3_av_event(s, 0x10000001, NULL, 0);
    }
    if (s->av_event_bits & 0x02) {          /* PLUGGED, with its modes */
        ps3_av_monitor_info(info, 0);
        ps3_av_event(s, 0x10000002, info, 204);
    }
}

static void ps3_av_hdcp_event(PS3BootROMState *s)
{
    uint8_t pkt[8];

    if (!(s->av_event_bits & 0x04) || s->av_hdcp_done) {
        return;
    }
    s->av_hdcp_done = true;
    ps3_put_be32(pkt, 1);                   /* one key */
    pkt[4] = 0xFF;                          /* the sink's BKSV */
    pkt[5] = 0xFF;
    pkt[6] = 0xF0;
    pkt[7] = 0x00;
    ps3_av_event(s, 0x10000003, pkt, sizeof(pkt));
}

/*
 * AVB_PARAM: the video and audio set-up in one packet.  Its sub-packets are
 * the ones the standalone commands carry; the video mode is where the console
 * hands the display its resolution, and an AV video packet is where a real
 * link finishes authenticating.
 */
static void ps3_av_avb_param(PS3BootROMState *s, const uint8_t *pkt,
                             unsigned size)
{
    unsigned video = ps3_be16(pkt + 8);
    unsigned audio = ps3_be16(pkt + 10);
    unsigned av_video = ps3_be16(pkt + 12);
    unsigned av_audio = ps3_be16(pkt + 14);
    const uint8_t *at = pkt + 16;
    const uint8_t *end = pkt + size;
    uint32_t status = PS3_AV_STATUS_SUCCESS;
    bool hdcp = false;
    unsigned i;

    if (video > 2 || av_video > 4 || av_audio > 4) {
        ps3_av_reply(s, 0x04000001, PS3_AV_STATUS_INVALID_CMD, NULL, 0);
        return;
    }

    for (i = 0; i < video + audio + av_video + av_audio; i++) {
        unsigned sub;

        if (at + 8 > end) {
            status = PS3_AV_STATUS_INVALID_CMD;
            break;
        }
        sub = ps3_be16(at + 2) + 4;
        if (sub < 8 || at + sub > end) {
            status = PS3_AV_STATUS_INVALID_CMD;
            break;
        }

        if (i < video) {                    /* a video mode packet */
            if (ps3_be32(at + 4) == 0x01000002 && sub >= 48) {
                uint32_t head = ps3_be32(at + 8);
                uint32_t w = ps3_be32(at + 20);
                uint32_t h = ps3_be32(at + 24);

                if (head == 0 && w && h) {
                    ps3_vga_set_mode(w, h);
                }
            }
        } else if (i >= video + audio) {    /* an AV video (HDMI setup) */
            if (at[8] == 0 && at[9] <= 1) {
                hdcp = true;
            }
        }

        at += sub;
    }

    ps3_av_reply(s, 0x04000001, status, NULL, 0);
    if (status == PS3_AV_STATUS_SUCCESS && hdcp) {
        ps3_av_hdcp_event(s);
    }
}

/* One command packet.  Unknown ones are answered with nothing, as the device. */
static void ps3_av_command(PS3BootROMState *s, const uint8_t *pkt)
{
    uint32_t cid = ps3_be32(pkt + 4);
    uint8_t body[208];
    uint16_t port;
    unsigned i;

    memset(body, 0, sizeof(body));

    switch (cid) {
    case 0x00000001:                    /* AV_INIT */
        s->av_version = ps3_be16(pkt);
        s->av_event_bits |= ps3_be32(pkt + 8);
        if (s->av_event_bits & 0x80000000u) {
            ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, body, 4);
        } else {
            ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, NULL, 0);
        }
        break;
    case 0x00000002:                    /* AV_FIN */
        s->av_event_bits = 0;
        s->av_hdcp_done = false;
        ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, NULL, 0);
        break;
    case 0x00000003:                    /* AV_GET_HW_CONF */
        ps3_put_be16(body + 0, 1);      /* one HDMI head */
        ps3_put_be16(body + 2, 1);      /* one analogue head */
        ps3_put_be16(body + 4, 1);      /* one S/PDIF */
        ps3_put_be16(body + 6, 1);      /* bitstream audio */
        ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, body, 8);
        break;
    case 0x00000004:                    /* AV_GET_MONITOR_INFO */
        port = ps3_be16(pkt + 8);
        if (port == 0x10) {
            ps3_av_monitor_info(body, port);
            ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, body, 208);
        } else if (port <= 1) {
            /* The HDMI reply is four bytes short of the structure. */
            ps3_av_monitor_info(body, port);
            ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, body, 204);
        } else {
            ps3_av_reply(s, cid, PS3_AV_STATUS_BAD_PORT, NULL, 0);
        }
        break;
    case 0x00000005: {                  /* AV_GET_BKSV_LIST */
        port = ps3_be16(pkt + 8);
        if (port > 1) {
            ps3_av_reply(s, cid, PS3_AV_STATUS_BAD_PORT, NULL, 0);
            break;
        }
        ps3_put_be16(body + 0, port);
        ps3_put_be32(body + 4, 1);
        body[8] = 0xFF;
        body[9] = 0xFF;
        body[10] = 0xF0;
        body[11] = 0x00;
        body[12] = 0x00;
        ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, body, 16);
        break;
    }
    case 0x00000006:                    /* AV_ENABLE_EVENT */
        s->av_event_bits |= ps3_be32(pkt + 8);
        ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, NULL, 0);
        break;
    case 0x00000007:                    /* AV_DISABLE_EVENT */
        s->av_event_bits &= ~ps3_be32(pkt + 8);
        ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, NULL, 0);
        break;
    case 0x0000000A:                    /* AV_TV_MUTE */
    case 0x0000000B:                    /* AV_NULL_CMD */
        ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, NULL, 0);
        break;
    case 0x0000000C:                    /* AV_GET_AKSV */
        ps3_put_be32(body + 0, 5);
        body[4] = 0x00;
        body[5] = 0x00;
        body[6] = 0x0F;
        body[7] = 0xFF;
        body[8] = 0xFF;
        ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, body, 16);
        break;
    case 0x00010003:                    /* VIDEO_DISABLE_SIG */
    case 0x00010004:                    /* VIDEO_YTRAPCONTROL */
    case 0x00030001:                    /* ADD_SIGNAL_CTL */
    case 0x00030003:                    /* SET_CGMS_WSS */
        ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, NULL, 0);
        break;
    case 0x00020002:                    /* AUDIO_MUTE */
        port = pkt[8];
        if (!(port == 0 || port == 1 || port == 0x10 || port == 0x11 ||
              port == 0x20 || port == 0x21)) {
            ps3_av_reply(s, cid, PS3_AV_STATUS_BAD_PORT, NULL, 0);
        } else {
            ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, NULL, 0);
        }
        break;
    case 0x00020003:                    /* ACP_CTRL */
    case 0x00020004:                    /* SET_ACP_PACKET */
        if (pkt[8] > 1) {
            ps3_av_reply(s, cid, PS3_AV_STATUS_BAD_PORT, NULL, 0);
        } else {
            ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, NULL, 0);
        }
        break;
    case 0x00040001:                    /* HDMI mode */
        s->av_hdmi_mode = pkt[8];
        ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, NULL, 0);
        ps3_av_hdmi_events(s);
        break;
    case 0x000A0002:                    /* GET_CEC_CONFIG */
        ps3_put_be32(body, 1);
        ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, body, 4);
        break;
    case 0x000A0001:                    /* CEC message and the unknowns */
    case 0x000A0003:
    case 0x000A0004:
        ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, NULL, 0);
        break;
    case 0x01000001:                    /* VIDEO_INIT */
        ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, NULL, 0);
        break;
    case 0x01000002: {                  /* VIDEO_MODE */
        uint32_t head = ps3_be32(pkt + 8);
        uint32_t w = ps3_be32(pkt + 20);
        uint32_t h = ps3_be32(pkt + 24);

        if (head > 1 || !w || !h) {
            ps3_av_reply(s, cid, PS3_AV_STATUS_BAD_VIDEO, NULL, 0);
        } else {
            if (head == 0) {
                ps3_vga_set_mode(w, h);
            }
            ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, NULL, 0);
        }
        break;
    }
    case 0x01000003:                    /* VIDEO_ROUTE: only PS2 has a GX */
        ps3_av_reply(s, cid, PS3_AV_STATUS_NO_SEL, NULL, 0);
        break;
    case 0x01000004:                    /* VIDEO_FORMAT */
        if (ps3_be32(pkt + 8) > 1 || ps3_be16(pkt + 18) > 1 ||
            ps3_be32(pkt + 12) > 16) {
            ps3_av_reply(s, cid, PS3_AV_STATUS_BAD_VIDEO, NULL, 0);
        } else {
            ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, NULL, 0);
        }
        break;
    case 0x01000005:                    /* VIDEO_PITCH */
        if (ps3_be32(pkt + 8) > 1 || (ps3_be32(pkt + 12) & 7)) {
            ps3_av_reply(s, cid, PS3_AV_STATUS_BAD_VIDEO, NULL, 0);
        } else {
            ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, NULL, 0);
        }
        break;
    case 0x01000006:                    /* VIDEO_GET_HW_CONF */
        ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, body, 4);
        break;
    case 0x02000001:                    /* AUDIO_INIT */
    case 0x02000003:                    /* AUDIO_MUTE */
    case 0x02000004:                    /* AUDIO_ACTIVE */
    case 0x02000005:                    /* AUDIO_INACTIVE */
    case 0x02000006:                    /* AUDIO_SPDIF_BIT */
    case 0x02000007:                    /* AUDIO_CTRL */
        ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, NULL, 0);
        break;
    case 0x02000002:                    /* AUDIO_MODE */
        port = pkt[8];
        if (!(port == 0 || port == 1 || port == 0x10 || port == 0x11 ||
              port == 0x20 || port == 0x21) || ps3_be32(pkt + 20) > 7) {
            ps3_av_reply(s, cid, PS3_AV_STATUS_BAD_AUDIO, NULL, 0);
        } else {
            ps3_av_reply(s, cid, PS3_AV_STATUS_SUCCESS, NULL, 0);
        }
        break;
    case 0x04000001:                    /* AVB_PARAM */
        ps3_av_avb_param(s, pkt, ps3_be16(pkt + 2) + 4);
        break;
    default:
        if (s->ppu_trace) {
            info_report("ps3-av: command 0x%08X has no handler; the device "
                        "stays silent", cid);
        }
        break;
    }

    (void)i;
}

/* Take queued bytes out of the device and into the guest. */
static unsigned ps3_av_take(PS3BootROMState *s, uint8_t *ram,
                            uint64_t ram_size, uint32_t buf, uint32_t size)
{
    unsigned n = MIN(s->av_rx_len, size);

    if (!n) {
        return 0;
    }
    if (!buf || (uint64_t)buf + n > ram_size) {
        return 0;
    }
    memcpy(ram + buf, s->av_rx, n);
    memmove(s->av_rx, s->av_rx + n, s->av_rx_len - n);
    s->av_rx_len -= n;
    return n;
}

/* A receive with nothing to read waits on the port, not on a queue. */
static void ps3_av_park(PS3BootROMState *s, uint32_t buf, uint32_t size)
{
    PS3Thread *t;

    if (s->thr_cur < 0 || !s->thr[s->thr_cur].used) {
        return;
    }
    t = &s->thr[s->thr_cur];
    t->parked = true;
    t->blocked = true;
    t->wait_eq = PS3_AV_WAIT;
    t->wait_ea = 0;
    t->wait_ticks = -1;
    t->uart_buf = buf;
    t->uart_size = size;
    s->lv2_park = true;
    s->sched_pending = true;
}

/* Hand what the device just queued to the receiver waiting for it. */
static bool ps3_av_wake(PS3BootROMState *s, uint8_t *ram, uint64_t ram_size)
{
    unsigned i;

    for (i = 0; i < PS3_THREAD_MAX; i++) {
        PS3Thread *t = &s->thr[i];
        unsigned n;

        if (!t->used || !t->parked || t->wait_eq != PS3_AV_WAIT) {
            continue;
        }
        n = ps3_av_take(s, ram, ram_size, t->uart_buf, t->uart_size);
        if (!n) {
            return false;
        }
        if (s->ppu_trace) {
            info_report("ps3-av: %u byte(s) wake thread 0x%X", n, t->id);
        }
        ps3_thread_finish_call(s, t, ram, ram_size, n);
        return true;
    }
    return false;
}

/* Walk the packets the guest has sent, answering the ones it can. */
static void ps3_av_parse(PS3BootROMState *s)
{
    unsigned at = 0;

    while (s->av_tx_len - at >= 8) {
        const uint8_t *pkt = s->av_tx + at;
        unsigned size = ps3_be16(pkt + 2) + 4;

        if (ps3_be16(pkt + 2) == 0xFFFC) {
            ps3_av_reply(s, 0xDEAD, PS3_AV_STATUS_FAILURE, NULL, 0);
            at = s->av_tx_len;
            break;
        }
        if (size < 8 || size > PS3_AV_TX_SIZE) {
            at = s->av_tx_len;
            break;
        }
        if (s->av_tx_len - at < size) {
            break;              /* the rest of the packet is still coming */
        }
        if (ps3_be16(pkt) != PS3_AV_VERSION) {
            ps3_av_reply(s, ps3_be32(pkt + 4), PS3_AV_STATUS_INVALID_CMD,
                         NULL, 0);
            at = s->av_tx_len;
            break;
        }
        if (s->ppu_trace) {
            info_report("ps3-av: command 0x%08X, %u byte(s)",
                        ps3_be32(pkt + 4), size);
        }
        ps3_av_command(s, pkt);
        at += size;
    }

    if (at) {
        memmove(s->av_tx, s->av_tx + at, s->av_tx_len - at);
        s->av_tx_len -= at;
    }
}

static void ps3_lv2_service(PS3BootROMState *s)
{
    CPUState *cs = qemu_get_cpu(0);
    PowerPCCPU *cpu;
    uint8_t *ram;
    uint64_t ram_size;
    uint32_t nr, a0, a1, a2, a3, a4, a5;
    unsigned i;
    int32_t ret = PS3_LV2_ENOSYS;

    if (!cs) {
        return;
    }

    cpu = POWERPC_CPU(cs);
    ram = memory_region_get_ram_ptr(s->ram);
    ram_size = memory_region_size(s->ram);
    /*
     * A new `sc` has entered the trampoline: its frame is not folded up yet -
     * unless this is the call whose frame is already folded, published again
     * because the thread was preempted between the publishing store and the
     * instruction after it.  Folding a frame twice steps r1 past the caller's
     * own frame, and the caller's epilogue then reads a local as the saved LR
     * and returns into address 0 (the null-LR fault at the 0x700 vector).
     */
    if (s->thr_cur >= 0 && s->thr[s->thr_cur].used) {
        PS3Thread *t = &s->thr[s->thr_cur];

        if (t->call_folded_srr0 != (uint64_t)cpu->env.spr[SPR_SRR0]) {
            t->call_collected = false;
            t->call_folded_srr0 = 0;
        }
    }
    nr = cpu->env.gpr[11];
    /*
     * The last few calls, kept in memory rather than printed: when a thread
     * lands on a vector, the calls that led there are what names the fault,
     * and printing them as they happen changes the timing that produces it.
     */
    {
        PS3Call *c = &s->call_ring[s->call_ring_pos % PS3_CALL_RING];

        c->nr = nr;
        c->lr = cpu->env.lr;
        c->sp = cpu->env.gpr[1];
        c->srr0 = cpu->env.spr[SPR_SRR0];
        c->tid = s->thr_cur;
        s->call_ring_pos++;
    }
    a0 = cpu->env.gpr[3];
    a1 = cpu->env.gpr[4];
    a2 = cpu->env.gpr[5];
    a3 = cpu->env.gpr[6];
    a4 = cpu->env.gpr[7];
    a5 = cpu->env.gpr[8];

    /* A started SPE group runs alongside the PPU, a slice per lv2 call. */
    ps3_spu_lv2_pump(s, 1u << 12);

    /* The wired link: lv2's sys_net calls run on the host's sockets. */
    if (ps3_lv2_net(s, ram, ram_size, nr, a0, a1, a2, a3,
                    cpu->env.gpr[7], cpu->env.gpr[8], &ret)) {
        goto publish;
    }

    /* The drives: the BD drive and the disk behind lv2's sys_storage. */
    if (ps3_lv2_storage(s, &cpu->env, ram, ram_size, nr, &ret)) {
        goto publish;
    }

    /*
     * The RSX: device, local memory, context, FIFO and display.  Its arguments
     * are the full 64-bit registers, because the graphics library packs two
     * 32-bit values into several of them (a display buffer is w<<32|h).
     */
    if (ps3_lv2_rsx(s, ram, ram_size, nr, cpu->env.gpr[3], cpu->env.gpr[4],
                    cpu->env.gpr[5], cpu->env.gpr[6], cpu->env.gpr[7],
                    cpu->env.gpr[8], &ret)) {
        goto publish;
    }

    if (s->ppu_trace) {
        info_report("ps3-ppu: lv2 syscall 0x%X (lr=0x%" PRIX64
                    ", pc=0x%" PRIX64 ", thr=%d) a=0x%X,0x%X,0x%X,0x%X", nr,
                    (uint64_t)cpu->env.lr, (uint64_t)cpu->env.nip,
                    s->thr_cur, (uint32_t)a0, (uint32_t)a1, (uint32_t)a2,
                    (uint32_t)a3);
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
        if (s->warm_reset) {
            /*
             * A process that asks for a restart and then exits is the
             * recovery program's normal ending, and on a console the reset
             * line is already pulled: reset rather than leave the run.
             */
            qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
        } else {
            qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
        }
        return;
    case 0x019:                 /* sys_process_get_sdk_version(pid, u32*) */
        /*
         * The version of the SDK the running program was built with.  The
         * libraries that ask are deciding between interface revisions - the
         * audio device's port count and queue depth among them - so they are
         * answered with the firmware this model boots, 4.93, rather than a
         * failure the caller would have to invent a default for.
         */
        if ((uint64_t)a1 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        ps3_put_be32(ram + a1, PS3_LV2_SDK_VERSION);
        if (s->ppu_trace) {
            info_report("ps3-ppu: lv2: process sdk version 0x%X for pid %u "
                        "(lr=0x%" PRIX64 ")", PS3_LV2_SDK_VERSION, a0,
                        (uint64_t)cpu->env.lr);
        }
        ret = 0;
        break;
    case 0x01E:                 /* _sys_process_get_paramsfo(buf) */
        if ((uint64_t)a0 + 0x40 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        ps3_process_sfo_put(ram, ram_size, a0);
        ret = 0;
        break;
    /*
     * The event service, for real.  This is the handshake between the VSH's
     * main thread and its service workers: each worker owns a queue, blocks
     * in sys_event_queue_receive on it, and the main thread hands it work
     * through that queue's port.  Answering the receive with ENOSYS instead
     * put the workers in a permanent error spin and left the main thread
     * spinning on the mutex around the very list they were meant to fill.
     */
    case 0x080: {               /* sys_event_queue_create(id*, attr*, key,
                                 * size) */
        /* The key is 64 bits wide: sys_audio names its own queue "MIO22" +
         * 1, and half of that key is a name, not a handle. */
        uint64_t key = cpu->env.gpr[5];
        unsigned j;
        int idx = -1;

        if ((uint64_t)a0 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        /*
         * lv2 hands the key to one queue only, and the VSH's audio client
         * relies on that: it creates key + 1 and, when the answer is EEXIST,
         * moves on to key + 2 and key + 3.
         */
        if (ps3_eq_index_key(s, key) >= 0) {
            if (s->ppu_trace) {
                info_report("ps3-ppu: lv2: event queue create: key 0x%"
                            PRIX64 " is taken (lr=0x%" PRIX64 ")", key,
                            (uint64_t)cpu->env.lr);
            }
            ret = PS3_LV2_EEXIST;
            break;
        }
        for (j = 0; j < PS3_EQ_MAX; j++) {
            if (!s->eq[j].used) {
                idx = j;
                break;
            }
        }
        if (idx < 0) {
            ret = PS3_LV2_EAGAIN;
            break;
        }
        memset(&s->eq[idx], 0, sizeof(s->eq[idx]));
        s->eq[idx].used = true;
        s->eq[idx].id = ++s->lv2_next_id;
        s->eq[idx].key = key;
        s->eq[idx].size = a3;
        ps3_put_be32(ram + a0, s->eq[idx].id);
        if (s->ppu_trace) {
            info_report("ps3-ppu: lv2: event queue 0x%X created (key 0x%"
                        PRIX64 ", %u bytes)", s->eq[idx].id, key, a3);
        }
        ret = 0;
        break;
    }
    case 0x081: {               /* sys_event_queue_destroy(eq, mode) */
        int q = ps3_eq_index(s, a0);
        unsigned j;

        if (q < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        for (j = 0; j < PS3_THREAD_MAX; j++) {
            if (s->thr[j].used && s->thr[j].parked &&
                s->thr[j].wait_eq == q) {
                ps3_thread_finish_call(s, &s->thr[j], ram, ram_size,
                                       PS3_LV2_ESRCH);
            }
        }
        for (j = 0; j < PS3_EP_MAX; j++) {
            if (s->ep[j].used && s->ep[j].eq == q) {
                s->ep[j].eq = -1;
            }
        }
        memset(&s->eq[q], 0, sizeof(s->eq[q]));
        ret = 0;
        break;
    }
    case 0x082: {               /* sys_event_queue_receive(eq, event*,
                                 * timeout_us) */
        int q = ps3_eq_index(s, a0);
        PS3Event ev;

        if (q < 0) {
            if (s->ppu_trace) {
                info_report("ps3-ppu: lv2: event_queue_receive: no queue "
                            "0x%X (lr=0x%" PRIX64 ")", a0,
                            (uint64_t)cpu->env.lr);
            }
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (ps3_eq_pop(&s->eq[q], &ev)) {
            ps3_event_store(ram, ram_size, a1, &ev);
            cpu->env.gpr[4] = ev.source;
            cpu->env.gpr[5] = ev.data1;
            cpu->env.gpr[6] = ev.data2;
            cpu->env.gpr[7] = ev.data3;
            if (s->ppu_trace) {
                info_report("ps3-ppu: lv2: event_queue_receive 0x%X: source "
                            "0x%" PRIX64 ", d1 0x%" PRIX64 ", d2 0x%" PRIX64
                            ", d3 0x%" PRIX64, a0, ev.source, ev.data1,
                            ev.data2, ev.data3);
            }
            ret = 0;
            break;
        }
        if (s->ppu_trace) {
            info_report("ps3-ppu: lv2: event_queue_receive 0x%X: nothing "
                        "queued, parking thread 0x%X on index %d", a0,
                        s->thr[s->thr_cur].id, q);
        }
        ps3_eq_park(s, q, a1, a2);
        ret = 0;
        break;
    }
    case 0x083: {               /* sys_event_queue_tryreceive(eq, event*,
                                 * count, number*) */
        int q = ps3_eq_index(s, a0);
        PS3Event ev;
        uint32_t n = 0;

        if (q < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (ps3_eq_pop(&s->eq[q], &ev)) {
            ps3_event_store(ram, ram_size, a1, &ev);
            n = 1;
        }
        if (a3 && (uint64_t)a3 + 4 <= ram_size) {
            ps3_put_be32(ram + a3, n);
        }
        ret = 0;
        break;
    }
    case 0x085: {               /* sys_event_queue_drain(eq) */
        int q = ps3_eq_index(s, a0);

        if (q < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        s->eq[q].head = 0;
        s->eq[q].count = 0;
        ret = 0;
        break;
    }
    case 0x086: {               /* sys_event_port_create(id*, type, name) */
        unsigned j;
        int idx = -1;

        if ((uint64_t)a0 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        for (j = 0; j < PS3_EP_MAX; j++) {
            if (!s->ep[j].used) {
                idx = j;
                break;
            }
        }
        if (idx < 0) {
            ret = PS3_LV2_EAGAIN;
            break;
        }
        memset(&s->ep[idx], 0, sizeof(s->ep[idx]));
        s->ep[idx].used = true;
        s->ep[idx].id = ++s->lv2_next_id;
        s->ep[idx].type = a1;
        s->ep[idx].eq = -1;
        s->ep[idx].name = a2;
        ps3_put_be32(ram + a0, s->ep[idx].id);
        if (s->ppu_trace) {
            info_report("ps3-ppu: lv2: event port 0x%X created (type %u, "
                        "name 0x%X)", s->ep[idx].id, a1, a2);
        }
        ret = 0;
        break;
    }
    case 0x087: {               /* sys_event_port_destroy(port) */
        int p = ps3_ep_index(s, a0);

        if (p < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        memset(&s->ep[p], 0, sizeof(s->ep[p]));
        ret = 0;
        break;
    }
    case 0x088: {               /* sys_event_port_connect_local(port, eq) */
        int p = ps3_ep_index(s, a0);
        int q = ps3_eq_index(s, a1);

        if (p < 0 || q < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        /* lv2 checks the port's kind, as RPCS3's does: a local port can only
         * take a local queue and an IPC port only a key. */
        if (s->ep[p].type != 1) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        if (s->ep[p].eq >= 0) {
            ret = PS3_LV2_EISCONN;
            break;
        }
        s->ep[p].eq = q;
        if (s->ppu_trace) {
            info_report("ps3-ppu: lv2: event_port_connect_local: port 0x%X "
                        "-> queue 0x%X (index %d)", s->ep[p].id,
                        s->eq[q].id, q);
        }
        ret = 0;
        break;
    }
    case 0x08C: {               /* sys_event_port_connect_ipc(port, key) */
        int p = ps3_ep_index(s, a0);
        /* A key is 64 bits: the audio client's key spells "MIO22" and its
         * own queue's key is that plus one, not two different 32-bit keys. */
        uint64_t key = cpu->env.gpr[4];
        unsigned j;

        if (p < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (!key) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        if (s->ep[p].type != 3) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        if (s->ep[p].eq >= 0) {
            ret = PS3_LV2_EISCONN;
            break;
        }
        /*
         * A queue of that key is the sending end; otherwise the peer is in
         * another process, which this model does not have.  lv2 answers that
         * case with ESRCH rather than pretending the port is connected - a
         * caller that then sends gets ENOTCONN from a call it had no reason
         * to expect failure from, which is how the VSH's media eject tracker
         * reported its failure.
         */
        for (j = 0; j < PS3_EQ_MAX; j++) {
            if (s->eq[j].used && s->eq[j].key == key) {
                s->ep[p].eq = j;
                break;
            }
        }
        /*
         * The one key whose peer the model runs itself: MIO2, the service
         * the console's audio library talks to.  Opening it here is what the
         * client is waiting for - on a console it is there before anything
         * is loaded, but the model only needs it when it is asked for.
         */
        if (s->ep[p].eq < 0 && key == PS3_MIO2_KEY) {
            j = ps3_mio2_open(s);
            if ((int)j >= 0) {
                s->ep[p].eq = (int)j;
            }
        }
        if (s->ep[p].eq < 0) {
            /*
             * The peer is a process this model does not run (sysmgr and the
             * other system tasks own most of these keys).  Accepting the
             * connection is what a console with those processes running looks
             * like from here, and refusing it is worse than accepting: the
             * VSH's media eject tracker retries a refused connect forever.
             * The key is kept so a send can still find the queue if the guest
             * creates it later, and a send with no taker is discarded - the
             * same fate an event has when nobody reads its queue.
             */
            s->ep[p].key = key;
            if (s->ppu_trace) {
                info_report("ps3-ppu: lv2: event_port_connect_ipc: port 0x%X "
                            "key 0x%" PRIX64 ": no peer in the model, "
                            "sends are dropped", s->ep[p].id, key);
            }
        }
        /*
         * RPCS3's lv2 refuses the connection with ESRCH when no queue carries
         * that key, so a caller that gets 0 from here expects its send to be
         * delivered.  Say what was asked for and what answered, so a caller
         * that then takes an error path can be traced to this call.
         */
        if (s->ppu_trace) {
            info_report("ps3-ppu: lv2: event_port_connect_ipc: port 0x%X "
                        "key 0x%" PRIX64 " (%s)", s->ep[p].id, key,
                        s->ep[p].eq >= 0 ? "queue found" :
                        "no queue with that key");
        }
        ret = 0;
        break;
    }
    case 0x089: {               /* sys_event_port_disconnect(port) */
        int p = ps3_ep_index(s, a0);

        if (p < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        s->ep[p].eq = -1;
        s->ep[p].key = 0;
        ret = 0;
        break;
    }
    case 0x08A: {               /* sys_event_port_send(port, d1, d2, d3) */
        int p = ps3_ep_index(s, a0);
        PS3Event ev;
        int q;

        if (p < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        q = s->ep[p].eq;
        if (q < 0 && s->ep[p].key) {
            /* Late binding: the guest may have created the peer queue. */
            unsigned j;

            for (j = 0; j < PS3_EQ_MAX; j++) {
                if (s->eq[j].used && s->eq[j].key == s->ep[p].key) {
                    s->ep[p].eq = q = j;
                    break;
                }
            }
        }
        if (q < 0) {
            if (s->ep[p].key) {
                /* No peer, no taker: the event is accepted and discarded. */
                ret = 0;
                break;
            }
            if (s->ppu_trace) {
            info_report("ps3-ppu: lv2: event_port_send: port 0x%X "
                        "(name 0x%" PRIX64 ") is not connected, answering "
                        "ENOTCONN (lr=0x%" PRIX64 ")", s->ep[p].id,
                        s->ep[p].name, (uint64_t)cpu->env.lr);
            }
            ret = PS3_LV2_ENOTCONN;
            break;
        }
        /*
         * A service the model owns does not queue the request for a thread:
         * it answers it.  MIO2 is one, and the four event words are 64 bits
         * each, so the payload comes from the registers, not from the
         * 32-bit copies the rest of the table works with.
         */
        if (s->eq[q].model) {
            ps3_mio2_request(s, ram, ram_size, p, cpu->env.gpr[4],
                             cpu->env.gpr[5], cpu->env.gpr[6]);
            ret = 0;
            break;
        }
        ev.source = s->ep[p].name;
        ev.data1 = a1;
        ev.data2 = a2;
        ev.data3 = a3;
        ps3_eq_push(&s->eq[q], &ev);
        if (!ps3_eq_wake(s, ram, ram_size, q) && s->ppu_trace) {
            /*
             * The event stays queued for whoever waits next.  Name the queue
             * and the port, because a send that never finds a taker is how a
             * missing peer shows up in this model.
             */
            info_report("ps3-ppu: lv2: event queued on 0x%X (index %d, "
                        "port 0x%X, no taker yet)", s->eq[q].id, q,
                        s->ep[p].id);
        }
        ret = 0;
        break;
    }
    /*
     * Mutexes and conditions, with real blocking.  The VSH's thread pool is
     * built on them: its workers park in sys_cond_wait and the thread that
     * has work signals them.  Answering every wait with 0 turned the pool
     * into a spin - thousands of calls a second, and nothing ever ran.
     */
    case 0x064: {               /* sys_mutex_create(id*, attr*) */
        unsigned j;
        int m = -1;

        if ((uint64_t)a0 + 4 > ram_size) {
            if (s->ppu_trace) {
                info_report("ps3-ppu: lv2: mutex_create: out 0x%X is outside "
                            "RAM (lr=0x%" PRIX64 ")", a0,
                            (uint64_t)cpu->env.lr);
            }
            ret = PS3_LV2_EFAULT;
            break;
        }
        for (j = 0; j < PS3_MUTEX_MAX; j++) {
            if (!s->mtx[j].used) {
                m = j;
                break;
            }
        }
        if (m < 0) {
            ret = PS3_LV2_EAGAIN;
            break;
        }
        s->mtx[m].used = true;
        s->mtx[m].id = ++s->lv2_next_id;
        s->mtx[m].owner = 0;
        ps3_put_be32(ram + a0, s->mtx[m].id);
        ret = 0;
        break;
    }
    case 0x065: {               /* sys_mutex_destroy(id) */
        int m = ps3_mutex_index(s, a0);
        unsigned j;

        if (m < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        for (j = 0; j < PS3_THREAD_MAX; j++) {
            if (s->thr[j].used && s->thr[j].parked &&
                s->thr[j].wait_mutex_id == a0) {
                ps3_thread_finish_call(s, &s->thr[j], ram, ram_size,
                                       PS3_LV2_ESRCH);
            }
        }
        memset(&s->mtx[m], 0, sizeof(s->mtx[m]));
        ret = 0;
        break;
    }
    case 0x066:                 /* sys_mutex_lock(id, timeout) */
    case 0x067: {               /* sys_mutex_trylock(id) */
        int m = ps3_mutex_index(s, a0);
        uint32_t tid = s->thr_cur >= 0 ? s->thr[s->thr_cur].id : 1;

        if (m < 0) {
            if (s->ppu_trace) {
                info_report("ps3-ppu: lv2: mutex_lock: no mutex 0x%X "
                            "(lr=0x%" PRIX64 ")", a0,
                            (uint64_t)cpu->env.lr);
            }
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (!s->mtx[m].owner || s->mtx[m].owner == tid) {
            s->mtx[m].owner = tid;
            ret = 0;
            break;
        }
        if (nr == 0x067) {
            ret = PS3_LV2_EAGAIN;
            break;
        }
        if (s->thr_cur >= 0) {
            s->thr[s->thr_cur].wait_mutex_id = s->mtx[m].id;
            ps3_sync_park(s, a1);
        }
        ret = 0;
        break;
    }
    case 0x068: {               /* sys_mutex_unlock(id) */
        int m = ps3_mutex_index(s, a0);

        if (m < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        s->mtx[m].owner = 0;
        ps3_mutex_handoff(s, ram, ram_size, m);
        ret = 0;
        break;
    }
    case 0x069: {               /* sys_cond_create(id*, mutex_id, attr*) */
        unsigned j;
        int c = -1;

        if ((uint64_t)a0 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        for (j = 0; j < PS3_COND_MAX; j++) {
            if (!s->cond[j].used) {
                c = j;
                break;
            }
        }
        if (c < 0) {
            ret = PS3_LV2_EAGAIN;
            break;
        }
        s->cond[c].used = true;
        s->cond[c].id = ++s->lv2_next_id;
        s->cond[c].mutex = a1;
        ps3_put_be32(ram + a0, s->cond[c].id);
        ret = 0;
        break;
    }
    case 0x06A: {               /* sys_cond_destroy(id) */
        int c = ps3_cond_index(s, a0);

        if (c < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        ps3_cond_wake(s, ram, ram_size, c, true);
        memset(&s->cond[c], 0, sizeof(s->cond[c]));
        ret = 0;
        break;
    }
    case 0x06B: {               /* sys_cond_wait(cond, timeout) */
        /*
         * lv2 takes only the condition and the timeout here: the mutex is the
         * one the condition was created with, and lv2 releases and retakes it
         * around the wait.  Reading r4 as a mutex id made every wait in the
         * VSH fail with ESRCH - the call sites pass 0 there - and the workers
         * took their error path instead of parking.
         */
        int c = ps3_cond_index(s, a0);
        int m = c >= 0 ? ps3_mutex_index(s, s->cond[c].mutex) : -1;

        if (c < 0 || m < 0) {
            if (s->ppu_trace) {
                info_report("ps3-ppu: lv2: cond_wait: cond 0x%X %s, "
                            "mutex 0x%X %s (lr=0x%" PRIX64 ")",
                            a0, c < 0 ? "missing" : "ok", a1,
                            m < 0 ? "missing" : "ok",
                            (uint64_t)cpu->env.lr);
            }
            ret = PS3_LV2_ESRCH;
            break;
        }
        /* lv2 releases the mutex as part of the wait. */
        s->mtx[m].owner = 0;
        ps3_mutex_handoff(s, ram, ram_size, m);
        if (s->thr_cur >= 0) {
            s->thr[s->thr_cur].wait_cond_id = s->cond[c].id;
            s->thr[s->thr_cur].wait_mutex_id = s->cond[c].mutex;
            ps3_sync_park(s, a1);
        }
        ret = 0;
        break;
    }
    case 0x06C:                 /* sys_cond_signal(cond) */
    case 0x06D:                 /* sys_cond_signal_all(cond) */
    case 0x06E: {               /* sys_cond_signal_to(cond, thread) */
        int c = ps3_cond_index(s, a0);

        if (c < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        ps3_cond_wake(s, ram, ram_size, c, nr != 0x06C);
        ret = 0;
        break;
    }
    /*
     * Semaphores: the VSH's shutdown worker sleeps on one with a zero count,
     * so a wait that never blocks is a thread spinning for the whole run.
     */
    case 0x05A: {               /* sys_semaphore_create(id*, attr*,
                                 * count, max) */
        unsigned j;
        int m = -1;

        if ((uint64_t)a0 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        for (j = 0; j < PS3_SEM_MAX; j++) {
            if (!s->sem[j].used) {
                m = j;
                break;
            }
        }
        if (m < 0) {
            ret = PS3_LV2_EAGAIN;
            break;
        }
        s->sem[m].used = true;
        s->sem[m].id = ++s->lv2_next_id;
        s->sem[m].count = (int32_t)a2;
        s->sem[m].max = a3 ? (int32_t)a3 : 0x7FFFFFFF;
        ps3_put_be32(ram + a0, s->sem[m].id);
        ret = 0;
        break;
    }
    case 0x05B: {               /* sys_semaphore_destroy(id) */
        int m = ps3_sem_index(s, a0);
        unsigned j;

        if (m < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        for (j = 0; j < PS3_THREAD_MAX; j++) {
            if (s->thr[j].used && s->thr[j].parked &&
                s->thr[j].wait_sem_id == a0) {
                ps3_thread_finish_call(s, &s->thr[j], ram, ram_size,
                                       PS3_LV2_ESRCH);
            }
        }
        memset(&s->sem[m], 0, sizeof(s->sem[m]));
        ret = 0;
        break;
    }
    case 0x05C: {               /* sys_semaphore_wait(id, timeout) */
        int m = ps3_sem_index(s, a0);

        if (m < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (s->sem[m].count > 0) {
            s->sem[m].count--;
            ret = 0;
            break;
        }
        if (s->thr_cur >= 0) {
            s->thr[s->thr_cur].wait_sem_id = s->sem[m].id;
            ps3_sync_park(s, a1);
        }
        ret = 0;
        break;
    }
    case 0x05D: {               /* sys_semaphore_post(id, count) */
        int m = ps3_sem_index(s, a0);
        int32_t n = a1 ? (int32_t)a1 : 1;

        if (m < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        s->sem[m].count = MIN(s->sem[m].count + n, s->sem[m].max);
        while (s->sem[m].count > 0 && s->sem[m].id) {
            unsigned before = 0;
            unsigned j;

            for (j = 0; j < PS3_THREAD_MAX; j++) {
                if (s->thr[j].used && s->thr[j].parked &&
                    s->thr[j].wait_sem_id == s->sem[m].id) {
                    ps3_sem_handoff(s, ram, ram_size, m);
                    before = 1;
                    break;
                }
            }
            if (!before) {
                break;
            }
        }
        ret = 0;
        break;
    }
    case 0x05E: {               /* sys_semaphore_get_value(id, value*) */
        int m = ps3_sem_index(s, a0);

        if (m < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (a1 && (uint64_t)a1 + 4 <= ram_size) {
            ps3_put_be32(ram + a1, (uint32_t)s->sem[m].count);
        }
        ret = 0;
        break;
    }
    case 0x078: {               /* sys_rwlock_create(id*, attr*) */
        unsigned j;
        int r = -1;

        if ((uint64_t)a0 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        for (j = 0; j < PS3_RWLOCK_MAX; j++) {
            if (!s->rw[j].used) {
                r = j;
                break;
            }
        }
        if (r < 0) {
            ret = PS3_LV2_EAGAIN;
            break;
        }
        s->rw[r].used = true;
        s->rw[r].id = ++s->lv2_next_id;
        s->rw[r].readers = 0;
        s->rw[r].wait_writers = 0;
        s->rw[r].writer = 0;
        ps3_put_be32(ram + a0, s->rw[r].id);
        ret = 0;
        break;
    }
    case 0x079: {               /* sys_rwlock_destroy(id) */
        int r = ps3_rwlock_index(s, a0);

        if (r < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        /* lv2 only destroys a lock nobody holds and nobody queues for. */
        if (s->rw[r].readers || s->rw[r].writer || s->rw[r].wait_writers) {
            ret = PS3_LV2_EBUSY;
            break;
        }
        memset(&s->rw[r], 0, sizeof(s->rw[r]));
        ret = 0;
        break;
    }
    case 0x07A:                 /* sys_rwlock_rlock(id) */
    case 0x07B:                 /* sys_rwlock_tryrlock(id) */
    case 0x07D:                 /* sys_rwlock_wlock(id) */
    case 0x07E: {               /* sys_rwlock_trywlock(id) */
        bool write = (nr == 0x07D || nr == 0x07E);
        bool try = (nr == 0x07B || nr == 0x07E);
        int r = ps3_rwlock_index(s, a0);

        if (r < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (write) {
            if (!s->rw[r].readers && !s->rw[r].writer &&
                !s->rw[r].wait_writers) {
                s->rw[r].writer = s->thr_cur >= 0 ? s->thr[s->thr_cur].id : 1;
                ret = 0;
                break;
            }
        } else if (!s->rw[r].writer && !s->rw[r].wait_writers) {
            s->rw[r].readers++;
            ret = 0;
            break;
        }
        if (try) {
            ret = PS3_LV2_EBUSY;
            break;
        }
        if (s->thr_cur >= 0) {
            if (write) {
                s->rw[r].wait_writers++;
            }
            s->thr[s->thr_cur].wait_rwlock_id = s->rw[r].id;
            s->thr[s->thr_cur].wait_rwlock_write = write;
            ps3_sync_park(s, 0);
        }
        ret = 0;                /* handed the lock when it is woken */
        break;
    }
    case 0x07C:                 /* sys_rwlock_runlock(id) */
    case 0x07F: {               /* sys_rwlock_wunlock(id) */
        int r = ps3_rwlock_index(s, a0);

        if (r < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (nr == 0x07F) {
            s->rw[r].writer = 0;
        } else if (s->rw[r].readers) {
            s->rw[r].readers--;
        }
        ps3_rwlock_handoff(s, ram, ram_size, r);
        ret = 0;
        break;
    }
    case 0x05F: {               /* _sys_lwmutex_create(id*, protocol,
                                 * control, has_name, name) */
        unsigned j;
        int m = -1;

        if ((uint64_t)a0 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        /* lv2 only builds one on a control block it can write. */
        if (!a2 || (uint64_t)a2 + 0x14 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        for (j = 0; j < PS3_LWMUTEX_MAX; j++) {
            if (!s->lwm[j].used) {
                m = j;
                break;
            }
        }
        if (m < 0) {
            ret = PS3_LV2_EAGAIN;
            break;
        }
        s->lwm[m].used = true;
        s->lwm[m].id = ++s->lv2_next_id;
        s->lwm[m].control = (uint32_t)a2;
        s->lwm[m].owner = 0;
        s->lwm[m].attribute = (uint32_t)a1;
        s->lwm[m].parked = 0;
        /*
         * The guest has already initialised the block (its own attribute and
         * an owner of free); all the model adds is the pseudo-id lv2 hands
         * back in `sleep_queue' and an owner word it can compare.
         */
        ps3_lwmutex_sync(s, ram, ram_size, m);
        ps3_put_be32(ram + a0, s->lwm[m].id);
        if (s->ppu_trace && !s->lwmutex_reported) {
            s->lwmutex_reported = true;
            info_report("ps3-ppu: lv2: lightweight mutex 0x%X on control "
                        "0x%X (protocol 0x%X)", s->lwm[m].id,
                        (unsigned)a2, (unsigned)a1);
        }
        ret = 0;
        break;
    }
    case 0x060: {               /* _sys_lwmutex_destroy(id) */
        int m = ps3_lwmutex_index(s, a0);

        if (m < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        memset(&s->lwm[m], 0, sizeof(s->lwm[m]));
        ret = 0;
        break;
    }
    case 0x061:                 /* _sys_lwmutex_lock(id, timeout) */
    case 0x063: {               /* _sys_lwmutex_trylock(id) */
        int m = ps3_lwmutex_index(s, a0);
        uint32_t tid = s->thr_cur >= 0 ? s->thr[s->thr_cur].id : 1;

        if (m < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        ps3_lwmutex_reconcile(s, ram, ram_size, m);

        if (s->lwm[m].owner == tid) {
            /*
             * Its own lock: taken again, with the recursion count the library
             * keeps in the block, so an unlock really releases it.  lv2's own
             * answer here would be CELL_EDEADLK for a non-recursive lock, but
             * the library only reaches lv2 on its slow path and a retry there
             * would spin forever instead of making the caller's nesting
             * visible, so the block's count is what the model follows.
             */
            if (s->lwm[m].control &&
                (uint64_t)s->lwm[m].control + 0x10 <= ram_size) {
                uint32_t at = s->lwm[m].control;
                uint32_t count = ps3_be32(ram + at + 0xC);

                if (count != 0xFFFFFFFFu) {
                    ps3_put_be32(ram + at + 0xC, count + 1);
                }
            }
            ret = 0;
            break;
        }

        if (!s->lwm[m].owner) {
            s->lwm[m].owner = tid;
            ps3_lwmutex_sync(s, ram, ram_size, m);
            ret = 0;
            break;
        }

        if (nr == 0x063 || a1 == 0) {
            /* Trylock, or a lock lv2 is allowed to fail at once. */
            ret = PS3_LV2_EBUSY;
            break;
        }

        if (s->thr_cur >= 0) {
            s->lwm[m].parked++;
            ps3_lwmutex_sync(s, ram, ram_size, m);
            s->thr[s->thr_cur].wait_lwmutex_id = s->lwm[m].id;
            ps3_sync_park(s, a1);
        }
        ret = 0;
        break;
    }
    case 0x062:                 /* _sys_lwmutex_unlock(id) */
    case 0x075: {               /* _sys_lwmutex_unlock2(id, ...) */
        int m = ps3_lwmutex_index(s, a0);
        uint32_t tid = s->thr_cur >= 0 ? s->thr[s->thr_cur].id : 1;

        if (m < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        ps3_lwmutex_reconcile(s, ram, ram_size, m);

        if (s->lwm[m].owner && s->lwm[m].owner != tid) {
            ret = PS3_LV2_EPERM;
            break;
        }
        s->lwm[m].owner = 0;
        if (s->lwm[m].parked) {
            ps3_lwmutex_handoff(s, ram, ram_size, m);
        } else {
            ps3_lwmutex_sync(s, ram, ram_size, m);
        }
        ret = 0;
        break;
    }
    case 0x144:                 /* sys_memory_container_create(id*, size) */
        if ((uint64_t)a0 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        if (!a1) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        /* lv2 rounds a container up to its 1 MiB granularity. */
        s->lv2_container_size = (a1 + 0xFFFFF) & ~0xFFFFFu;
        ps3_put_be32(ram + a0, ++s->lv2_next_id);
        ret = 0;
        break;
    case 0x145:                 /* sys_memory_container_destroy(id) */
        ret = 0;
        break;
    case 0x157:                 /* sys_memory_container_get_size(size*, id) */
        if ((uint64_t)a0 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        ps3_put_be32(ram + a0, s->lv2_container_size);
        ret = 0;
        break;
    case 0x160: {               /* sys_memory_get_user_memory_size(info*) */
        uint32_t used = s->lv2_heap - 0x01000000;

        if ((uint64_t)a0 + 8 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        ps3_put_be32(ram + a0, (uint32_t)ram_size);
        ps3_put_be32(ram + a0 + 4, (uint32_t)ram_size - used);
        ret = 0;
        break;
    }
    /*
     * The mapper: the RSX memory the VSH maps in is the same flat RAM here,
     * so an address only has to be handed out, 1 MiB aligned as lv2 requires,
     * and the map/unmap calls simply succeed.  This is the range the library
     * keeps its mapped surfaces in, so it starts above the guest's own heap.
     */
#define PS3_LV2_MMAP_BASE   0x08000000u
#define PS3_LV2_MMAP_ALIGN  0x00001000u
    case 0x146:                 /* sys_mmapper_allocate_fixed_address */
    case 0x147:                 /* sys_mmapper_enable_page_fault_notification */
    case 0x149:                 /* sys_mmapper_free_shared_memory(id) */
    case 0x14D:                 /* sys_mmapper_set_shared_memory_flag */
    case 0x14E:                 /* sys_mmapper_map_shared_memory(addr,id,f) */
    case 0x14F:                 /* sys_mmapper_unmap_shared_memory(addr) */
    case 0x150:                 /* sys_mmapper_change_address_access_right */
    case 0x17E:                 /* sys_sm_initialize */
        ret = 0;
        break;
    case 0x14A:                 /* sys_mmapper_allocate_address(size, flags,
                                 * alignment, u32 *addr) */
    case 0x151: {               /* sys_mmapper_search_and_map(size, flags,
                                 * alignment, u32 *addr) */
        uint64_t size = ((uint64_t)a0 + PS3_LV2_MMAP_ALIGN - 1) &
                        ~(uint64_t)(PS3_LV2_MMAP_ALIGN - 1);
        uint32_t addr;

        if (!size || size > ram_size) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        if ((uint64_t)a3 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        /*
         * The guest asks for a virtual range, but this model has no MMU and
         * only flat RAM, so the address handed back has to be inside RAM.
         * The range is therefore clamped to the room that is left: the guest
         * has only the address, and every byte it touches has to land
         * somewhere.  Handing back the old base at 0x10000000 did not: that
         * is exactly ram_size, so the VSH's heap was outside the machine and
         * the pointers it built from it faulted.
         */
        if (!s->lv2_mmap_next || s->lv2_mmap_next >= ram_size) {
            s->lv2_mmap_next = PS3_LV2_MMAP_BASE;
        }
        addr = s->lv2_mmap_next;
        {
            uint64_t room = (ram_size - addr) &
                            ~(uint64_t)(PS3_LV2_MMAP_ALIGN - 1);
            uint64_t step = MIN(size, room);

            s->lv2_mmap_next = (addr + step + PS3_LV2_MMAP_ALIGN - 1) &
                               ~(PS3_LV2_MMAP_ALIGN - 1);
            if (step < size) {
                /* A second reservation starts over at the bottom. */
                s->lv2_mmap_next = PS3_LV2_MMAP_BASE;
            }
        }
        ps3_put_be32(ram + a3, addr);
        info_report("ps3-ppu: lv2: mmapper %s: 0x%" PRIX64 " at 0x%X",
                    nr == 0x14A ? "address" : "search_and_map", size, addr);
        ret = 0;
        break;
    }
    case 0x14B:                 /* sys_mmapper_free_address(addr) */
        ret = 0;
        break;
    case 0x14C:                 /* sys_mmapper_allocate_shared_memory(key, size,
                                 * flags, u32 *mem_id) */
    case 0x153: {               /* sys_mmapper_allocate_shared_memory_ext */
        if ((uint64_t)a3 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        ps3_put_be32(ram + a3, ++s->lv2_next_id);
        ret = 0;
        break;
    }
    case 0x369:                 /* sys_ss_get_cache_of_product_mode(u8*) */
        if (a0 && (uint64_t)a0 + 1 <= ram_size) {
            ram[a0] = 0;        /* 0 = CEX, the retail product mode */
        }
        ret = 0;
        break;
    case PS3_LV2_MISSING_CALL: {  /* an import with no provider */
        /*
         * The trap returns into the stub, so lr is the word after its sc and
         * names the stub exactly.  The NID cell is only a cross-check: low
         * memory is not the model's alone once the guest starts writing it.
         */
        uint32_t nid = ps3_be32(ram + PS3_LV2_STUB_NID);
        const PS3Lv2Stub *stub = ps3_lv2_stub_lookup_nid(s, nid);

        /* sys_io and the helpers libpad's threading needs come first. */
        if (ps3_lv2_sys_io(s, &cpu->env, ram, ram_size, nid, &ret)) {
            break;
        }
        /* The AV layer: this is how the VSH reads the sink and picks a mode. */
        if (ps3_lv2_video_out(s, &cpu->env, ram, ram_size, nid, &ret)) {
            break;
        }
        /* The GCM display path: buffers and flips land on the same scanout. */
        if (ps3_lv2_gcm(s, &cpu->env, ram, ram_size, nid, &ret)) {
            break;
        }
        /* The microphone: cellMic over the host's capture input. */
        if (ps3_lv2_mic(s, &cpu->env, ram, ram_size, nid, &ret)) {
            break;
        }
        /* The directory side of sys_fs, which the VSH's file layer imports. */
        if (ps3_lv2_fs_lib(s, &cpu->env, ram, ram_size, nid, &ret)) {
            break;
        }
        /* sysPrxForUser's miscellany: printf and the light-weight waits. */
        if (ps3_lv2_prx_user(s, &cpu->env, ram, ram_size, nid, &ret)) {
            break;
        }

        /*
         * Entries the model answers with a value rather than a stub.
         *
         * The VSH's modules link against libraries this flash tree does not
         * carry - every mms module imports mms_db and no module on the flash
         * publishes it - and the entries they call first are initialisers
         * whose result the caller does not test.  Each line below is here
         * because the caller's own code was read: mms calls this one as
         * (0, 0), and again with two descriptors, and returns CELL_OK itself
         * either way; basic_plugins passes it a result buffer and bails out
         * cleanly on a nonzero status.  Answering success lets the module's
         * start finish instead of ending on its first call.
         */
        if (stub) {
            static const struct {
                const char *lib;
                uint32_t nid;
                int32_t value;
                const char *what;
            } known[] = {
                { "mms_db", 0x8AE0383Au, 0, "mms database init/term" },
                /*
                 * Every one of this entry's seventeen call sites in mms is
                 * `cmpwi r3, 0' and a branch, so its result is a status and
                 * not a handle.
                 */
                { "mms_db", 0xD5F8CA15u, 0, "mms database query" },
                { "sys_io", 0x2F1774D5u, 0, "sys_io device query" },
                /*
                 * A stat on an open handle: the 52-byte CellFsStat the caller
                 * passes is zeroed by the caller's own memset, and both
                 * callers only test the status before using it (vshmain_util
                 * compares the size field against 2 TB, mms prints).  Success
                 * with the empty stat is what the console reports for a
                 * device whose media is not there.
                 */
                { "sys_fs", 0x7DE6DCEDu, 0, "handle stat" },
            };
            unsigned k;

            for (k = 0; k < ARRAY_SIZE(known); k++) {
                if (known[k].nid != nid || strcmp(known[k].lib, stub->lib)) {
                    continue;
                }
                if (!s->lv2_known_reported[k]) {
                    s->lv2_known_reported[k] = true;
                    info_report("ps3-ppu: lv2: %s:0x%08X (%s) answered %d by "
                                "the model", stub->lib, nid, known[k].what,
                                known[k].value);
                }
                ret = known[k].value;
                break;
            }
            if (k < ARRAY_SIZE(known)) {
                break;
            }
            /*
             * The mms database library is not on this flash tree at all: no
             * module publishes mms_db, and mms, mms_db_full and
             * mms_maintenance all import it.  Every call the VSH's modules
             * make into it is a status check on the caller's side - mms's own
             * two initialisers ignore the value - so the model answers
             * success for the whole library and lets the media database come
             * up empty, which is what a console with a fresh HDD has.
             */
            if (!strcmp(stub->lib, "mms_db") ||
                !strcmp(stub->lib, "mms_db_full")) {
                if (!s->lv2_mms_db_reported) {
                    s->lv2_mms_db_reported = true;
                    info_report("ps3-ppu: lv2: %s entries answer CELL_OK: the "
                                "flash does not carry the mms database",
                                stub->lib);
                }
                ret = 0;
                break;
            }
        }

        /*
         * sys_fs answers with an error code, never a pointer, so an entry the
         * model does not implement can report success without leaving the
         * caller anything unusable - which is what the console says for a
         * device that is mounted with nothing on it.  The callers seen so far
         * (vshmain_util's handle stat and its size probe) only test the
         * status, and their buffers are theirs to initialise.
         */
        if (stub && !strcmp(stub->lib, "sys_fs")) {
            ret = 0;
            break;
        }

        /*
         * A worker that calls a service the model does not have cannot be
         * answered with -1: the lv2 library it came from uses the return as
         * a pointer and the whole machine ends at 0x700.  Retire the thread
         * instead - it lands on its exit stub, wakes anyone joining it and
         * the scheduler moves on.  The process's main thread keeps -1, where
         * a failure is the guest's own decision to handle.
         */
        if (s->thr_cur >= 0 && s->thr[s->thr_cur].used &&
            !s->thr[s->thr_cur].main && s->thr[s->thr_cur].exit_stub) {
            PS3Thread *t = &s->thr[s->thr_cur];

            info_report("ps3-ppu: lv2: thread 0x%X retired: no provider for "
                        "%s:0x%08X called from lr=0x%" PRIX64 " (it cannot "
                        "use -1 as a pointer)",
                        t->id, stub ? stub->lib : "?", nid,
                        (uint64_t)cpu->env.lr);
            cpu->env.spr[SPR_SRR0] = t->exit_stub;
            s->sched_pending = true;
            ret = 0;
            break;
        }

        /*
         * libpadconfig asserts ret == CELL_OK on every call it makes, so a
         * cellPad entry this model does not answer must still report success
         * rather than -1 - a missing pad reply is not a fatal condition, the
         * port simply has no data.
         */
        if (stub && (!strcmp(stub->lib, "cellPad") ||
                     !strncmp(stub->lib, "libpad", 6))) {
            ret = 0;
            break;
        }

        /*
         * sys_audio's camera and mic bring-up asks sysPrxForUser for helpers
         * whose failure is fatal to those workers, and there is no camera or
         * mic hardware here at all.  Succeeding them keeps the services alive
         * and idle instead of retiring the threads.
         */
        {
            static const uint32_t camera_ok[] = {
                0x318F17E1, 0x2F85C0EF, 0xBDB18F83, 0xF7F7FB20,
                0xB5D5F64E, 0x8EECD140,
            };
            static bool camera_reported;

            for (i = 0; i < ARRAY_SIZE(camera_ok); i++) {
                if (camera_ok[i] == nid) {
                    if (!camera_reported) {
                        camera_reported = true;
                        info_report("ps3-ppu: lv2: camera/mic service stubbed "
                                    "(no camera hardware); the workers idle");
                    }
                    ret = 0;
                    break;
                }
            }
            if (i < ARRAY_SIZE(camera_ok)) {
                break;
            }
        }

        if (stub) {
            info_report("ps3-ppu: lv2: unresolved import %s:0x%08X called "
                        "(lr=0x%" PRIX64 ", thr=%d), answering -1", stub->lib,
                        stub->nid, (uint64_t)cpu->env.lr, s->thr_cur);
        } else {
            info_report("ps3-ppu: lv2: unresolved import NID 0x%08X called "
                        "(lr=0x%" PRIX64 "), answering -1", nid,
                        (uint64_t)cpu->env.lr);
        }
        ret = -1;
        break;
    }
    case 0x077:                 /* sys_time_get_rtc(u64 *rtc) */
        if ((uint64_t)a0 + 8 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        /* Host wall clock, in the microseconds lv2's RTC counts. */
        ps3_put_be64(ram + a0,
                     (uint64_t)g_get_real_time() / 1000ULL + 0x20000ULL);
        ret = 0;
        break;
    case 0x08F:                 /* sys_time_set_timezone(id) */
        ret = 0;
        break;
    case 0x15F: {               /* sys_memory_get_page_attribute(addr, attr*) */
        if (!a1 || (uint64_t)a1 + 0x18 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        /*
         * lv2's sys_page_attr_t, in the order the guest reads it:
         * { u64 attribute; u64 access_right; u32 page_size; u32 pad; }.
         * Writing the page size into the first word (as this did) left
         * `page_size' reading 0 - the caller that sizes a mapping from it then
         * walked off into nothing - and made `attribute' a page size instead
         * of a protection value.
         */
        memset(ram + a1, 0, 0x18);
        ps3_put_be64(ram + a1, 0x0000000000040000ULL);      /* read/write */
        ps3_put_be64(ram + a1 + 8, 0x8ULL);                 /* PPU thread */
        ps3_put_be32(ram + a1 + 0x10, 4096);                /* page size */
        ret = 0;
        break;
    }
    case 0x050:                 /* sys_interrupt_tag_create */
    case 0x051:                 /* sys_interrupt_tag_destroy */
    case 0x053:                 /* sys_event_flag_destroy(id) */
    case 0x058:                 /* sys_interrupt_thread_eoi */
    case 0x059:                 /* _sys_interrupt_thread_disestablish */
    case 0x16F:                 /* sys_uart_initialize */
        /*
         * libavst opens the AV device here.  It is part of the console, so it
         * answers whatever the VSH sends it; a second open is the same device
         * and succeeds too.
         */
        s->av_up = true;
        ret = 0;
        break;
    case 0x052:                 /* sys_event_flag_create(id*, attr*, init) */
    case 0x054:                 /* _sys_interrupt_thread_establish(tid*, tag,
                                 * handler, arg) */
        if ((uint64_t)a0 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        ps3_put_be32(ram + a0, ++s->lv2_next_id);
        ret = 0;
        break;
    case 0x055:                 /* sys_event_flag_wait(id, bit, mode, res*,
                                 * timeout) */
    case 0x056:                 /* sys_event_flag_trywait */
        /*
         * There is no other thread to wait for a flag in this model, and a
         * blocking wait cannot be modelled without one: the bits the caller
         * asks for are reported set, which is what a service that publishes
         * them would have done.
         */
        if (a3 && (uint64_t)a3 + 8 <= ram_size) {
            ps3_put_be64(ram + a3, a1);
        }
        ret = 0;
        break;
    case 0x057:                 /* sys_event_flag_set(id, bit) */
        ret = 0;
        break;
    case 0x170: {               /* sys_uart_receive(buf, size, mode) */
        unsigned got;

        if (!a1) {              /* size == 0 is an immediate success */
            ret = 0;
            break;
        }
        if (a0 && (uint64_t)a0 + a1 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        got = ps3_av_take(s, ram, ram_size, a0, a1);
        if (got) {
            ret = got;
            break;
        }
        if (a2 & 1) {           /* the caller waits for the device to speak */
            ps3_av_park(s, a0, a1);
        }
        ret = 0;
        break;
    }
    case 0x171: {               /* sys_uart_send(buf, size) */
        if ((uint64_t)a0 + a1 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        if (!a1) {
            ret = 0;
            break;
        }
        if (s->av_tx_len + a1 > PS3_AV_TX_SIZE) {
            ret = PS3_LV2_EAGAIN;   /* the device's own buffer is full */
            break;
        }
        memcpy(s->av_tx + s->av_tx_len, ram + a0, a1);
        s->av_tx_len += a1;
        ps3_av_parse(s);
        ps3_av_wake(s, ram, ram_size);
        /*
         * lv2 answers a write with the byte count it took, not with 0: the
         * VSH's libavst wrapper compares the answer with the length it asked
         * to send and treats anything else as a short write.  A zero here
         * made avst_init tear its own channels down right after the flush.
         */
        ret = a1;
        break;
    }
    case 0x172:                 /* sys_uart_get_params(out) */
        if (a0 && (uint64_t)a0 + 16 <= ram_size) {
            ps3_put_be64(ram + a0, PS3_AV_RX_SIZE);
            ps3_put_be64(ram + a0 + 8, PS3_AV_RX_SIZE);
        }
        ret = 0;
        break;
    case 0x072:                 /* sys_semaphore_get_value(id, val*) */
        if ((uint64_t)a1 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        ps3_put_be32(ram + a1, 1);
        ret = 0;
        break;
    case 0x17A: {               /* sys_sm_get_ext_event2(event*, param*,
                                 * status*, which) */
        /*
         * The system manager's extended event queue: the power and eject
         * buttons, the console's thermal state and the shop mode arrive
         * here.  Nothing is pressed on a run, so the answer is "no event" -
         * lv2 says that with CELL_EAGAIN after zeroing the three outputs,
         * which is what RPCS3's sys_sm_get_ext_event2 does.  Answering
         * ESRCH (the model's generic reply to a call it does not have)
         * reads as "that queue does not exist", and a poller that treats it
         * as an absent service never asks again.
         */
        if (a3 != 0 && a3 != 1) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        if (!a0 || (uint64_t)a0 + 8 > ram_size ||
            !a1 || (uint64_t)a1 + 8 > ram_size ||
            !a2 || (uint64_t)a2 + 8 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        ps3_put_be64(ram + a0, 0);
        ps3_put_be64(ram + a1, 0);
        ps3_put_be64(ram + a2, 0);
        ret = PS3_LV2_EAGAIN;
        break;
    }
    case 0x17B:                 /* sys_sm_shutdown(action, ...) */
        /*
         * emer_init ends by asking the system manager to power the console
         * down (0) or restart it (0x100), having written the recover byte into
         * the EEPROM.  A restart is the console's warm reset: the model asks
         * QEMU for one, and the reset entry re-enters the recovery program
         * with the recover flag still set - so a recovery program that asks
         * for a restart loops in recovery instead of ending the run.
         */
        info_report("ps3-ppu: lv2: sys_sm_shutdown(0x%X) - the recovery "
                    "program asks for a %s", a0,
                    a0 ? "restart in recovery mode" : "power off");
        if (a0) {
            s->warm_reset = true;
            /* The byte the program just wrote is what makes the restart come
             * back into recovery. */
            s->syscon_recover = true;
        }
        ret = 0;
        break;
    case 0x17C:                 /* sys_sm_get_params(a, b, c, d) */
        if (!a0 || !a1 || (uint64_t)a2 + 4 > ram_size ||
            (uint64_t)a3 + 8 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        ram[a0] = 0;
        ram[a1] = 0;
        ps3_put_be32(ram + a2, 0x200);
        ps3_put_be32(ram + a3, 0);
        ps3_put_be32(ram + a3 + 4, 7);
        ret = 0;
        break;
    case 0x185:                 /* sys_sm_set_fan_policy(policy, unknown,
                                 * duty) */
        /*
         * The thermal loop only needs the console to answer: there is no fan
         * to turn, so the policy is state and the duty is what the policy
         * says.  policy 0 = auto, 1 = manual, 2 = full.
         */
        s->lv2_fan_policy = a0 > 2 ? 0 : a0;
        s->lv2_fan_duty = (uint8_t)a2;
        info_report("ps3-ppu: lv2: fan policy %u, manual duty 0x%02X",
                    s->lv2_fan_policy, s->lv2_fan_duty);
        ret = 0;
        break;
    case 0x199: {               /* sys_sm_get_fan_policy(setting, unknown*,
                                 * duty*, temp*) */
        uint8_t duty;

        if ((a1 && (uint64_t)a1 + 1 > ram_size) ||
            (a2 && (uint64_t)a2 + 1 > ram_size) ||
            (a3 && (uint64_t)a3 + 1 > ram_size)) {
            ret = PS3_LV2_EFAULT;
            break;
        }

        if (s->lv2_fan_policy == 2) {
            duty = 0xFF;                /* full speed */
        } else if (s->lv2_fan_policy == 1) {
            duty = s->lv2_fan_duty;     /* manual */
        } else {
            duty = 0x4E;                /* auto, the idle curve */
        }

        if (a1) {
            ram[a1] = 0;                /* unknown */
        }
        if (a2) {
            ram[a2] = duty;
        }
        if (a3) {
            ram[a3] = 45;               /* an idle CELL, degrees Celsius */
        }
        s->lv2_fan_duty = duty;
        ret = 0;
        break;
    }
    case 0x15D:                 /* sys_memory_free(addr) */
        ret = 0;
        break;
    case 0x1E0:                 /* _sys_prx_load_module(path, flags, opt) */
    case 0x1F1:                 /* _sys_prx_load_module_on_memcontainer(path,
                                 * container, flags, opt) */
        ret = ps3_lv2_prx_load(s, ram, ram_size, a0);
        break;
    case 0x1E1:                 /* _sys_prx_start_module(id, flags, opt) */
    case 0x1E2: {               /* _sys_prx_stop_module(id, flags, opt) */
        PS3Lv2Module *m = ps3_lv2_module(s, a0);
        uint32_t opd;
        uint64_t cmd, res;

        if (!m) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (!a2 || (uint64_t)a2 + 0x28 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }

        cmd = ps3_be64(ram + a2 + 0x08);
        res = ps3_be64(ram + a2 + 0x18);

        /*
         * lv2 runs no guest code here: it fills the caller's option block
         * with the module's entry point and the caller invokes it.  That is
         * why `cmd' comes back a second time, with the result in `res'.
         */
        switch (cmd & 0xF) {
        case 1:
            opd = nr == 0x1E1 ? m->start_opd : m->stop_opd;
            ps3_put_be64(ram + a2 + 0x10, opd ? opd : ~0ull);
            if (opd && ps3_be64(ram + a2) != 0x20) {
                ps3_put_be64(ram + a2 + 0x20,
                             m->prologue_opd ? m->prologue_opd : ~0ull);
            }
            info_report("ps3-ppu: prx: %s: %s entry 0x%X", m->path,
                        nr == 0x1E1 ? "start" : "stop", opd);
            ret = 0;
            break;
        case 2:
            if (res & 0xFFFFFFFF) {
                info_report("ps3-ppu: prx: %s: %s routine returned 0x%" PRIX64,
                            m->path, nr == 0x1E1 ? "start" : "stop", res);
                ret = (int32_t)res;
                break;
            }
            if (nr == 0x1E1) {
                m->started = true;
            } else {
                m->started = false;
            }
            ret = 0;
            break;
        default:
            ret = PS3_LV2_EINVAL;
            break;
        }
        break;
    }
    case 0x1E3:                 /* _sys_prx_unload_module(id, flags, opt) */
        for (i = 0; i < s->lv2_mod_count; i++) {
            if (s->lv2_mod[i].id == a0) {
                break;
            }
        }
        if (i < s->lv2_mod_count) {
            /*
             * Its NIDs go away with it; the image itself stays mapped.  The
             * process's own exports carry owner zero and are never a module
             * slot's to drop.
             */
            for (unsigned j = 0; j < s->lv2_export_count; j++) {
                if (s->lv2_export[j].owner &&
                    s->lv2_export[j].owner == i + 1) {
                    s->lv2_export[j].owner = 0;
                    s->lv2_export[j].opd = 0;
                }
            }
            s->lv2_mod[i].id = 0;
            s->lv2_mod[i].started = false;
            ret = 0;
        } else {
            ret = PS3_LV2_ESRCH;
        }
        break;
    case 0x1EE: {               /* _sys_prx_get_module_list(flags, opt) */
        uint32_t max, count = 0, list;

        if (!a1 || (uint64_t)a1 + 0x1C > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }

        max = ps3_be32(ram + a1 + 0x0C);
        list = ps3_be32(ram + a1 + 0x14);

        for (i = 0; i < s->lv2_mod_count && count < max; i++) {
            if (!s->lv2_mod[i].id) {
                continue;
            }
            if (list && (uint64_t)list + 4 * (count + 1) <= ram_size) {
                ps3_put_be32(ram + list + 4 * count, s->lv2_mod[i].id);
            }
            count++;
        }

        ps3_put_be32(ram + a1 + 0x10, count);
        ret = 0;
        break;
    }
    case 0x1EF: {               /* _sys_prx_get_module_info(id, flags, opt) */
        PS3Lv2Module *m = ps3_lv2_module(s, a0);
        uint32_t info;
        uint32_t filename, filename_size;

        if (!m) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (!a2 || (uint64_t)a2 + 0x10 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }

        info = ps3_be32(ram + a2 + 0x08);
        if (!info || (uint64_t)info + 0x48 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }

        memset(ram + info + 0x08, 0, 0x40);
        g_strlcpy((char *)ram + info + 0x08, m->name, 30);
        ram[info + 0x26] = m->version[0];
        ram[info + 0x27] = m->version[1];
        ps3_put_be32(ram + info + 0x28, m->attributes);
        ps3_put_be32(ram + info + 0x2C, m->start_opd);
        ps3_put_be32(ram + info + 0x30, m->stop_opd);
        ps3_put_be32(ram + info + 0x34, m->segments);

        filename = ps3_be32(ram + info + 0x38);
        filename_size = ps3_be32(ram + info + 0x3C);
        if (filename && filename_size &&
            (uint64_t)filename + filename_size <= ram_size) {
            g_strlcpy((char *)ram + filename, m->path,
                      MIN(filename_size, (uint32_t)sizeof(m->path)));
        }
        ps3_put_be32(ram + info + 0x44, 0);
        ret = 0;
        break;
    }
    case 0x1F0: {               /* _sys_prx_get_module_id_by_name(name, ...) */
        char name[28];

        if (!ps3_lv2_guest_string(ram, ram_size, a0, name, sizeof(name))) {
            ret = PS3_LV2_EFAULT;
            break;
        }

        for (i = 0; i < s->lv2_mod_count; i++) {
            if (s->lv2_mod[i].id && !strcmp(s->lv2_mod[i].name, name)) {
                break;
            }
        }
        ret = i < s->lv2_mod_count ? (int32_t)s->lv2_mod[i].id : 0;
        break;
    }
    case 0x1CD: {               /* _sys_prx_get_module_id_by_address(addr) */
        uint32_t id = 0;

        for (i = 0; i < s->lv2_mod_count; i++) {
            const PS3Lv2Module *m = &s->lv2_mod[i];

            if (a0 >= m->base && a0 < m->base + m->size) {
                id = m->id;
                break;
            }
        }
        ret = (int32_t)id;
        break;
    }
    case 0x1E4:                 /* _sys_prx_register_module(param*) */
    case 0x1E6:                 /* _sys_prx_register_library(param*) */
        ret = 0;
        break;
    case 0x090: {               /* sys_time_get_timezone(int*, int*) */
        GDateTime *now = g_date_time_new_now_local();
        int offset = now ? (int)(g_date_time_get_utc_offset(now) /
                                 G_TIME_SPAN_MINUTE) : 0;

        if (now) {
            g_date_time_unref(now);
        }
        if (a0 && (uint64_t)a0 + 4 <= ram_size) {
            ps3_put_be32(ram + a0, offset);
        }
        if (a1 && (uint64_t)a1 + 4 <= ram_size) {
            ps3_put_be32(ram + a1, 0);
        }
        ret = 0;
        break;
    }
    case 0x091: {               /* sys_time_get_current_time(sec*, nsec*) */
        gint64 usec = g_get_real_time();

        if (a0 && (uint64_t)a0 + 8 <= ram_size) {
            ps3_put_be64(ram + a0, (uint64_t)(usec / 1000000));
        }
        if (a1 && (uint64_t)a1 + 8 <= ram_size) {
            ps3_put_be64(ram + a1, (uint64_t)(usec % 1000000) * 1000);
        }
        if (!s->lv2_time_reported) {
            s->lv2_time_reported = true;
            info_report("ps3-ppu: lv2: sys_time_get_current_time: host UTC, "
                        "%" PRId64 " s", usec / 1000000);
        }
        ret = 0;
        break;
    }
    case 0x092:                 /* sys_time_set_current_time(sec, nsec) */
        info_report("ps3-ppu: lv2: sys_time_set_current_time(%" PRIu64
                    ", %" PRIu64 "): the host clock is authoritative",
                    (uint64_t)cpu->env.gpr[3], (uint64_t)cpu->env.gpr[4]);
        ret = 0;
        break;
    case 0x093:                 /* sys_time_get_timebase_frequency */
        ret = 79800000;
        break;
    case 0x08D: {               /* sys_timer_usleep(sleep_time) */
        /*
         * The VSH sleeps 100 ms between polls while it initialises and while
         * it idles.  This model has no scheduler and no guest wall clock, and
         * the PPU runs in TCG, so a sleep that really waited would stall the
         * whole machine; answering at once lets the guest's next poll move
         * the boot on.
         */
        if (!s->lv2_usleep_reported) {
            s->lv2_usleep_reported = true;
            info_report("ps3-ppu: lv2: sys_timer_usleep(%" PRIu64 " us): "
                        "yields to the next guest thread",
                        (uint64_t)cpu->env.gpr[3]);
        }
        /* TEMP: what the main thread's acquire loop is waiting on. */
        if (s->thr_cur >= 0 && s->thr[s->thr_cur].used &&
            !s->thr[s->thr_cur].id && cpu->env.lr == 0x5DACF8 &&
            (uint64_t)cpu->env.gpr[30] + 0x40 <= ram_size) {
            static unsigned probe_n;

            if (++probe_n == 200) {
                uint32_t obj = (uint32_t)cpu->env.gpr[30];
                unsigned k;

                info_report("ps3-ppu: lv2: probe obj 0x%X r3 0x%X r13 0x%X:",
                            obj, (uint32_t)cpu->env.gpr[3],
                            (uint32_t)cpu->env.gpr[13]);
                for (k = 0; k < 16; k += 4) {
                    info_report("ps3-ppu: lv2:   obj+0x%02X: %08X %08X %08X "
                                "%08X", k * 4, ps3_be32(ram + obj + k * 4),
                                ps3_be32(ram + obj + k * 4 + 4),
                                ps3_be32(ram + obj + k * 4 + 8),
                                ps3_be32(ram + obj + k * 4 + 12));
                }
                info_report("ps3-ppu: lv2:   tls 0x%X: %08X %08X %08X %08X",
                            (uint32_t)cpu->env.gpr[13] - 0x7030,
                            ps3_be32(ram + (uint32_t)cpu->env.gpr[13] - 0x7030),
                            ps3_be32(ram + (uint32_t)cpu->env.gpr[13] - 0x702C),
                            ps3_be32(ram + (uint32_t)cpu->env.gpr[13] - 0x7028),
                            ps3_be32(ram + (uint32_t)cpu->env.gpr[13] - 0x7024));
                for (k = 0; k < PS3_THREAD_MAX; k++) {
                    PS3Thread *t = &s->thr[k];

                    if (!t->used) {
                        continue;
                    }
                    info_report("ps3-ppu: lv2:   t[%u] id 0x%X nip 0x%" PRIx64
                                " lr 0x%" PRIx64 " park %d blk %d dead %d"
                                " mutex 0x%X cond 0x%X sem 0x%X eq %d",
                                k, t->id, t->nip, t->lr, t->parked, t->blocked,
                                t->dead, t->wait_mutex_id, t->wait_cond_id,
                                t->wait_sem_id, t->wait_eq);
                }
            }
        }
        /* A sleep is the scheduler's yield: run whoever is waiting. */
        s->sched_pending = true;
        ret = 0;
        break;
    }
    case 0x15C:                 /* sys_memory_allocate(size, flags, addr*) */
        ret = ps3_lv2_alloc(s, ram, ram_size, a0, a2);
        break;
    case 0x15E:                 /* sys_memory_allocate_from_container(id,
                                 * size, flags, addr*) */
        ret = ps3_lv2_alloc(s, ram, ram_size, a1, a3);
        break;
    case 0x18E: {               /* sys_console_write(buf) */
        uint32_t at = a0;

        if (at >= ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        for (; at < ram_size && ram[at]; at++) {
            ps3_uart_putc(s, ram[at]);
        }
        ret = 0;
        break;
    }
    case 0x3DC:                 /* debug exception handler: nothing to install */
        ret = 0;
        break;
    case 0x35F: {               /* sys_ss_update_manager(op, arg, size) */
        /*
         * 0x600B/0x600C are the system controller's EEPROM, not a buffer: the
         * offset is the first argument and the value is the second.  Treating
         * them as a buffer wrote zeroes at the offset and left the caller's
         * byte untouched, so emer_init read a stale 0xFF as its recover flag,
         * saw a console that was not in recovery and exited before drawing.
         */
        switch (a0) {
        case 0x600B: {          /* read eeprom: offset, u8 *value */
            uint32_t ptr = a2;

            if (!ptr || (uint64_t)ptr + 1 > ram_size) {
                ret = PS3_LV2_EFAULT;
                break;
            }
            ram[ptr] = ps3_syscon_read(s, a1);
            if (s->ppu_trace) {
                info_report("ps3-ppu: syscon: eeprom[0x%X] -> 0x%02X",
                            a1, ram[ptr]);
            }
            ret = 0;
            break;
        }
        case 0x600C:            /* write eeprom: offset, value */
            ps3_syscon_write(s, a1, (uint8_t)a2);
            ret = 0;
            break;
        case 0x6003:            /* get installed package info */
        case 0x6011:            /* get applicable version */
            if (a2 && (uint64_t)a2 + 8 <= ram_size) {
                /* Firmware 3.01, in the 0xVVVRRRPP form RPCS3 writes. */
                ps3_put_be64(ram + a2, 0x3001000000000000ULL);
            }
            ret = 0;
            break;
        default:
            if (s->ppu_trace) {
                info_report("ps3-ppu: update_manager op 0x%X (0x%X, 0x%X)",
                            a0, a1, a2);
            }
            ret = 0;
            break;
        }
        break;
    }
    case 0x363: {               /* sys_ss_appliance_info_manager(op, arg, size) */
        if (a1 && a2 && (uint64_t)a1 + a2 <= ram_size) {
            memset(ram + a1, 0, a2);
        }
        ret = 0;
        break;
    }
    case 0x36B: {               /* sys_ss_get_boot_device(u64 *dev) */
        /*
         * The console reports which medium it came up from, and the VSH's
         * boot path branches on it before it starts its own boot animation.
         * 0x190 is the value RPCS3 hands back (the HDD, i.e. the console's
         * own system), and the VSH accepts it as "normal boot".
         */
        if (!a0 || (uint64_t)a0 + 8 > ram_size) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        ps3_put_be64(ram + a0, 0x190);
        ret = 0;
        break;
    }
    case 0x12C: {               /* sys_vm_memory_map(vsize, psize, cid, flag,
                                 * policy, addr*) */
        uint64_t vsize = a0;
        uint64_t psize = a1;
        uint64_t flag = cpu->env.gpr[6];
        uint64_t policy = cpu->env.gpr[7];
        uint32_t out = cpu->env.gpr[8];
        uint32_t base;

        if (!out || (uint64_t)out + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        /* lv2's own checks, taken from the same places RPCS3 keeps them. */
        if (!vsize || vsize % 0x2000000 || vsize > 0x10000000 ||
            !psize || psize % 0x10000 || policy != 0 || (flag & 0xF4)) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        /*
         * The model has one flat RAM, so the mapping is a grant: the region
         * comes out of the same bump the model's other allocations use, at
         * lv2's 16 MiB granularity, and the guest is told where it landed.
         */
        base = (s->lv2_heap + 0xFFFFFu) & ~0xFFFFFu;
        if ((uint64_t)base + vsize > ram_size) {
            ret = PS3_LV2_ENOMEM;
            break;
        }
        s->lv2_heap = base + (uint32_t)vsize;
        ps3_put_be32(ram + PS3_LV2_HEAP, s->lv2_heap);
        ps3_put_be32(ram + out, base);
        if (s->ppu_trace) {
            info_report("ps3-ppu: lv2: vm_memory_map 0x%" PRIX64
                        " bytes at 0x%X (pages 0x%" PRIX64 ")",
                        vsize, base, psize);
        }
        ret = 0;
        break;
    }
    case 0x12D:                 /* sys_vm_unmap(addr, size) */
    case 0x12E:                 /* sys_vm_append_memory(addr, size) */
    case 0x037:                 /* the slot lv2 leaves empty: nothing to do */
    case 0x0C1:                 /* sys_spu_thread_bind_queue: one queue per */
    case 0x231:                 /* thread here, so binding is the default */
        ret = 0;
        break;
    case 0x36A: {               /* sys_ss_get_cache_of_flash_ext_flag(u8 *flag) */
        /*
         * One byte, not a word: the caller's local is a byte, and a wider
         * store overruns it.  0xFE with the LSB clear is a NOR machine, which
         * is what this flash image is; emer_init reads the same byte back as
         * its recover mode.
         */
        if (a0 >= ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        ram[a0] = 0xFE;
        ret = 0;
        break;
    }
    case 0x193: {               /* sys_tty_write(channel, buf, len, written) */
        uint32_t n;

        if ((uint64_t)a1 + a2 > ram_size || (uint64_t)a3 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        for (n = 0; n < a2; n++) {
            ps3_uart_putc(s, ram[a1 + n]);
        }
        ps3_put_be32(ram + a3, a2);
        ret = 0;
        break;
    }
    case 0x029: {               /* sys_ppu_thread_exit(errorcode) */
        int idx = s->thr_cur;

        if (idx >= 0 && s->thr[idx].used) {
            uint32_t id = s->thr[idx].id;
            uint8_t *exit_ram = ram;

            s->thr[idx].dead = true;
            s->thr[idx].exit_status = a0;
            if (s->ppu_trace) {
                info_report("ps3-ppu: lv2: thread 0x%X exited with 0x%X", id,
                            a0);
            }
            for (i = 0; i < PS3_THREAD_MAX; i++) {
                PS3Thread *j = &s->thr[i];

                if (!j->used || j->id == id ||
                    j->join_target != id) {
                    continue;
                }
                /*
                 * Finish the parked join here: the joiner's frame is still in
                 * the trampoline, and finishing it the way a wake does steps
                 * r1 out of that frame and returns to the instruction after
                 * its `sc'.
                 */
                j->join_target = 0;
                if (j->join_ea && (uint64_t)j->join_ea + 8 <= ram_size) {
                    ps3_put_be64(exit_ram + j->join_ea, a0);
                }
                if (j->parked) {
                    ps3_thread_finish_call(s, j, exit_ram, ram_size, 0);
                } else {
                    j->blocked = false;
                }
            }
            s->sched_pending = true;
        }
        ret = 0;
        break;
    }
    case 0x02C: {               /* sys_ppu_thread_join(id, vptr) */
        PS3Thread *t = NULL;

        for (i = 0; i < PS3_THREAD_MAX; i++) {
            if (s->thr[i].used && s->thr[i].id == a0) {
                t = &s->thr[i];
                break;
            }
        }
        if (!t) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (t->detached) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        if (t->dead) {
            if (a1 && (uint64_t)a1 + 8 <= ram_size) {
                ps3_put_be64(ram + a1, t->exit_status);
            }
            ret = 0;
            break;
        }
        /*
         * The target is still running: the caller blocks until it exits.  It
         * has to be parked in the call, not merely flagged, or it runs on with
         * `blocked' set and the scheduler never picks it again - which is what
         * froze the VSH's main thread at its first join of a worker.
         */
        if (s->ppu_trace) {
            info_report("ps3-ppu: lv2: join 0x%X from thread 0x%X (lr "
                        "0x%" PRIX64 ")", a0,
                        s->thr_cur >= 0 ? s->thr[s->thr_cur].id : 0,
                        (uint64_t)cpu->env.lr);
        }
        if (s->thr_cur >= 0 && s->thr[s->thr_cur].used) {
            PS3Thread *j = &s->thr[s->thr_cur];

            j->parked = true;
            j->blocked = true;
            j->join_target = a0;
            j->join_ea = a1;
            j->wait_eq = -3;        /* a join, not a queue */
            j->wait_ticks = -1;     /* lv2 has no timeout on a join */
            s->lv2_park = true;
            s->sched_pending = true;
        }
        ret = 0;
        break;
    }
    case 0x02A:                 /* sys_ppu_thread_yield */
        s->sched_pending = true;
        ret = 0;
        break;
    case 0x02D: {               /* sys_ppu_thread_detach(thread_id) */
        for (i = 0; i < PS3_THREAD_MAX; i++) {
            if (s->thr[i].used && s->thr[i].id == a0) {
                break;
            }
        }
        if (i == PS3_THREAD_MAX) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (s->thr[i].dead) {
            ret = PS3_LV2_EAGAIN;       /* already exited */
            break;
        }
        if (s->thr[i].detached) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        s->thr[i].detached = true;
        ret = 0;
        break;
    }
    case 0x02E: {               /* sys_ppu_thread_get_join_state(u32 *joinable) */
        uint32_t tid = s->thr_cur >= 0 ? s->thr[s->thr_cur].id : 0;
        bool detach = s->thr_cur >= 0 && s->thr[s->thr_cur].detached;

        if (!a0 || (uint64_t)a0 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        (void)tid;
        /* lv2 answers 1 while the thread can still be joined. */
        ps3_put_be32(ram + a0, detach ? 0 : 1);
        ret = 0;
        break;
    }
    case 0x02F:                 /* sys_ppu_thread_set_priority(id, prio) */
        for (i = 0; i < PS3_THREAD_MAX; i++) {
            if (s->thr[i].used && s->thr[i].id == a0) {
                s->thr[i].prio = (int32_t)a1;
                break;
            }
        }
        ret = i == PS3_THREAD_MAX ? PS3_LV2_ESRCH : 0;
        break;
    case 0x030: {               /* sys_ppu_thread_get_priority(id, s32 *prio) */
        if (!a1 || (uint64_t)a1 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        for (i = 0; i < PS3_THREAD_MAX; i++) {
            if (s->thr[i].used && s->thr[i].id == a0) {
                break;
            }
        }
        if (i == PS3_THREAD_MAX) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        ps3_put_be32(ram + a1, (uint32_t)s->thr[i].prio);
        ret = 0;
        break;
    }
    case 0x031: {               /* sys_ppu_thread_get_stack_information(
                                 * sys_ppu_thread_stack_t *info) */
        /* { u32 addr; u32 size; } for the calling thread. */
        if (!a0 || (uint64_t)a0 + 8 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        if (s->thr_cur < 0) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        ps3_put_be32(ram + a0, s->thr[s->thr_cur].stack_base);
        ps3_put_be32(ram + a0 + 4, s->thr[s->thr_cur].stack_size);
        ret = 0;
        break;
    }
    case 0x32:                  /* sys_ppu_thread_stop(thread_id) */
    case 0x33:                  /* sys_ppu_thread_restart(thread_id) */
    case 0x35:                  /* sys_ppu_thread_start(thread_id) */
        for (i = 0; i < PS3_THREAD_MAX; i++) {
            if (s->thr[i].used && s->thr[i].id == a0) {
                s->thr[i].blocked = nr == 0x32;
                if (nr != 0x32) {
                    s->thr[i].dead = false;
                }
                break;
            }
        }
        s->sched_pending = nr != 0x32;
        ret = 0;
        break;
    case 0x34: {                /* _sys_ppu_thread_create(id*, param*, arg,
                                 * unk, prio, stack, flags, name*)
                                 *
                                 * param is { entry descriptor, tls, pad }:
                                 * the descriptor is not the parameter block,
                                 * and the TLS word is where lv2 takes r13
                                 * from, so neither can be reconstructed
                                 * from the creator's registers.
                                 */
        uint32_t name = cpu->env.gpr[10];
        uint32_t entry, tls;

        if (!a0 || (uint64_t)a0 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        if (!a1 || (uint64_t)a1 + 16 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        /* sys_ppu_thread_param_t: the entry is a 32-bit OPD address and the
         * TLS word sits right behind it.  Reading the pair as one 64-bit
         * value put the TLS where the entry belongs, so the thread started on
         * whatever the TLS page happened to contain. */
        entry = ps3_be32(ram + a1);
        tls = ps3_be32(ram + a1 + 4);
        {
            uint32_t tid = ps3_lv2_thread_created(s, ram, ram_size,
                                                  &cpu->env, entry, tls, a2,
                                                  a5, (int32_t)a4, name);

            if (!tid) {
                if (s->ppu_trace) {
                    info_report("ps3-ppu: lv2: thread creation failed (entry "
                                "descriptor 0x%X, stack 0x%X, heap 0x%X, "
                                "param %08X %08X %08X %08X, opd %08X %08X)",
                                entry, a5, s->lv2_heap,
                                ps3_be32(ram + a1), ps3_be32(ram + a1 + 4),
                                ps3_be32(ram + a1 + 8),
                                ps3_be32(ram + a1 + 12),
                                (uint32_t)entry + 8 <= ram_size ?
                                    ps3_be32(ram + (uint32_t)entry) : 0,
                                (uint32_t)entry + 8 <= ram_size ?
                                    ps3_be32(ram + (uint32_t)entry + 4) : 0);
                }
                ret = -EAGAIN;
                break;
            }
            /*
             * sys_ppu_thread_t is a u64 on the console: `_sys_ppu_thread_create`
             * takes a `u64 *` and the guest reads the whole word back.  Storing
             * only the low half left the number in the high word and zero in
             * the low one, so every later call that takes an id in r3 - start,
             * join, detach, set_priority - was handed 0: the start started
             * nothing, and the x3 worker it was meant to launch never ran.
             */
            if ((uint64_t)a0 + 8 <= ram_size) {
                ps3_put_be64(ram + a0, tid);
            } else {
                ps3_put_be32(ram + a0, tid);
            }
        }
        ret = 0;
        break;
    }
    /*
     * sys_rsxaudio: the audio module's view of the hardware.  One instance
     * exists at a time, as on the console.  The shared page it hands out is
     * where the guest writes its ring buffers; the timer above plays them.
     */
    case 0x28A: {               /* sys_rsxaudio_initialize(handle*) */
        uint32_t shmem;

        if (!a0 || (uint64_t)a0 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        if (s->rsxaudio_handle) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        if (ps3_lv2_alloc(s, ram, ram_size, 0x1000, a0) != 0) {
            ret = PS3_LV2_ENOMEM;
            break;
        }
        shmem = ps3_be32(ram + a0);
        memset(ram + shmem, 0, 0x1000);
        s->rsxaudio_shmem = shmem;
        s->rsxaudio_handle = 1;
        ps3_put_be32(ram + a0, s->rsxaudio_handle);
        ret = 0;
        break;
    }
    case 0x28B:                 /* sys_rsxaudio_finalize(handle) */
        if (a0 != s->rsxaudio_handle) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        s->rsxaudio_running = false;
        s->rsxaudio_shmem = 0;
        s->rsxaudio_handle = 0;
        ret = 0;
        break;
    case 0x28C:                 /* sys_rsxaudio_import_shared_memory(h, addr*) */
        if (a0 != s->rsxaudio_handle) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (!a1 || (uint64_t)a1 + 8 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        ps3_put_be64(ram + a1, s->rsxaudio_shmem);
        ret = 0;
        break;
    case 0x28D:                 /* sys_rsxaudio_unimport_shared_memory(h) */
    case 0x28E:                 /* sys_rsxaudio_create_connection(h) */
    case 0x28F:                 /* sys_rsxaudio_close_connection(h) */
    case 0x290:                 /* sys_rsxaudio_prepare_process(h) */
        if (a0 != s->rsxaudio_handle) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        ret = 0;
        break;
    case 0x291:                 /* sys_rsxaudio_start_process(h) */
        if (a0 != s->rsxaudio_handle) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (!s->rsxaudio_running) {
            s->rsxaudio_running = true;
            ps3_rsxaudio_kick(s);
        }
        if (!s->lv2_audio_reported) {
            s->lv2_audio_reported = true;
            info_report("ps3-audio: sound driver running, serial ring at "
                        "0x%X%s", s->rsxaudio_shmem,
                        ps3_audio_active(s->audio) ? "" :
                        " (no host backend: silence)");
        }
        ret = 0;
        break;
    case 0x292:                 /* sys_rsxaudio_stop_process(h) */
        if (a0 != s->rsxaudio_handle) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        s->rsxaudio_running = false;
        ret = 0;
        break;
    case 0x293:                 /* sys_rsxaudio_get_dma_param(h, flag, out*) */
        if (a0 != s->rsxaudio_handle) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (!a2 || (uint64_t)a2 + 8 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        ps3_put_be64(ram + a2, 0);
        ret = 0;
        break;
    case 0x182:                 /* sys_sm_control_led(led, action) */
        ps3_console_led(s, a0, a1);
        ret = 0;
        break;
    case 0x1F4: {               /* sys_hid_manager_open(device_type, port,
                                 * handle*) */
        uint32_t type = a0, port_no = a1;

        if (type > 3) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        if (!a2 || (uint64_t)a2 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        if (!s->hid_next_handle) {
            s->hid_next_handle = 0x100;     /* where real lv2 starts */
        }
        ps3_put_be32(ram + a2, s->hid_next_handle);

        if (type == 1) {
            /*
             * Opening a pad port through sys_hid is what the VSH's
             * hidportassign thread does, and lv2 answers it by bringing the
             * pad library up and turning press and sensor mode on for that
             * port.
             */
            if (!s->pad_max_connect) {
                s->pad_max_connect = PS3_PAD_PORT_MAX;
            }
            if (port_no < PS3_PAD_PORT_MAX) {
                s->pad_setting[port_no] |= PS3_PAD_SETTING_PRESS_ON |
                                           PS3_PAD_SETTING_SENSOR_ON;
            }
        }

        info_report("ps3-ppu: lv2: sys_hid_manager_open(type %u, port %u) -> "
                    "handle 0x%X", type, port_no, s->hid_next_handle);
        s->hid_next_handle++;
        ret = 0;
        break;
    }
    case 0x1F5:                 /* sys_hid_manager_close(handle) */
    case 0x1F8:                 /* sys_hid_manager_map_logical_id_to_port_id */
    case 0x1F9:                 /* ...unmap... */
    case 0x1FA:                 /* sys_hid_manager_add_hot_key_observer */
    case 0x1FB:                 /* sys_hid_manager_remove_hot_key_observer */
    case 0x1FC:                 /* sys_hid_manager_grab_focus */
    case 0x1FD:                 /* sys_hid_manager_release_focus */
    case 0x1FF:                 /* sys_hid_manager_set_master_process */
    case 0x201:                 /* sys_hid_manager_513 */
    case 0x202:                 /* sys_hid_manager_514 */
        ret = 0;
        break;
    case 0x1FE:                 /* sys_hid_manager_check_focus */
    case 0x200:                 /* sys_hid_manager_is_process_permission_root */
        ret = 1;
        break;
    case 0x1F6: {               /* sys_hid_manager_read(handle, pkg, buf,
                                 * size) */
        uint8_t data[PS3_PAD_DATA_SIZE];
        unsigned words;

        if (!a2) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        if ((a1 == 2 || a1 == 0x81) && ps3_pad_connect(s) &&
            (uint64_t)a2 + 2 <= ram_size) {
            ps3_pad_data(s, 0, data, false);
            words = MIN(ps3_be32(data) / 2, MIN(a3, 64));
            if ((uint64_t)a2 + words * 2 > ram_size) {
                ret = PS3_LV2_EFAULT;
                break;
            }
            memcpy(ram + a2, data + 4, words * 2);
            ret = a1 == 2 ? (int32_t)(words * 2) : (int32_t)words;
        } else {
            ret = 0;
        }
        break;
    }
    case 0x1F7: {               /* sys_hid_manager_ioctl(handle, pkg, buf,
                                 * size) */
        const PS3PadProduct *p = ps3_pad_product(s, 0);

        if (!a2) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        if (a1 == 2 && (uint64_t)a2 + 4 <= ram_size) {
            /*
             * A DualShock 3's ids followed by the tail of its HID report
             * descriptor, which is what a real console answers here.
             */
            static const uint8_t hid[] = {
                0x01, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x08, 0x03, 0x50, 0x00, 0x00, 0x1C, 0x1F,
            };
            unsigned n = MIN(a3, (uint32_t)sizeof(hid));

            ram[a2] = p->vendor >> 8;
            ram[a2 + 1] = p->vendor;
            ram[a2 + 2] = p->product >> 8;
            ram[a2 + 3] = p->product;
            if ((uint64_t)a2 + 4 + n > ram_size) {
                n = ram_size - a2 - 4;
            }
            memcpy(ram + a2 + 4, hid, n);
        } else if (a1 == 5 && (uint64_t)a2 + 4 <= ram_size) {
            ram[a2] = p->vendor >> 8;
            ram[a2 + 1] = p->vendor;
            ram[a2 + 2] = p->product >> 8;
            ram[a2 + 3] = p->product;
        }
        ret = 0;
        break;
    }
    case 0x204:                 /* sys_config_open(queue, config*) */
        if (!a1 || (uint64_t)a1 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        ps3_put_be32(ram + a1, ++s->lv2_next_id);
        ret = 0;
        break;
    case 0x205:                 /* sys_config_close(config) */
        ret = 0;
        break;
    case 0x206:                 /* sys_config_get_service_event(...) */
        /* No service event is ever queued: the ports do not change. */
        ret = PS3_LV2_ESRCH;
        break;
    case 0x207: {               /* sys_config_add_service_listener(cfg,
                                 * service, verbosity, in, size, type,
                                 * listener*) */
        uint32_t out = cpu->env.gpr[9];

        if (!out || (uint64_t)out + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        ps3_put_be32(ram + out, ++s->lv2_next_id);
        ret = 0;
        break;
    }
    case 0x208:                 /* sys_config_remove_service_listener */
        ret = 0;
        break;
    case 0x209: {               /* sys_config_register_service(cfg, service,
                                 * user, verbosity, data, size, service*) */
        uint32_t out = cpu->env.gpr[9];

        if (!out || (uint64_t)out + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        ps3_put_be32(ram + out, ++s->lv2_next_id);
        info_report("ps3-ppu: lv2: sys_config_register_service(service 0x%X, "
                    "user %u, %u byte(s))", a1, a2,
                    (uint32_t)cpu->env.gpr[8]);
        ret = 0;
        break;
    }
    case 0x20A:                 /* sys_config_unregister_service */
        ret = 0;
        break;
    case 0x27B:                 /* sys_btsetting_if(cmd, msg) */
        /*
         * libbtsetting's whole lv2 interface is this call: initialise, then
         * read and write the adapter's address and the paired-device table.
         * There is no Bluetooth hardware here, so every command is
         * acknowledged.  Answering -ENOSYS made btsetting_initialize() fail
         * with CELL_ENOSYS (0x80010003) and the VSH printed that on the
         * console.
         */
        if (!s->lv2_btsetting_reported) {
            s->lv2_btsetting_reported = true;
            info_report("ps3-ppu: lv2: sys_btsetting_if(cmd 0x%" PRIx64 "): no "
                        "Bluetooth hardware, acknowledged",
                        (uint64_t)cpu->env.gpr[3]);
        }
        ret = 0;
        break;
    /*
     * lv2's AV service: the console's display layer asks it what the sink is
     * before it selects a mode, then hands over the framebuffer it rendered
     * into.  ps3-vga is that sink here, so the calls go straight to it: the
     * guest reads the HDMI EDID (720p/1080p modes included) and then owns the
     * scanout, which the overlay still composes its console lines over.
     */
    case 0x2A0: {               /* av: read the sink's EDID */
        uint8_t edid[256];
        unsigned n;

        if (!a0 || (uint64_t)a0 + a1 > ram_size || !a1) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        n = ps3_vga_hdmi_edid(edid, MIN(a1, (uint32_t)sizeof(edid)));
        memcpy(ram + a0, edid, n);
        if (!s->lv2_av_reported) {
            s->lv2_av_reported = true;
            info_report("ps3-ppu: lv2: av: guest read the HDMI EDID "
                        "(%u bytes): sink 1, up to 1920x1080", n);
        }
        ret = n;
        break;
    }
    case 0x2A1:                 /* av: guest gives us its framebuffer */
        ps3_vga_guest_scanout(a0, a1, a2, a3);
        ret = 0;
        break;
    case 0x345: {               /* sys_fs_mount(dev, fs, path, ...) */
        char dev[128];

        ret = 0;
        if (ps3_lv2_guest_string(ram, ram_size, a0, dev, sizeof(dev))) {
            info_report("ps3-ppu: lv2: sys_fs_mount(%s)", dev);
        }
        break;
    }
    case 0x346:                 /* sys_fs_unmount(dev) */
    case 0x347:                 /* sys_fs_sync */
    case 0x348: {               /* sys_fs_disk_free(path, free*, avail*) */
        uint64_t total = s->hdd_size ?: (20 * GiB);

        if (a1 && (uint64_t)a1 + 8 <= ram_size) {
            ps3_put_be64(ram + a1, total);
        }
        if (a2 && (uint64_t)a2 + 8 <= ram_size) {
            ps3_put_be64(ram + a2, total);
        }
        ret = 0;
        break;
    }
    case 0x320:                 /* sys_fs_test(dev, ...) */
    case 0x32F:                 /* sys_fs_utime(path, time*) */
    case 0x331: {               /* sys_fs_fcntl(fd, op, arg, size) */
        /*
         * The VSH's own file library does its positional I/O through this
         * call, not through sys_fs_read: a silent success with no result
         * written leaves the caller's buffer untouched and its file position
         * unadvanced, which is how a resource came to be decompressed from the
         * middle of a zlib stream.  The operations the library uses are the
         * read/write-with-offset pair, whose argument block carries the buffer,
         * the offset, the size and the two results.
         */
        uint32_t op = a1, arg = a2;
        uint32_t blk_len = cpu->env.gpr[6];

        if (s->ppu_trace) {
            info_report("ps3-ppu: lv2: fcntl(fd %d, op 0x%X, 0x%X, 0x%X)",
                        (int)a0, op, arg, blk_len);
        }
        if (op == 0xC0000006) {
            /* The mountpoint query: its block carries out_code at 0x18 and
             * out_id at 0x1C, and the firmware answers "not supported" for a
             * point it does not handle.  Leaving them untouched let the caller
             * read its own uninitialised stack instead. */
            if (!arg || (uint64_t)arg + 0x20 > ram_size) {
                ret = PS3_LV2_EFAULT;
                break;
            }
            ps3_put_be32(ram + arg + 0x18, 0x80010003);     /* CELL_ENOTSUP */
            ps3_put_be32(ram + arg + 0x1C, 0);
            ret = 0;
            break;
        }
        if (op != 0x8000000a && op != 0x8000000b) {
            ret = 0;
            break;
        }
        if (!arg || (uint64_t)arg + 0x40 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        {
            uint8_t *blk = ram + arg;
            uint32_t buf = ps3_be32(blk + 0x18);
            uint64_t off = ps3_be64(blk + 0x20);
            uint64_t size = ps3_be64(blk + 0x28);
            int hfd = ps3_lv2_fd_host(s, a0);
            size_t done;

            if (s->ppu_trace) {
                info_report("ps3-ppu: lv2:   fcntl block: buf 0x%X off 0x%"
                            PRIX64 " size 0x%" PRIX64, buf, off, size);
            }
            if (hfd < 0) {
                ret = PS3_LV2_EINVAL;
                break;
            }
            if (!buf || buf >= ram_size) {
                ret = PS3_LV2_EFAULT;
                break;
            }
            size = MIN(size, ram_size - buf);
            if (lseek(hfd, (off_t)off, SEEK_SET) < 0) {
                ret = ps3_lv2_fs_error(errno);
                break;
            }
            done = op == 0x8000000a ?
                   (size_t)read(hfd, ram + buf, size) :
                   (size_t)write(hfd, ram + buf, size);
            if ((ssize_t)done < 0) {
                ret = ps3_lv2_fs_error(errno);
                break;
            }
            ps3_put_be32(blk + 0x30, 0);        /* out_code: CELL_OK */
            ps3_put_be64(blk + 0x34, done);     /* out_size */
        }
        ret = 0;
        break;
    }
    case 0x333:                 /* sys_fs_fdatasync(fd) */
    case 0x334:                 /* sys_fs_fsync(fd) */
    case 0x342:                 /* sys_fs_chmod(path, mode) */
    case 0x343:                 /* sys_fs_chown(path, uid, gid) */
    case 0x344:                 /* sys_fs_newfs(dev, ...) */
        ret = 0;
        break;
    case 0x321: {               /* sys_fs_open(path, flags, fd*, mode, arg) */
        g_autofree gchar *host = ps3_lv2_path(s, ram, ram_size, a0);
        int host_flags, hfd, gfd;

        if (s->ppu_trace) {
            char path[160];

            if (ps3_lv2_guest_string(ram, ram_size, a0, path, sizeof(path))) {
                info_report("ps3-ppu: lv2: open(%s) flags 0x%08X (lr=0x%" PRIX64
                            ")", path, (unsigned)a1, (uint64_t)cpu->env.lr);
            }
        }
        if (!host) {
            /* Name the path: a missing one is what a boot that stops early
             * is usually waiting on, and the guest only sees ENOENT. */
            if (s->ppu_trace) {
                char path[160];

                if (ps3_lv2_guest_string(ram, ram_size, a0, path,
                                         sizeof(path))) {
                    info_report("ps3-ppu: lv2: open(%s): no such path in "
                                "the model (lr=0x%" PRIX64 ")", path,
                                (uint64_t)cpu->env.lr);
                }
            }
            ret = PS3_LV2_ENOENT;
            break;
        }
        if (!a2 || (uint64_t)a2 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }

        switch (a1 & 3) {
        case 0:
            host_flags = O_RDONLY;
            break;
        case 1:
            host_flags = O_WRONLY;
            break;
        default:
            host_flags = O_RDWR;
            break;
        }
        if (a1 & 0100) {
            host_flags |= O_CREAT;
        }
        if (a1 & 0200) {
            host_flags |= O_EXCL;
        }
        if (a1 & 01000) {
            host_flags |= O_TRUNC;
        }
        if (a1 & 02000) {
            host_flags |= O_APPEND;
        }

        /*
         * A guest file is a byte stream.  The Windows CRT opens in text mode
         * unless told otherwise, and there a read stops at the first 0x1A and
         * drops every CR - an 8192-byte block of an RCO or a SELF came back as
         * 76 or 4499 bytes and the file's contents were shifted.  The guest saw
         * short reads and gave up, which is what "resource load failed" was.
         */
        hfd = g_open(host, host_flags | O_BINARY, a3 ? a3 : 0644);
        if (hfd < 0) {
            if (s->ppu_trace) {
                char path[160];

                ps3_lv2_guest_string(ram, ram_size, a0, path, sizeof(path));
                info_report("ps3-ppu: lv2: open(%s) -> %s: %s (lr=0x%" PRIX64
                            ")", path, host, strerror(errno),
                            (uint64_t)cpu->env.lr);
            }
            ret = ps3_lv2_fs_error(errno);
            break;
        }

        gfd = ps3_lv2_fd_alloc(s, hfd);
        if (gfd < 0) {
            close(hfd);
            ret = PS3_LV2_EIO;
            break;
        }

        ps3_put_be32(ram + a2, gfd);
        ret = 0;
        break;
    }
    case 0x322: {               /* sys_fs_read(fd, buf, nbytes, nread*) */
        int hfd = ps3_lv2_fd_host(s, a0);
        uint64_t n = cpu->env.gpr[5];
        int64_t before;
        ssize_t got;

        if (hfd < 0) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        if (!a1 || a1 >= ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        n = MIN(n, ram_size - a1);
        before = (int64_t)lseek(hfd, 0, SEEK_CUR);
        got = read(hfd, ram + a1, n);
        if (got < 0) {
            ret = ps3_lv2_fs_error(errno);
            break;
        }
        if (s->ppu_trace) {
            struct stat st;

            if (fstat(hfd, &st) != 0) {
                st.st_size = -1;
            }
            info_report("ps3-ppu: lv2: read(fd %d, 0x%X, %" PRIu64 ") -> %"
                        PRId64 " (lr=0x%" PRIX64 ") [host fd %d, offset before "
                        "0x%" PRIX64 ", size 0x%" PRIX64 "]",
                        (int)a0, (unsigned)a1, n, (int64_t)got,
                        (uint64_t)cpu->env.lr, hfd, (uint64_t)before,
                        (uint64_t)st.st_size);
            if (got >= 8) {
                info_report("ps3-ppu: lv2:   first bytes %02X %02X %02X %02X "
                            "%02X %02X %02X %02X",
                            ram[a1], ram[a1 + 1], ram[a1 + 2], ram[a1 + 3],
                            ram[a1 + 4], ram[a1 + 5], ram[a1 + 6], ram[a1 + 7]);
            }
        }
        if (a3 && (uint64_t)a3 + 8 <= ram_size) {
            ps3_put_be64(ram + a3, got);
        }
        ret = 0;
        break;
    }
    case 0x323: {               /* sys_fs_write(fd, buf, nbytes, nwrite*) */
        int hfd = ps3_lv2_fd_host(s, a0);
        uint64_t n = cpu->env.gpr[5];
        ssize_t put;

        if (hfd < 0) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        if (!a1 || a1 >= ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        n = MIN(n, ram_size - a1);
        put = write(hfd, ram + a1, n);
        if (put < 0) {
            ret = ps3_lv2_fs_error(errno);
            break;
        }
        if (a3 && (uint64_t)a3 + 8 <= ram_size) {
            ps3_put_be64(ram + a3, put);
        }
        ret = 0;
        break;
    }
    case 0x324: {               /* sys_fs_close(fd) */
        int hfd = ps3_lv2_fd_host(s, a0);

        if (hfd < 0) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        s->lv2_fd_open[a0 - 3] = false;
        close(hfd);
        ret = 0;
        break;
    }
    case 0x325:                 /* sys_fs_opendir(path, fd*) */
        ret = ps3_lv2_fs_opendir(s, ram, ram_size, a0, a1);
        break;
    case 0x326:                 /* sys_fs_readdir(fd, dirent*, nread*) */
        ret = ps3_lv2_fs_readdir(s, ram, ram_size, a0, a1, a2);
        break;
    case 0x327:                 /* sys_fs_closedir(fd) */
        ret = ps3_lv2_fs_closedir(s, a0);
        break;
    case 0x328: {               /* sys_fs_stat(path, stat*) */
        g_autofree gchar *host = ps3_lv2_path(s, ram, ram_size, a0);
        GStatBuf st;

        if (s->ppu_trace) {
            char path[160];

            if (ps3_lv2_guest_string(ram, ram_size, a0, path, sizeof(path))) {
                info_report("ps3-ppu: lv2: stat(%s) (lr=0x%" PRIX64 ")", path,
                            (uint64_t)cpu->env.lr);
            }
        }
        if (!host) {
            ret = PS3_LV2_ENOENT;
            break;
        }
        if (!a1 || (uint64_t)a1 + 0x34 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        if (g_stat(host, &st) != 0) {
            ret = ps3_lv2_fs_error(errno);
            break;
        }
        ps3_lv2_stat(ram + a1, S_ISDIR(st.st_mode), st.st_atime,
                     st.st_mtime, st.st_ctime, st.st_size);
        ret = 0;
        break;
    }
    case 0x329: {               /* sys_fs_fstat(fd, stat*) */
        int hfd = ps3_lv2_fd_host(s, a0);
        struct stat st;

        if (hfd < 0) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        if (!a1 || (uint64_t)a1 + 0x34 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        if (fstat(hfd, &st) != 0) {
            ret = ps3_lv2_fs_error(errno);
            break;
        }
        ps3_lv2_stat(ram + a1, S_ISDIR(st.st_mode), st.st_atime,
                     st.st_mtime, st.st_ctime, st.st_size);
        ret = 0;
        break;
    }
    case 0x32B: {               /* sys_fs_mkdir(path, mode) */
        g_autofree gchar *host = ps3_lv2_path(s, ram, ram_size, a0);

        if (!host) {
            ret = PS3_LV2_ENOENT;
            break;
        }
        if (g_mkdir(host, 0755) != 0) {
            /* A MakePath that walks an existing tree must not fail on it. */
            if (errno == EEXIST && g_file_test(host, G_FILE_TEST_IS_DIR)) {
                ret = 0;
                break;
            }
            ret = ps3_lv2_fs_error(errno);
            break;
        }
        ret = 0;
        break;
    }
    case 0x32C: {               /* sys_fs_rename(from, to) */
        g_autofree gchar *from = ps3_lv2_path(s, ram, ram_size, a0);
        g_autofree gchar *to = ps3_lv2_path(s, ram, ram_size, a1);

        if (!from || !to) {
            ret = PS3_LV2_ENOENT;
            break;
        }
        if (g_rename(from, to) != 0) {
            ret = ps3_lv2_fs_error(errno);
            break;
        }
        ret = 0;
        break;
    }
    case 0x32D: {               /* sys_fs_rmdir(path) */
        g_autofree gchar *host = ps3_lv2_path(s, ram, ram_size, a0);

        if (!host) {
            ret = PS3_LV2_ENOENT;
            break;
        }
        if (g_rmdir(host) != 0) {
            ret = ps3_lv2_fs_error(errno);
            break;
        }
        ret = 0;
        break;
    }
    case 0x32E: {               /* sys_fs_unlink(path) */
        g_autofree gchar *host = ps3_lv2_path(s, ram, ram_size, a0);

        if (!host) {
            ret = PS3_LV2_ENOENT;
            break;
        }
        if (g_unlink(host) != 0) {
            ret = ps3_lv2_fs_error(errno);
            break;
        }
        ret = 0;
        break;
    }
    case 0x330: {               /* sys_fs_access(path, mode) */
        g_autofree gchar *host = ps3_lv2_path(s, ram, ram_size, a0);

        if (!host || !g_file_test(host, G_FILE_TEST_EXISTS)) {
            ret = PS3_LV2_ENOENT;
            break;
        }
        ret = 0;
        break;
    }
    case 0x332: {               /* sys_fs_lseek(fd, offset, whence, pos*) */
        int hfd = ps3_lv2_fd_host(s, a0);
        off_t pos;
        uint32_t out = cpu->env.gpr[6];

        if (hfd < 0) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        /*
         * (`fd', `offset', `whence', `pos*'): the out pointer is the fourth
         * argument.  Reading whence from the fifth read the pointer itself as
         * a whence and every rewind failed with EINVAL, which the guest sees
         * as EIO - the VSH's file loops then retried forever.
         */
        pos = lseek(hfd, (off_t)cpu->env.gpr[4], cpu->env.gpr[5]);
        if (pos < 0) {
            ret = ps3_lv2_fs_error(errno);
            break;
        }
        if (out && (uint64_t)out + 8 <= ram_size) {
            ps3_put_be64(ram + out, pos);
        }
        if (s->ppu_trace) {
            info_report("ps3-ppu: lv2: lseek(fd %d, %" PRId64 ", %u) -> "
                        "0x%" PRIX64 " (lr=0x%" PRIX64 ")",
                        (int)a0, (int64_t)cpu->env.gpr[4],
                        (unsigned)cpu->env.gpr[5], (uint64_t)pos,
                        (uint64_t)cpu->env.lr);
        }
        ret = 0;
        break;
    }
    case 0x335:                 /* sys_fs_fget_block_size(fd, sector*, block*,
                                 * arg4*, flags*) */
    case 0x336: {               /* sys_fs_get_block_size(path, sector*, block*,
                                 * arg4*) */
        uint64_t values[3] = { PS3_LV2_SECTOR, 4096, 0 };
        uint32_t addrs[3] = { a1, a2, a3 };
        unsigned n;

        for (n = 0; n < 3; n++) {
            if (addrs[n] && (uint64_t)addrs[n] + 8 <= ram_size) {
                ps3_put_be64(ram + addrs[n], values[n]);
            }
        }
        ret = 0;
        break;
    }
    case 0x33F: {               /* sys_fs_truncate(path, size) */
        g_autofree gchar *host = ps3_lv2_path(s, ram, ram_size, a0);
        int hfd;

        if (!host) {
            ret = PS3_LV2_ENOENT;
            break;
        }
        hfd = g_open(host, O_WRONLY | O_BINARY, 0);
        if (hfd < 0) {
            ret = ps3_lv2_fs_error(errno);
            break;
        }
        if (ftruncate(hfd, (off_t)cpu->env.gpr[4]) != 0) {
            ret = ps3_lv2_fs_error(errno);
            close(hfd);
            break;
        }
        close(hfd);
        ret = 0;
        break;
    }
    case 0x340: {               /* sys_fs_ftruncate(fd, size) */
        int hfd = ps3_lv2_fd_host(s, a0);

        if (hfd < 0) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        if (ftruncate(hfd, (off_t)cpu->env.gpr[4]) != 0) {
            ret = ps3_lv2_fs_error(errno);
            break;
        }
        ret = 0;
        break;
    }
    /*
     * The SPEs.  libspu reaches lv2 through these calls: an application imports
     * its SPU ELF, creates a group, initialises one thread per SPE with
     * arg1..arg4 and starts the group.  The model loads the image into the
     * thread's local store, runs it against guest RAM and reports its stop
     * code, so the PPU side sees the results a real SPE would have left.
     */
    case 0x09B: {               /* _sys_spu_image_get_information(img,
                                 * entry*, nsegs*) */
        PS3SPUImage *img;

        if (!a0 || (uint64_t)a0 + 0x10 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        img = ps3_spu_lv2_image(s, ps3_be32(ram + a0 + 4));
        if (!img) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (a1 && (uint64_t)a1 + 4 <= ram_size) {
            ps3_put_be32(ram + a1, img->entry);
        }
        if (a2 && (uint64_t)a2 + 4 <= ram_size) {
            ps3_put_be32(ram + a2, img->nsegs);
        }
        ret = 0;
        break;
    }
    case 0x09C: {               /* sys_spu_image_open(img, path) */
        g_autofree gchar *host = ps3_lv2_path(s, ram, ram_size, a1);
        g_autofree gchar *data = NULL;
        gsize len = 0;
        uint32_t base, end;
        PS3SPUImage *img;

        if (!a0 || (uint64_t)a0 + 0x10 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        if (!host || !g_file_get_contents(host, &data, &len, NULL) || !len) {
            ret = PS3_LV2_ENOENT;
            break;
        }
        base = (s->lv2_heap + 0xFF) & ~0xFFu;
        end = (base + (uint32_t)len + 0xFF) & ~0xFFu;
        if (end < base || (uint64_t)end + 0x100 > ram_size) {
            ret = PS3_LV2_ENOMEM;
            break;
        }
        memcpy(ram + base, data, len);
        s->lv2_heap = end;
        ps3_put_be32(ram + PS3_LV2_HEAP, end);

        img = ps3_spu_lv2_image_new(s, ram + base, len, base);
        if (!img) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        ps3_spu_lv2_publish(ram, ram_size, a0, img);
        ret = 0;
        break;
    }
    case 0x09D: {               /* _sys_spu_image_import(img, src, size,
                                 * type) */
        PS3SPUImage *img;

        if (!a0 || (uint64_t)a0 + 0x10 > ram_size ||
            !a1 || !a2 || (uint64_t)a1 + a2 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        img = ps3_spu_lv2_image_new(s, ram + a1, a2, a1);
        if (!img) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        ps3_spu_lv2_publish(ram, ram_size, a0, img);
        ret = 0;
        break;
    }
    case 0x09E: {               /* _sys_spu_image_close(img) */
        PS3SPUImage *img;

        if (!a0 || (uint64_t)a0 + 0x10 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        img = ps3_spu_lv2_image(s, ps3_be32(ram + a0 + 4));
        if (!img) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        img->used = false;
        ret = 0;
        break;
    }
    case 0x09F: {               /* _sys_spu_image_get_segments(img, segs*,
                                 * nseg) */
        PS3SPUImage *img;
        unsigned n, count;

        if (!a0 || (uint64_t)a0 + 0x10 > ram_size || (int32_t)a3 <= 0) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        img = ps3_spu_lv2_image(s, ps3_be32(ram + a0 + 4));
        if (!img) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        count = MIN((unsigned)a3, img->nsegs);
        for (n = 0; n < count; n++) {
            uint32_t at = a1 + n * 0x18;

            if (!a1 || (uint64_t)at + 0x18 > ram_size) {
                break;
            }
            ps3_put_be32(ram + at, img->seg[n].type);
            ps3_put_be32(ram + at + 0x04, img->seg[n].ls);
            ps3_put_be32(ram + at + 0x08, img->seg[n].size);
            ps3_put_be32(ram + at + 0x0C, img->seg[n].addr);
            ps3_put_be64(ram + at + 0x10, 0);
        }
        ret = 0;
        break;
    }
    case 0x0A5: {               /* sys_spu_thread_get_exit_status(id,
                                 * status*) */
        PS3SPU *spu = ps3_spu_lv2_thread(s, a0, NULL);

        if (!spu) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (a1 && (uint64_t)a1 + 4 <= ram_size) {
            ps3_put_be32(ram + a1,
                         ps3_spe_halted(spu) ? ps3_spu_stop_code(spu) : 0);
        }
        ret = 0;
        break;
    }
    case 0x0A6: {               /* sys_spu_thread_set_argument(id, arg*) */
        PS3SPU *spu = ps3_spu_lv2_thread(s, a0, NULL);
        unsigned n;

        if (!spu) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (!a1 || (uint64_t)a1 + 0x20 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        for (n = 0; n < 4; n++) {
            ps3_spu_set_gpr64(spu, 3 + n, ps3_be64(ram + a1 + n * 8));
        }
        ret = 0;
        break;
    }
    case 0x0A9:                 /* sys_spu_initialize(usable, raw) */
        info_report("ps3-ppu: sys_spu_initialize(%u usable, %u raw)",
                    a0, a1);
        ret = 0;
        break;
    case 0x0AA: {               /* sys_spu_thread_group_create(id*, num, prio,
                                 * attr*) */
        PS3SPULv2Group *g;
        uint32_t gid = 0;

        if (!a0 || (uint64_t)a0 + 4 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        g = ps3_spu_lv2_group_new(s, ram, ram_size, a1, &gid);
        if (!g) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        ps3_put_be32(ram + a0, gid);
        info_report("ps3-ppu: spu group 0x%X: %u SPE(s), priority %d",
                    gid, a1, (int32_t)a2);
        ret = 0;
        break;
    }
    case 0x0AB: {               /* sys_spu_thread_group_destroy(id) */
        PS3SPULv2Group *g = ps3_spu_lv2_group(s, a0);

        if (!g) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        ps3_spu_lv2_group_free(g);
        ret = 0;
        break;
    }
    case 0x0AC: {               /* sys_spu_thread_initialize(thread*,
                                 * group, spu_num, img*, attr*, arg*) */
        PS3SPUImage user = { 0 }, *img = &user;
        PS3SPULv2Group *g;
        PS3SPU *spu;
        unsigned n;

        if (!a3 || (uint64_t)a3 + 0x10 > ram_size) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        g = ps3_spu_lv2_group(s, a1);
        if (!g) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (a2 >= g->count) {
            ret = PS3_LV2_EINVAL;
            break;
        }

        if (ps3_be32(ram + a3) == 1) {
            /* A kernel image: `entry_point' is the model's image id. */
            img = ps3_spu_lv2_image(s, ps3_be32(ram + a3 + 4));
            if (!img) {
                ret = PS3_LV2_ESRCH;
                break;
            }
        } else if (ps3_be32(ram + a3) == 0) {
            /* A user image: the segments themselves are guest memory. */
            uint32_t entry = ps3_be32(ram + a3 + 4);
            uint32_t segs = ps3_be32(ram + a3 + 8);
            uint32_t nsegs = ps3_be32(ram + a3 + 0xC);

            if (!entry || entry >= PS3_LS_SIZE || !segs ||
                !nsegs || nsegs > 0x20) {
                ret = PS3_LV2_EINVAL;
                break;
            }
            user.entry = entry;
            user.nsegs = nsegs;
            for (n = 0; n < nsegs; n++) {
                uint32_t at = segs + n * 0x18;

                if ((uint64_t)at + 0x18 > ram_size) {
                    break;
                }
                user.seg[n].type = ps3_be32(ram + at);
                user.seg[n].ls = ps3_be32(ram + at + 0x04);
                user.seg[n].size = ps3_be32(ram + at + 0x08);
                user.seg[n].addr = ps3_be32(ram + at + 0x0C);
            }
        } else {
            ret = PS3_LV2_EINVAL;
            break;
        }

        spu = ps3_spes_spu(g->spes, a2);
        if (!ps3_spu_lv2_deploy(spu, img, ram, ram_size)) {
            ret = PS3_LV2_EFAULT;
            break;
        }
        if (a5 && (uint64_t)a5 + 0x20 <= ram_size) {
            for (n = 0; n < 4; n++) {
                ps3_spu_set_gpr64(spu, 3 + n, ps3_be64(ram + a5 + n * 8));
            }
        }
        g->thread[a2] = true;
        /* thread* is the first argument: lv2 hands back group_id | spu_num. */
        if (a0 && (uint64_t)a0 + 4 <= ram_size) {
            ps3_put_be32(ram + a0, g->id | a2);
        }
        ret = 0;
        break;
    }
    case 0x0A7:                 /* sys_spu_thread_group_start_on_exit */
        ret = 0;
        break;
    case 0x0AD: {               /* sys_spu_thread_group_start(id) */
        PS3SPULv2Group *g = ps3_spu_lv2_group(s, a0);
        unsigned n;

        if (!g) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        for (n = 0; n < g->count; n++) {
            if (g->thread[n]) {
                ps3_spe_run(ps3_spes_spu(g->spes, n), true);
            }
        }
        g->started = true;
        g->terminated = false;
        ps3_spu_lv2_pump(s, 1u << 20);
        ret = 0;
        break;
    }
    case 0x0AE:                 /* sys_spu_thread_group_suspend(id) */
    case 0x0AF: {               /* sys_spu_thread_group_resume(id) */
        PS3SPULv2Group *g = ps3_spu_lv2_group(s, a0);
        bool run = (nr == 0x0AF);
        unsigned n;

        if (!g) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        for (n = 0; n < g->count; n++) {
            if (g->thread[n]) {
                ps3_spe_run(ps3_spes_spu(g->spes, n), run);
            }
        }
        if (run) {
            ps3_spu_lv2_pump(s, 1u << 14);
        }
        ret = 0;
        break;
    }
    case 0x0B0:                 /* sys_spu_thread_group_yield(id) */
        ps3_spu_lv2_pump(s, 1u << 14);
        ret = 0;
        break;
    case 0x0B1: {               /* sys_spu_thread_group_terminate(id,
                                 * status) */
        PS3SPULv2Group *g = ps3_spu_lv2_group(s, a0);
        unsigned n;

        if (!g) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        for (n = 0; n < g->count; n++) {
            if (g->thread[n]) {
                ps3_spe_run(ps3_spes_spu(g->spes, n), false);
            }
        }
        g->terminated = true;
        g->started = false;
        g->exit_cause = 1;
        if (a1) {
            info_report("ps3-ppu: spu group 0x%X terminated with status %d",
                        g->id, (int32_t)a1);
        }
        ret = 0;
        break;
    }
    case 0x0B2: {               /* sys_spu_thread_group_join(id, cause*,
                                 * status*, timeout*) */
        PS3SPULv2Group *g = ps3_spu_lv2_group(s, a0);

        if (!g) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        ps3_spu_lv2_pump(s, 1u << 22);
        if (a1 && (uint64_t)a1 + 4 <= ram_size) {
            ps3_put_be32(ram + a1, g->exit_cause ? g->exit_cause : 1);
        }
        if (a2 && (uint64_t)a2 + 4 <= ram_size) {
            ps3_put_be32(ram + a2, 0);
        }
        ret = 0;
        break;
    }
    case 0x0B3:                 /* sys_spu_thread_group_set_priority */
        ret = 0;
        break;
    case 0x0B4: {               /* sys_spu_thread_group_get_priority(id,
                                 * prio*) */
        PS3SPULv2Group *g = ps3_spu_lv2_group(s, a0);

        if (!g) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (a1 && (uint64_t)a1 + 4 <= ram_size) {
            ps3_put_be32(ram + a1, 0);
        }
        ret = 0;
        break;
    }
    case 0x0B5: {               /* sys_spu_thread_write_ls(id, lsa, value,
                                 * type) */
        PS3SPU *spu = ps3_spu_lv2_thread(s, a0, NULL);
        unsigned bytes = a3, n;
        uint8_t buf[8];
        uint64_t value = cpu->env.gpr[7];

        if (!spu) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (!bytes || bytes > 8 || (bytes & (bytes - 1)) ||
            (a1 & (bytes - 1)) || a1 >= PS3_LS_SIZE) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        for (n = 0; n < bytes; n++) {
            buf[n] = (uint8_t)(value >> (8 * (bytes - 1 - n)));
        }
        ps3_spu_load_ls(spu, a1, buf, bytes);
        ret = 0;
        break;
    }
    case 0x0B6: {               /* sys_spu_thread_read_ls(id, lsa, value*,
                                 * type) */
        PS3SPU *spu = ps3_spu_lv2_thread(s, a0, NULL);
        unsigned bytes = a3;
        uint8_t buf[8];
        uint64_t value = 0;

        if (!spu) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (!bytes || bytes > 8 || (bytes & (bytes - 1)) ||
            (a1 & (bytes - 1)) || a1 >= PS3_LS_SIZE ||
            !a2 || (uint64_t)a2 + 8 > ram_size) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        memcpy(buf, ps3_spu_ls_ptr(spu, a1), bytes);
        for (unsigned n = 0; n < bytes; n++) {
            value = (value << 8) | buf[n];
        }
        ps3_put_be64(ram + a2, value);
        ret = 0;
        break;
    }
    case 0x0B8: {               /* sys_spu_thread_write_snr(id, number,
                                 * value) */
        PS3SPU *spu = ps3_spu_lv2_thread(s, a0, NULL);

        if (!spu) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (a1 != 1 && a1 != 2) {
            ret = PS3_LV2_EINVAL;
            break;
        }
        ps3_spe_set_signal(spu, a1 - 1, a2);
        ps3_spu_lv2_pump(s, 1u << 12);
        ret = 0;
        break;
    }
    case 0x0B9:                 /* sys_spu_thread_group_connect_event */
    case 0x0BA:                 /* sys_spu_thread_group_disconnect_event */
    case 0x0BF:                 /* sys_spu_thread_connect_event */
    case 0x0C0:                 /* sys_spu_thread_disconnect_event */
        ret = 0;
        break;
    case 0x0BB: {               /* sys_spu_thread_set_spu_cfg(id, cfg) */
        PS3SPULv2Group *g = NULL;
        PS3SPU *spu = ps3_spu_lv2_thread(s, a0, &g);

        if (!spu) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        g->cfg[a0 & 0xFF] = a1;
        ret = 0;
        break;
    }
    case 0x0BC: {               /* sys_spu_thread_get_spu_cfg(id, cfg*) */
        PS3SPULv2Group *g = NULL;
        PS3SPU *spu = ps3_spu_lv2_thread(s, a0, &g);

        if (!spu) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        if (a1 && (uint64_t)a1 + 4 <= ram_size) {
            ps3_put_be32(ram + a1, g->cfg[a0 & 0xFF]);
        }
        ret = 0;
        break;
    }
    case 0x0BE: {               /* sys_spu_thread_write_spu_mb(id, value) */
        PS3SPU *spu = ps3_spu_lv2_thread(s, a0, NULL);

        if (!spu) {
            ret = PS3_LV2_ESRCH;
            break;
        }
        ps3_spe_push_in_mbox(spu, a1);
        ps3_spu_lv2_pump(s, 1u << 12);
        ret = 0;
        break;
    }
    default:
        if (s->ppu_trace) {
            info_report("ps3-ppu: lv2 syscall 0x%X is not modelled", nr);
        }
        break;
    }

publish:
    if (s->ppu_trace && ret) {
        info_report("ps3-ppu: lv2 syscall 0x%X returned 0x%X (lr=0x%" PRIX64
                    ")", nr, (uint32_t)ret, (uint64_t)cpu->env.lr);
    }
    ps3_put_be32(ram + PS3_LV2_SCRATCH, (uint32_t)ret);
    /*
     * The exit flag belongs to this call alone: a stale one would park the
     * next call the guest makes, whatever it is.
     */
    ps3_put_be32(ram + PS3_LV2_SCRATCH + 4, s->lv2_park ? 1 : 0);
    s->lv2_park = false;
}

static void rs6000_ps3_lv2_page(MemoryRegion *sysmem, MemoryRegion *ram);

/*
 * The HDD: one raw image of the size a superslim ships with.  A console's
 * disk is not encrypted with PCK1 itself - PCK1 is the root - but with the
 * ATA data and tweak keys derived from it (lv1ldr runs the AES-256-CBC
 * ladder over the two SB seeds; the seeds are at 0x1B5C0 and 0x1B600 in the
 * 4.93 lv1ldr ELF, which is why they are in that loader and not in
 * sb_iso_spu_module.self).  The keys are also kept on the disk itself: sector
 * 0 holds them wrapped under PCK1, so a console with its EID root key can
 * read any disk it ever wrote.
 *
 * The model therefore stores the image exactly as a console's disk is stored:
 * sector 0 AES-256-CBC under the EID root key, every other sector XTS-AES
 * under the ATA keys.  Nothing in this file carries a console's key - the
 * root key comes from `erk' or `erk-file', i.e. from the user's own dump.
 */

#define PS3_HDD_KEY_SECTOR  0

/* Sector 0, once unwrapped under PCK1: magic, data key, tweak key, zeros. */
static const uint8_t ps3_hdd_key_magic[8] = {
    'P', 'S', '3', 'A', 'T', 'A', '0', '1',
};

static void ps3_hdd_key_sector_build(PS3BootROMState *s, uint8_t *plain)
{
    memset(plain, 0, PS3_LV2_SECTOR);
    memcpy(plain, ps3_hdd_key_magic, sizeof(ps3_hdd_key_magic));
    memcpy(plain + 0x08, s->hdd_data_key, 32);
    memcpy(plain + 0x28, s->hdd_tweak_key, 32);
}

/*
 * Sector 0 is the one sector PCK1 encrypts directly, which is what makes the
 * rest of the disk readable: decrypt it, and the ATA keys are there.
 */
static bool ps3_hdd_key_sector_read(PS3BootROMState *s, uint8_t *plain)
{
    uint8_t raw[PS3_LV2_SECTOR];

    if (!s->hdd || !s->has_erk) {
        return false;
    }

    if (blk_pread(s->hdd, 0, sizeof(raw), raw, 0) < 0) {
        return false;
    }

    ps3_aes_cbc256_decrypt(s->erk, s->erk + 32, raw, plain, sizeof(raw));

    return !memcmp(plain, ps3_hdd_key_magic, sizeof(ps3_hdd_key_magic));
}

static bool ps3_hdd_key_sector_write(PS3BootROMState *s)
{
    uint8_t plain[PS3_LV2_SECTOR], raw[PS3_LV2_SECTOR];

    if (!s->hdd || !s->has_erk) {
        return false;
    }

    ps3_hdd_key_sector_build(s, plain);
    ps3_aes_cbc256_encrypt(s->erk, s->erk + 32, plain, raw, sizeof(raw));

    return blk_pwrite(s->hdd, 0, sizeof(raw), raw, 0) == 0;
}

/*
 * Sectors the guest reads and writes.  A read is decrypted on the way out and
 * a write is re-encrypted before it reaches the image, so the file on the
 * host stays the byte-for-byte disk the console wrote.
 */
static bool ps3_hdd_read(PS3BootROMState *s, uint64_t sector, void *buf,
                         size_t sectors)
{
    uint8_t *p = buf;
    size_t i;

    if (!s->hdd || sector == PS3_HDD_KEY_SECTOR || !sectors) {
        return false;
    }

    if (blk_pread(s->hdd, sector * PS3_LV2_SECTOR,
                  sectors * PS3_LV2_SECTOR, buf, 0) < 0) {
        return false;
    }

    if (!s->hdd_keyed) {
        return true;
    }

    for (i = 0; i < sectors; i++) {
        ps3_xts_crypt_sector(s->hdd_data_key, s->hdd_tweak_key,
                             sector + i, p + i * PS3_LV2_SECTOR,
                             PS3_LV2_SECTOR, false);
    }

    return true;
}

static bool ps3_hdd_write(PS3BootROMState *s, uint64_t sector, void *buf,
                          size_t sectors)
{
    uint8_t *p = buf;
    size_t i;

    if (!s->hdd || sector == PS3_HDD_KEY_SECTOR || !sectors) {
        return false;
    }

    if (s->hdd_keyed) {
        for (i = 0; i < sectors; i++) {
            ps3_xts_crypt_sector(s->hdd_data_key, s->hdd_tweak_key,
                                 sector + i, p + i * PS3_LV2_SECTOR,
                                 PS3_LV2_SECTOR, true);
        }
    }

    if (blk_pwrite(s->hdd, sector * PS3_LV2_SECTOR,
                   sectors * PS3_LV2_SECTOR, buf, 0) < 0) {
        return false;
    }

    if (s->hdd_keyed) {
        for (i = 0; i < sectors; i++) {
            ps3_xts_crypt_sector(s->hdd_data_key, s->hdd_tweak_key,
                                 sector + i, p + i * PS3_LV2_SECTOR,
                                 PS3_LV2_SECTOR, false);
        }
    }

    return true;
}
/*
 * The eMMC, sector for sector.  Every access goes through ps3_emmc_crypt with
 * the encdec keys, so the host image stays the ciphertext the console wrote
 * and the guest sees the plaintext flash; a kernel image built for this model
 * can be dropped into the same image the console uses.
 */
static bool ps3_emmc_read(PS3BootROMState *s, uint64_t sector, void *buf,
                          size_t sectors)
{
    if (!s->emmc || !sectors) {
        return false;
    }

    if (blk_pread(s->emmc, sector * PS3_LV2_SECTOR,
                  sectors * PS3_LV2_SECTOR, buf, 0) < 0) {
        return false;
    }

    if (s->emmc_keyed) {
        ps3_emmc_crypt(s->emmc_data_key, s->emmc_tweak_key, sector, buf,
                       sectors * PS3_LV2_SECTOR, false);
    }

    return true;
}

static bool ps3_emmc_write(PS3BootROMState *s, uint64_t sector, void *buf,
                           size_t sectors)
{
    g_autofree uint8_t *sealed = NULL;

    if (!s->emmc || !sectors) {
        return false;
    }

    if (s->emmc_keyed) {
        size_t len = sectors * PS3_LV2_SECTOR;

        sealed = g_memdup2(buf, len);
        ps3_emmc_crypt(s->emmc_data_key, s->emmc_tweak_key, sector, sealed,
                       len, true);
        buf = sealed;
    }

    return blk_pwrite(s->emmc, sector * PS3_LV2_SECTOR,
                      sectors * PS3_LV2_SECTOR, buf, 0) >= 0;
}

static bool ps3_emmc_setup(PS3BootROMState *s, Error **errp)
{
    Error *err = NULL;
    QDict *opts;
    int fd;

    if (!s->emmc_file) {
        if (s->has_erk) {
            info_report("ps3-boot-rom: EID root key read; encdec (eMMC) keys "
                        "derived, no eMMC image to key");
        }
        return true;
    }

    if (!g_file_test(s->emmc_file, G_FILE_TEST_EXISTS)) {
        fd = qemu_open_old(s->emmc_file, O_RDWR | O_CREAT | O_EXCL | O_BINARY,
                           0600);
        if (fd < 0) {
            error_setg_errno(errp, errno, "ps3-boot-rom: cannot create %s",
                             s->emmc_file);
            return false;
        }
        if (ftruncate(fd, s->emmc_size) < 0) {
            error_setg_errno(errp, errno, "ps3-boot-rom: cannot size %s to "
                             "%" PRIu64 " bytes", s->emmc_file,
                             s->emmc_size);
            close(fd);
            return false;
        }
        close(fd);
        s->emmc_created = true;
    }

    opts = qdict_new();
    qdict_put_str(opts, "driver", "raw");
    s->emmc = blk_new_open(s->emmc_file, NULL, opts, BDRV_O_RDWR, &err);
    if (!s->emmc) {
        error_setg(errp, "ps3-boot-rom: cannot open eMMC image %s: %s",
                   s->emmc_file,
                   err ? error_get_pretty(err) : "unknown error");
        error_free(err);
        return false;
    }

    if (s->has_erk) {
        ps3_encdec_keys(s->erk, s->emmc_data_key, s->emmc_tweak_key);
        s->emmc_keyed = true;
    }

    s->emmc_size = blk_getlength(s->emmc);

    info_report("ps3-boot-rom: eMMC: %s, %" PRIu64 " MiB raw%s%s",
                s->emmc_file, s->emmc_size / MiB,
                s->emmc_created ? " (created)" : "",
                s->emmc_keyed ? ", encdec keys from the EID root key"
                              : ", unkeyed");
    ps3_vga_printf("EMMC: %" PRIu64 " MIB, %s", s->emmc_size / MiB,
                   s->emmc_keyed ? "ENCDEC KEYS FROM EID ROOT KEY" : "UNKEYED");

    /*
     * Sector 7 is past any header a real image starts with and inside the
     * region the loaders occupy, so a decrypt/encrypt round trip there proves
     * the ladder and the IV before the guest reads the flash.
     */
    {
        uint8_t raw[PS3_LV2_SECTOR], plain[PS3_LV2_SECTOR], back[PS3_LV2_SECTOR];

        if (blk_pread(s->emmc, 7 * PS3_LV2_SECTOR, sizeof(raw), raw, 0) == 0) {
            memcpy(plain, raw, sizeof(plain));
            if (!ps3_emmc_read(s, 7, plain, 1) ||
                !ps3_emmc_write(s, 7, plain, 1)) {
                error_setg(errp, "ps3-boot-rom: eMMC sector 7 does not round "
                           "trip");
                return false;
            }
            memset(back, 0, sizeof(back));
            if (blk_pread(s->emmc, 7 * PS3_LV2_SECTOR, sizeof(back), back,
                          0) < 0 || memcmp(raw, back, sizeof(raw))) {
                error_setg(errp, "ps3-boot-rom: eMMC re-encryption did not "
                           "reproduce sector 7");
                return false;
            }
            info_report("ps3-boot-rom: eMMC sector 7: decrypt and re-encrypt "
                        "reproduce the image byte for byte");
        }
    }

    return true;
}

/*
 * Where the boot ROM looks.  A NOR boot is the default (`-drive if=pflash`),
 * but a console whose firmware lives on eMMC boots from that image, and a
 * chain staged on the disk can be booted by naming the HDD - the same
 * container search then runs over the decrypted sectors of whichever medium
 * was named.
 */
/*
 * The eMMC console's flash region begins 256 KiB into the device (the CFI
 * header and the metadata block), and its storage area begins past the
 * 256 MiB flash region.  scripts/ps3_emmc_create.py writes this layout.
 */
#define PS3_EMMC_FLASH_OFF   0x00040000u
#define PS3_EMMC_TREE_OFF    0x10040000u

static bool ps3_boot_medium_setup(PS3BootROMState *s, Error **errp)
{
    const char *medium = s->boot_medium ?: "flash";
    BlockBackend *blk;
    uint64_t len, sectors, i, base = 0;

    if (!strcmp(medium, "flash")) {
        return true;
    }

    if (!strcmp(medium, "emmc")) {
        blk = s->emmc;
        /*
         * An eMMC console's logical flash region starts 256 KiB into the
         * device: the first 0x40000 bytes are the CFI header and the flash
         * metadata block, and the Flash Region Table sits at 0x40200.  The
         * mask ROM's view - bootldr at offset 0, the container search over the
         * first 16 MiB - begins at that 0x40000, so that is what the model
         * copies.
         */
        base = PS3_EMMC_FLASH_OFF;
    } else if (!strcmp(medium, "hdd")) {
        blk = s->hdd;
    } else {
        error_setg(errp, "ps3-boot-rom: boot-medium must be flash, emmc or "
                   "hdd, not \"%s\"", medium);
        return false;
    }

    if (!blk) {
        error_setg(errp, "ps3-boot-rom: boot-medium=%s but no image was "
                   "given", medium);
        return false;
    }

    len = blk_getlength(blk);
    if (len <= 0) {
        error_setg(errp, "ps3-boot-rom: the %s image has no size", medium);
        return false;
    }
    if (base > len) {
        error_setg(errp, "ps3-boot-rom: the %s image is shorter than its "
                   "flash region starts (0x%" PRIX64 ")", medium, base);
        return false;
    }
    len -= base;
    if (len > 16 * MiB) {
        len = 16 * MiB;
    }

    sectors = len / PS3_LV2_SECTOR;
    g_free(s->flash);
    s->flash = g_malloc0(len);
    s->flash_len = len;

    if (!sectors || blk_pread(blk, base, len, s->flash, 0) < 0) {
        error_setg(errp, "ps3-boot-rom: cannot read the %s image", medium);
        return false;
    }

    if (!strcmp(medium, "emmc") && s->emmc_keyed) {
        ps3_emmc_crypt(s->emmc_data_key, s->emmc_tweak_key, 0, s->flash,
                       sectors * PS3_LV2_SECTOR, false);
    } else if (!strcmp(medium, "hdd") && s->hdd_keyed) {
        /*
         * Sector 0 of a keyed disk is the wrapped key sector, not data, and
         * the chain does not start there; leave it out of the view.
         */
        memset(s->flash, 0, PS3_LV2_SECTOR);
        for (i = 1; i < sectors; i++) {
            ps3_xts_crypt_sector(s->hdd_data_key, s->hdd_tweak_key, i,
                                 s->flash + i * PS3_LV2_SECTOR,
                                 PS3_LV2_SECTOR, false);
        }
    }

    info_report("ps3-boot-rom: boot medium %s: the container search runs over "
                "the first %" PRIu64 " MiB of %s", medium, len / MiB,
                medium);
    ps3_vga_printf("BOOT MEDIUM: %s", medium);

    return true;
}

static bool ps3_hdd_setup(PS3BootROMState *s, Error **errp)
{
    Error *err = NULL;
    uint8_t sector[PS3_LV2_SECTOR], plain[PS3_LV2_SECTOR];
    QDict *opts;
    int fd;

    if (s->erk_prop) {
        size_t len = 0;

        if (!ps3_stage_parse_hex(s->erk_prop, s->erk, sizeof(s->erk),
                                 &len) || len != sizeof(s->erk)) {
            error_setg(errp, "ps3-boot-rom: erk must be 96 hex digits (48 "
                       "bytes: the EID root key, PCK1)");
            return false;
        }
        s->has_erk = true;
    } else if (s->erk_file) {
        g_autofree gchar *buf = NULL;
        GError *gerr = NULL;
        gsize len = 0;

        if (!g_file_get_contents(s->erk_file, &buf, &len, &gerr)) {
            error_setg(errp, "ps3-boot-rom: cannot read %s: %s", s->erk_file,
                       gerr->message);
            g_error_free(gerr);
            return false;
        }
        if (len != sizeof(s->erk)) {
            error_setg(errp, "ps3-boot-rom: %s is %u byte(s), the EID root "
                       "key is 48", s->erk_file, (unsigned)len);
            return false;
        }
        memcpy(s->erk, buf, sizeof(s->erk));
        s->has_erk = true;
    }

    if (s->has_erk) {
        ps3_ata_keys(s->erk, s->hdd_data_key, s->hdd_tweak_key);
        s->hdd_keyed = true;
    }

    if (!s->hdd_file) {
        if (s->has_erk) {
            info_report("ps3-boot-rom: EID root key (PCK1) read; ATA data "
                        "and tweak keys derived, no HDD image to key");
        }
        return true;
    }

    if (!g_file_test(s->hdd_file, G_FILE_TEST_EXISTS)) {
        fd = qemu_open_old(s->hdd_file,
                           O_RDWR | O_CREAT | O_EXCL | O_BINARY, 0600);
        if (fd < 0) {
            error_setg_errno(errp, errno, "ps3-boot-rom: cannot create %s",
                             s->hdd_file);
            return false;
        }
        if (ftruncate(fd, s->hdd_size) < 0) {
            error_setg_errno(errp, errno, "ps3-boot-rom: cannot size %s to "
                             "%" PRIu64 " bytes", s->hdd_file, s->hdd_size);
            close(fd);
            return false;
        }
        close(fd);
        s->hdd_created = true;
    }

    opts = qdict_new();
    qdict_put_str(opts, "driver", "raw");
    s->hdd = blk_new_open(s->hdd_file, NULL, opts, BDRV_O_RDWR, &err);
    if (!s->hdd) {
        error_setg(errp, "ps3-boot-rom: cannot open HDD image %s: %s",
                   s->hdd_file,
                   err ? error_get_pretty(err) : "unknown error");
        error_free(err);
        return false;
    }

    /*
     * The image on disk decides the disk: `hdd-size' only sizes one the model
     * creates, and lv2's block geometry has to agree with what the guest can
     * actually read, or a smaller image reports a capacity it cannot reach.
     */
    s->hdd_size = blk_getlength(s->hdd);

    info_report("ps3-boot-rom: HDD: %s, %" PRIu64 " bytes raw%s%s",
                s->hdd_file, s->hdd_size,
                s->hdd_created ? " (created)" : "",
                s->hdd_keyed ? ", ATA keys from the EID root key" : ", unkeyed");

    if (s->hdd_keyed) {
        if (s->hdd_size >= GiB) {
            ps3_vga_printf("HDD: %" PRIu64 " GIB RAW, ATA KEYS FROM EID "
                           "ROOT KEY", s->hdd_size / GiB);
        } else {
            ps3_vga_printf("HDD: %" PRIu64 " MIB RAW, ATA KEYS FROM EID "
                           "ROOT KEY", s->hdd_size / MiB);
        }
    }

    if (!s->hdd_keyed) {
        return true;
    }

    /*
     * Read the disk's own copy of the ATA keys first: sector 0 is wrapped
     * under this console's EID root key, so a disk written by this console opens and
     * a disk written by another one does not.  A fresh image has no key
     * sector yet, so the derived keys are written there, encrypted, before
     * any data sector is touched.
     */
    if (ps3_hdd_key_sector_read(s, plain)) {
        uint8_t derived_data[32], derived_tweak[32];
        bool same;

        memcpy(s->hdd_data_key, plain + 0x08, 32);
        memcpy(s->hdd_tweak_key, plain + 0x28, 32);

        ps3_ata_keys(s->erk, derived_data, derived_tweak);
        same = !memcmp(derived_data, s->hdd_data_key, 32) &&
               !memcmp(derived_tweak, s->hdd_tweak_key, 32);

        info_report("ps3-boot-rom: HDD key sector unwrapped under the EID "
                    "root key; ATA keys %s the ones it derives",
                    same ? "match" : "differ from");
    } else if (s->hdd_created || blk_pread(s->hdd, 0, PS3_LV2_SECTOR,
                                           plain, 0) < 0 ||
               buffer_is_zero(plain, PS3_LV2_SECTOR)) {
        if (!ps3_hdd_key_sector_write(s)) {
            error_setg(errp, "ps3-boot-rom: cannot write the HDD key sector");
            return false;
        }
        info_report("ps3-boot-rom: HDD key sector written, ATA keys "
                    "re-encrypted under the EID root key");
    } else {
        info_report("ps3-boot-rom: HDD sector 0 does not open under this "
                    "EID root key; using the derived ATA keys and leaving "
                    "the image untouched");
    }

    /*
     * Prove both directions before the guest is given the disk: read sector 1
     * through the decryption path, write the same sector back through the
     * re-encryption path, and check the image on the host is unchanged.  A
     * write that does not reproduce the original ciphertext would silently
     * corrupt every file the guest saves.
     */
    if (blk_pread(s->hdd, PS3_LV2_SECTOR, PS3_LV2_SECTOR, sector, 0) == 0) {
        memcpy(plain, sector, sizeof(plain));

        if (!ps3_hdd_read(s, 1, sector, 1) ||
            !ps3_hdd_write(s, 1, sector, 1)) {
            error_setg(errp, "ps3-boot-rom: HDD sector 1 does not round trip");
            return false;
        }

        memset(sector, 0, sizeof(sector));
        if (blk_pread(s->hdd, PS3_LV2_SECTOR, PS3_LV2_SECTOR, sector, 0) < 0 ||
            memcmp(plain, sector, sizeof(plain))) {
            error_setg(errp, "ps3-boot-rom: HDD re-encryption did not "
                       "reproduce the image's sector 1");
            return false;
        }

        info_report("ps3-boot-rom: HDD sector 1: decrypt and re-encrypt "
                    "reproduce the image byte for byte");
    }

    return true;
}

/*
 * The disk's own file tree.
 *
 * A console keeps its firmware and its /dev_hdd0 files inside the disk, not
 * beside it, so an image built by scripts/ps3_hdd_tree.py carries them: a
 * superblock at 32 MiB, then one 4 KiB block per directory or file, with
 * each block read through ps3_hdd_read() so the XTS layer is the same one the
 * guest's sys_storage calls use.  When the image has this tree and the caller
 * named no host directory for a device, the tree is what the model boots
 * from: it is unpacked once into `<image>.tree` and the dev_flash roots point
 * there, so the SELF files the VSH loads are the ones stored on the disk.
 */
#define PS3_HDD_TREE_MAGIC   "PS3HDFS1"
/* Past the first 16 MiB, which boot-medium=hdd reads as the flash copy. */
#define PS3_HDD_TREE_OFF     0x02000000u
#define PS3_HDD_TREE_BLOCK   4096u
#define PS3_HDD_TREE_NAME    48
#define PS3_HDD_TREE_ENTRY   64
#define PS3_HDD_TREE_SECTORS (PS3_HDD_TREE_BLOCK / PS3_LV2_SECTOR)
#define PS3_HDD_TREE_DEPTH   12

typedef struct PS3HddTreeEnt {
    char name[PS3_HDD_TREE_NAME];
    uint8_t type;               /* 1 directory, 2 file */
    uint32_t size;
    uint64_t block;
} PS3HddTreeEnt;

/*
 * The tree sits past the flash on whichever medium carries it: 32 MiB into a
 * disk image (which keeps a 16 MiB flash copy in its first blocks), and past
 * the 256 MiB flash region on an eMMC, whose own first 256 KiB are the CFI
 * preamble.
 */
static bool ps3_hdd_tree_block(PS3BootROMState *s, uint64_t block, void *buf)
{
    uint64_t sector = block * PS3_HDD_TREE_SECTORS;
    uint64_t limit;

    if (s->tree_emmc) {
        sector += PS3_EMMC_TREE_OFF / PS3_LV2_SECTOR;
        limit = s->emmc_size;
        if ((sector + PS3_HDD_TREE_SECTORS) * PS3_LV2_SECTOR > limit) {
            return false;
        }
        return ps3_emmc_read(s, sector, buf, PS3_HDD_TREE_SECTORS);
    }

    sector += PS3_HDD_TREE_OFF / PS3_LV2_SECTOR;
    limit = s->hdd_size;
    if ((sector + PS3_HDD_TREE_SECTORS) * PS3_LV2_SECTOR > limit) {
        return false;
    }
    return ps3_hdd_read(s, sector, buf, PS3_HDD_TREE_SECTORS);
}

/*
 * A directory block starts with the block that continues it, so a directory
 * with more entries than one block holds runs as a chain.
 */
#define PS3_HDD_TREE_DIR_HEAD 8

static uint32_t ps3_hdd_tree_dir_next(const uint8_t *blk)
{
    return ps3_be32(blk);
}

/* The next entry of a directory block; `o' walks the block. */
static bool ps3_hdd_tree_entry(const uint8_t *blk, unsigned *o,
                               PS3HddTreeEnt *e)
{
    const uint8_t *p;
    unsigned len;

    if (*o < PS3_HDD_TREE_DIR_HEAD) {
        *o = PS3_HDD_TREE_DIR_HEAD;
    }
    if (*o + PS3_HDD_TREE_ENTRY > PS3_HDD_TREE_BLOCK) {
        return false;
    }
    p = blk + *o;

    len = p[0];
    if (!len) {
        return false;
    }
    if (len >= PS3_HDD_TREE_NAME) {
        len = PS3_HDD_TREE_NAME - 1;
    }

    memcpy(e->name, p + 16, len);
    e->name[len] = 0;
    e->type = p[1];
    e->size = ps3_be32(p + 4);
    e->block = ps3_be64(p + 8);

    *o += PS3_HDD_TREE_ENTRY;
    return true;
}

/* Walk `/dev_flash/...' from the root and return the entry it names. */
static bool ps3_hdd_tree_lookup(PS3BootROMState *s, const char *path,
                                PS3HddTreeEnt *out)
{
    g_autofree uint8_t *blk = g_malloc(PS3_HDD_TREE_BLOCK);
    const char *p = path;
    uint64_t block = 1;

    if (!ps3_hdd_tree_block(s, 0, blk) ||
        memcmp(blk, PS3_HDD_TREE_MAGIC, 8)) {
        return false;
    }
    block = ps3_be32(blk + 8);
    if (!block) {
        return false;
    }

    while (*p == '/') {
        p++;
    }

    while (*p) {
        char part[PS3_HDD_TREE_NAME];
        const char *slash = strchr(p, '/');
        unsigned len = slash ? (unsigned)(slash - p) : strlen(p);
        PS3HddTreeEnt e;
        unsigned o = 0;
        bool found = false;

        if (len >= sizeof(part)) {
            return false;
        }
        memcpy(part, p, len);
        part[len] = 0;

        while (block) {
            if (!ps3_hdd_tree_block(s, block, blk)) {
                return false;
            }
            o = 0;
            while (ps3_hdd_tree_entry(blk, &o, &e)) {
                if (!strcmp(e.name, part)) {
                    found = true;
                    break;
                }
            }
            if (found) {
                break;
            }
            block = ps3_hdd_tree_dir_next(blk);
        }
        if (!found) {
            return false;
        }

        if (!slash) {
            if (out) {
                *out = e;
            }
            return true;
        }

        if (e.type != 1) {
            return false;
        }
        block = e.block;
        p = slash;
        while (*p == '/') {
            p++;
        }
    }

    return false;
}

/* Write one file from the tree, block by block, under `dest'. */
static bool ps3_hdd_tree_extract_file(PS3BootROMState *s, const PS3HddTreeEnt *e,
                                      const char *dest)
{
    g_autofree uint8_t *blk = g_malloc(PS3_HDD_TREE_BLOCK);
    g_autoptr(GError) err = NULL;
    uint64_t left = e->size, block = e->block;
    g_autofree char *dir = g_path_get_dirname(dest);
    g_autofree char *tmp = g_strconcat(dest, ".part", NULL);
    FILE *f;

    g_mkdir_with_parents(dir, 0755);

    f = fopen(tmp, "wb");
    if (!f) {
        return false;
    }

    while (left) {
        unsigned n = MIN(left, (uint64_t)PS3_HDD_TREE_BLOCK);

        if (!ps3_hdd_tree_block(s, block, blk) ||
            fwrite(blk, 1, n, f) != n) {
            fclose(f);
            g_unlink(tmp);
            return false;
        }
        left -= n;
        block++;
    }

    fclose(f);

    if (g_rename(tmp, dest) < 0) {
        g_unlink(tmp);
        return false;
    }

    (void)err;
    return true;
}

static bool ps3_hdd_tree_extract_dir(PS3BootROMState *s, uint64_t block,
                                     const char *dest, unsigned depth)
{
    g_autofree uint8_t *blk = g_malloc(PS3_HDD_TREE_BLOCK);
    PS3HddTreeEnt e;
    unsigned o = 0;
    bool any = false;

    if (depth > PS3_HDD_TREE_DEPTH) {
        return false;
    }

    while (block) {
        if (!ps3_hdd_tree_block(s, block, blk)) {
            return false;
        }
        o = 0;
        while (ps3_hdd_tree_entry(blk, &o, &e)) {
            g_autofree char *path = g_build_filename(dest, e.name, NULL);

            any = true;
            if (e.type == 1) {
                g_mkdir_with_parents(path, 0755);
                if (!ps3_hdd_tree_extract_dir(s, e.block, path, depth + 1)) {
                    return false;
                }
            } else if (!ps3_hdd_tree_extract_file(s, &e, path)) {
                return false;
            }
        }
        block = ps3_hdd_tree_dir_next(blk);
    }

    (void)any;
    return true;
}

/*
 * Unpack the tree once per build.  The superblock carries a generation word: a
 * new image bumps it, the stamp file records the one already unpacked, and a
 * matching stamp skips the copy so a boot does not rewrite 187 MiB of
 * firmware.
 */
static bool ps3_hdd_tree_setup(PS3BootROMState *s, Error **errp)
{
    g_autofree uint8_t *blk = g_malloc(PS3_HDD_TREE_BLOCK);
    g_autofree char *tree = NULL;
    g_autofree char *stamp = NULL;
    g_autofree gchar *have = NULL;
    uint32_t generation, root;
    const char *devs[] = { "dev_flash", "dev_flash2", "dev_flash3",
                           "dev_hdd0" };
    char text[32];
    gsize have_len = 0;
    bool fresh = true;
    unsigned i;

    const char *image = NULL;

    /* The tree lives on the medium the console boots from. */
    s->tree_emmc = s->boot_medium && !strcmp(s->boot_medium, "emmc") &&
                   s->emmc && s->emmc_size;
    if (s->tree_emmc) {
        image = s->emmc_file;
    } else if (s->hdd && s->hdd_size) {
        image = s->hdd_file;
    } else {
        return true;
    }

    if (!ps3_hdd_tree_block(s, 0, blk) ||
        memcmp(blk, PS3_HDD_TREE_MAGIC, 8)) {
        return true;            /* the image has no tree of its own */
    }

    root = ps3_be32(blk + 8);
    generation = ps3_be32(blk + 12);
    if (!root) {
        return true;
    }

    tree = g_strconcat(image, ".tree", NULL);
    stamp = g_build_filename(tree, ".generation", NULL);
    snprintf(text, sizeof(text), "%u\n", generation);

    if (g_file_get_contents(stamp, &have, &have_len, NULL) &&
        have_len && !strcmp(have, text)) {
        fresh = false;
    }

    if (fresh) {
        g_mkdir_with_parents(tree, 0755);
        if (!ps3_hdd_tree_extract_dir(s, root, tree, 0)) {
            error_setg(errp, "ps3-boot-rom: cannot unpack the HDD tree "
                       "from %s into %s", image, tree);
            return false;
        }
        if (!g_file_set_contents(stamp, text, -1, NULL)) {
            error_setg(errp, "ps3-boot-rom: cannot write %s", stamp);
            return false;
        }
        info_report("ps3-boot-rom: HDD tree generation %u unpacked from %s "
                    "into %s", generation, image, tree);
    } else {
        info_report("ps3-boot-rom: HDD tree generation %u already unpacked "
                    "in %s", generation, tree);
    }

    /*
     * A caller's own directories win; when it named none, the firmware and
     * the disk's file area are the ones stored inside the image.
     */
    {
        gchar **slot[] = { &s->dev_flash, &s->dev_flash2, &s->dev_flash3,
                           &s->hdd_dir };

        for (i = 0; i < ARRAY_SIZE(devs); i++) {
            g_autofree char *dir = g_build_filename(tree, devs[i], NULL);

            if (*slot[i] || !g_file_test(dir, G_FILE_TEST_IS_DIR)) {
                continue;
            }
            *slot[i] = g_strdup(dir);
            info_report("ps3-boot-rom: %s from the HDD image (%s)", devs[i],
                        dir);
        }
    }

    if (!s->dev_flash) {
        error_setg(errp, "ps3-boot-rom: the HDD tree has no dev_flash");
        return false;
    }

    return true;
}

/* The PS3 has no interrupt controller wired to an ISA bus; the IDE line is
 * accepted and dropped, which is enough for a polled ATA driver. */
static void ps3_isa_noop(void *opaque, int line, int level)
{
}

static void ps3_rom_realize(DeviceState *dev, Error **errp)
{
    PS3BootROMState *kbd_s = PS3_BOOT_ROM(dev);
    unsigned net_i;

    /*
     * The RSX's local memory: 256 MiB of real RAM at the console's local
     * base, which is where cellGcmSetDisplayBuffer's offsets point and what
     * the scanout reads when the guest flips.  It must be mapped before the
     * guest runs, and nothing else may sit there.
     */
    memory_region_init_ram(&kbd_s->rsx_local, OBJECT(kbd_s), "ps3.rsx.local",
                           PS3_RSX_LOCAL_SIZE, &error_fatal);
    memory_region_add_subregion(get_system_memory(), PS3_RSX_LOCAL_BASE,
                                &kbd_s->rsx_local);
    kbd_s->rsx_ready = true;
    kbd_s->rsx_context = 0;
    kbd_s->rsx_mem_allocated = false;
    kbd_s->rsx_mem_handle = 0;
    kbd_s->rsx_local_size = 0;
    kbd_s->rsx_dma = 0;
    kbd_s->rsx_driver = 0;
    kbd_s->rsx_reports = 0;
    kbd_s->rsx_device = 0;
    kbd_s->rsx_event_port = 0;
    kbd_s->rsx_event_queue = 0;
    memset(kbd_s->rsx_iomap_used, 0, sizeof(kbd_s->rsx_iomap_used));
    memset(kbd_s->rsx_iomap_ea, 0, sizeof(kbd_s->rsx_iomap_ea));
    memset(kbd_s->rsx_tiles, 0, sizeof(kbd_s->rsx_tiles));
    memset(kbd_s->rsx_zculls, 0, sizeof(kbd_s->rsx_zculls));
    kbd_s->rsx_db_count = 0;
    kbd_s->rsx_vblank_timer = NULL;

    /* No guest thread has been created yet; the first switch registers one. */
    kbd_s->thr_cur = -1;

    /*
     * The Blu-ray drive's media, for lv2's storage layer.  An image that is a
     * decrypted ISO is served exactly the way a drive serves a disc: 2048-byte
     * sectors of the image, so the VSH's x3 layer can mount /dev_bdvd and read
     * the game's files.  Without one the drawer is empty and every read
     * reports no sectors, which is what a console with no disc says.
     *
     * It is a second, read-only block backend on the same file the ATAPI
     * device was given: the legacy drive is already connected to that device
     * and cannot be attached twice, and a disc is read-only anyway.
     */
    if (kbd_s->disc_file && !kbd_s->disc) {
        QDict *opts = qdict_new();
        Error *derr = NULL;
        int64_t disc_len;

        qdict_put_str(opts, "driver", "raw");
        /* No write flag: the drive is read-only media. */
        kbd_s->disc = blk_new_open(kbd_s->disc_file, NULL, opts, 0, &derr);
        if (!kbd_s->disc) {
            error_setg(errp, "ps3-boot-rom: cannot open BD image %s: %s",
                       kbd_s->disc_file,
                       derr ? error_get_pretty(derr) : "unknown error");
            error_free(derr);
            return;
        }
        disc_len = blk_getlength(kbd_s->disc);
        kbd_s->disc_size = disc_len > 0 ? (uint64_t)disc_len : 0;
        info_report("ps3-boot-rom: BD drive: %s, %" PRIu64 " sector(s) of "
                    "2048 byte(s) (%" PRIu64 " MiB)", kbd_s->disc_file,
                    kbd_s->disc_size / PS3_STOR_SECT_BD,
                    kbd_s->disc_size / MiB);
    }

    /*
     * The disc's own filesystem, mounted as /dev_bdvd: the descriptors are
     * read here so a boot says what the media holds - and whether the update
     * file is on it - rather than waiting for the guest's first look-up.
     */
    ps3_iso_setup(kbd_s);

    memset(kbd_s->stor, 0, sizeof(kbd_s->stor));

    /* No sockets are open until the guest asks for one. */
    for (net_i = 0; net_i < PS3_NET_MAX; net_i++) {
        kbd_s->net_used[net_i] = false;
        kbd_s->net_fd[net_i] = -1;
    }

    info_report("ps3-boot-rom: wired network: lv2 sys_net sockets on the "
                "host's stack");

    /* The console's keyboard: the window's keys are the pad's buttons. */
    kbd_s->kbd = qemu_input_handler_register(dev, &ps3_kbd_handler);

    /* One hour without input: auto-off, as the VSH's setting describes. */
    if (kbd_s->idle_off_seconds) {
        kbd_s->idle_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ps3_idle_off,
                                         kbd_s);
        ps3_input_kick(kbd_s);
    }
    PS3BootROMState *s = PS3_BOOT_ROM(dev);
    gchar *buf = NULL;
    gsize len = 0;
    GError *err = NULL;

    /*
     * The boot chain cannot start if the block cipher is wrong, and every
     * later symptom (a bad MAC, a loader that stops at 0x30) looks like a key
     * problem instead.  Check the AES-256 CBC ladder, the ATA derivation and
     * XTS against fixed answers once, here, so a broken cipher is named.
     */
    {
        char why[96];

        if (!ps3_aes_selftest(why, sizeof(why))) {
            error_setg(errp, "ps3-boot-rom: AES selftest failed: %s", why);
            return;
        }
        info_report("ps3-boot-rom: AES-256 CBC, ATA ladder and XTS selftest ok");
    }

    /*
     * The sound driver.  A host with no audiodev still boots; the rings are
     * drained and dropped, so a missing backend never stops the guest.
     */
    {
        Error *audio_err = NULL;

        s->audio = ps3_audio_new(s->audio_dev, &audio_err);
        if (!s->audio) {
            /*
             * The usual cause is worth naming: `-nodefaults` turns off the
             * default `-audiodev` this build would otherwise create, so the
             * machine has nothing to open and the rings are drained silently.
             */
            warn_report("ps3-audio: %s (running silent; pass "
                        "-audiodev dsound,id=snd -global "
                        "ps3-boot-rom.audio=snd for sound, and drop "
                        "-nodefaults to get this build's default backend)",
                        error_get_pretty(audio_err));
            error_free(audio_err);
        }
    }

    /*
     * The microphone path, once, when asked: the same reason the AES selftest
     * exists - a ring or byte-order mistake here sounds like a guest bug.
     */
    if (s->mic_selftest) {
        char why[160];

        if (!ps3_mic_selftest(s, why, sizeof(why))) {
            error_setg(errp, "ps3-boot-rom: microphone selftest failed: %s",
                       why);
            return;
        }
    }

    /*
     * Describe the gamepad ports first: lv2 hands them to the VSH during its
     * startup, and the front LED starts out as the pretend "console is on"
     * green rather than dark.
     */
    if (!ps3_pad_defaults(s, errp)) {
        return;
    }

    /* The host's controller, whenever the display has one open. */
    qemu_gamepad_set_handler(ps3_gamepad_event, s);

    if (s->pad_selftest) {
        char why[160];

        if (!ps3_pad_selftest(s, why, sizeof(why))) {
            error_setg(errp, "ps3-boot-rom: pad selftest failed: %s", why);
            return;
        }
    }
    if (!ps3_hdd_setup(s, errp)) {
        return;
    }
    if (!ps3_hdd_tree_setup(s, errp)) {
        return;
    }
    if (!ps3_emmc_setup(s, errp)) {
        return;
    }
    if (!ps3_boot_medium_setup(s, errp)) {
        return;
    }

    /*
     * PCK2 is the console's per-console root key 2: it unwraps the ERK the .2
     * loaders carry, which is what the following SELF stages then use.  Like
     * every other key here it comes from the caller's dump, never the model.
     */
    if (s->pck2_prop) {
        size_t plen = 0;

        if (!ps3_stage_parse_hex(s->pck2_prop, s->pck2, sizeof(s->pck2),
                                 &plen) || plen != sizeof(s->pck2)) {
            error_setg(errp, "ps3-boot-rom: pck2 must be 96 hex digits (48 "
                       "bytes: the per-console root key 2)");
            return;
        }
        s->has_pck2 = true;
    } else if (s->pck2_file) {
        g_autofree gchar *kbuf = NULL;
        GError *gerr = NULL;
        gsize klen = 0;

        if (!g_file_get_contents(s->pck2_file, &kbuf, &klen, &gerr)) {
            error_setg(errp, "ps3-boot-rom: cannot read %s: %s",
                       s->pck2_file, gerr->message);
            g_error_free(gerr);
            return;
        }
        if (klen != sizeof(s->pck2)) {
            error_setg(errp, "ps3-boot-rom: %s is %u byte(s), PCK2 is 48",
                       s->pck2_file, (unsigned)klen);
            return;
        }
        memcpy(s->pck2, kbuf, sizeof(s->pck2));
        s->has_pck2 = true;
    }

    if (s->has_pck2) {
        info_report("ps3-boot-rom: per-console root key 2 (PCK2) read; the "
                    ".2 loaders' ERK can be unwrapped");
    }
    snprintf(s->led_text, sizeof(s->led_text), "green on");
    qemu_console_set_status_led(s->led_text);
    info_report("ps3-boot-rom: front LED: %s (pretend; the display puts it in "
                "its window title)", s->led_text);

    /*
     * lv2's low page belongs to the VSH run, not to the boot chain: the
     * 0xC00 vector sits in the page lv0 loads its own trampoline into (lv0's
     * entry is 0xC40, inside it), so installing the shim for an lv0 stage
     * would overwrite the hypervisor's first instructions with a syscall
     * vector and send it to 0.
     */
    if (s->vsh_run) {
        rs6000_ps3_lv2_page(get_system_memory(), s->ram);
    }

    memory_region_init_io(&s->regs_mr, OBJECT(s), &ps3_rom_regs_ops, s,
                          "ps3-boot-rom.regs", 0x40);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->regs_mr);

    memory_region_init_ram(&s->ls_mr, OBJECT(s), "ps3.spes.ls",
                           (size_t)PS3_SPE_MAX * PS3_LS_SIZE, &error_fatal);

    /* The boot path's 0xF1000000 window stays a 256 KiB alias of SPE 0, so it
     * keeps mmio index 1; the whole array is index 2, mapped at
     * PS3_SPES_LS_BASE, which is also the effective address the isolation
     * check uses for each SPE's store. */
    memory_region_init_alias(&s->ls_alias_mr, OBJECT(s), "ps3.ls",
                             &s->ls_mr, 0, PS3_LS_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->ls_alias_mr);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->ls_mr);

    memory_region_init_ram(&s->rom_mr, OBJECT(s), "ps3.spu-rom", PS3_ROM_SIZE,
                           &error_fatal);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->rom_mr);

    memory_region_init_io(&s->uart_mr, OBJECT(s), &ps3_ppe_uart_ops, s,
                          "ps3-ppe-uart", PS3_PPE_UART_SIZE);

    if (serial_hd(0)) {
        Error *err = NULL;

        if (qemu_chr_fe_init(&s->chr, serial_hd(0), &err)) {
            s->chr_ready = true;
            qemu_chr_fe_set_handlers(&s->chr, ps3_uart_can_receive,
                                     ps3_uart_receive, NULL, NULL, s, NULL,
                                     true);
            {
                Chardev *chr = qemu_chr_fe_get_driver(&s->chr);

                info_report("rs6000-ps3: console on %s",
                            chr && chr->label[0] ? chr->label : "a chardev");
            }
        } else {
            info_report("rs6000-ps3: console chardev refused: %s",
                        err ? error_get_pretty(err) : "unknown");
            error_free(err);
        }
    }
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

    s->spes = ps3_spes_new(PS3_SPE_MAX,
                           memory_region_get_ram_ptr(&s->ls_mr),
                           (size_t)PS3_SPE_MAX * PS3_LS_SIZE,
                           s->flash, s->flash_len, PS3_SPES_LS_BASE);
    if (!s->spes) {
        error_setg(errp, "ps3-boot-rom: cannot allocate the SPE group");
        return;
    }
    s->spu = ps3_spes_spu(s->spes, 0);

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
    /*
     * The application is on the console's disk, under the dev_flash tree the
     * HDD image carries - never a file the caller named on the host.  The tree
     * the model unpacked from the image is the only place vsh.self is looked
     * for, so a run says what an unmodified console says: no image, no VSH.
     */
    if (s->dev_flash) {
        s->vsh_self = g_build_filename(s->dev_flash, "vsh", "module",
                                       "vsh.self", NULL);
        s->app_path = g_strdup("/dev_flash/vsh/module/vsh.self");
    }

    /*
     * dev_flash3 is the second writable firmware mount; some dumps put the
     * application tree there instead of dev_flash.
     */
    if (s->dev_flash3) {
        g_autofree char *alt = g_build_filename(s->dev_flash3, "vsh",
                                                "module", "vsh.self", NULL);

        if ((!s->vsh_self || !g_file_test(s->vsh_self, G_FILE_TEST_EXISTS)) &&
            g_file_test(alt, G_FILE_TEST_EXISTS)) {
            g_free(s->vsh_self);
            s->vsh_self = g_strdup(alt);
            g_free(s->app_path);
            s->app_path = g_strdup("/dev_flash3/vsh/module/vsh.self");
        }
    }

    /*
     * The attached storage: dev_usb000 is a host directory, so the VSH and the
     * updater read it through sys_fs.  The update flow looks for an update file
     * under PS3/UPDATE, so say whether the one that will be attached has it.
     */
    /*
     * A new HDD: the image is blank, so the VSH boots its recovery and asks to
     * format the disk.  The format writes into this directory, which is what
     * dev_hdd0 resolves to, so the console comes up with its own storage.
     */
    if (s->hdd_dir) {
        bool fresh = !g_file_test(s->hdd_dir, G_FILE_TEST_IS_DIR);

        if (fresh) {
            g_mkdir_with_parents(s->hdd_dir, 0755);
        }
        info_report("ps3-boot-rom: dev_hdd0 %s at %s%s",
                    fresh ? "created" : "attached", s->hdd_dir,
                    s->hdd_created ? ", new blank HDD: recovery will offer to "
                    "format it" : "");
    }

    if (s->hdd1_dir) {
        if (!g_file_test(s->hdd1_dir, G_FILE_TEST_IS_DIR)) {
            g_mkdir_with_parents(s->hdd1_dir, 0755);
        }
        info_report("ps3-boot-rom: dev_hdd1 at %s", s->hdd1_dir);
    }

    if (s->usb_dir) {
        g_autofree char *update = g_build_filename(s->usb_dir, "PS3", "UPDATE",
                                                   "PS3UPDAT.PUP", NULL);

        if (!g_file_test(s->usb_dir, G_FILE_TEST_IS_DIR)) {
            info_report("ps3-boot-rom: usb-dir %s is not a directory",
                        s->usb_dir);
        } else if (g_file_test(update, G_FILE_TEST_EXISTS)) {
            info_report("ps3-boot-rom: dev_usb000 attached from %s, update "
                        "file PS3/UPDATE/PS3UPDAT.PUP present", s->usb_dir);
        } else {
            info_report("ps3-boot-rom: dev_usb000 attached from %s, no "
                        "PS3/UPDATE/PS3UPDAT.PUP in it", s->usb_dir);
        }
    }

    /*
     * Which application comes up is lv2's decision, not a command-line one.
     * The chain is asked first: when it verifies and vsh.self is on dev_flash,
     * the initial process is /dev_flash/vsh.self.  When it does not - the
     * flash is missing, the readout does not open the container, or there is no
     * vsh.self - lv2 does what the firmware does and creates the vflash recover
     * process (emergency program), which is emer_init.self.
     */
    if (s->vsh_run) {
        char why[192] = "";
        bool chain_ok = ps3_chain_check(s, why, sizeof(why));
        bool vsh_ok = s->vsh_self &&
                      g_file_test(s->vsh_self, G_FILE_TEST_EXISTS);

        if (!s->recover_prop && chain_ok && vsh_ok) {
            info_report("ps3-boot-rom: chain checks passed; lv2 starts %s",
                        s->app_path ?: "/dev_flash/vsh/module/vsh.self");
        } else {
            /*
             * The EEPROM's recover flag decides this before the chain does:
             * a console whose flag is set comes up in recovery whatever the
             * flash holds, which is how `recover' boots the emergency program
             * on a healthy image.
             */
            const char *reason = s->recover_prop ?
                "the EEPROM's recover flag is set" :
                (chain_ok ? "no vsh.self on dev_flash" : why);
            char where[64] = "";
            int bank = -1;
            Error *rerr = NULL;

            info_report("ps3-boot-rom: ### Vflash recovery mode");

            /*
             * The emergency program is a file in the flash's recovery banks,
             * the same place lv0ldr finds it: lv2 does not read it off a host
             * path, and neither does this model.
             */
            if (!ps3_flash_ros_read(s, "emer_init.self", &s->app_img,
                                    &s->app_img_len, where, sizeof(where),
                                    &bank)) {
                info_report("ps3-boot-rom: %s, but the flash has no "
                            "emer_init.self (%s): the console stays in "
                            "recovery", reason, where);
                s->recovery = true;
                s->syscon_recover = true;
                ps3_vga_boot_logo("RECOVERY", reason);
                return;
            }

            g_free(s->app_path);
            s->app_path = g_strdup("/dev_flash/sys/emerge/emer_init.self");
            g_free(s->vsh_self);
            s->vsh_self = NULL;
            s->recovery = true;
            s->syscon_recover = true;

            info_report("ps3-boot-rom: %s; creating the vflash recover "
                        "process (emergency program): /dev_flash/sys/emerge/"
                        "emer_init.self, %" PRIu64 " bytes from the flash's %s",
                        reason, (uint64_t)s->app_img_len, where);

            /* In recovery /dev_flash is the flash bank that was booted. */
            {
                gchar *ros = ps3_flash_ros_mount(s, bank >= 0 ? (unsigned)bank
                                                                : 0, &rerr);

                if (ros) {
                    g_free(s->dev_flash);
                    s->dev_flash = ros;
                } else if (rerr) {
                    info_report("ps3-boot-rom: %s", error_get_pretty(rerr));
                    error_free(rerr);
                    s->dev_flash = NULL;
                }
            }

            ps3_vga_printf("RECOVERY: %s",
                           s->recover_prop ? "RECOVER FLAG SET" :
                           (chain_ok ? "NO VSH.SELF" : why));
        }
    }

    if (s->vsh_self || (s->app_img && s->app_img_len)) {
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
/*
 * Open a stage SELF the way the chain does: with the ERK unwrapped from the
 * caller's PCK2 when one is supplied, and with the published loader keysets
 * otherwise.  A PCK2 that does not belong to the image falls through to the
 * keyset search, so a wrong key is reported by the normal "no keyset opened"
 * message rather than silently corrupting the stage.
 */
static bool ps3_stage_open_self(PS3BootROMState *s, uint8_t *img, size_t len,
                                char *why, size_t why_len)
{
    char pck_why[160];

    if (s->has_pck2) {
        if (ps3_self_decrypt_pck2(img, len, s->pck2, pck_why,
                                  sizeof(pck_why))) {
            info_report("ps3-spu-stage: %s", pck_why);
            return true;
        }
        info_report("ps3-spu-stage: %s; trying the loader keysets",
                    pck_why);
    }

    return ps3_self_decrypt(img, len, why, why_len);
}

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
            if (!ps3_stage_open_self(s, img, len, why, sizeof(why))) {
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
        char pck_why[160];
        int opened;

        /*
         * A .2 loader carries its ERK wrapped under the caller's PCK2.  Open
         * it that way first; ps3_self_load_ls then sees sections that are
         * already plaintext and loads them as they stand.  A PCK2 from a
         * different console simply does not open the metadata, and the normal
         * keyset search below still runs.
         */
        if (s->has_pck2) {
            if (ps3_self_decrypt_pck2(img, len, s->pck2, pck_why,
                                      sizeof(pck_why))) {
                info_report("ps3-spu-stage: %s: %s", s->stage_elf, pck_why);
            } else {
                info_report("ps3-spu-stage: %s: %s; trying the loader "
                            "keysets", s->stage_elf, pck_why);
            }
        }

        opened = ps3_self_load_ls(img, len, ls, PS3_LS_SIZE, &stage_entry,
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

/*
 * Open a PPU stage file: either a SELF (opened with the same loader keysets
 * the SPU stages use) or a plain 64-bit big-endian ELF.  The ELF header is
 * normally at the front of the certified file, but a SELF's extended header
 * leaves it at a small offset, so the first 0x400 bytes are searched.
 *
 * Returns a pointer to the ELF header inside `img' (which the caller owns),
 * or NULL with `why' set.
 */
static const uint8_t *ps3_ppu_open(PS3BootROMState *s, uint8_t *img,
                                   size_t len, uint64_t *seg_shift,
                                   char *why, size_t why_len)
{
    const uint8_t *elf = img;
    size_t elf_len = len;

    *seg_shift = 0;

    if (len >= 4 && !memcmp(img, "SCE\0", 4)) {
        if (!ps3_stage_open_self(s, img, len, why, why_len)) {
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

    elf = ps3_ppu_open(s, img, len, &seg_shift, why, sizeof(why));
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

/*
 * Register the reset entry once.
 *
 * Staging an application must not add a handler per call: the warm reset
 * re-stages one from inside the reset sequence, and QEMU iterates its
 * resettable children while the handlers run, so adding a child there is an
 * assertion rather than a new handler.
 */
static void ps3_ppu_reset_register(PS3BootROMState *s)
{
    if (s->reset_registered) {
        return;
    }

    qemu_register_reset(ps3_ppu_reset_entry, s);
    s->reset_registered = true;
}

/*
 * The console's warm reset.
 *
 * A recovery program ends by writing the EEPROM's recover byte and asking
 * sys_sm_shutdown(0x100) to restart the console.  On hardware that pulls the
 * system reset line: RAM is cleared, lv2 comes back up with nothing but the
 * EEPROM, and because the recover byte is set the application lv2 starts is
 * the emergency program again.  That is why a recovery program that asks for a
 * restart loops instead of exiting, and what this function does - everything
 * the old process owned goes, the recovery image is staged again, and the
 * reset entry below enters it.
 */
static bool ps3_lv2_warm_reset(PS3BootROMState *s)
{
    Error *err = NULL;
    uint8_t *ram = memory_region_get_ram_ptr(s->ram);
    uint64_t ram_size = memory_region_size(s->ram);
    unsigned i;

    /* The files and directories the process had open are gone with it. */
    for (i = 0; i < PS3_LV2_FD_MAX; i++) {
        if (s->lv2_fd_open[i] && s->lv2_fd[i] >= 0) {
            close(s->lv2_fd[i]);
        }
        s->lv2_fd_open[i] = false;
        s->lv2_fd[i] = -1;

        if (s->lv2_dir[i]) {
            g_dir_close(s->lv2_dir[i]);
            s->lv2_dir[i] = NULL;
        }
        g_clear_pointer(&s->lv2_dir_path[i], g_free);
        s->lv2_dir_step[i] = 0;
    }

    /* And so is every socket the process had: the link comes up again. */
    for (i = 0; i < PS3_NET_MAX; i++) {
        if (s->net_used[i]) {
            closesocket(s->net_fd[i]);
        }
        s->net_used[i] = false;
        s->net_fd[i] = -1;
        g_clear_pointer(&s->net_pending[i], g_free);
        s->net_pending_len[i] = 0;
    }

    /* Its SPEs, with their local stores. */
    for (i = 0; i < PS3_SPU_LV2_GROUPS; i++) {
        ps3_spu_lv2_group_free(&s->spug[i]);
    }

    /* lv2's objects, the modules it loaded, its heap and its ids. */
    memset(s->thr, 0, sizeof(s->thr));
    memset(s->mtx, 0, sizeof(s->mtx));
    memset(s->rw, 0, sizeof(s->rw));
    memset(s->lwm, 0, sizeof(s->lwm));
    memset(s->cond, 0, sizeof(s->cond));
    memset(s->sem, 0, sizeof(s->sem));
    memset(s->eq, 0, sizeof(s->eq));
    memset(s->ep, 0, sizeof(s->ep));
    memset(s->spuimg, 0, sizeof(s->spuimg));
    memset(s->lv2_mod, 0, sizeof(s->lv2_mod));
    memset(s->lv2_export, 0, sizeof(s->lv2_export));
    memset(s->lv2_known_reported, 0, sizeof(s->lv2_known_reported));
    memset(s->stor, 0, sizeof(s->stor));

    s->lv2_mod_count = 0;
    s->lv2_export_count = 0;
    s->lv2_export_full = false;
    s->lv2_stub_next = 0;
    s->lv2_stub_records = 0;
    s->lv2_reloc_probe = 0;
    s->lv2_ref_unknown = false;
    s->lv2_preload_depth = 0;
    s->spu_next_id = 0;
    s->lv2_next_id = 0;
    s->lv2_container_size = 0;
    s->lv2_mmap_next = 0;
    s->lv2_heap = 0x01000000;
    s->thr_cur = -1;
    s->sched_pending = false;
    s->sched_queued = false;
    s->lv2_park = false;
    s->all_parked_reported = false;
    s->lv2_exited = false;
    s->lv2_exit_status = 0;
    s->lv2_fan_policy = 0;
    s->lv2_fan_duty = 0;
    s->lv2_usleep_reported = false;
    s->hid_next_handle = 0;
    s->pad_max_connect = 0;

    /* The RSX is reset with the system: no context, no display buffers. */
    s->rsx_context = 0;
    s->rsx_mem_handle = 0;
    s->rsx_mem_allocated = false;
    s->rsx_local_size = 0;
    s->rsx_dma = s->rsx_driver = s->rsx_reports = s->rsx_device = 0;
    s->rsx_event_port = s->rsx_event_queue = 0;
    s->rsx_get = s->rsx_put = 0;
    s->rsx_db_count = 0;
    s->rsx_vsync = false;
    s->rsx_second_vhandler = false;
    s->rsx_surface_format = s->rsx_surface_pitch = s->rsx_surface_offset = 0;
    s->rsx_surface_target = s->rsx_clear_color = s->rsx_begin_end = 0;
    s->rsx_prim = 0;
    s->rsx_clause_n = 0;
    s->rsx_inline_words = 0;
    s->rsx_vprog_ready = false;
    s->rsx_vprog_load = s->rsx_vprog_word = s->rsx_vprog_start = 0;
    s->rsx_vprog_fallback_reported = false;
    s->rsx_vconst_load = s->rsx_vconst_word = 0;
    s->rsx_fprog_ready = false;
    s->rsx_fprog_len = 0;
    s->rsx_fprog_reported = false;
    s->rsx_shader_control = 0;
    s->rsx_vtx_base = s->rsx_vtx_index_base = 0;
    s->rsx_index_addr = s->rsx_index_dma = 0;
    s->rsx_viewport_h = s->rsx_viewport_v = 0;
    s->rsx_scissor_h = s->rsx_scissor_v = 0;
    s->rsx_blend = s->rsx_blend_s = s->rsx_blend_d = s->rsx_blend_eq = 0;
    s->rsx_color_mask = s->rsx_cull = s->rsx_depth_test = 0;
    s->rsx_head_queued[0] = s->rsx_head_queued[1] = 0;
    s->rsx_head_flags[0] = s->rsx_head_flags[1] = 0;
    s->rsx_draw_reported = false;
    s->rsx_noattr_reported = false;
    s->rsx_immediate_reported = false;
    s->rsx_methods_logged = 0;
    memset(s->rsx_iomap_used, 0, sizeof(s->rsx_iomap_used));
    memset(s->rsx_iomap_ea, 0, sizeof(s->rsx_iomap_ea));
    memset(s->rsx_tiles, 0, sizeof(s->rsx_tiles));
    memset(s->rsx_zculls, 0, sizeof(s->rsx_zculls));
    memset(s->rsx_vtx_off, 0, sizeof(s->rsx_vtx_off));
    memset(s->rsx_vtx_fmt, 0, sizeof(s->rsx_vtx_fmt));
    memset(s->rsx_db_offset, 0, sizeof(s->rsx_db_offset));
    memset(s->rsx_db_pitch, 0, sizeof(s->rsx_db_pitch));
    memset(s->rsx_db_w, 0, sizeof(s->rsx_db_w));
    memset(s->rsx_db_h, 0, sizeof(s->rsx_db_h));
    memset(s->rsx_tex, 0, sizeof(s->rsx_tex));

    /* The AV link and the sound device the process had started. */
    s->av_up = false;
    s->av_rx_len = 0;
    s->av_tx_len = 0;
    s->av_version = 0;
    s->av_event_bits = 0;
    s->av_hdcp_done = false;
    s->rsxaudio_running = false;
    s->rsxaudio_handle = 0;
    s->rsxaudio_shmem = 0;
    s->rsxaudio_blocks = 0;
    s->vsh_why[0] = 0;

    /*
     * The memory the process could see comes back cleared, as it does off the
     * console's reset line - main RAM, the RSX's local memory (its driver
     * info and display buffers) and the SPEs' local stores.  A process that
     * came back to the driver page its predecessor left behind would read a
     * descriptor that no longer describes anything.
     */
    memset(ram, 0, ram_size);
    memset(memory_region_get_ram_ptr(&s->rsx_local), 0, PS3_RSX_LOCAL_SIZE);
    memset(memory_region_get_ram_ptr(&s->ls_mr), 0,
           memory_region_size(&s->ls_mr));

    if (s->spu) {
        ps3_spe_reset(s->spu);
    }

    /* The scanout goes back to the console's own screen, not the last frame
     * the old process left in it. */
    ps3_vga_reset_screen();

    s->recovery_boots++;
    info_report("ps3-ppu: warm reset %u: the recover flag is set, so lv2 "
                "starts the emergency program again (%s)",
                s->recovery_boots, s->app_path ?: "the application");
    ps3_vga_printf("WARM RESET %u: RECOVERY RESTART", s->recovery_boots);

    if (!ps3_vsh_stage(s, &err)) {
        info_report("ps3-ppu: the restart could not re-enter %s: %s",
                    s->app_path ?: "the application",
                    err ? error_get_pretty(err) : "unknown error");
        error_free(err);
        return false;
    }

    return true;
}

static void ps3_ppu_reset_entry(void *opaque)
{
    PS3BootROMState *s = opaque;
    CPUState *cs = qemu_get_cpu(0);

    if (!cs || !s->ppu_entry) {
        return;
    }

    if (s->warm_reset) {
        s->warm_reset = false;

        if (!ps3_lv2_warm_reset(s)) {
            /* Nothing to re-enter: end the run the way the exit would. */
            qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
            return;
        }
        cs = qemu_get_cpu(0);   /* the reset may have rebuilt the CPU state */
    }

    PowerPCCPU *cpu = POWERPC_CPU(cs);
    unsigned i;

    /*
     * The reset vector is entered with a defined register file.  QEMU's own
     * PowerPC reset clears the SPRs but leaves the GPRs, FPRs and VRs alone,
     * so without this a warm reset would hand the new process the dead one's
     * registers - its TLS base in r13, its saved r31, its condition register -
     * and the same binary would take a different path on its second entry than
     * it did on its first.
     */
    memset(cpu->env.gpr, 0, sizeof(cpu->env.gpr));
    memset(cpu->env.vsr, 0, sizeof(cpu->env.vsr));      /* FPRs and VRs */
    cpu->env.lr = 0;
    cpu->env.ctr = 0;
    cpu->env.crf[0] = cpu->env.crf[1] = cpu->env.crf[2] = 0;
    cpu->env.crf[3] = cpu->env.crf[4] = cpu->env.crf[5] = 0;
    cpu->env.crf[6] = cpu->env.crf[7] = 0;
    cpu->env.xer = 0;
    cpu->env.fpscr = 0;
    cpu->env.vscr = 0;

    cpu->env.nip = s->ppu_entry;
    cpu->env.msr |= (1ULL << MSR_SF) | (1ULL << MSR_ME);
    cpu->env.msr &= ~((1ULL << MSR_IR) | (1ULL << MSR_DR));

    if (s->vsh_run && s->vsh_toc) {
        /*
         * lv2 enables floating point and Altivec for a user process before it
         * enters it; the VSH uses both, and without MSR[FP] its first float
         * operation would take the 0x800 vector instead of running.
         */
        uint8_t *ram = memory_region_get_ram_ptr(s->ram);
        uint64_t ram_size = memory_region_size(s->ram);
        uint32_t argv = (uint32_t)ram_size - 0x400;
        uint32_t str = (uint32_t)ram_size - 0x380;
        const char *path = s->app_path ?: s->vsh_self ?: "";
        size_t len = strlen(path);

        cpu->env.msr |= (1ULL << MSR_FP) | (1ULL << MSR_VR);
        cpu->env.gpr[2] = s->vsh_toc;
        cpu->env.gpr[1] = ram_size - 0x100;

        /* The process's argv block, which the reset path must not lose. */
        if (len && (uint64_t)str + len + 1 <= ram_size) {
            memcpy(ram + str, path, len + 1);
            ps3_put_be32(ram + argv, str);
            ps3_put_be32(ram + argv + 4, 0);
            cpu->env.gpr[3] = 1;
            cpu->env.gpr[4] = argv;
        } else {
            cpu->env.gpr[3] = 0;
            cpu->env.gpr[4] = 0;
        }
    }
}

/* The 970's exception vectors, so a run that lands on one says why. */
static const char *ps3_ppu_vector_name(uint64_t nip)
{
    switch (nip) {
    case 0x100: return "system reset";
    case 0x200: return "machine check";
    case 0x300: return "data storage interrupt";
    case 0x380: return "data segment interrupt";
    case 0x400: return "instruction storage interrupt";
    case 0x480: return "instruction segment interrupt";
    case 0x500: return "external interrupt";
    case 0x600: return "alignment interrupt";
    case 0x700: return "program interrupt";
    case 0x800: return "FP unavailable";
    case 0x900: return "decrementer interrupt";
    case 0xC00: return "system call";
    case 0xD00: return "trace interrupt";
    case 0xE00: return "performance monitor interrupt";
    case 0xF00: return "vector unavailable";
    case 0xF20: return "VSX unavailable";
    default: return NULL;
    }
}

static void ps3_ppu_tick(void *opaque)
{
    PS3BootROMState *s = opaque;
    CPUState *cs = qemu_get_cpu(0);
    PowerPCCPU *cpu = POWERPC_CPU(cs);

    s->ppu_last_pc = cpu->env.nip;
    s->ppu_tick_count++;

    /*
     * A thread that lands on an exception vector has nowhere to go: this
     * model installs no handler, so it spins there and every slice the
     * scheduler gives it is wasted.  Say so once and retire a worker; the
     * process's main thread is left in place, because its fault is the run's
     * own answer and not something to hide.
     */
    if (s->thr_cur >= 0 && s->thr[s->thr_cur].used) {
        PS3Thread *t = &s->thr[s->thr_cur];
        const char *vector = ps3_ppu_vector_name(cpu->env.nip);

        if (vector && cpu->env.nip != 0xC00) {      /* 0xC00 is the `sc` path */
            if (!t->fault_reported) {
                t->fault_reported = true;
                info_report("ps3-ppu: thread 0x%X took the %s vector at "
                            "0x%" PRIX64 " (lr=0x%" PRIX64 ")", t->id, vector,
                            (uint64_t)cpu->env.nip, (uint64_t)cpu->env.lr);
                /*
                 * A vector is where a run dies, and the nested fault that
                 * follows immediately overwrites SRR0 with the vector's own
                 * address, so the interesting thing is what the thread was
                 * doing: its stack pointer, the words around the frame and the
                 * registers the ABI uses to return.
                 */
                {
                    uint8_t *ram = memory_region_get_ram_ptr(s->ram);
                    uint64_t ram_size = memory_region_size(s->ram);
                    uint32_t sp = (uint32_t)cpu->env.gpr[1];

                    info_report("ps3-ppu:   srr0=0x%" PRIX64 " srr1=0x%" PRIX64
                                " dar=0x%" PRIX64 " dsisr=0x%X",
                                (uint64_t)cpu->env.spr[SPR_SRR0],
                                (uint64_t)cpu->env.spr[SPR_SRR1],
                                (uint64_t)cpu->env.spr[SPR_DAR],
                                (uint32_t)cpu->env.spr[SPR_DSISR]);
                    if ((uint64_t)cpu->env.spr[SPR_SRR0] + 4 <= ram_size) {
                        uint32_t off = (uint32_t)cpu->env.spr[SPR_SRR0];
                        info_report("ps3-ppu:   srr0 holds 0x%08X %08X",
                                    ps3_be32(ram + off),
                                    off + 4 <= ram_size ?
                                    ps3_be32(ram + off + 4) : 0);
                    }
                    {
                        unsigned k;
                        unsigned n = s->call_ring_pos < PS3_CALL_RING ?
                                     s->call_ring_pos : PS3_CALL_RING;

                        for (k = 0; k < n; k++) {
                            PS3Call *c = &s->call_ring[(s->call_ring_pos - n + k)
                                                      % PS3_CALL_RING];

                            info_report("ps3-ppu:   call 0x%X from lr=0x%"
                                        PRIX64 " sp=0x%" PRIX64 " srr0=0x%"
                                        PRIX64 " tid=%d", c->nr, c->lr, c->sp,
                                        c->srr0, c->tid);
                        }
                    }
                    info_report("ps3-ppu:   r1=0x%X r2=0x%X r3=0x%" PRIX64
                                " r11=0x%" PRIX64 " r12=0x%" PRIX64
                                " r29=0x%" PRIX64 " r30=0x%" PRIX64
                                " r31=0x%" PRIX64 " ctr=0x%" PRIX64,
                                sp, (uint32_t)cpu->env.gpr[2],
                                (uint64_t)cpu->env.gpr[3],
                                (uint64_t)cpu->env.gpr[11],
                                (uint64_t)cpu->env.gpr[12],
                                (uint64_t)cpu->env.gpr[29],
                                (uint64_t)cpu->env.gpr[30],
                                (uint64_t)cpu->env.gpr[31],
                                (uint64_t)cpu->env.ctr);
                    /*
                     * A 0x700 from a `bctrl` is a call through a descriptor
                     * that was never filled.  The call site says which table
                     * the descriptor came from and the words around it say
                     * what the loader left there, which is the difference
                     * between a stub lv2 should have planted and an entry the
                     * module's own relocation wrote.
                     */
                    if (cpu->env.nip == 0x700) {
                        uint32_t site = (uint32_t)cpu->env.lr;

                        if (site >= 8 && (uint64_t)site + 8 <= ram_size) {
                            info_report("ps3-ppu:   call site 0x%X:%08X"
                                        " %08X %08X %08X", site - 8,
                                        ps3_be32(ram + site - 8),
                                        ps3_be32(ram + site - 4),
                                        ps3_be32(ram + site),
                                        ps3_be32(ram + site + 4));
                        }
                        {
                            static const char *const what[] = {
                                "r11", "r12", "ctr", "r0",
                            };
                            uint64_t ptr[4];
                            unsigned r;

                            ptr[0] = cpu->env.gpr[11];
                            ptr[1] = cpu->env.gpr[12];
                            ptr[2] = cpu->env.ctr;
                            ptr[3] = cpu->env.gpr[0];
                            for (r = 0; r < 4; r++) {
                                uint32_t a = (uint32_t)ptr[r];

                                if ((uint64_t)a + 0x10 > ram_size) {
                                    info_report("ps3-ppu:   => %s 0x%"
                                                PRIX64 " is outside RAM",
                                                what[r], ptr[r]);
                                    continue;
                                }
                                info_report("ps3-ppu:   => %s 0x%X:"
                                            " %08X %08X %08X %08X",
                                            what[r], a,
                                            ps3_be32(ram + a),
                                            ps3_be32(ram + a + 4),
                                            ps3_be32(ram + a + 8),
                                            ps3_be32(ram + a + 12));
                            }
                        }
                    }
                    if ((uint64_t)sp + 0x40 <= ram_size) {
                        char words[256];
                        size_t at = 0;
                        unsigned n;

                        for (n = 0; n < 8; n++) {
                            at += snprintf(words + at, sizeof(words) - at,
                                           " %08X",
                                           ps3_be32(ram + sp + 4 * n));
                        }
                        info_report("ps3-ppu:   frame%s", words);
                    }
                    /*
                     * The ABI's registers are only half the picture when the
                     * fault is a call: a `bctrl` through a descriptor that was
                     * never filled leaves its address in one of the caller's
                     * registers and the call's own word just before the link
                     * register.  Dump both, so the site and its target can be
                     * read off without another run.
                     */
                    if (s->ppu_trace) {
                        unsigned n;

                        for (n = 0; n < 32; n += 8) {
                            info_report("ps3-ppu:   r%u-r%u %016" PRIX64
                                        " %016" PRIX64 " %016" PRIX64
                                        " %016" PRIX64 " %016" PRIX64
                                        " %016" PRIX64 " %016" PRIX64
                                        " %016" PRIX64,
                                        n, n + 7,
                                        (uint64_t)cpu->env.gpr[n + 0],
                                        (uint64_t)cpu->env.gpr[n + 1],
                                        (uint64_t)cpu->env.gpr[n + 2],
                                        (uint64_t)cpu->env.gpr[n + 3],
                                        (uint64_t)cpu->env.gpr[n + 4],
                                        (uint64_t)cpu->env.gpr[n + 5],
                                        (uint64_t)cpu->env.gpr[n + 6],
                                        (uint64_t)cpu->env.gpr[n + 7]);
                        }
                        info_report("ps3-ppu:   srr0=0x%" PRIX64 " srr1=0x%"
                                    PRIX64,
                                    (uint64_t)cpu->env.spr[SPR_SRR0],
                                    (uint64_t)cpu->env.spr[SPR_SRR1]);
                        if (cpu->env.lr >= 4 &&
                            (uint64_t)cpu->env.lr <= ram_size) {
                            info_report("ps3-ppu:   the instruction before "
                                        "lr is %08X at 0x%" PRIX64,
                                        ps3_be32(ram +
                                                 (uint32_t)cpu->env.lr - 4),
                                        (uint64_t)cpu->env.lr - 4);
                        }
                    }
                }
            }
            if (!t->main && t->exit_stub) {
                t->dead = true;
                s->sched_pending = true;
            }
        }
    }

    /*
     * A fault leaves the core at a vector with SRR0 naming the instruction and
     * SRR1 the interrupt cause.  Report the first one once: it is the only
     * useful thing a bring-up run can say about a vector it has no handler for.
     */
    {
        const char *vector = ps3_ppu_vector_name(s->ppu_last_pc);

        if (vector && s->ppu_fault_reports < 3) {
            s->ppu_fault_reports++;
            info_report("ps3-ppu: %s at pc 0x%" PRIx64 " (srr0=0x%" PRIx64
                        ", srr1=0x%" PRIx64 ", lr=0x%" PRIx64
                        ", ctr=0x%" PRIx64 ", r3=0x%" PRIx64
                        ", r4=0x%" PRIx64 ", r31=0x%" PRIx64
                        ", msr=0x%" PRIx64 ")",
                        vector, s->ppu_last_pc,
                        (uint64_t)cpu->env.spr[SPR_SRR0],
                        (uint64_t)cpu->env.spr[SPR_SRR1],
                        (uint64_t)cpu->env.lr, (uint64_t)cpu->env.ctr,
                        (uint64_t)cpu->env.gpr[3], (uint64_t)cpu->env.gpr[4],
                        (uint64_t)cpu->env.gpr[31],
                        (uint64_t)cpu->env.msr);
            /*
             * The frame a thread died in is only half the story: a return
             * address that came out of a clobbered linkage area is the
             * symptom, and the frames above it name the caller that built the
             * bad slot.  Walk the back chain and print each frame's saved LR,
             * which is what a `blr` out of it would use.
             */
            if (s->ppu_last_pc == 0x700 && s->ppu_trace) {
                uint8_t *ram = memory_region_get_ram_ptr(s->ram);
                uint64_t ram_size = memory_region_size(s->ram);
                uint32_t sp = (uint32_t)cpu->env.gpr[1];
                unsigned depth;

                for (depth = 0; depth < 6 && (uint64_t)sp + 0x20 <= ram_size;
                     depth++) {
                    info_report("ps3-ppu:   chain[%u] sp=0x%X lr=0x%" PRIX64
                                " back=0x%X", depth, sp,
                                ps3_be64(ram + sp + 0x10),
                                ps3_be32(ram + sp));
                    if (!ps3_be32(ram + sp) || ps3_be32(ram + sp) <= sp) {
                        break;
                    }
                    sp = ps3_be32(ram + sp);
                }
            }

            if (s->ppu_last_pc == 0x700 && s->ppu_trace) {
                unsigned n;

                for (n = 0; n < PS3_THREAD_MAX; n++) {
                    if (s->thr[n].used) {
                        info_report("ps3-ppu:   thread[%u] id 0x%X nip 0x%"
                                    PRIx64 " lr 0x%" PRIx64 " msr 0x%"
                                    PRIx64 "%s%s", n, s->thr[n].id,
                                    s->thr[n].nip, s->thr[n].lr,
                                    s->thr[n].msr,
                                    s->thr[n].parked ? " parked" : "",
                                    s->thr[n].blocked ? " blocked" : "");
                    }
                }
            }
        }
    }

    if (s->ppu_trace) {
        info_report("ps3-ppu: tick %" PRIu64 " pc=0x%" PRIx64
                    " lr=0x%" PRIx64 " msr=0x%" PRIx64 " thr=%d",
                    s->ppu_tick_count, (uint64_t)cpu->env.nip,
                    (uint64_t)cpu->env.lr, (uint64_t)cpu->env.msr,
                    s->thr_cur);
    }

    if (s->ppu_ticks && s->ppu_tick_count >= s->ppu_ticks) {
        info_report("ps3-ppu: stopping after %" PRIu64 " ticks at pc=0x%"
                    PRIx64 " (lr=0x%" PRIx64 ")",
                    s->ppu_tick_count, s->ppu_last_pc,
                    (uint64_t)cpu->env.lr);
        /*
         * Where a bounded run stops is often a wait the guest is sitting in,
         * and the call that led there is the useful thing to know: walk the
         * back chain of the thread that holds the core and print each frame's
         * saved LR, and name every thread's last PC besides.
         */
        if (s->ppu_trace) {
            uint8_t *ram = memory_region_get_ram_ptr(s->ram);
            uint64_t ram_size = memory_region_size(s->ram);
            uint32_t sp = (uint32_t)cpu->env.gpr[1];
            unsigned depth;

            for (depth = 0; depth < 8 && (uint64_t)sp + 0x20 <= ram_size;
                 depth++) {
                info_report("ps3-ppu:   chain[%u] sp=0x%X lr=0x%" PRIX64
                            " back=0x%X", depth, sp,
                            ps3_be64(ram + sp + 0x10), ps3_be32(ram + sp));
                if (!ps3_be32(ram + sp) || ps3_be32(ram + sp) <= sp) {
                    break;
                }
                sp = ps3_be32(ram + sp);
            }
            for (depth = 0; depth < PS3_THREAD_MAX; depth++) {
                PS3Thread *t = &s->thr[depth];
                unsigned step;
                uint32_t fsp;

                if (!t->used) {
                    continue;
                }
                info_report("ps3-ppu:   thread[%u] id 0x%X nip 0x%"
                            PRIx64 " lr 0x%" PRIx64 "%s%s", depth, t->id,
                            t->nip, t->lr,
                            t->parked ? " parked" : "",
                            t->blocked ? " blocked" : "");
                /* Where a parked thread's wait was called from. */
                fsp = (uint32_t)t->gpr[1];
                for (step = 0; step < 6 && (uint64_t)fsp + 0x20 <= ram_size;
                     step++) {
                    info_report("ps3-ppu:     t%u chain[%u] sp=0x%X lr=0x%"
                                PRIX64 " back=0x%X", t->id, step, fsp,
                                ps3_be64(ram + fsp + 0x10),
                                ps3_be32(ram + fsp));
                    if (!ps3_be32(ram + fsp) || ps3_be32(ram + fsp) <= fsp) {
                        break;
                    }
                    fsp = ps3_be32(ram + fsp);
                }
            }
        }
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

    elf = ps3_ppu_open(s, img, len, &seg_shift, why, sizeof(why));
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
    ps3_ppu_reset_register(s);
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
    /* A recovery application comes from the flash, not from a host path. */
    const char *name = s->app_path ?: s->vsh_self ?: "the application";
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

    if (s->app_img && s->app_img_len) {
        img = g_memdup2(s->app_img, s->app_img_len);
        len = s->app_img_len;
    } else if (!g_file_get_contents(s->vsh_self, (gchar **)&img, &len, &err)) {
        error_setg(errp, "ps3-vsh: cannot read %s: %s", name,
                   err->message);
        return false;
    }

    is_self = len >= 4 && !memcmp(img, "SCE\0", 4);
    elf = ps3_vsh_open(s, img, len, &header_len, &meta_offset, why,
                       sizeof(why));
    if (!elf) {
        error_setg(errp, "ps3-vsh: %s: %s", name, why);
        return false;
    }

    phoff = is_self ? ps3_be64(img + 0x38) : ps3_be64(elf + 0x20);
    phentsize = ((unsigned)elf[0x36] << 8) | elf[0x37];
    phnum = ((unsigned)elf[0x38] << 8) | elf[0x39];

    if (phentsize < 0x38 || phnum > 0x20 ||
        phoff + (uint64_t)phnum * phentsize > len) {
        error_setg(errp, "ps3-vsh: %s: program header table 0x%" PRIX64
                   "/%u does not fit", name, phoff, phnum);
        return false;
    }

    if (is_self) {
        section_count = ps3_be32(img + meta_offset + 0x60 + 0x0C);
        if (section_count > 0x40 ||
            meta_offset + 0x80 + 0x30 * (uint64_t)section_count > header_len) {
            error_setg(errp, "ps3-vsh: %s: section table %u does not fit",
                       name, section_count);
            return false;
        }
    }

    ram = memory_region_get_ram_ptr(s->ram);
    ram_size = memory_region_size(s->ram);
    s->vsh_lo = 0;
    s->vsh_hi = 0;

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
                       "file", name, i);
            return false;
        }

        if (pa + memsz > ram_size) {
            pa &= 0x0FFFFFFF;
        }
        if (pa + memsz > ram_size) {
            error_setg(errp, "ps3-vsh: %s: segment %u (0x%" PRIX64
                       "/0x%" PRIX64 ") does not fit RAM",
                       name, i, pa, memsz);
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
                           name, i, rc);
                return false;
            }

            memcpy(ram + pa, buf, MIN((uint64_t)out, memsz));
            bytes += out;
            g_free(buf);
        } else {
            memcpy(ram + pa, src, MIN(src_len, memsz));
            bytes += MIN(src_len, memsz);
        }

        if (!s->vsh_lo || pa < s->vsh_lo) {
            s->vsh_lo = pa;
        }
        s->vsh_hi = MAX(s->vsh_hi, (uint32_t)(pa + memsz));

        loaded++;
        info_report("ps3-vsh: segment %u: 0x%" PRIX64 " + 0x%" PRIX64
                    " -> RAM 0x%" PRIX64 " (stored 0x%" PRIX64
                    ", compression %u)", i, vaddr, memsz, pa, src_len,
                    compression);
    }

    if (!loaded) {
        error_setg(errp, "ps3-vsh: %s carries no loadable segment", name);
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
    }        info_report("ps3-vsh: %s: entry=0x%" PRIX64 ", %u segment(s), "
                    "0x%" PRIu64 " bytes mapped into RAM%s", name, entry,
                loaded, bytes,
                s->vsh_run ? ", PPU entering it" : " (load-only)");

    ps3_vga_printf("VSH: %u SEGMENT(S), %" PRIu64 " BYTES MAPPED%s",
                   loaded, bytes, s->vsh_run ? ", ENTERING" : "");

    if (s->vsh_run) {
        CPUState *cs = qemu_get_cpu(0);
        PowerPCCPU *cpu;

        /*
         * Thread slices end on a 1 ms timer, and without icount that timer
         * follows the host's clock rather than the guest's instructions: the
         * state a thread is preempted in then depends on how fast the host
         * happened to run, so two runs of the same guest stop in different
         * places.  Say so once, because a debugging run is worthless if the
         * run before it could never have matched.
         */
        if (!icount_enabled()) {
            info_report("ps3-vsh: note: no -icount, so thread slices follow "
                        "host time and this run is not reproducible; add "
                        "-icount shift=6,sleep=off for a run that stops in "
                        "the same place every time");
        }
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

        /*
         * A process starts with argc/argv, and the recovery program reads
         * them: emer_init prints its argument vector and exits before drawing
         * anything when argc is 0.  lv2 builds the block inside the new
         * process's stack; here it sits just below the initial stack pointer
         * with the image path as argv[0].
         */
        {
            uint32_t argv = (uint32_t)ram_size - 0x400;
            uint32_t str = (uint32_t)ram_size - 0x380;
            const char *path = s->app_path ?: s->vsh_self ?: "";
            size_t len = strlen(path);

            if (len && (uint64_t)str + len + 1 <= ram_size) {
                memcpy(ram + str, path, len + 1);
                ps3_put_be32(ram + argv, str);
                ps3_put_be32(ram + argv + 4, 0);
                cpu->env.gpr[3] = 1;
                cpu->env.gpr[4] = argv;
            } else {
                cpu->env.gpr[3] = 0;
                cpu->env.gpr[4] = 0;
            }
        }
        cpu->env.msr |= (1ULL << MSR_SF) | (1ULL << MSR_ME) |
                        (1ULL << MSR_FP) | (1ULL << MSR_VR);
        cpu->env.msr &= ~((1ULL << MSR_IR) | (1ULL << MSR_DR));
        /*
         * The lv2 syscall boundary at 0xC00 is a ROM region the board puts
         * there (rs6000_ps3_lv2_page), so the guest cannot overwrite it.  The
         * shim is a bring-up lv2, not a full kernel: it handles the calls the
         * VSH's C runtime makes while it initializes (memory, locks, timebase,
         * tty), reports each number at 0xF1040014, and returns -ENOSYS for
         * anything else.
         */

        /* lv2 scratch, then the heap above the VSH image and below the stack. */
        memset(ram + PS3_LV2_SCRATCH, 0, 8);
        s->lv2_next_id = 0;
        s->lv2_container_size = 0;
        s->lv2_mod_count = 0;
        s->lv2_export_count = 0;
        ps3_lv2_register_process_exports(s, ram, ram_size);
        ps3_lv2_link_process(s, ram, ram_size);
        s->lv2_exited = false;
        s->lv2_fan_policy = 0;
        s->lv2_fan_duty = 0;
        s->lv2_stub_next = 0;
        s->lv2_export_full = false;
        s->lv2_exit_status = 0;
        s->lv2_heap = 0x01000000;
        ps3_put_be32(ram + PS3_LV2_HEAP, s->lv2_heap);

        s->ppu_entry = code;
        s->ppu_last_pc = code;
        ps3_ppu_reset_register(s);

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
    DEFINE_PROP_STRING("disc-file", PS3BootROMState, disc_file),
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
    DEFINE_PROP_UINT8("pad-count", PS3BootROMState, pad_ports, 1),
    DEFINE_PROP_STRING("pad-types", PS3BootROMState, pad_types_prop),
    DEFINE_PROP_STRING("stage-dump", PS3BootROMState, stage_dump),
    DEFINE_PROP_STRING("stage-args", PS3BootROMState, stage_args),
    DEFINE_PROP_UINT32("stage-entry", PS3BootROMState, stage_entry, 0),
    DEFINE_PROP_UINT64("stage-limit", PS3BootROMState, stage_limit, 0),
    DEFINE_PROP_UINT64("stage-wait", PS3BootROMState, stage_wait, 0),
    DEFINE_PROP_UINT64("stage-version", PS3BootROMState, stage_version, 0),
    DEFINE_PROP_STRING("audio", PS3BootROMState, audio_dev),

    DEFINE_PROP_STRING("vsh-dump", PS3BootROMState, vsh_dump),
    DEFINE_PROP_STRING("vsh-erk", PS3BootROMState, vsh_erk),
    DEFINE_PROP_STRING("vsh-riv", PS3BootROMState, vsh_riv),

    DEFINE_PROP_STRING("usb-dir", PS3BootROMState, usb_dir),

    DEFINE_PROP_STRING("hdd1-dir", PS3BootROMState, hdd1_dir),
    DEFINE_PROP_UINT32("idle-off-seconds", PS3BootROMState, idle_off_seconds,
                       3600),
    DEFINE_PROP_BOOL("threads", PS3BootROMState, threads_enabled, false),
    DEFINE_PROP_STRING("hdd-file", PS3BootROMState, hdd_file),
    DEFINE_PROP_STRING("emmc-file", PS3BootROMState, emmc_file),
    DEFINE_PROP_UINT64("emmc-size", PS3BootROMState, emmc_size, 12 * GiB),
    DEFINE_PROP_STRING("boot-medium", PS3BootROMState, boot_medium),
    DEFINE_PROP_BOOL("boot-logo", PS3BootROMState, boot_logo, true),
    /* Boot with the EEPROM's recover flag set, i.e. into the recovery loop. */
    DEFINE_PROP_BOOL("recover", PS3BootROMState, recover_prop, false),

    DEFINE_PROP_UINT64("hdd-size", PS3BootROMState, hdd_size, 20 * GiB),
    DEFINE_PROP_STRING("erk", PS3BootROMState, erk_prop),
    DEFINE_PROP_STRING("erk-file", PS3BootROMState, erk_file),
    DEFINE_PROP_STRING("pck2", PS3BootROMState, pck2_prop),
    DEFINE_PROP_STRING("pck2-file", PS3BootROMState, pck2_file),
    DEFINE_PROP_BOOL("vsh-run", PS3BootROMState, vsh_run, false),
    DEFINE_PROP_STRING("rom-file", PS3BootROMState, rom_file),
    DEFINE_PROP_STRING("container", PS3BootROMState, container),
    DEFINE_PROP_STRING("readout", PS3BootROMState, readout),
    DEFINE_PROP_STRING("readout-file", PS3BootROMState, readout_file),
    DEFINE_PROP_BOOL("selftest", PS3BootROMState, selftest, true),
    DEFINE_PROP_BOOL("mic-selftest", PS3BootROMState, mic_selftest, false),
    DEFINE_PROP_BOOL("pad-selftest", PS3BootROMState, pad_selftest, false),
    DEFINE_PROP_BOOL("spu", PS3BootROMState, spu_run, true),
    DEFINE_PROP_BOOL("spu-trace", PS3BootROMState, spu_trace, false),
    DEFINE_PROP_STRING("ls-dump", PS3BootROMState, ls_dump),
    DEFINE_PROP_STRING("prx-dump", PS3BootROMState, prx_dump),
    DEFINE_PROP_UINT64("flash-base", PS3BootROMState, flash_base, 0x20000000),
};

static void ps3_rom_unrealize(DeviceState *dev)
{
    PS3BootROMState *s = PS3_BOOT_ROM(dev);
    unsigned i;

    for (i = 0; i < PS3_SPU_LV2_GROUPS; i++) {
        ps3_spu_lv2_group_free(&s->spug[i]);
    }

    ps3_spes_free(s->spes);
    s->spes = NULL;
    s->spu = NULL;
}

static void ps3_rom_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = ps3_rom_realize;
    dc->unrealize = ps3_rom_unrealize;
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
#define PS3_VGA_MMIO_BASE  0xF0200000

static void rs6000_ps3_cpu_reset(void *opaque)
{
    PowerPCCPU *cpu = opaque;
    CPUPPCState *env = &cpu->env;

    cpu_reset(CPU(cpu));

    /* The Cell PPU comes out of reset in 64-bit mode with translation off. */
    env->msr = (1ULL << MSR_SF) | (1ULL << MSR_ME);
    env->nip = PS3_BOOT_ROM_BASE + 0x100;
}

/*
 * lv2's low page, protected from the process.
 *
 * On hardware the first 32 KiB belong to lv2: a user process cannot store
 * there, and the 0xC00 syscall vector is the kernel's.  This model runs the
 * PPU with translation off, so a guest store reaches RAM directly, and the
 * VSH's later initialisation memsets a table straight through the page - it
 * takes out the trampoline and the next `sc` runs the fill pattern.
 *
 * Two overlays stand in for the mapping the model does not have:
 *
 *   0x800..0x900  the bump pointer at 0x808 and the result block at 0x880.
 *                 Reads pass through to RAM; stores are dropped, and the first
 *                 one is reported with the pc, lr and argument registers so the
 *                 writer is identified rather than guessed at.
 *   0xC00..0xC60  the syscall trampoline as ROM.  It is executable, reads the
 *                 result block as usual, and a store from the guest is a no-op
 *                 instead of the next `sc` faulting at 0x700.
 *
 * The container's authority is in the device (lv2_heap), so the fill cannot
 * move the heap even where it does land.
 */
#define PS3_LV2_TRAP_BASE   0x800
#define PS3_LV2_TRAP_SIZE   0x100
#define PS3_LV2_VECTOR      0xC00
#define PS3_LV2_VECTOR_SIZE 0x60

typedef struct PS3Lv2Trap {
    MemoryRegion *ram;
    bool reported;
    uint64_t stores;
} PS3Lv2Trap;

static uint64_t ps3_lv2_trap_read(void *opaque, hwaddr addr, unsigned size)
{
    PS3Lv2Trap *t = opaque;
    const uint8_t *p = memory_region_get_ram_ptr(t->ram) +
                       PS3_LV2_TRAP_BASE + addr;
    uint64_t v = 0;
    unsigned i;

    for (i = 0; i < size; i++) {
        v = (v << 8) | p[i];
    }

    return v;
}

static void ps3_lv2_trap_write(void *opaque, hwaddr addr, uint64_t value,
                              unsigned size)
{
    PS3Lv2Trap *t = opaque;
    CPUState *cs = qemu_get_cpu(0);

    t->stores++;

    if (t->reported || !cs) {
        return;
    }

    t->reported = true;
    {
        CPUPPCState *env = &POWERPC_CPU(cs)->env;

        info_report("ps3-ppu: lv2: store of 0x%" PRIX64 " to 0x%X ignored "
                    "(pc=0x%" PRIX64 ", lr=0x%" PRIX64 ", r3=0x%" PRIX64
                    ", r4=0x%" PRIX64 ", r5=0x%" PRIX64 ", ctr=0x%" PRIX64
                    ")",
                    value, (unsigned)(PS3_LV2_TRAP_BASE + addr),
                    (uint64_t)env->nip, (uint64_t)env->lr,
                    (uint64_t)env->gpr[3], (uint64_t)env->gpr[4],
                    (uint64_t)env->gpr[5], (uint64_t)env->ctr);

        /* The top of the stack names the caller chain that got here. */
        {
            const uint8_t *base = memory_region_get_ram_ptr(t->ram);
            uint64_t ram_len = memory_region_size(t->ram);
            uint32_t sp = env->gpr[1];
            unsigned row;

            for (row = 0; row < 4; row++) {
                uint64_t at = (uint64_t)sp + row * 0x20;

                if (at + 0x20 > ram_len) {
                    break;
                }

                info_report("ps3-ppu: lv2:   sp+0x%02X: %08X %08X %08X %08X "
                            "%08X %08X %08X %08X",
                            row * 0x20, ps3_be32(base + at),
                            ps3_be32(base + at + 4), ps3_be32(base + at + 8),
                            ps3_be32(base + at + 12), ps3_be32(base + at + 16),
                            ps3_be32(base + at + 20), ps3_be32(base + at + 24),
                            ps3_be32(base + at + 28));
            }
        }
    }
}

static const MemoryRegionOps ps3_lv2_trap_ops = {
    .read = ps3_lv2_trap_read,
    .write = ps3_lv2_trap_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
};

static void rs6000_ps3_lv2_page(MemoryRegion *sysmem, MemoryRegion *ram)
{
    PS3Lv2Trap *trap = g_new0(PS3Lv2Trap, 1);
    MemoryRegion *trap_mr = g_new0(MemoryRegion, 1);
    MemoryRegion *vector = g_new0(MemoryRegion, 1);
    uint8_t *p;
    size_t i;

    trap->ram = ram;
    memory_region_init_io(trap_mr, NULL, &ps3_lv2_trap_ops, trap,
                          "ps3.lv2-scratch", PS3_LV2_TRAP_SIZE);
    memory_region_add_subregion_overlap(sysmem, PS3_LV2_TRAP_BASE, trap_mr, 1);

    memory_region_init_rom(vector, NULL, "ps3.lv2-vector",
                           PS3_LV2_VECTOR_SIZE, &error_fatal);
    p = memory_region_get_ram_ptr(vector);
    memset(p, 0, PS3_LV2_VECTOR_SIZE);
    for (i = 0; i < ARRAY_SIZE(ps3_lv2_shim); i++) {
        ps3_put_be32(p + i * 4, ps3_lv2_shim[i]);
    }
    memory_region_add_subregion_overlap(sysmem, PS3_LV2_VECTOR, vector, 1);

    info_report("rs6000-ps3: lv2 low page: %u-word sc vector at 0x%X as ROM, "
                "scratch 0x%X..0x%X trapped",
                (unsigned)ARRAY_SIZE(ps3_lv2_shim), PS3_LV2_VECTOR,
                PS3_LV2_TRAP_BASE, PS3_LV2_TRAP_BASE + PS3_LV2_TRAP_SIZE);
}

static void rs6000_ps3_init(MachineState *machine)
{
    MemoryRegion *sysmem = get_system_memory();
    MemoryRegion *ram = machine->ram;
    MemoryRegion *boot = g_new(MemoryRegion, 1);
    PowerPCCPU *cpu;
    DeviceState *mic, *rom, *vga;
    DriveInfo *dinfo, *disc_drive;

    /*
     * Hardware acceleration runs the host's CPU, so on this target it can only
     * run the board on a POWER host, through KVM.  HVF (macOS) and WHPX
     * (Windows) only virtualise x86 and ARM guests, so a Cell PPU cannot use
     * them: those hosts run TCG and there is nothing to switch on.  When KVM
     * is in use the CPU must be the host's - a modelled 970 is a TCG CPU.
     */
    if (kvm_enabled()) {
        if (!strcmp(machine->cpu_type,
                    POWERPC_CPU_TYPE_NAME("970fx_v3.1"))) {
            machine->cpu_type = POWERPC_CPU_TYPE_NAME("host");
        }
    }

    {
        const char *accel = "TCG";

        if (kvm_enabled()) {
            accel = "KVM, host CPU";
        }
#ifdef CONFIG_HVF
        else if (hvf_enabled()) {
            accel = "HVF, host CPU";
        }
#endif
#ifdef CONFIG_WHPX
        else if (whpx_enabled()) {
            accel = "WHPX, host CPU";
        }
#endif
        info_report("rs6000-ps3: acceleration: %s", accel);
    }

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

    /*
     * The display.  The RSX does not exist yet, so this is a linear
     * framebuffer the guest can point at its own memory; it is what puts a
     * window on screen instead of -display none.  It is created before the
     * boot ROM device so the ROM's own progress lines land on the screen.
     */
    vga = qdev_new("ps3-vga");
    if (vga_interface_type == VGA_RSX) {
        /*
         * -vga rsx: the RSX display.  `gl=on' requires a GL backend (SDL or
         * GTK with gl=on); `gl=off' keeps the CPU scanout, and no gl= leaves
         * it to whether the display has a GL context.  The check runs after
         * the display frontend attaches, in ps3-vga itself.
         */
        qdev_prop_set_bit(vga, "gl", vga_rsx_gl != 0);
        qdev_prop_set_bit(vga, "gl-required", vga_rsx_gl == 1);
        vga_interface_created = true;
        info_report("rs6000-ps3: display: rsx (gl=%s)",
                    vga_rsx_gl > 0 ? "on" :
                    vga_rsx_gl < 0 ? "auto" : "off");
    }
    sysbus_realize_and_unref(SYS_BUS_DEVICE(vga), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(vga), 0, PS3_VGA_MMIO_BASE);

    /*
     * The disc.  On hardware the Blu-ray drive is an ATA device; the guest's
     * ATA driver reaches it through the same command block either way, so the
     * model hands it QEMU's legacy IDE/ATAPI interface with the image as a
     * CD-ROM.  `-drive if=ide,media=cdrom,file=disc.iso,format=raw` attaches
     * it; without one the channel is simply empty.
     */
    {
        ISABus *isabus = isa_bus_new(NULL, get_system_memory(),
                                     get_system_io(), &error_fatal);

        disc_drive = drive_get(IF_IDE, 0, 0);
        isa_bus_register_input_irqs(isabus,
                                    qemu_allocate_irqs(ps3_isa_noop, NULL, 16));
        isa_ide_init(isabus, 0x1F0, 0x3F6, 14, disc_drive, NULL);
        info_report("rs6000-ps3: disc: IDE/ATAPI channel at 0x1F0%s",
                    disc_drive ? " with the image attached" : " (no image)");
    }

    rom = qdev_new(TYPE_PS3_BOOT_ROM);
    object_property_set_link(OBJECT(rom), "ram", OBJECT(ram), &error_abort);

    if (machine->firmware) {
        qdev_prop_set_string(rom, "rom-file", machine->firmware);
    }

    dinfo = drive_get(IF_PFLASH, 0, 0);

    if (dinfo) {
        qdev_prop_set_drive(rom, "drive", blk_by_legacy_dinfo(dinfo));
    }

    if (disc_drive) {
        /*
         * lv2's storage layer reads the same media the ATAPI device serves,
         * so both the guest's own ATA driver and the VSH's x3 layer see one
         * disc instead of two views of it.
         */
        const char *disc_path = qemu_opt_get(disc_drive->opts, "file");

        if (disc_path) {
            qdev_prop_set_string(rom, "disc-file", disc_path);
        }
    }

    sysbus_realize_and_unref(SYS_BUS_DEVICE(rom), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(rom), 0, PS3_BOOT_ROM_REGS);
    sysbus_mmio_map(SYS_BUS_DEVICE(rom), 1, PS3_LS_BASE);
    sysbus_mmio_map(SYS_BUS_DEVICE(rom), 2, PS3_SPES_LS_BASE);
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
