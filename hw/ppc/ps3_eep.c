/*
 * The PlayStation 3's system-controller EEPROM
 *
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The console keeps its configuration in the syscon's EEPROM, a 32 KiB part:
 * 0x4000 blocks of two bytes each.  Nothing on the Cell side sees the chip
 * directly - lv2 reaches it through sys_ss_update_manager(), whose 0x600B and
 * 0x600C operations take an address and one byte.  The addresses the firmware
 * and the applications use are windows, not part offsets: the resolve side of
 * the address map (scaddr sub_2ED82) folds 0x48000, 0x48800, 0x48C00 and
 * 0x48D00 onto NVS 0x7000, 0x7100, 0x7200 and 0x7300, 0x100 bytes each, and a
 * bare address below 0x8000 is the part's own byte.  So 0x48C07 is NVS byte
 * 0x7207 and 0x48D3E is 0x733E.
 *
 * The fields, from the console's own documentation (the SC EEPROM table and
 * graf_chokolo's hypervisor notes):
 *
 *   0x48C06   1   FSELF control flag
 *   0x48C07   1   product mode; 0xFF retail, 0x00/0xFE factory (service) mode
 *   0x48C0A   1   QA flag
 *   0x48C13   1   device type; 0xFF retail, 0x00 factory/service
 *   0x48C30   1   number of usable SPEs, 0x06 stock, 0x07 all eight
 *   0x48C42   1   HDD copy mode
 *   0x48C50  16   debug support flags
 *   0x48C60   1   update status
 *   0x48C61   1   recover mode flag; selects the ros1 bank over ros0
 *   0x48D3E  80   QA token
 *
 * The image in ps3_eep_image.h is a real console's readout, not a synthetic
 * one: 0x5000 of its 0x8000 bytes are written and the tail is erased, and its
 * bytes are the part's own (the syscon stores them sealed, which is why the
 * readout is not plain text).  It is compiled in on purpose - the model
 * always has a console's EEPROM and no run-time dump is accepted - so the
 * image below is the only source of EEPROM bytes.
 *
 * Two bytes cannot come from it.
 *
 * The recover flag describes how *this* console was started: clear on a
 * console whose service jumper was set, which is what a recovery run is.  It
 * is state here, retail (0xFF) until the machine enters recovery.
 *
 * Product mode is not the machine's: it is what a program writes to select
 * factory (service) mode, 0x00/0xFE, and a program's write is the state a
 * later read and the next boot see.  A console in recovery is still a retail
 * console, so product mode reads 0xFF there; tying the two together made
 * emer_init read product mode 0x00 in recovery and take its factory branch,
 * writing the recover flag and restarting instead of drawing the menu.
 *
 * The readout's own bytes at those offsets are left alone.
 */
#include "qemu/osdep.h"
#include "hw/ppc/ps3_eep.h"
#include "hw/ppc/ps3_eep_image.h"

/* Guest and model writes, which outlive the readout for the length of a run. */
static struct {
    uint32_t off;
    uint8_t val;
} ps3_eep_writes[32];
static int ps3_eep_nwrites;

static bool ps3_eep_service;

/*
 * The four windows the firmware names, and the NVS bytes they fold onto.  A
 * window is 0x100 bytes; the two halves of the first page (0x48000, 0x48800)
 * are 0x800 apart in the guest's address space and adjacent here.
 */
static const struct {
    uint32_t page;
    uint32_t nvs;
} ps3_eep_fold[] = {
    { 0x48000, 0x7000 },
    { 0x48800, 0x7100 },
    { 0x48C00, 0x7200 },
    { 0x48D00, 0x7300 },
};

/* The NVS byte an address names, or false when it names none of them. */
static bool ps3_eep_nvs_byte(uint32_t nvs_off, uint32_t *nvs_byte)
{
    for (unsigned i = 0; i < ARRAY_SIZE(ps3_eep_fold); i++) {
        if (nvs_off >= ps3_eep_fold[i].page &&
            nvs_off < ps3_eep_fold[i].page + 0x100) {
            *nvs_byte = ps3_eep_fold[i].nvs + (nvs_off - ps3_eep_fold[i].page);
            return true;
        }
    }
    if (nvs_off < PS3_EEP_IMAGE_SIZE) {
        *nvs_byte = nvs_off;                /* the part's own byte */
        return true;
    }
    return false;
}

uint8_t ps3_eep_read(uint32_t nvs_off)
{
    uint32_t nvs_byte;
    int i;

    /*
     * A program's own writes come first: they are how a factory-mode program
     * selects product mode, and how one clears the recover flag before asking
     * for the restart that leaves recovery.
     */
    for (i = 0; i < ps3_eep_nwrites; i++) {
        if (ps3_eep_writes[i].off == nvs_off) {
            return ps3_eep_writes[i].val;
        }
    }
    /*
     * Retail until a program says otherwise: recovery is a retail console
     * whose recover flag is clear, not a factory one, and the emergency
     * program takes the factory branch when product mode reads 0x00.
     */
    if (nvs_off == PS3_EEP_PRODUCT_MODE) {
        return 0xFF;
    }
    if (nvs_off == PS3_EEP_RECOVER) {
        return ps3_eep_service ? 0x00 : 0xFF;
    }
    if (ps3_eep_nvs_byte(nvs_off, &nvs_byte) &&
        nvs_byte < PS3_EEP_IMAGE_USED) {
        return ps3_eep_image[nvs_byte];
    }
    return 0xFF;                            /* erased, or past the part */
}

void ps3_eep_write(uint32_t nvs_off, uint8_t val)
{
    int i;

    for (i = 0; i < ps3_eep_nwrites; i++) {
        if (ps3_eep_writes[i].off == nvs_off) {
            ps3_eep_writes[i].val = val;
            return;
        }
    }
    if (ps3_eep_nwrites < ARRAY_SIZE(ps3_eep_writes)) {
        ps3_eep_writes[ps3_eep_nwrites].off = nvs_off;
        ps3_eep_writes[ps3_eep_nwrites].val = val;
        ps3_eep_nwrites++;
    }
}

void ps3_eep_set_service_mode(bool on)
{
    ps3_eep_service = on;
}

bool ps3_eep_service_mode(void)
{
    return ps3_eep_service;
}

uint32_t ps3_eep_image_used(void)
{
    return PS3_EEP_IMAGE_USED;
}
