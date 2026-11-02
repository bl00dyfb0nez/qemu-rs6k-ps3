/*
 * The PlayStation 3's system-controller EEPROM
 *
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef HW_PPC_PS3_EEP_H
#define HW_PPC_PS3_EEP_H

#include "qemu/osdep.h"

/* The part's 0x8000 bytes sit at this page of the NVS address space. */
#define PS3_EEP_NVS_PAGE        0x48000u

/* The documented bytes, by their NVS address. */
#define PS3_EEP_FSELF           0x48C06u
#define PS3_EEP_PRODUCT_MODE    0x48C07u
#define PS3_EEP_QA_FLAG         0x48C0Au
#define PS3_EEP_DEVICE_TYPE     0x48C13u
#define PS3_EEP_SPE_COUNT       0x48C30u
#define PS3_EEP_HDD_COPY        0x48C42u
#define PS3_EEP_DEBUG_FLAGS     0x48C50u
#define PS3_EEP_DEBUG_LEN       0x10u
#define PS3_EEP_UPDATE_STATUS   0x48C60u
#define PS3_EEP_RECOVER         0x48C61u
#define PS3_EEP_QA_TOKEN        0x48D3Eu
#define PS3_EEP_QA_TOKEN_LEN    0x50u

uint8_t ps3_eep_read(uint32_t nvs_off);
void ps3_eep_write(uint32_t nvs_off, uint8_t val);

/* How this console was started: the two bytes the machine, not the part, owns. */
void ps3_eep_set_service_mode(bool on);
bool ps3_eep_service_mode(void);

/* The number of readout bytes the embedded image carries. */
uint32_t ps3_eep_image_used(void);

#endif /* HW_PPC_PS3_EEP_H */
