/*
 * SPU execution model for the PS3 boot path.
 *
 * Local research model, not intended for upstream QEMU contributions.
 *
 * It executes the SPU instruction set (see ps3_spu.c): 256 KiB of local
 * storage, the 128 quadword registers, the channels and a synchronous MFC over
 * a writable copy of the console's flash image.  The goal is to run the payload
 * the mask ROM leaves at LS[0x400], not to be a complete SPE.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct PS3SPU PS3SPU;

PS3SPU *ps3_spu_new(uint8_t *ls, size_t ls_size,
                    const uint8_t *flash, size_t flash_size);
void ps3_spu_free(PS3SPU *spu);

/* The 32 bytes the ROM reads from channel 66, in read order. */
void ps3_spu_set_ch66(PS3SPU *spu, const uint8_t key[32]);

/* SPU_RdSigNotify1/2, the image effective address the ROM fetches. */
void ps3_spu_set_sig(PS3SPU *spu, uint32_t hi, uint32_t lo);

/*
 * Set one register in every slot before starting.  The mask ROM is entered
 * with $90 preset (the isolation loader leaves the local-store hand-off
 * address there): it DMA-prefetches its header to LS 0x410 and reads it back
 * through $90 - 0x40 .. $90 - 0x10.
 */
void ps3_spu_set_reg(PS3SPU *spu, unsigned reg, uint32_t value);

/* One line per instruction on stderr. */
void ps3_spu_set_trace(PS3SPU *spu, bool on);

/*
 * Run from `entry' for at most `limit' instructions.  Returns 0 when the
 * program executed a stop, 1 on the instruction limit, 2 on an opcode the
 * model does not implement (or an address outside local storage).  `why'
 * always receives a one-line description, including the instructions that led
 * to a fault.
 */
int ps3_spu_run(PS3SPU *spu, uint32_t entry, uint64_t limit,
                char *why, size_t why_len);

/*
 * Run until the program reaches `stop_pc' (the ROM's hand-off at 0x400), or
 * stops on its own.  Returns 0 when the PC reached `stop_pc', 1 on the
 * instruction limit, 2 on a fault.
 */
int ps3_spu_run_to(PS3SPU *spu, uint32_t entry, uint32_t stop_pc,
                   uint64_t limit, char *why, size_t why_len);

uint64_t ps3_spu_insns(const PS3SPU *spu);
uint32_t ps3_spu_pc(const PS3SPU *spu);
uint32_t ps3_spu_gpr_word(const PS3SPU *spu, unsigned reg, unsigned lane);

/* The immediate of the stop instruction that ended the run, 0 if none. */
unsigned ps3_spu_stop_code(const PS3SPU *spu);

/* MFC activity: what the payload pulled in and what it wrote back out. */
uint64_t ps3_spu_mfc_gets(const PS3SPU *spu);
uint64_t ps3_spu_mfc_puts(const PS3SPU *spu);
uint32_t ps3_spu_last_put_ea(const PS3SPU *spu);
uint32_t ps3_spu_last_put_size(const PS3SPU *spu);

/* The writable external memory: the flash image plus whatever was PUT. */
uint8_t *ps3_spu_ext_ptr(PS3SPU *spu, size_t *size);
