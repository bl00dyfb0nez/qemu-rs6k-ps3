/*
 * SPU execution model for the PS3 boot path.
 *
 * Local research model, not intended for upstream QEMU contributions.
 *
 * It executes the SPU instruction set (see ps3_spu.c): 256 KiB of local
 * storage, the 128 quadword registers, the channels and a synchronous MFC over
 * a writable copy of the console's flash image.  The whole ISA is implemented -
 * integer, single- and double-precision floating point, the multiply family,
 * the halt variants, SPRs, the user-mode channel map and MFC lists/atomics.
 *
 * Concurrency is modelled: an SPE group holds up to eight SPEs, each with its
 * own local store, channels and run state, sharing one external memory and
 * scheduled round-robin.  The timing figure is an issue-slot and
 * register-hazard estimate (two pipes, latency classes), not a cycle-accurate
 * model of the Cell pipeline.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct PS3SPU PS3SPU;
typedef struct PS3SPEGroup PS3SPEGroup;

/* Cell has eight SPEs on the die; the model can start any number up to this. */
#define PS3_SPE_MAX 8
#define PS3_LS_SIZE_BYTES 0x40000

/*
 * Run status, shared by ps3_spu_run() and ps3_spes_run_quantum().
 *   0  the program stopped (stop/stopd, or every SPE halted)
 *   1  the instruction budget ran out
 *   2  the model faulted (unknown opcode, bad local-store address)
 *   3  the SPE is blocked on a channel whose count is zero
 */
#define PS3_SPU_STOPPED 0
#define PS3_SPU_LIMIT   1
#define PS3_SPU_FAULT   2
#define PS3_SPU_BLOCKED 3

/*
 * A stand-alone SPE with its own copy of `flash' as external memory.  The
 * local store is the caller's buffer; the model reads and writes it in place.
 */
PS3SPU *ps3_spu_new(uint8_t *ls, size_t ls_size,
                    const uint8_t *flash, size_t flash_size);
void ps3_spu_free(PS3SPU *spu);

/*
 * A group of `count' SPEs (1..PS3_SPE_MAX) sharing one external memory.  The
 * caller supplies the local-store backing store: `ls_block' must be at least
 * count * PS3_LS_SIZE_BYTES, and SPE n uses the n-th 256 KiB slice.  The
 * external memory is `flash_size' bytes plus 4 MiB of scratch, copied from
 * `flash' (which may be NULL).
 *
 * `ls_ea_base' is the effective address at which SPE 0's local store appears
 * to MFC transfers; SPE n is at ls_ea_base + n * 0x40000.  It is what the
 * isolation check uses to recognise a transfer aimed at another SPE's store.
 */
PS3SPEGroup *ps3_spes_new(unsigned count, uint8_t *ls_block, size_t block_size,
                          const uint8_t *flash, size_t flash_size,
                          uint32_t ls_ea_base);
void ps3_spes_free(PS3SPEGroup *group);

unsigned ps3_spes_count(const PS3SPEGroup *group);
PS3SPU *ps3_spes_spu(PS3SPEGroup *group, unsigned n);

/*
 * Run each runnable, non-halted SPE for up to `slice' instructions, in a
 * round-robin, until every SPE has stopped/halted, the total budget is used
 * up, one faults, or every remaining SPE is blocked on a channel.
 */
int ps3_spes_run_quantum(PS3SPEGroup *group, uint64_t slice,
                         uint64_t *insns_run, char *why, size_t why_len);

/* The finish time of the slowest SPE, in estimated issue cycles. */
uint64_t ps3_spes_cycles(const PS3SPEGroup *group);
/* Aggregate MFC and protection counters over the group. */
uint64_t ps3_spes_mfc_gets(const PS3SPEGroup *group);
uint64_t ps3_spes_mfc_puts(const PS3SPEGroup *group);
uint64_t ps3_spes_protection_faults(const PS3SPEGroup *group);

/* External memory shared by the group (writable). */
uint8_t *ps3_spes_ext_ptr(PS3SPEGroup *group, size_t *size);

/*
 * Point a group at memory the caller owns - lv2's SPEs share guest RAM rather
 * than a copy - instead of the buffer ps3_spes_new() allocated.  The group
 * releases only memory it allocated itself.
 */
void ps3_spes_map_ext(PS3SPEGroup *group, uint8_t *ext, size_t size);

/* ---- local storage, as lv2's sys_spu_thread_*_ls sees it --------------- */

/* Copy an SPU image segment into a thread's local store. */
void ps3_spu_load_ls(PS3SPU *spu, uint32_t lsa, const void *src, size_t len);
/* Fill a local-store range with one word, for SYS_SPU_SEGMENT_TYPE_FILL. */
void ps3_spu_fill_ls(PS3SPU *spu, uint32_t lsa, size_t len, uint32_t value);

const uint8_t *ps3_spu_ls_ptr(const PS3SPU *spu, uint32_t lsa);
uint32_t ps3_spu_ls_read32(const PS3SPU *spu, uint32_t lsa);

/*
 * The SPU ABI passes a 64-bit argument in the preferred slot: the low half of
 * the quadword register, i.e. lanes 2 and 3.  sys_spu_thread_initialize puts
 * arg1..arg4 in $3..$6 that way before the thread starts.
 */
void ps3_spu_set_gpr64(PS3SPU *spu, unsigned reg, uint64_t value);

/* ---- PPU-side SPE control (the problem/privileged state registers) ---- */

/* SPU_RunCntl: start or stop issuing instructions. */
void ps3_spe_run(PS3SPU *spu, bool run);
bool ps3_spe_running(const PS3SPU *spu);
bool ps3_spe_halted(const PS3SPU *spu);
void ps3_spe_reset(PS3SPU *spu);

/* SPU_RunCntl values 10/11: isolation exit and isolation load requests. */
void ps3_spe_request_isolation(PS3SPU *spu);
void ps3_spe_exit_isolation(PS3SPU *spu);
bool ps3_spe_isolated(const PS3SPU *spu);

/* SPU_Status: the next program counter the PPU can read or write. */
uint32_t ps3_spe_pc(const PS3SPU *spu);
void ps3_spe_set_pc(PS3SPU *spu, uint32_t pc);

/* SPU_LSLR: the local-storage address limit (default: the whole store). */
void ps3_spe_set_ls_limit(PS3SPU *spu, uint32_t limit);
uint32_t ps3_spe_ls_limit(const PS3SPU *spu);

/* Inbound mailbox: true when the four-entry queue had room. */
bool ps3_spe_push_in_mbox(PS3SPU *spu, uint32_t value);

/*
 * The loader's private channel window, 0x40-0x44, which the ISA calls reserved
 * and the boot chain uses as its own message block.  The ROM anchors 0x40: at
 * 0x3C4 it writes 1 to it just before falling through to the payload at 0x400,
 * so 0x40 is the stage-side command word out.  lv0ldr.2 writes 0 then 2 there
 * and reads its data in on 0x43, so the block is: 0x40 command out, 0x41 status
 * in, 0x42 the ROM's root-key readout, 0x43 data in, 0x44 data out.
 *
 * 0x41 and 0x44 are the reverse directions and both report a depth of zero
 * until the host posts something: status words on 0x41, or room on 0x44 with
 * ps3_spu_set_loader_sink().  A stage that writes 0x44 before a sink is posted
 * blocks there, the same way it blocks reading 0x41 before status is posted.
 */
#define PS3_SPU_LOADER_CMD_MAX     32
#define PS3_SPU_LOADER_STATUS_MAX  64
#define PS3_SPU_LOADER_FEED_MAX   1024
#define PS3_SPU_LOADER_SINK_MAX   256

/* Words a producer posts on 0x41 (status in), and the finite feed on 0x43. */
void ps3_spu_set_loader_status(PS3SPU *spu, const uint32_t *words, unsigned count);
void ps3_spu_set_loader_feed(PS3SPU *spu, const uint32_t *words, unsigned count);
/* Room the host posts on 0x44 (data out).  Zero means the stage blocks on its
 * first data word; the words are never silently discarded. */
void ps3_spu_set_loader_sink(PS3SPU *spu, unsigned depth);
unsigned ps3_spu_loader_sink_left(const PS3SPU *spu);
uint64_t ps3_spu_loader_cmd_total(const PS3SPU *spu);
uint32_t ps3_spu_loader_cmd_last(const PS3SPU *spu);
unsigned ps3_spu_loader_status_left(const PS3SPU *spu);
unsigned ps3_spu_loader_feed_left(const PS3SPU *spu);
uint64_t ps3_spu_loader_data_out(const PS3SPU *spu);
/* which: 0 = 0x41 read with nothing posted, 1 = 0x43 feed drained, 2 = 0x44
 * write with no sink room. */
uint64_t ps3_spu_loader_starved(const PS3SPU *spu, unsigned which);

/* ---- the 128-entry channel map ---------------------------------------- */

/*
 * The SPU channel space is 128 entries wide.  The ISA names 39 of them and
 * calls the rest reserved; the boot chain then uses a few of the reserved ones
 * (0x40-0x44, and 0x49 for the loader version), which is why a map that stops
 * at the named channels cannot describe the firmware.  This model carries all
 * 128 in one table: name, direction, and whether the behaviour is implemented.
 *
 * A channel that is not implemented - reserved, or named but outside what the
 * boot path needs - behaves as a channel with no producer and no consumer: a
 * depth of zero, a read that blocks, and a write that is dropped and counted.
 * Nothing is handed back as a made-up zero word, so a stage waiting on a
 * channel that does not exist stops where it is instead of continuing on data
 * the console never sent.
 */
unsigned ps3_spu_channel_count(void);
const char *ps3_spu_channel_name(unsigned ch);   /* "reserved" when unnamed */
bool ps3_spu_channel_named(unsigned ch);         /* the ISA defines a name */
bool ps3_spu_channel_modelled(unsigned ch);      /* this model implements it */
bool ps3_spu_channel_readable(unsigned ch);
bool ps3_spu_channel_writable(unsigned ch);

/* Access accounting, one entry per channel.  `reads' counts rdch/rchcnt,
 * `writes' counts wrch, `faults' counts accesses the map does not define:
 * a reserved channel, or the wrong direction for a mapped one. */
unsigned ps3_spu_channel_reads(const PS3SPU *spu, unsigned ch);
unsigned ps3_spu_channel_writes(const PS3SPU *spu, unsigned ch);
unsigned ps3_spu_channel_faults(const PS3SPU *spu, unsigned ch);
bool ps3_spu_channel_touched(const PS3SPU *spu, unsigned ch);
unsigned ps3_spu_channel_touched_count(const PS3SPU *spu);
unsigned ps3_spu_channel_fault_count(const PS3SPU *spu);
/* The channel a stalled read/write was on, or -1. */
int ps3_spu_channel_stall(const PS3SPU *spu);
bool ps3_spu_channel_stall_reserved(const PS3SPU *spu);

/*
 * The PPU side of the inbound mailbox, for a stage whose lv2 does not exist:
 * the peer answers an empty ch29 read with this message, once per poll.  NULL
 * or a zero count disarms it.  These are the words an lv2 writer would send;
 * they are a model parameter, not a console constant.
 */
void ps3_spu_set_mbox_peer(PS3SPU *spu, const uint32_t *words, unsigned count);
uint64_t ps3_spu_mbox_peer_posts(const PS3SPU *spu);
/* Outbound (non-interrupt) mailbox: true when a word was available. */
bool ps3_spe_pop_out_mbox(PS3SPU *spu, uint32_t *value);
/* Outbound interrupt mailbox, the channel that raises a PPE interrupt. */
bool ps3_spe_pop_out_intr_mbox(PS3SPU *spu, uint32_t *value);

/* Signal notification: the PPE writes, the SPE reads through channel 3/4. */
void ps3_spe_set_signal(PS3SPU *spu, unsigned which, uint32_t value);
void ps3_spe_set_signal_overwrite(PS3SPU *spu, unsigned which, bool overwrite);

/* ---- the boot path's single-SPE entry points ------------------------- */

/* The 32 bytes the ROM reads from channel 66, in read order. */
void ps3_spu_set_ch66(PS3SPU *spu, const uint8_t key[32]);

/*
 * The reads the ROM has completed on channel 66 (0..8) and the value of one of
 * them.  This is the capture: it records what `rdch $35,$ch66` returned while
 * the ROM ran, not what the caller put in the buffer.
 */
unsigned ps3_spu_ch66_read_count(const PS3SPU *spu);
uint32_t ps3_spu_ch66_read(const PS3SPU *spu, unsigned index);

/*
 * Channel 73: the loader version is handed over in two rounds.  isoldr reads
 * the high 32 bits first and the low 32 bits second; 0x0003004100000000 is
 * firmware 3.41's answer, i.e. 0x00030041 then 0.
 */
void ps3_spu_set_ch73(PS3SPU *spu, uint32_t hi, uint32_t lo);

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
 * Run from `entry' for at most `limit' instructions.  Returns a PS3_SPU_*
 * status.  `why' always receives a one-line description, including the
 * instructions that led to a fault.
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

/*
 * Estimated issue cycles: two issue pipes per cycle, the latency class of each
 * operation and the register hazards between neighbouring instructions.  It is
 * a profile figure, not a cycle count a hardware timing test can rely on.
 */
uint64_t ps3_spu_cycles(const PS3SPU *spu);
uint64_t ps3_spu_dual_issue_pairs(const PS3SPU *spu);
uint64_t ps3_spu_stall_cycles(const PS3SPU *spu);

/* MFC protection: transfers refused because they aimed at an isolated SPE. */
uint64_t ps3_spu_protection_faults(const PS3SPU *spu);
uint64_t ps3_spu_dma_errors(const PS3SPU *spu);

/*
 * Run the instruction-set self-test: one program per family (integer,
 * floating point, double precision, multiply, halt, channel, SPR, MFC list and
 * atomic forms) plus a two-SPE concurrent run through shared memory with the
 * isolation check.  Returns 0 when every check passes, -1 with a description
 * when one does not.  The boot selftest calls it on every run.
 */
int ps3_spu_isa_selftest(char *why, size_t why_len);

/* The immediate of the stop instruction that ended the run, 0 if none. */
unsigned ps3_spu_stop_code(const PS3SPU *spu);

/* MFC activity: what the payload pulled in and what it wrote back out. */
uint64_t ps3_spu_mfc_gets(const PS3SPU *spu);
uint64_t ps3_spu_mfc_puts(const PS3SPU *spu);
uint32_t ps3_spu_last_put_ea(const PS3SPU *spu);
uint32_t ps3_spu_last_put_size(const PS3SPU *spu);

/* The writable external memory: the flash image plus whatever was PUT. */
uint8_t *ps3_spu_ext_ptr(PS3SPU *spu, size_t *size);

/*
 * How many of the big-endian words in `bytes` decode to a real instruction,
 * with the word count in `total`.  Ciphertext decodes at a little over half by
 * chance and an SPU image at essentially all of it, so the pair tells the two
 * apart; ps3_self.c uses it to recognise a SELF whose segments a previous
 * unself already decrypted.
 */
unsigned ps3_spu_code_words(const uint8_t *bytes, size_t len,
                            unsigned *total);
