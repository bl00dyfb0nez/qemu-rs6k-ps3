/*
 * SPU execution model for the PS3 boot path.
 *
 * Local research model, not intended for upstream QEMU contributions.
 *
 * The mask ROM leaves the decrypted boot loader at LS[0x400] and jumps there.
 * This is an interpreter for the SPU instruction set, executing the payload the
 * ROM produced rather than modelling what it is expected to do: 256 KiB of
 * local storage, the 128 quadword registers, the channels, and a synchronous
 * MFC that reads the flash image and writes back what the payload puts.  There
 * are no SPEs, no interrupts and no timing - the question it answers is "what
 * did the loader actually compute", which is exactly the part a C model cannot
 * answer honestly.
 *
 * Decoding is table-driven (ps3_spu_isa.h, generated from the ISA's opcode and
 * field tables).  Semantics follow the ISA document: the rotate-and-mask family
 * shifts right by the two's complement of the count, shufb's control bytes
 * 0x80-0xBF/0xC0-0xDF/0xE0-0xFF produce 0x00/0xFF/0x80, gb gathers the sign of
 * each byte and gbb the low bit.  Those three are where a "close enough" model
 * silently produces wrong AES output, so they are spelled out in the comments.
 */

#include "qemu/osdep.h"
#include "qemu/units.h"

#include <math.h>

#include "ps3_spu.h"
#include "ps3_spu_isa.h"

#define SPU_LS_MASK 0x3FFFFu
#define SPU_MAX_GPR 128

/*
 * Slots are numbered in memory order: gpr[reg][0] holds the four bytes at the
 * load address, gpr[reg][3] the last four.  That is the ISA's slot 3 first -
 * the preferred slot is the one at the lowest address - and it is what makes
 * `lqa $12,0x420` then `brz $12` test the length word rather than the nonce.
 * Byte 0 of a quadword is likewise the first byte in memory.
 */
#define SPU_PREFERRED 0
#define SPU_TAG_FIFO 64

struct PS3SPU {
    uint8_t *ls;
    size_t ls_size;

    /* External memory as the MFC sees it: a writable copy of the flash image.
     * GET reads it, PUT writes it, and anything the boot loader stores is
     * therefore still there to be inspected afterwards. */
    uint8_t *ext;
    size_t ext_size;

    uint32_t gpr[SPU_MAX_GPR][4];  /* four 32-bit slots, big-endian order */
    uint32_t pc;

    uint8_t ch66[32];
    bool has_ch66;
    unsigned ch66_pos;

    /* Channel 73: two 32-bit version words, drained in order by isoldr. */
    uint32_t ch73[2];
    bool has_ch73;
    unsigned ch73_pos;

    uint32_t sig_hi;
    uint32_t sig_lo;

    /* MFC registers, as the ISA numbers them. */
    uint32_t mfc_lsa;
    uint32_t mfc_eah;
    uint32_t mfc_eal;
    uint32_t mfc_size;
    uint32_t mfc_tag;
    uint32_t mfc_cmd;
    uint32_t tag_mask;

    /*
     * The rest of the channel set: the event/mailbox/decrementer state and
     * SRR0.  The boot path only used the DMA and signal channels, but real
     * SPU code - and the VSH's audio and codecs - drive these too, so they
     * have storage and the counts and blocking rules the ISA gives them.
     */
    uint32_t srr0;
    uint32_t event_mask;
    uint32_t event_stat;
    uint32_t decrementer;
    uint32_t in_mbox;
    bool in_mbox_valid;
    uint32_t out_mbox;
    uint32_t iso_control;

    /* mfspr/mtspr: 128-bit SPRs, of which this model keeps the preferred slot. */
    uint32_t spr[128];

    /* The FPSCR the single-precision code updates (exception flags). */
    uint32_t fpscr;

    /*
     * An issue model, not a cycle-accurate one: one slot per instruction, plus
     * the latency class of the multi-cycle operations.  It is enough to show
     * where the time goes in a profile and to let `ps3_spu_cycles' report a
     * figure, and it is labelled as an estimate everywhere it is printed.
     */
    uint64_t cycles;
    uint64_t dual_issue_pairs;
    bool last_pipe_even;
    bool last_pipe_valid;
    bool halted;

    uint8_t tag_fifo[SPU_TAG_FIFO];
    unsigned tag_head;
    unsigned tag_count;

    uint64_t insns;
    uint32_t last_pc;
    uint32_t last_word;

    /* Exact-PC histogram, direct-mapped: enough to tell "still working" from
     * "spinning in a three-instruction loop" when the budget runs out.  A
     * collision only loses counts, so the hottest PC still reports itself. */
    struct {
        uint32_t pc;
        uint32_t count;
    } hot[4096];

    /* The last few instructions, so a fault can say how it got there. */
    struct {
        uint32_t pc;
        uint32_t word;
    } hist[16];
    unsigned hist_pos;

    uint64_t mfc_gets;
    uint64_t mfc_puts;
    uint32_t last_get_ea;
    uint32_t last_get_size;
    uint32_t last_put_ea;
    uint32_t last_put_size;
    uint32_t last_put_lsa;

    bool trace;
    bool log_events;
    unsigned stop_code;   /* the stop instruction's immediate, when it stops */
};

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}

static uint32_t sext(uint32_t value, unsigned bits)
{
    const uint32_t sign = 1u << (bits - 1);

    return (value ^ sign) - sign;
}

/* ---- register and local-store helpers -------------------------------- */

static uint32_t gpr_w(const PS3SPU *spu, unsigned reg, unsigned lane)
{
    return spu->gpr[reg & 127][lane & 3];
}

static void gpr_set_w(PS3SPU *spu, unsigned reg, unsigned lane, uint32_t v)
{
    spu->gpr[reg & 127][lane & 3] = v;
}

/* Immediate-load semantics: the same 32-bit word in all four slots. */
static void gpr_fill(PS3SPU *spu, unsigned reg, uint32_t v)
{
    for (unsigned i = 0; i < 4; i++) {
        spu->gpr[reg & 127][i] = v;
    }
}

/* The preferred slot: where branches, shifts and channel addresses read the
 * value (see SPU_PREFERRED). */
static uint32_t scw(const PS3SPU *spu, unsigned reg)
{
    return gpr_w(spu, reg, SPU_PREFERRED);
}

static uint8_t qbyte(const PS3SPU *spu, unsigned reg, unsigned i)
{
    return (gpr_w(spu, reg, i / 4) >> (24 - 8 * (i % 4))) & 0xFF;
}

static void qbyte_set(PS3SPU *spu, unsigned reg, unsigned i, uint8_t v)
{
    uint32_t w = gpr_w(spu, reg, i / 4);
    const unsigned shift = 24 - 8 * (i % 4);

    w = (w & ~(0xFFu << shift)) | ((uint32_t)v << shift);
    gpr_set_w(spu, reg, i / 4, w);
}

static uint16_t qhalf(const PS3SPU *spu, unsigned reg, unsigned i)
{
    return (gpr_w(spu, reg, i / 2) >> (16 - 16 * (i % 2))) & 0xFFFF;
}

static void qhalf_set(PS3SPU *spu, unsigned reg, unsigned i, uint16_t v)
{
    uint32_t w = gpr_w(spu, reg, i / 2);
    const unsigned shift = 16 - 16 * (i % 2);

    w = (w & ~(0xFFFFu << shift)) | ((uint32_t)v << shift);
    gpr_set_w(spu, reg, i / 2, w);
}

static void gpr_set_bytes(PS3SPU *spu, unsigned reg, const uint8_t *bytes)
{
    for (unsigned i = 0; i < 4; i++) {
        gpr_set_w(spu, reg, i, be32(bytes + i * 4));
    }
}

static void gpr_get_bytes(const PS3SPU *spu, unsigned reg, uint8_t *bytes)
{
    for (unsigned i = 0; i < 4; i++) {
        put_be32(bytes + i * 4, gpr_w(spu, reg, i));
    }
}

/* ---- single-precision, extended range --------------------------------- */
/*
 * The SPU's single format is IEEE-shaped but not IEEE: exponent 255 is a
 * normal value (Smax is 0x7FFFFFFF, 1.999... * 2^128), denormals read as zero,
 * and the only rounding mode is truncation toward zero.  Arithmetic therefore
 * runs in long double and is truncated back into that format; using the host's
 * float would round to nearest-even and would turn exponent 255 into an
 * infinity, which real code does observe.
 */
#define SPU_SF_MAX      0x7FFFFFFFu
#define SPU_SF_SIGN     0x80000000u
#define SPU_SF_EXP      0x7F800000u
#define SPU_SF_FRAC     0x007FFFFFu

/* FPSCR exception flags this model accumulates (OVF/UNF/DBZ/DIFF). */
#define SPU_FP_OVF      0x00000001u
#define SPU_FP_UNF      0x00000002u
#define SPU_FP_DBZ      0x00000004u
#define SPU_FP_DIFF     0x00000008u

static long double spu_sf_value(uint32_t bits)
{
    const int sign = (bits & SPU_SF_SIGN) ? -1 : 1;
    const unsigned exp = (bits >> 23) & 0xFF;
    const uint32_t frac = bits & SPU_SF_FRAC;

    /* A zero exponent with a fraction is a denormal: the format reads it as
     * zero (DIFF is flagged by the caller when it matters). */
    if (!exp) {
        return sign < 0 ? -0.0L : 0.0L;
    }

    return sign * ldexpl(1.0L + (long double)frac / 8388608.0L,
                         (int)exp - 127);
}

static uint32_t spu_sf_pack(long double v, uint32_t *flags)
{
    const bool neg = signbit(v);
    long double a = fabsl(v);
    const long double smax = ldexpl(2.0L - ldexpl(1.0L, -23), 128);
    int e, biased;
    uint32_t frac;

    if (isnan(a)) {
        /* The format has no NaNs; the default QNaN bits would be Smax. */
        return SPU_SF_MAX;
    }

    if (isinf(a) || a >= smax) {
        *flags |= SPU_FP_OVF;
        return (neg ? SPU_SF_SIGN : 0) | SPU_SF_MAX;
    }

    if (a == 0) {
        return neg ? SPU_SF_SIGN : 0;
    }

    frexpl(a, &e);                  /* a = m * 2^e, 0.5 <= m < 1 */
    biased = e - 1 + 127;

    if (biased < 1) {               /* below Smin = 2^-126 */
        *flags |= SPU_FP_UNF | SPU_FP_DIFF;
        return neg ? SPU_SF_SIGN : 0;
    }

    if (biased > 255) {
        *flags |= SPU_FP_OVF;
        return (neg ? SPU_SF_SIGN : 0) | SPU_SF_MAX;
    }

    /* Truncation toward zero is what the ISA specifies. */
    frac = (uint32_t)floorl((ldexpl(a, 1 - e) - 1.0L) * 8388608.0L);
    if (frac > SPU_SF_FRAC) {
        frac = SPU_SF_FRAC;
    }

    return (neg ? SPU_SF_SIGN : 0) | ((uint32_t)biased << 23) | frac;
}

static bool spu_sf_is_denormal(uint32_t bits)
{
    return (bits & SPU_SF_EXP) == 0 && (bits & SPU_SF_FRAC) != 0;
}

static void spu_sf_flags(PS3SPU *spu, uint32_t bits)
{
    if (spu_sf_is_denormal(bits)) {
        spu->fpscr |= SPU_FP_DIFF;
    }
}

/*
 * The reciprocal-estimate tables.  FREST returns a 13-bit base fraction and a
 * 10-bit step; FI interpolates between them using 19 bits of the input.  The
 * fractions below are the hardware table's (the same values RPCS3 uses), and
 * the exponent halves are generated from the header's rule: 
 * FREST exponent = (254 - e) for e in 1..254, 0x7F800000 for zero (DBZ), and
 * FRSQEST exponent = 189 - (e - 1) / 2 for e in 1..255.
 */
static const uint32_t spu_frest_fraction[32] = {
    0x7FFBE0, 0x7F87A6, 0x70EF72, 0x708B40, 0x638B12, 0x633AEA, 0x5792C4, 0x574AA0,
    0x4CCA7E, 0x4C9262, 0x430A44, 0x42D62A, 0x3A2E12, 0x39FDFA, 0x3215E4, 0x31F1D2,
    0x2AA9BE, 0x2A85AC, 0x23D59A, 0x23BD8E, 0x1D8576, 0x1D8576, 0x17AD5A, 0x17AD5A,
    0x124543, 0x124543, 0x0D392D, 0x0D392D, 0x08851A, 0x08851A, 0x041D07, 0x041D07,
};

static const uint32_t spu_frsqest_fraction[64] = {
    0x350160, 0x34E954, 0x2F993D, 0x2F993D, 0x2AA523, 0x2AA523, 0x26190D, 0x26190D,
    0x21E4F9, 0x21E4F9, 0x1E00E9, 0x1E00E9, 0x1A5CD9, 0x1A5CD9, 0x16F8CB, 0x16F8CB,
    0x13CCC0, 0x13CCC0, 0x10CCB3, 0x10CCB3, 0x0E00AA, 0x0E00AA, 0x0B58A1, 0x0B58A1,
    0x08D498, 0x08D498, 0x067491, 0x067491, 0x043089, 0x043089, 0x020C83, 0x020C83,
    0x7FFDF4, 0x7FD1DE, 0x7859C8, 0x783DBA, 0x71559C, 0x71559C, 0x6AE57C, 0x6AE57C,
    0x64F561, 0x64F561, 0x5F7149, 0x5F7149, 0x5A4D33, 0x5A4D33, 0x55811F, 0x55811F,
    0x51050F, 0x51050F, 0x4CC8FE, 0x4CC8FE, 0x48D0F0, 0x48D0F0, 0x4510E4, 0x4510E4,
    0x4180D7, 0x4180D7, 0x3E24CC, 0x3E24CC, 0x3AF4C3, 0x3AF4C3, 0x37E8BA, 0x37E8BA,
};

static uint32_t spu_frest_exponent(unsigned e)
{
    if (e == 0) {
        return 0x7F800000u;
    }
    return e <= 254 ? ((254u - e) << 23) : 0;
}

static uint32_t spu_frsqest_exponent(unsigned e)
{
    if (e == 0) {
        return 0x7F800000u;
    }
    return (189u - (e - 1) / 2) << 23;
}

/* ---- double-precision -------------------------------------------------- */

static uint64_t gpr_d(const PS3SPU *spu, unsigned reg, unsigned slot)
{
    return ((uint64_t)gpr_w(spu, reg, slot * 2) << 32) |
           gpr_w(spu, reg, slot * 2 + 1);
}

static void gpr_set_d(PS3SPU *spu, unsigned reg, unsigned slot, uint64_t v)
{
    gpr_set_w(spu, reg, slot * 2, (uint32_t)(v >> 32));
    gpr_set_w(spu, reg, slot * 2 + 1, (uint32_t)v);
}

static double spu_d_value(uint64_t bits)
{
    double d;

    memcpy(&d, &bits, sizeof(d));
    return d;
}

static uint64_t spu_d_bits(double d)
{
    uint64_t bits;

    memcpy(&bits, &d, sizeof(bits));
    return bits;
}

static uint64_t spu_d_mask(bool hit)
{
    return hit ? UINT64_MAX : 0;
}

/* Local-store addresses wrap at 32 bits first, then lose the four low bits:
 * `lqx $14,$90,$88` with $88 = -0x40 must read 0x400, not 0x40000. */
static uint32_t ls_addr(uint32_t addr)
{
    return (addr & SPU_LS_MASK) & ~0xFu;
}

static void ls_read(const PS3SPU *spu, uint32_t addr, uint8_t out[16])
{
    const uint32_t a = ls_addr(addr);

    for (unsigned i = 0; i < 16; i++) {
        out[i] = (a + i < spu->ls_size) ? spu->ls[a + i] : 0;
    }
}

static void ls_write(PS3SPU *spu, uint32_t addr, const uint8_t in[16])
{
    const uint32_t a = ls_addr(addr);

    for (unsigned i = 0; i < 16 && a + i < spu->ls_size; i++) {
        spu->ls[a + i] = in[i];
    }
}

/* ---- quadword operations --------------------------------------------- */

static void qrotl_bytes(uint8_t out[16], const uint8_t in[16], unsigned n)
{
    n &= 15;

    for (unsigned i = 0; i < 16; i++) {
        out[i] = in[(i + n) & 15];
    }
}

/* Shift left by whole bytes: zeros at the right, a count of 16 or more is zero. */
static void qshl_bytes(uint8_t out[16], const uint8_t in[16], unsigned n)
{
    for (unsigned i = 0; i < 16; i++) {
        out[i] = (n < 16 && i + n < 16) ? in[i + n] : 0;
    }
}

/* Shift right by whole bytes: zeros at the left (rotqmby's "and mask"). */
static void qshr_bytes(uint8_t out[16], const uint8_t in[16], unsigned n)
{
    for (unsigned i = 0; i < 16; i++) {
        out[i] = (n < 16 && i >= n) ? in[i - n] : 0;
    }
}

static void qrotl_bits(uint8_t out[16], const uint8_t in[16], unsigned n)
{
    n &= 127;

    for (unsigned i = 0; i < 16; i++) {
        out[i] = 0;

        for (unsigned b = 0; b < 8; b++) {
            const unsigned src = (i * 8 + n + b) % 128;

            if (in[src / 8] & (0x80u >> (src % 8))) {
                out[i] |= 0x80u >> b;
            }
        }
    }
}

static void qshl_bits(uint8_t out[16], const uint8_t in[16], unsigned n)
{
    n &= 7;

    for (unsigned i = 0; i < 16; i++) {
        out[i] = 0;

        for (unsigned b = 0; b < 8; b++) {
            const int src = (int)(i * 8 + b) - (int)n;

            if (src >= 0 && (in[src / 8] & (0x80u >> (src % 8)))) {
                out[i] |= 0x80u >> b;
            }
        }
    }
}

static void qshr_bits(uint8_t out[16], const uint8_t in[16], unsigned n)
{
    n &= 7;

    for (unsigned i = 0; i < 16; i++) {
        out[i] = 0;

        for (unsigned b = 0; b < 8; b++) {
            const unsigned src = i * 8 + b + n;

            if (src < 128 && (in[src / 8] & (0x80u >> (src % 8)))) {
                out[i] |= 0x80u >> b;
            }
        }
    }
}

/* Table 5-1: what a control byte selects.  The three constant ranges are not
 * interchangeable with "zero": 0xC0-0xDF is 0xFF, and AES code relies on it. */
static void shufb(uint8_t out[16], const uint8_t a[16], const uint8_t b[16],
                  const uint8_t c[16])
{
    uint8_t both[32];

    memcpy(both, a, 16);
    memcpy(both + 16, b, 16);

    for (unsigned i = 0; i < 16; i++) {
        const uint8_t sel = c[i];

        if (!(sel & 0x80)) {
            out[i] = both[sel & 0x1F];
        } else if ((sel & 0xC0) == 0x80) {
            out[i] = 0x00;
        } else if ((sel & 0xE0) == 0xC0) {
            out[i] = 0xFF;
        } else {
            out[i] = 0x80;
        }
    }
}

/* Generate-controls (Tables B-1..B-4): insert `size' bytes from RA at `pos',
 * every other byte selects RB.  A zero byte is 0x80, so a "not selected" byte
 * of 0x10+i would read RB; cbd/chd/cwd/cdd use that. */
static void gen_controls(uint8_t out[16], unsigned pos, unsigned size)
{
    if (size == 1) {
        for (unsigned i = 0; i < 16; i++) {
            out[i] = 0x10 + i;
        }
        out[pos & 0xF] = 0x03;
        return;
    }

    pos &= ~(size - 1);

    for (unsigned i = 0; i < 16; i++) {
        out[i] = (i >= pos && i < pos + size) ? (i - pos) : (0x10 + i);
    }
}

/* ---- channels and MFC ------------------------------------------------- */

static void tag_complete(PS3SPU *spu)
{
    if (spu->tag_count == SPU_TAG_FIFO) {
        return;
    }

    spu->tag_fifo[(spu->tag_head + spu->tag_count) % SPU_TAG_FIFO] =
        spu->mfc_tag & 0x1F;
    spu->tag_count++;
}

static void mfc_start(PS3SPU *spu)
{
    const uint32_t size = (spu->mfc_size & 0xFFFF) ? (spu->mfc_size & 0xFFFF)
                                                   : 0x4000;
    /* LSA bits 3:17: the low four bits are not part of the address. */
    const uint32_t lsa = spu->mfc_lsa & SPU_LS_MASK & ~0xFu;
    const uint64_t ea = ((uint64_t)spu->mfc_eah << 32) | spu->mfc_eal;

    if (spu->mfc_cmd & 0x40) {              /* MFC_GET */
        for (uint32_t i = 0; i < size; i++) {
            const uint64_t src = ea + i;
            const uint32_t dst = (lsa + i) & SPU_LS_MASK;

            if (dst < spu->ls_size) {
                spu->ls[dst] = (src < spu->ext_size) ? spu->ext[src] : 0;
            }
        }

        spu->mfc_gets++;
        spu->last_get_ea = (uint32_t)ea;
        spu->last_get_size = size;

        /* The first transfers say whether the loader is walking its input as
         * intended (a size of 0 is the 16 KiB maximum, not an empty one). */
        if (spu->log_events && spu->mfc_gets <= 8) {
            fprintf(stderr,
                    "[spu] get %u bytes ea=0x%" PRIX64 " -> lsa=0x%X at 0x%X"
                    " (cmd=0x%X)\n",
                    size, ea, lsa, spu->last_pc, spu->mfc_cmd);
        }
    } else if (spu->mfc_cmd & 0x20) {       /* MFC_PUT */
        for (uint32_t i = 0; i < size; i++) {
            const uint32_t src = (lsa + i) & SPU_LS_MASK;
            const uint64_t dst = ea + i;

            if (dst < spu->ext_size) {
                spu->ext[dst] = (src < spu->ls_size) ? spu->ls[src] : 0;
            }
        }

        spu->mfc_puts++;
        spu->last_put_ea = (uint32_t)ea;
        spu->last_put_size = size;
        spu->last_put_lsa = lsa;

        /* Few enough to be worth a line each, and the only trace of where the
         * loader sent its output.  Small transfers carry the word itself. */
        if (spu->log_events) {
            if (size == 4) {
                fprintf(stderr,
                        "[spu] put %u bytes lsa=0x%X -> ea=0x%" PRIX64
                        " at 0x%X: 0x%08X\n",
                        size, lsa, ea, spu->last_pc,
                        be32(spu->ls + lsa));
            } else {
                fprintf(stderr,
                        "[spu] put %u bytes lsa=0x%X -> ea=0x%" PRIX64
                        " at 0x%X\n", size, lsa, ea, spu->last_pc);
            }
        }
    }

    tag_complete(spu);
}

static uint32_t ch_read(PS3SPU *spu, unsigned ch)
{
    switch (ch) {
    case 0x00:                                  /* SPU_RdEventStat */
        return spu->event_stat & spu->event_mask;
    case 0x08:                                  /* SPU_RdDec */
        return spu->decrementer;
    case 0x0B:                                  /* SPU_RdEventMask */
        return spu->event_mask;
    case 0x0C:                                  /* MFC_RdTagMask */
        return spu->tag_mask;
    case 0x0F:                                  /* SPU_RdSRR0 */
        return spu->srr0;
    case 0x1D:                                  /* SPU_RdInMbox */
        if (spu->in_mbox_valid) {
            spu->in_mbox_valid = false;
            return spu->in_mbox;
        }
        return 0;
    case 0x03:                                  /* SPU_RdSigNotify1 */
        return spu->sig_hi;
    case 0x04:                                  /* SPU_RdSigNotify2 */
        return spu->sig_lo;
    case 0x0D:                                  /* SPU_RdMachStat */
        return 0x00020000;
    case 0x18:                                  /* MFC_RdTagStat */
        if (spu->tag_count) {
            const uint8_t tag = spu->tag_fifo[spu->tag_head];

            spu->tag_head = (spu->tag_head + 1) % SPU_TAG_FIFO;
            spu->tag_count--;
            return 0x80000000u | tag;
        }
        return 0;
    case 0x42:                                  /* channel 66: root key */
        if (spu->has_ch66 && spu->ch66_pos < 8) {
            return be32(spu->ch66 + 4 * spu->ch66_pos++);
        }
        return 0;
    case 0x49:                                  /* channel 73: loader version */
        if (spu->has_ch73 && spu->ch73_pos < 2) {
            return spu->ch73[spu->ch73_pos++];
        }
        return 0;
    default:
        return 0;
    }
}

static uint32_t ch_read_count(PS3SPU *spu, unsigned ch)
{
    switch (ch) {
    case 0x00:                                  /* SPU_RdEventStat */
        return (spu->event_stat & spu->event_mask) ? 1 : 0;
    case 0x08:                                  /* SPU_RdDec */
    case 0x0B:                                  /* SPU_RdEventMask */
    case 0x0C:                                  /* MFC_RdTagMask */
    case 0x0E:                                  /* SPU_WrSRR0 */
    case 0x0F:                                  /* SPU_RdSRR0 */
        return 1;
    case 0x1D:                                  /* SPU_RdInMbox */
        return spu->in_mbox_valid ? 1 : 0;
    case 0x18:                                  /* MFC_RdTagStat */
        return spu->tag_count;
    case 0x42:
        return (spu->has_ch66 && spu->ch66_pos < 8) ? 1 : 0;
    case 0x49:
        return (spu->has_ch73 && spu->ch73_pos < 2) ? 2 - spu->ch73_pos : 0;
    default:
        return 0;
    }
}

static void ch_write(PS3SPU *spu, unsigned ch, uint32_t value)
{
    switch (ch) {
    case 0x01:                                  /* SPU_WrEventMask */
        spu->event_mask = value;
        break;
    case 0x02:                                  /* SPU_WrEventAck */
        spu->event_stat &= ~value;
        break;
    case 0x07:                                  /* SPU_WrDec */
        spu->decrementer = value;
        break;
    case 0x0E:                                  /* SPU_WrSRR0 */
        spu->srr0 = value;
        break;
    case 0x1C:                                  /* SPU_WrOutMbox */
    case 0x1E:                                  /* SPU_WrOutIntrMbox */
        spu->out_mbox = value;
        break;
    case 0x19:                                  /* MFC_WrListStallAck */
    case 0x45:                                  /* SPU_Set_Bkmk_Tag */
    case 0x46:                                  /* SPU_PM_Start_Ev */
    case 0x47:                                  /* SPU_PM_Stop_Ev */
        break;
    case 0x40:                                  /* SPU_IsoCntl */
        /*
         * Isolation is recorded, not enforced: this model's local store is a
         * flat 256 KiB array with no requestor ID, so there is no boundary to
         * check.  Reading the state back is what a test needs to see it took.
         */
        spu->iso_control = value;
        break;
    case 0x10:                                  /* MFC_LSA */
        spu->mfc_lsa = value;
        break;
    case 0x11:                                  /* MFC_EAH */
        spu->mfc_eah = value;
        break;
    case 0x12:                                  /* MFC_EAL */
        spu->mfc_eal = value;
        break;
    case 0x13:                                  /* MFC_Size */
        spu->mfc_size = value;
        break;
    case 0x14:                                  /* MFC_TagID */
        spu->mfc_tag = value;
        break;
    case 0x15:                                  /* MFC_Cmd: starts the transfer */
        spu->mfc_cmd = value;
        mfc_start(spu);
        break;
    case 0x16:                                  /* MFC_WrTagMask */
        spu->tag_mask = value;
        break;
    case 0x17:                                  /* MFC_WrTagUpdate */
        /* The engine is synchronous, so a completion update has nothing to
         * wait for; the tag queue already holds the result. */
        break;
    default:
        break;
    }
}

/* ---- decode ----------------------------------------------------------- */

typedef struct {
    const SpuOpcode *op;
    unsigned rt, ra, rb, rc;
    uint32_t i7, i8, i10, i16, a18, bd;
} Insn;

static const SpuOpcode *decode(uint32_t word)
{
    for (size_t i = 0; i < ARRAY_SIZE(spu_opcodes); i++) {
        const SpuOpcode *e = &spu_opcodes[i];

        if ((word >> (32 - e->len)) == e->op) {
            return e;
        }
    }

    return NULL;
}

static void field_decode(Insn *in, uint32_t word)
{
    const bool four = in->op->len == 4;

    in->rc = word & 0x7F;
    in->ra = (word >> 7) & 0x7F;
    in->rb = (word >> 14) & 0x7F;
    in->rt = four ? ((word >> 21) & 0x7F) : (word & 0x7F);
    in->i7 = (word >> 14) & 0x7F;
    in->i8 = (word >> 14) & 0xFF;
    in->i10 = (word >> 14) & 0x3FF;
    in->i16 = (word >> 7) & 0xFFFF;
    in->a18 = (word >> 7) & 0x3FFFF;
    in->bd = sext((word >> 7) & 0xFFFF, 16) << 2;
}

/* ---- the interpreter -------------------------------------------------- */

PS3SPU *ps3_spu_new(uint8_t *ls, size_t ls_size,
                    const uint8_t *flash, size_t flash_size)
{
    PS3SPU *spu = g_new0(PS3SPU, 1);

    spu->ls = ls;
    spu->ls_size = ls_size;

    /* One byte of external memory per byte of the image, plus room for the
     * loader to put its output past the end of the flash window. */
    spu->ext_size = flash_size + 4 * MiB;
    spu->ext = g_malloc0(spu->ext_size);
    spu->log_events = true;

    if (flash) {
        memcpy(spu->ext, flash, flash_size);
    }

    return spu;
}

void ps3_spu_free(PS3SPU *spu)
{
    if (!spu) {
        return;
    }

    g_free(spu->ext);
    g_free(spu);
}

void ps3_spu_set_ch66(PS3SPU *spu, const uint8_t key[32])
{
    memcpy(spu->ch66, key, 32);
    spu->has_ch66 = true;
    spu->ch66_pos = 0;
}

void ps3_spu_set_ch73(PS3SPU *spu, uint32_t hi, uint32_t lo)
{
    spu->ch73[0] = hi;
    spu->ch73[1] = lo;
    spu->has_ch73 = true;
    spu->ch73_pos = 0;
}

void ps3_spu_set_sig(PS3SPU *spu, uint32_t hi, uint32_t lo)
{
    spu->sig_hi = hi;
    spu->sig_lo = lo;
}

void ps3_spu_set_reg(PS3SPU *spu, unsigned reg, uint32_t value)
{
    gpr_fill(spu, reg, value);
}

void ps3_spu_set_trace(PS3SPU *spu, bool on)
{
    spu->trace = on;
}

uint64_t ps3_spu_insns(const PS3SPU *spu)
{
    return spu->insns;
}

uint32_t ps3_spu_pc(const PS3SPU *spu)
{
    return spu->pc;
}

uint32_t ps3_spu_gpr_word(const PS3SPU *spu, unsigned reg, unsigned lane)
{
    return gpr_w(spu, reg, lane);
}

unsigned ps3_spu_stop_code(const PS3SPU *spu)
{
    return spu->stop_code;
}

uint64_t ps3_spu_cycles(const PS3SPU *spu)
{
    return spu->cycles;
}

uint64_t ps3_spu_dual_issue_pairs(const PS3SPU *spu)
{
    return spu->dual_issue_pairs;
}

uint64_t ps3_spu_mfc_gets(const PS3SPU *spu)
{
    return spu->mfc_gets;
}

uint64_t ps3_spu_mfc_puts(const PS3SPU *spu)
{
    return spu->mfc_puts;
}

uint32_t ps3_spu_last_put_ea(const PS3SPU *spu)
{
    return spu->last_put_ea;
}

uint32_t ps3_spu_last_put_size(const PS3SPU *spu)
{
    return spu->last_put_size;
}

uint8_t *ps3_spu_ext_ptr(PS3SPU *spu, size_t *size)
{
    if (size) {
        *size = spu->ext_size;
    }

    return spu->ext;
}

/* ---- instruction-set self-test ---------------------------------------- */
/*
 * Encoders for the test program below.  The opcode numbers are the ones the
 * generated table carries and the field positions are the ISA's, so a test
 * word is built the way an assembler would build it.
 */
static uint32_t t_rrr(uint32_t op, unsigned rt, unsigned ra, unsigned rb)
{
    return (op << 21) | (rb << 14) | (ra << 7) | rt;
}

static uint32_t t_rrrr(uint32_t op, unsigned rt, unsigned ra, unsigned rb,
                       unsigned rc)
{
    return (op << 28) | (rt << 21) | (rb << 14) | (ra << 7) | rc;
}

static uint32_t t_rr(uint32_t op, unsigned rt, unsigned ra)
{
    return (op << 21) | (ra << 7) | rt;
}

static uint32_t t_il(uint32_t op, unsigned rt, uint32_t i16)
{
    return (op << 23) | ((i16 & 0xFFFF) << 7) | rt;
}

static uint32_t t_lqd(unsigned rt, unsigned ra, unsigned i10)
{
    return (0x34u << 24) | ((i10 & 0x3FF) << 14) | (ra << 7) | rt;
}

static uint32_t t_scale(uint32_t op, unsigned rt, unsigned ra, unsigned i8)
{
    return (op << 22) | ((i8 & 0xFF) << 14) | (ra << 7) | rt;
}

static int spu_isa_fail(char *why, size_t why_len, const char *what,
                        uint32_t got, uint32_t want)
{
    snprintf(why, why_len, "ISA self-test: %s: got 0x%08X, want 0x%08X",
             what, got, want);
    return -1;
}

#define ISA_CHECK(what, expr, want)                                        \
    do {                                                                   \
        const uint32_t got_ = (expr);                                      \
        const uint32_t want_ = (uint32_t)(want);                           \
        if (got_ != want_) {                                               \
            return spu_isa_fail(why, why_len, what, got_, want_);           \
        }                                                                  \
    } while (0)

/*
 * Run a program that touches every family the interpreter implements and
 * compare the registers with the ISA's answers.  The boot selftest calls it,
 * so an instruction that breaks is visible on every run rather than only when
 * some loader happens to use it.
 */
int ps3_spu_isa_selftest(char *why, size_t why_len)
{
    uint8_t *ls = g_malloc0(256 * KiB);
    PS3SPU *spu;
    const unsigned entry = 0x1000;
    unsigned n = 0;
    int status;

#define EMIT(word) put_be32(ls + entry + n++ * 4, (word))

    /* doubles at 0x800 and the NaN the special-value test looks for at 0x900 */
    {
        /* Each double sits in its own quadword: lqd ignores the low four
         * address bits, so two doubles must not share one. */
        put_be32(ls + 0x800, 0x3FF00000);        /* 1.0 */
        put_be32(ls + 0x804, 0x00000000);
        put_be32(ls + 0x880, 0x40000000);        /* 2.0 */
        put_be32(ls + 0x884, 0x00000000);
        put_be32(ls + 0x900, 0x7FF80000);        /* NaN */
        put_be32(ls + 0x904, 0x00000000);
    }

    EMIT(t_il(0x081, 1, 1));                    /* il $1,1 */
    EMIT(t_il(0x082, 2, 0x3F80));               /* ilhu $2,0x3F80  = 1.0 */
    EMIT(t_il(0x082, 3, 0x4000));               /* ilhu $3,0x4000  = 2.0 */
    EMIT(t_rrr(0x2C4, 4, 2, 3));                /* fa  $4,$2,$3     = 3.0 */
    EMIT(t_rrr(0x2C5, 5, 3, 2));                /* fs  $5,$3,$2     = 1.0 */
    EMIT(t_rrr(0x2C6, 6, 3, 3));                /* fm  $6,$3,$3     = 4.0 */
    EMIT(t_rrrr(0x0E, 7, 2, 3, 3));             /* fma $7,$2,$3,$3  = 4.0 */
    EMIT(t_rrrr(0x0F, 8, 3, 3, 2));             /* fms $8,$3,$3,$2  = 3.0 */
    EMIT(t_rrrr(0x0D, 9, 2, 3, 4));             /* fnms $9,$2,$3,$4 = 1.0 */
    EMIT(t_scale(0x1DA, 10, 1, 155));           /* csflt $10,$1,155 = 1.0 */
    EMIT(t_scale(0x1D8, 11, 10, 173));          /* cflts $11,$10,173 = 1 */
    EMIT(t_scale(0x1DB, 12, 1, 155));           /* cuflt $12,$1,155 = 1.0 */
    EMIT(t_scale(0x1D9, 13, 10, 173));          /* cfltu $13,$10,173 = 1 */
    EMIT(t_rr(0x1B8, 14, 3));                   /* frest  $14,$3 */
    EMIT(t_rr(0x1B9, 15, 3));                   /* frsqest $15,$3 */
    EMIT(t_rrr(0x3D4, 16, 3, 14));              /* fi $16,$3,$14 */
    EMIT(t_rrr(0x3C2, 17, 2, 2));               /* fceq $17,$2,$2 */
    EMIT(t_rrr(0x2C2, 18, 3, 2));               /* fcgt $18,$3,$2 */
    EMIT(t_rrr(0x3CA, 19, 2, 3));               /* fcmeq $19,$2,$3 */
    EMIT(t_rrr(0x2CA, 20, 3, 2));               /* fcmgt $20,$3,$2 */
    EMIT(t_lqd(21, 0, 0x80));                   /* $21 = 1.0 (double) */
    EMIT(t_lqd(22, 0, 0x88));                   /* $22 = 2.0 (double) */
    EMIT(t_rrr(0x2CC, 23, 21, 22));             /* dfa $23,$21,$22 = 3.0 */
    EMIT(t_rrr(0x2CD, 24, 22, 21));             /* dfs $24,$22,$21 = 1.0 */
    EMIT(t_rrr(0x2CE, 25, 22, 22));             /* dfm $25,$22,$22 = 4.0 */
    EMIT(t_lqd(26, 0, 0x80));
    EMIT(t_rrr(0x35C, 26, 21, 22));             /* dfma $26,$21,$22 = 1*2+1 */
    EMIT(t_rrr(0x3C3, 27, 21, 21));             /* dfceq $27,$21,$21 */
    EMIT(t_rrr(0x2C3, 28, 22, 21));             /* dfcgt $28,$22,$21 */
    EMIT(t_rrr(0x2CB, 29, 21, 22));             /* dfcmgt $29,$21,$22 = 0 */
    EMIT(t_lqd(30, 0, 0x90));
    EMIT(t_rrr(0x3BF, 31, 30, 0x40));           /* dftsv $31,$30,NaN */

    /* integer multiply variants */
    EMIT(t_il(0x082, 32, 0x1234));              /* $32 = 0x12340000 */
    EMIT(t_il(0x081, 33, 0x5678));              /* $33 = 0x00005678 */
    EMIT(t_il(0x081, 34, 0x4000));
    EMIT(t_rrr(0x3C7, 35, 34, 34));             /* mpys  = 0x1000 */
    EMIT(t_rrr(0x3C5, 36, 32, 33));             /* mpyh  = 0x00600000 */
    EMIT(t_il(0x082, 37, 0x0002));              /* $37 = 0x00020000 */
    EMIT(t_rrr(0x3C6, 38, 32, 37));             /* mpyhh  = 0x2468 */
    EMIT(t_il(0x081, 39, 1));
    EMIT(t_rrr(0x346, 39, 32, 37));             /* mpyhha  += 0x2468 */
    EMIT(t_rrr(0x3CE, 40, 32, 37));             /* mpyhhu = 0x2468 */
    EMIT(t_il(0x081, 41, 1));
    EMIT(t_rrr(0x34E, 41, 32, 37));             /* mpyhhau += 0x2468 */

    /* borrow generate, or-across, SPRs */
    EMIT(t_il(0x081, 42, 5));
    EMIT(t_il(0x081, 43, 3));
    EMIT(t_il(0x081, 44, 1));
    EMIT(t_rrr(0x042, 45, 42, 43));             /* bg  $45,$42,$43 = 1 */
    EMIT(t_rrr(0x343, 44, 42, 43));             /* bgx $44,$42,$43 = 0 */
    EMIT(t_rr(0x1F0, 46, 2));                   /* orx $46,$2 */
    EMIT(t_rrr(0x10C, 3, 5, 0));                /* mtspr 5,$3 */
    EMIT(t_rrr(0x00C, 47, 5, 0));               /* mfspr $47,5 */

    /* quadword byte shifts whose count comes from the bit count */
    EMIT(t_il(0x081, 48, 32));                  /* count = 4 */
    EMIT(t_rrr(0x1CC, 49, 2, 48));              /* rotqbybi $49,$2,$48 */
    EMIT(t_rrr(0x1CF, 50, 2, 48));              /* shlqbybi $50,$2,$48 */
    EMIT(t_il(0x081, 51, 224));                 /* (0-4)&31 = 28 -> 4 */
    EMIT(t_rrr(0x1CD, 52, 2, 51));              /* rotqmbybi $52,$2,$51 */

    /* SRR0 and iret: branch to a stopd placed at 0x1200 */
    EMIT(t_il(0x081, 53, 0x1200));
    EMIT(t_rrr(0x10D, 53, 14, 0));              /* wrch $53, channel 14 */
    EMIT(t_rr(0x1AA, 0, 0));                    /* iret */

    put_be32(ls + 0x1200, 0x140u << 21);        /* stopd */

    spu = ps3_spu_new(ls, 256 * KiB, NULL, 0);
    spu->trace = true;
    status = ps3_spu_run(spu, entry, 1000, why, why_len);

    if (status != 0) {
        ps3_spu_free(spu);
        g_free(ls);
        return -1;
    }

    ISA_CHECK("fa", ps3_spu_gpr_word(spu, 4, 0), 0x40400000u);
    ISA_CHECK("fs", ps3_spu_gpr_word(spu, 5, 0), 0x3F800000u);
    ISA_CHECK("fm", ps3_spu_gpr_word(spu, 6, 0), 0x40800000u);
    ISA_CHECK("fma", ps3_spu_gpr_word(spu, 7, 0), 0x40800000u);
    ISA_CHECK("fms", ps3_spu_gpr_word(spu, 8, 0), 0x40400000u);
    ISA_CHECK("fnms", ps3_spu_gpr_word(spu, 9, 0), 0x3F800000u);
    ISA_CHECK("csflt", ps3_spu_gpr_word(spu, 10, 0), 0x3F800000u);
    ISA_CHECK("cflts", ps3_spu_gpr_word(spu, 11, 0), 1u);
    ISA_CHECK("cuflt", ps3_spu_gpr_word(spu, 12, 0), 0x3F800000u);
    ISA_CHECK("cfltu", ps3_spu_gpr_word(spu, 13, 0), 1u);
    ISA_CHECK("frest", ps3_spu_gpr_word(spu, 14, 0), 0x3F7FFBE0u);
    ISA_CHECK("frsqest", ps3_spu_gpr_word(spu, 15, 0), 0x3F350160u);
    ISA_CHECK("fi", ps3_spu_gpr_word(spu, 16, 0), 0x3F7FF800u);
    ISA_CHECK("fceq", ps3_spu_gpr_word(spu, 17, 0), 0xFFFFFFFFu);
    ISA_CHECK("fcgt", ps3_spu_gpr_word(spu, 18, 0), 0xFFFFFFFFu);
    ISA_CHECK("fcmeq", ps3_spu_gpr_word(spu, 19, 0), 0u);
    ISA_CHECK("fcmgt", ps3_spu_gpr_word(spu, 20, 0), 0xFFFFFFFFu);
    ISA_CHECK("lqd $21 hi", ps3_spu_gpr_word(spu, 21, 0), 0x3FF00000u);
    ISA_CHECK("lqd $21 lo", ps3_spu_gpr_word(spu, 21, 1), 0u);
    ISA_CHECK("lqd $22 hi", ps3_spu_gpr_word(spu, 22, 0), 0x40000000u);
    ISA_CHECK("lqd $22 lo", ps3_spu_gpr_word(spu, 22, 1), 0u);
    ISA_CHECK("dfa", ps3_spu_gpr_word(spu, 23, 0), 0x40080000u);
    ISA_CHECK("dfa lo", ps3_spu_gpr_word(spu, 23, 1), 0u);
    ISA_CHECK("dfs", ps3_spu_gpr_word(spu, 24, 0), 0x3FF00000u);
    ISA_CHECK("dfm", ps3_spu_gpr_word(spu, 25, 0), 0x40100000u);
    ISA_CHECK("dfma", ps3_spu_gpr_word(spu, 26, 0), 0x40080000u);
    ISA_CHECK("dfceq", ps3_spu_gpr_word(spu, 27, 0), 0xFFFFFFFFu);
    ISA_CHECK("dfcgt", ps3_spu_gpr_word(spu, 28, 0), 0xFFFFFFFFu);
    ISA_CHECK("dfcmgt", ps3_spu_gpr_word(spu, 29, 0), 0u);
    ISA_CHECK("dftsv", ps3_spu_gpr_word(spu, 31, 0), 0xFFFFFFFFu);
    ISA_CHECK("mpys", ps3_spu_gpr_word(spu, 35, 0), 0x00001000u);
    ISA_CHECK("mpyh", ps3_spu_gpr_word(spu, 36, 0), 0x00600000u);
    ISA_CHECK("mpyhh", ps3_spu_gpr_word(spu, 38, 0), 0x00002468u);
    ISA_CHECK("mpyhha", ps3_spu_gpr_word(spu, 39, 0), 0x00002469u);
    ISA_CHECK("mpyhhu", ps3_spu_gpr_word(spu, 40, 0), 0x00002468u);
    ISA_CHECK("mpyhhau", ps3_spu_gpr_word(spu, 41, 0), 0x00002469u);
    ISA_CHECK("bg", ps3_spu_gpr_word(spu, 45, 0), 1u);
    ISA_CHECK("bgx", ps3_spu_gpr_word(spu, 44, 0), 0u);
    ISA_CHECK("orx", ps3_spu_gpr_word(spu, 46, 0), 0x3F800000u);
    ISA_CHECK("orx slot 1", ps3_spu_gpr_word(spu, 46, 1), 0u);
    ISA_CHECK("mfspr", ps3_spu_gpr_word(spu, 47, 0), 0x40000000u);
    ISA_CHECK("mfspr slot 1", ps3_spu_gpr_word(spu, 47, 1), 0u);
    ISA_CHECK("rotqbybi count", ps3_spu_gpr_word(spu, 48, 0), 32u);
    ISA_CHECK("rotqbybi w0", ps3_spu_gpr_word(spu, 49, 0), 0u);
    ISA_CHECK("rotqbybi w1", ps3_spu_gpr_word(spu, 49, 1), 0u);
    ISA_CHECK("rotqbybi w2", ps3_spu_gpr_word(spu, 49, 2), 0u);
    ISA_CHECK("rotqbybi word3", ps3_spu_gpr_word(spu, 49, 3), 0x3F800000u);
    ISA_CHECK("shlqbybi", ps3_spu_gpr_word(spu, 50, 0), 0u);
    ISA_CHECK("rotqmbybi word0", ps3_spu_gpr_word(spu, 52, 0), 0u);
    ISA_CHECK("rotqmbybi word1", ps3_spu_gpr_word(spu, 52, 1), 0x3F800000u);

    ps3_spu_free(spu);
    g_free(ls);
    return 0;
#undef EMIT
}

unsigned ps3_spu_code_words(const uint8_t *bytes, size_t len,
                            unsigned *total)
{
    unsigned known = 0, words = len / 4;

    for (unsigned i = 0; i < words; i++) {
        uint32_t w = ((uint32_t)bytes[i * 4] << 24) |
                     ((uint32_t)bytes[i * 4 + 1] << 16) |
                     ((uint32_t)bytes[i * 4 + 2] << 8) |
                     (uint32_t)bytes[i * 4 + 3];

        if (decode(w)) {
            known++;
        }
    }

    if (total) {
        *total = words;
    }

    return known;
}

static bool fault(PS3SPU *spu, uint32_t pc, uint32_t word,
                  char *why, size_t why_len)
{
    const SpuOpcode *op = decode(word);
    GString *trail = g_string_new(NULL);

    for (unsigned i = 0; i < ARRAY_SIZE(spu->hist); i++) {
        const unsigned k = (spu->hist_pos + i) % ARRAY_SIZE(spu->hist);

        if (spu->hist[k].pc == UINT32_MAX) {
            continue;
        }

        g_string_append_printf(trail, " %X:", spu->hist[k].pc);
        if (decode(spu->hist[k].word)) {
            g_string_append(trail, decode(spu->hist[k].word)->name);
        } else {
            g_string_append_printf(trail, "0x%08X", spu->hist[k].word);
        }
    }

    snprintf(why, why_len, "unimplemented SPU %s (0x%08X) at 0x%X; before:%s",
             op ? op->name : "opcode", word, pc, trail->str);
    g_string_free(trail, true);
    return false;
}

/*
 * Which issue pipe an instruction can use.  The SPU issues one instruction to
 * each of two pipes per cycle; only the pairing is modelled here, not the
 * latencies or the hazards.  Even: floating point, integer multiply, shifts,
 * rotates, byte control and compares.  Odd: ALU, loads/stores, branches,
 * channels and the rest.
 */
static bool kind_even_pipe(unsigned kind)
{
    switch (kind) {
    case K_FA: case K_FS: case K_FM: case K_FMA: case K_FMS: case K_FNMS:
    case K_FREST: case K_FRSQEST: case K_FI: case K_FESD: case K_FRDS:
    case K_CSFLT: case K_CUFLT: case K_CFLTS: case K_CFLTU:
    case K_FCEQ: case K_FCGT: case K_FCMEQ: case K_FCMGT:
    case K_DFA: case K_DFS: case K_DFM: case K_DFMA: case K_DFMS:
    case K_DFNMS: case K_DFNMA: case K_DFCEQ: case K_DFCGT:
    case K_DFCMEQ: case K_DFCMGT: case K_DFTSV:
    case K_MPY: case K_MPYU: case K_MPYI: case K_MPYUI: case K_MPYA:
    case K_MPYS: case K_MPYH: case K_MPYHH: case K_MPYHHA:
    case K_MPYHHU: case K_MPYHHAU:
    case K_SHL: case K_SHLH: case K_SHLI: case K_SHLHI:
    case K_ROT: case K_ROTH: case K_ROTI: case K_ROTHI:
    case K_ROTM: case K_ROTHM: case K_ROTMI: case K_ROTHMI:
    case K_ROTMA: case K_ROTMAH: case K_ROTMAI: case K_ROTMAHI:
    case K_SHUFB: case K_SELB: case K_CBD: case K_CBX: case K_CHD:
    case K_CHX: case K_CWD: case K_CWX: case K_CDD: case K_CDX:
    case K_FSM: case K_FSMH: case K_FSMB: case K_CEQ: case K_CEQH:
    case K_CEQB: case K_CGT: case K_CGTH: case K_CGTB: case K_CLGT:
    case K_CLGTH: case K_CLGTB: case K_CLZ:
        return true;
    default:
        return false;
    }
}

static bool kind_is_branch(unsigned kind)
{
    switch (kind) {
    case K_BR: case K_BRA: case K_BRSL: case K_BRASL: case K_BRZ:
    case K_BRNZ: case K_BRHZ: case K_BRHNZ: case K_BI: case K_BISL:
    case K_BISLED: case K_BIZ: case K_BINZ: case K_BIHZ: case K_BIHNZ:
    case K_BG: case K_BGX: case K_IRET:
        return true;
    default:
        return false;
    }
}

static bool execute(PS3SPU *spu, uint32_t pc, char *why, size_t why_len)
{
    uint8_t a[16], b[16], c[16], out[16];
    uint32_t word;
    Insn in;
    uint32_t next = pc + 4;

    if (pc + 4 > spu->ls_size) {
        snprintf(why, why_len, "PC 0x%X is outside local storage", pc);
        return false;
    }

    word = be32(spu->ls + pc);
    spu->last_pc = pc;
    spu->last_word = word;

    spu->hist[spu->hist_pos].pc = pc;
    spu->hist[spu->hist_pos].word = word;
    spu->hist_pos = (spu->hist_pos + 1) % ARRAY_SIZE(spu->hist);
    {
        const unsigned slot = ((pc >> 2) * 2654435761u >> 20) & 0xFFF;

        if (spu->hot[slot].pc != pc) {
            spu->hot[slot].pc = pc;
            spu->hot[slot].count = 0;
        }
        spu->hot[slot].count++;
    }

    memset(&in, 0, sizeof(in));
    in.op = decode(word);

    if (!in.op) {
        return fault(spu, pc, word, why, why_len);
    }

    field_decode(&in, word);

    if (spu->trace) {
        fprintf(stderr, "[spu] %05X  %08X  %-8s rt=%u ra=%u rb=%u\n",
                pc, word, in.op->name, in.rt, in.ra, in.rb);
    }


    switch (in.op->kind) {
    /* ---- control ---------------------------------------------------- */
    case K_HALT:
        spu->stop_code = word & 0x3FFF;
        spu->halted = true;
        snprintf(why, why_len, "stop %u at 0x%X", spu->stop_code, pc);
        return false;

    case K_STOPD:
        /* Same PC update as stop, no signal value: a breakpoint that keeps
         * the instruction timing of the instruction it replaces. */
        spu->halted = true;
        spu->stop_code = 0x3FFF;
        snprintf(why, why_len, "stopd at 0x%X", pc);
        return false;

    case K_IRET:
        /* Back to the address the interrupt saved.  RA is ignored. */
        next = spu->srr0;
        break;

    case K_NONE:                  /* nop, lnop, sync, dsync, branch hints */
        break;

    /* ---- branches --------------------------------------------------- */
    case K_BR:
        next = pc + in.bd;
        break;

    case K_BRA:
        next = in.i16 << 2;
        break;

    case K_BRSL:
        gpr_fill(spu, in.rt, pc + 4);
        next = pc + in.bd;
        break;

    case K_BRASL:
        gpr_fill(spu, in.rt, pc + 4);
        next = in.i16 << 2;
        break;

    case K_BRZ:
    case K_BRNZ:
    case K_BRHZ:
    case K_BRHNZ: {
        uint32_t v = scw(spu, in.rt);
        bool taken;

        if (in.op->kind == K_BRHZ || in.op->kind == K_BRHNZ) {
            v &= 0xFFFF;
        }

        taken = (in.op->kind == K_BRZ || in.op->kind == K_BRHZ) ?
                (v == 0) : (v != 0);

        if (taken) {
            next = pc + in.bd;
        }
        break;
    }

    case K_BISLED:
        /* The external-data condition comes from outside the SPU (a signal on
         * its data interface); with no such source it is false, so this is a
         * fall-through.  The link register is only written when taken. */
        break;

    case K_BI:
        next = scw(spu, in.ra);
        break;

    case K_BISL:
        gpr_fill(spu, in.rt, pc + 4);
        next = scw(spu, in.ra);
        break;

    case K_BIZ:
    case K_BINZ:
    case K_BIHZ:
    case K_BIHNZ: {
        uint32_t v = scw(spu, in.rt);
        bool taken;

        if (in.op->kind == K_BIHZ || in.op->kind == K_BIHNZ) {
            v &= 0xFFFF;
        }

        taken = (in.op->kind == K_BIZ || in.op->kind == K_BIHZ) ?
                (v == 0) : (v != 0);

        if (taken) {
            next = scw(spu, in.ra);
        }
        break;
    }

    /* ---- immediate loads -------------------------------------------- */
    case K_IL:
        gpr_fill(spu, in.rt, sext(in.i16, 16));
        break;

    case K_ILH:
        gpr_fill(spu, in.rt, in.i16);
        break;

    case K_ILHU:
        gpr_fill(spu, in.rt, in.i16 << 16);
        break;

    case K_ILA:
        gpr_fill(spu, in.rt, in.a18);
        break;

    case K_IOHL:
        for (unsigned i = 0; i < 4; i++) {
            gpr_set_w(spu, in.rt, i, gpr_w(spu, in.rt, i) | in.i16);
        }
        break;

    case K_FSMBI:
        for (unsigned i = 0; i < 16; i++) {
            qbyte_set(spu, in.rt, i, (in.i16 & (0x8000u >> i)) ? 0xFF : 0x00);
        }
        break;

    /* ---- word-immediate arithmetic ---------------------------------- */
    case K_AI:
    case K_AHI:
    case K_SFI:
    case K_SFHI:
    case K_ORI:
    case K_ORHI:
    case K_ORBI:
    case K_ANDI:
    case K_ANDHI:
    case K_ANDBI:
    case K_XORI:
    case K_XORHI:
    case K_XORBI:
    case K_CGTI:
    case K_CGTHI:
    case K_CGTBI:
    case K_CLGTI:
    case K_CLGTHI:
    case K_CLGTBI:
    case K_CEQI:
    case K_CEQHI:
    case K_CEQBI: {
        const uint32_t i = sext(in.i10, 10);
        const uint32_t i8 = i & 0xFF;
        const uint32_t i16 = i & 0xFFFF;

        switch (in.op->kind) {
        case K_AI:
            for (unsigned k = 0; k < 4; k++) {
                gpr_set_w(spu, in.rt, k, gpr_w(spu, in.ra, k) + i);
            }
            break;
        case K_AHI:
            for (unsigned k = 0; k < 4; k++) {
                gpr_set_w(spu, in.rt, k, gpr_w(spu, in.ra, k) + (i << 16));
            }
            break;
        case K_SFI:
            for (unsigned k = 0; k < 4; k++) {
                gpr_set_w(spu, in.rt, k, i - gpr_w(spu, in.ra, k));
            }
            break;
        case K_SFHI:
            for (unsigned k = 0; k < 4; k++) {
                gpr_set_w(spu, in.rt, k, (i << 16) - gpr_w(spu, in.ra, k));
            }
            break;
        case K_ORI:
        case K_ORHI:
        case K_ORBI: {
            /* orbi replicates the low byte into all four bytes (ISA 13). */
            const uint32_t v = (in.op->kind == K_ORHI) ? (i << 16) :
                               (in.op->kind == K_ORBI) ? (i8 * 0x01010101u) : i;
            for (unsigned k = 0; k < 4; k++) {
                gpr_set_w(spu, in.rt, k, gpr_w(spu, in.ra, k) | v);
            }
            break;
        }
        case K_ANDI:
        case K_ANDHI:
        case K_ANDBI: {
            const uint32_t v = (in.op->kind == K_ANDHI) ? (i << 16) :
                               (in.op->kind == K_ANDBI) ? (i8 * 0x01010101u) : i;
            for (unsigned k = 0; k < 4; k++) {
                gpr_set_w(spu, in.rt, k, gpr_w(spu, in.ra, k) & v);
            }
            break;
        }
        case K_XORI:
        case K_XORHI:
        case K_XORBI: {
            const uint32_t v = (in.op->kind == K_XORHI) ? (i << 16) :
                               (in.op->kind == K_XORBI) ? (i8 * 0x01010101u) : i;
            for (unsigned k = 0; k < 4; k++) {
                gpr_set_w(spu, in.rt, k, gpr_w(spu, in.ra, k) ^ v);
            }
            break;
        }
        case K_CGTI:
            for (unsigned k = 0; k < 4; k++) {
                gpr_set_w(spu, in.rt, k,
                          (int32_t)gpr_w(spu, in.ra, k) > (int32_t)i
                          ? 0xFFFFFFFF : 0);
            }
            break;
        case K_CGTHI:
            for (unsigned k = 0; k < 8; k++) {
                qhalf_set(spu, in.rt, k,
                          (int16_t)qhalf(spu, in.ra, k) > (int16_t)i16
                          ? 0xFFFF : 0);
            }
            break;
        case K_CGTBI:
            for (unsigned k = 0; k < 16; k++) {
                qbyte_set(spu, in.rt, k,
                          (int8_t)qbyte(spu, in.ra, k) > (int8_t)i8
                          ? 0xFF : 0);
            }
            break;
        case K_CLGTI:
        case K_CLGTHI:
        case K_CLGTBI:
            if (in.op->kind == K_CLGTI) {
                for (unsigned k = 0; k < 4; k++) {
                    gpr_set_w(spu, in.rt, k, gpr_w(spu, in.ra, k) > i
                              ? 0xFFFFFFFF : 0);
                }
            } else if (in.op->kind == K_CLGTHI) {
                for (unsigned k = 0; k < 8; k++) {
                    qhalf_set(spu, in.rt, k, qhalf(spu, in.ra, k) > i16
                              ? 0xFFFF : 0);
                }
            } else {
                for (unsigned k = 0; k < 16; k++) {
                    qbyte_set(spu, in.rt, k, qbyte(spu, in.ra, k) > i8
                              ? 0xFF : 0);
                }
            }
            break;
        case K_CEQI:
            for (unsigned k = 0; k < 4; k++) {
                gpr_set_w(spu, in.rt, k, gpr_w(spu, in.ra, k) == i
                          ? 0xFFFFFFFF : 0);
            }
            break;
        case K_CEQHI:
            for (unsigned k = 0; k < 8; k++) {
                qhalf_set(spu, in.rt, k, qhalf(spu, in.ra, k) == i16
                          ? 0xFFFF : 0);
            }
            break;
        case K_CEQBI:
            for (unsigned k = 0; k < 16; k++) {
                qbyte_set(spu, in.rt, k, qbyte(spu, in.ra, k) == i8
                          ? 0xFF : 0);
            }
            break;
        }
        break;
    }
    case K_MPYI:
    case K_MPYUI: {
        const uint32_t i = sext(in.i10, 10);

        for (unsigned k = 0; k < 4; k++) {
            const uint32_t x = gpr_w(spu, in.ra, k);

            if (in.op->kind == K_MPYI) {
                gpr_set_w(spu, in.rt, k,
                          (uint32_t)((int64_t)(int32_t)x * (int32_t)i));
            } else {
                gpr_set_w(spu, in.rt, k, x * i);
            }
        }
        break;
    }

    /* ---- local store ------------------------------------------------- */
    case K_LQD:
    case K_STQD: {
        const uint32_t off = sext(in.i10, 10) << 4;
        const uint32_t addr = scw(spu, in.ra) + off;

        if (in.op->kind == K_LQD) {
            ls_read(spu, addr, a);
            gpr_set_bytes(spu, in.rt, a);
        } else {
            gpr_get_bytes(spu, in.rt, a);
            ls_write(spu, addr, a);
        }
        break;
    }

    case K_LQX:
    case K_STQX: {
        const uint32_t addr = scw(spu, in.ra) + scw(spu, in.rb);

        if (in.op->kind == K_LQX) {
            ls_read(spu, addr, a);
            gpr_set_bytes(spu, in.rt, a);
        } else {
            gpr_get_bytes(spu, in.rt, a);
            ls_write(spu, addr, a);
        }
        break;
    }

    case K_LQA:
    case K_STQA: {
        if (in.op->kind == K_LQA) {
            ls_read(spu, in.i16 << 2, a);
            gpr_set_bytes(spu, in.rt, a);
        } else {
            gpr_get_bytes(spu, in.rt, a);
            ls_write(spu, in.i16 << 2, a);
        }
        break;
    }

    case K_LQR:
    case K_STQR: {
        if (in.op->kind == K_LQR) {
            ls_read(spu, pc + (in.i16 << 2), a);
            gpr_set_bytes(spu, in.rt, a);
        } else {
            gpr_get_bytes(spu, in.rt, a);
            ls_write(spu, pc + (in.i16 << 2), a);
        }
        break;
    }

    /* ---- four-register ---------------------------------------------- */
    case K_SELB:
        gpr_get_bytes(spu, in.ra, a);
        gpr_get_bytes(spu, in.rb, b);
        gpr_get_bytes(spu, in.rc, c);
        for (unsigned i = 0; i < 16; i++) {
            out[i] = (c[i] & 0x80) ? b[i] : a[i];
        }
        gpr_set_bytes(spu, in.rt, out);
        break;

    case K_SHUFB:
        gpr_get_bytes(spu, in.ra, a);
        gpr_get_bytes(spu, in.rb, b);
        gpr_get_bytes(spu, in.rc, c);
        shufb(out, a, b, c);
        gpr_set_bytes(spu, in.rt, out);
        break;

    case K_MPYA:
        for (unsigned i = 0; i < 4; i++) {
            const uint32_t p = (uint32_t)((int64_t)(int32_t)gpr_w(spu, in.ra, i) *
                                          (int32_t)gpr_w(spu, in.rb, i));
            gpr_set_w(spu, in.rt, i, p + gpr_w(spu, in.rc, i));
        }
        break;

    /* ---- three-register word ops ------------------------------------ */
    case K_ADDX:
    case K_SFX:
        for (unsigned i = 0; i < 4; i++) {
            const uint32_t x = gpr_w(spu, in.ra, i);
            const uint32_t y = gpr_w(spu, in.rb, i);
            /* The carry in is bit 31 of RT itself: cg/addx is one chain. */
            const uint32_t cin = gpr_w(spu, in.rt, i) & 1;

            gpr_set_w(spu, in.rt, i, (in.op->kind == K_ADDX)
                      ? (x + y + cin) : (y + ~x + cin));
        }
        break;

    case K_CG:
    case K_CGX:
        for (unsigned i = 0; i < 4; i++) {
            const uint64_t sum = (uint64_t)gpr_w(spu, in.ra, i) +
                                 gpr_w(spu, in.rb, i) +
                                 ((in.op->kind == K_CGX)
                                  ? (gpr_w(spu, in.rt, i) & 1) : 0);

            gpr_set_w(spu, in.rt, i, (uint32_t)(sum >> 32));
        }
        break;

    case K_A:
    case K_AH:
    case K_SF:
    case K_SFH:
    case K_AND:
    case K_ANDC:
    case K_OR:
    case K_ORC:
    case K_XOR:
    case K_NAND:
    case K_NOR:
    case K_EQV:
        for (unsigned i = 0; i < 4; i++) {
            const uint32_t x = gpr_w(spu, in.ra, i);
            const uint32_t y = gpr_w(spu, in.rb, i);
            uint32_t r = 0;

            switch (in.op->kind) {
            case K_A:
                r = x + y;
                break;
            case K_AH:
                /* Each halfword adds on its own, with no carry between. */
                r = (((x & 0xFFFF) + (y & 0xFFFF)) & 0xFFFF) |
                    ((((x >> 16) + (y >> 16)) & 0xFFFF) << 16);
                break;
            case K_SF:
                r = y - x;
                break;
            case K_SFH:
                r = ((((y & 0xFFFF) - (x & 0xFFFF)) & 0xFFFF)) |
                    (((((y >> 16) - (x >> 16)) & 0xFFFF)) << 16);
                break;
            case K_AND:
                r = x & y;
                break;
            case K_ANDC:
                r = x & ~y;
                break;
            case K_OR:
                r = x | y;
                break;
            case K_ORC:
                r = x | ~y;
                break;
            case K_XOR:
                r = x ^ y;
                break;
            case K_NAND:
                r = ~(x & y);
                break;
            case K_NOR:
                r = ~(x | y);
                break;
            case K_EQV:
                r = ~(x ^ y);
                break;
            }
            gpr_set_w(spu, in.rt, i, r);
        }
        break;

    case K_MPY:
        for (unsigned i = 0; i < 4; i++) {
            gpr_set_w(spu, in.rt, i,
                      (uint32_t)((int64_t)(int32_t)gpr_w(spu, in.ra, i) *
                                 (int32_t)gpr_w(spu, in.rb, i)));
        }
        break;

    case K_MPYU:
        for (unsigned i = 0; i < 4; i++) {
            gpr_set_w(spu, in.rt, i,
                      (uint32_t)((uint64_t)gpr_w(spu, in.ra, i) *
                                 gpr_w(spu, in.rb, i)));
        }
        break;


    case K_AVGB:
        for (unsigned i = 0; i < 16; i++) {
            const unsigned x = qbyte(spu, in.ra, i);
            const unsigned y = qbyte(spu, in.rb, i);

            qbyte_set(spu, in.rt, i, (x + y + 1) >> 1);
        }
        break;

    case K_ABSDB:
        for (unsigned i = 0; i < 16; i++) {
            const int x = qbyte(spu, in.ra, i);
            const int y = qbyte(spu, in.rb, i);

            qbyte_set(spu, in.rt, i, x > y ? x - y : y - x);
        }
        break;

    case K_SUMB:
        for (unsigned i = 0; i < 4; i++) {
            uint32_t sum = 0;

            for (unsigned k = 0; k < 4; k++) {
                sum += qbyte(spu, in.ra, i * 4 + k);
            }
            gpr_set_w(spu, in.rt, i, sum);
        }
        break;

    /* ---- shifts and rotates ----------------------------------------- */
    case K_SHL:
    case K_ROT:
    case K_ROTM:
    case K_ROTMA:
        for (unsigned i = 0; i < 4; i++) {
            const uint32_t x = gpr_w(spu, in.ra, i);
            const uint32_t cnt = gpr_w(spu, in.rb, i);
            uint32_t r;

            switch (in.op->kind) {
            case K_SHL:
                r = x << (cnt & 0x1F);
                break;
            case K_ROT: {
                const unsigned s = cnt & 0x1F;

                r = s ? ((x << s) | (x >> (32 - s))) : x;
                break;
            }
            case K_ROTM: {
                const unsigned s = (0u - cnt) & 0x3F;

                r = (s < 32) ? (x >> s) : 0;
                break;
            }
            default: {
                const unsigned s = (0u - cnt) & 0x3F;

                r = (s < 32) ? (uint32_t)((int32_t)x >> s) : (x >> 31 ? ~0u : 0);
                break;
            }
            }
            gpr_set_w(spu, in.rt, i, r);
        }
        break;

    case K_SHLH:
    case K_ROTH:
    case K_ROTHM:
    case K_ROTMAH:
        for (unsigned i = 0; i < 8; i++) {
            const uint16_t x = qhalf(spu, in.ra, i);
            const uint16_t cnt = qhalf(spu, in.rb, i);
            uint16_t r;

            switch (in.op->kind) {
            case K_SHLH: {
                const unsigned s = cnt & 0x1F;

                r = (s > 15) ? 0 : (uint16_t)(x << s);
                break;
            }
            case K_ROTH: {
                const unsigned s = cnt & 0xF;

                r = s ? (uint16_t)((x << s) | (x >> (16 - s))) : x;
                break;
            }
            case K_ROTHM: {
                const unsigned s = (0u - cnt) & 0x1F;

                r = (s < 16) ? (uint16_t)(x >> s) : 0;
                break;
            }
            default: {
                const unsigned s = (0u - cnt) & 0x1F;

                r = (s < 16) ? (uint16_t)((int16_t)x >> s)
                             : ((x & 0x8000) ? 0xFFFF : 0);
                break;
            }
            }
            qhalf_set(spu, in.rt, i, r);
        }
        break;

    case K_SHLI:
    case K_ROTI:
    case K_ROTMI:
    case K_ROTMAI:
        for (unsigned i = 0; i < 4; i++) {
            const uint32_t x = gpr_w(spu, in.ra, i);
            uint32_t r;

            switch (in.op->kind) {
            case K_SHLI: {
                const unsigned s = in.i7 & 0x3F;

                r = (s < 32) ? (x << s) : 0;
                break;
            }
            case K_ROTI: {
                const unsigned s = in.i7 & 0x1F;

                r = s ? ((x << s) | (x >> (32 - s))) : x;
                break;
            }
            case K_ROTMI: {
                const unsigned s = (0u - in.i7) & 0x3F;

                r = (s < 32) ? (x >> s) : 0;
                break;
            }
            default: {
                const unsigned s = (0u - in.i7) & 0x3F;

                r = (s < 32) ? (uint32_t)((int32_t)x >> s)
                             : ((x & 0x80000000u) ? ~0u : 0);
                break;
            }
            }
            gpr_set_w(spu, in.rt, i, r);
        }
        break;

    case K_SHLHI:
    case K_ROTHI:
    case K_ROTHMI:
    case K_ROTMAHI:
        for (unsigned i = 0; i < 8; i++) {
            const uint16_t x = qhalf(spu, in.ra, i);
            uint16_t r;

            switch (in.op->kind) {
            case K_SHLHI: {
                const unsigned s = in.i7 & 0x1F;

                r = (s > 15) ? 0 : (uint16_t)(x << s);
                break;
            }
            case K_ROTHI: {
                const unsigned s = in.i7 & 0xF;

                r = s ? (uint16_t)((x << s) | (x >> (16 - s))) : x;
                break;
            }
            case K_ROTHMI: {
                const unsigned s = (0u - in.i7) & 0x1F;

                r = (s < 16) ? (uint16_t)(x >> s) : 0;
                break;
            }
            default: {
                const unsigned s = (0u - in.i7) & 0x1F;

                r = (s < 16) ? (uint16_t)((int16_t)x >> s)
                             : ((x & 0x8000) ? 0xFFFF : 0);
                break;
            }
            }
            qhalf_set(spu, in.rt, i, r);
        }
        break;

    case K_SHLQBY:
        gpr_get_bytes(spu, in.ra, a);
        qshl_bytes(out, a, scw(spu, in.rb) & 0x1F);
        gpr_set_bytes(spu, in.rt, out);
        break;

    case K_SHLQBYI:
        gpr_get_bytes(spu, in.ra, a);
        qshl_bytes(out, a, in.i7 & 0x1F);
        gpr_set_bytes(spu, in.rt, out);
        break;

    case K_ROTQBY:
        gpr_get_bytes(spu, in.ra, a);
        qrotl_bytes(out, a, scw(spu, in.rb) & 0x1F);
        gpr_set_bytes(spu, in.rt, out);
        break;

    case K_ROTQBYI:
        gpr_get_bytes(spu, in.ra, a);
        qrotl_bytes(out, a, in.i7);
        gpr_set_bytes(spu, in.rt, out);
        break;

    case K_ROTQMBY:
        gpr_get_bytes(spu, in.ra, a);
        qshr_bytes(out, a, (0u - scw(spu, in.rb)) & 0x1F);
        gpr_set_bytes(spu, in.rt, out);
        break;

    case K_ROTQMBYI:
        gpr_get_bytes(spu, in.ra, a);
        qshr_bytes(out, a, (0u - in.i7) & 0x1F);
        gpr_set_bytes(spu, in.rt, out);
        break;

    case K_ROTQBI:
        gpr_get_bytes(spu, in.ra, a);
        qrotl_bits(out, a, scw(spu, in.rb) & 7);
        gpr_set_bytes(spu, in.rt, out);
        break;

    case K_ROTQBII:
        gpr_get_bytes(spu, in.ra, a);
        qrotl_bits(out, a, in.i7 & 7);
        gpr_set_bytes(spu, in.rt, out);
        break;

    case K_ROTMQBI:
        gpr_get_bytes(spu, in.ra, a);
        qshr_bits(out, a, (0u - scw(spu, in.rb)) & 7);
        gpr_set_bytes(spu, in.rt, out);
        break;

    case K_ROTQMBII:
        gpr_get_bytes(spu, in.ra, a);
        qshr_bits(out, a, (0u - in.i7) & 7);
        gpr_set_bytes(spu, in.rt, out);
        break;

    case K_SHLQBI:
        gpr_get_bytes(spu, in.ra, a);
        qshl_bits(out, a, scw(spu, in.rb) & 7);
        gpr_set_bytes(spu, in.rt, out);
        break;

    case K_SHLQBII:
        gpr_get_bytes(spu, in.ra, a);
        qshl_bits(out, a, in.i7 & 7);
        gpr_set_bytes(spu, in.rt, out);
        break;

    /* ---- generate controls ------------------------------------------ */
    case K_CBD:
    case K_CHD:
    case K_CWD:
    case K_CDD: {
        const unsigned size = (in.op->kind == K_CBD) ? 1 :
                              (in.op->kind == K_CHD) ? 2 :
                              (in.op->kind == K_CWD) ? 4 : 8;
        const unsigned pos = (scw(spu, in.ra) + in.i7) & 0xF;

        gen_controls(out, pos, size);
        gpr_set_bytes(spu, in.rt, out);
        break;
    }

    case K_CBX:
    case K_CHX:
    case K_CWX:
    case K_CDX: {
        const unsigned size = (in.op->kind == K_CBX) ? 1 :
                              (in.op->kind == K_CHX) ? 2 :
                              (in.op->kind == K_CWX) ? 4 : 8;
        const unsigned pos = (scw(spu, in.ra) + scw(spu, in.rb)) & 0xF;

        gen_controls(out, pos, size);
        gpr_set_bytes(spu, in.rt, out);
        break;
    }

    /* ---- form select / gather --------------------------------------- */
    case K_FSM: {
        const uint32_t bits = scw(spu, in.ra);

        for (unsigned i = 0; i < 4; i++) {
            gpr_set_w(spu, in.rt, i, (bits & (1u << (3 - i))) ? 0xFFFFFFFF : 0);
        }
        break;
    }

    case K_FSMH: {
        const uint32_t bits = scw(spu, in.ra);

        for (unsigned i = 0; i < 8; i++) {
            qhalf_set(spu, in.rt, i,
                      (bits & (1u << (7 - i))) ? 0xFFFF : 0);
        }
        break;
    }

    case K_FSMB: {
        const uint32_t bits = scw(spu, in.ra);

        for (unsigned i = 0; i < 16; i++) {
            qbyte_set(spu, in.rt, i, (bits & (1u << (15 - i))) ? 0xFF : 0);
        }
        break;
    }

    case K_GB:
    case K_GBH:
    case K_GBB: {
        /* GB gathers the sign bit of each byte (16 bits), GBH the sign of each
         * halfword (8 bits), GBB the low bit of each byte.  The result sits in
         * the low half of the preferred slot, byte 0 -> bit 15. */
        uint32_t bits = 0;

        if (in.op->kind == K_GBH) {
            for (unsigned i = 0; i < 8; i++) {
                bits |= (uint32_t)(qhalf(spu, in.ra, i) >> 15) << (7 - i);
            }
        } else if (in.op->kind == K_GB) {
            for (unsigned i = 0; i < 16; i++) {
                bits |= (uint32_t)(qbyte(spu, in.ra, i) >> 7) << (15 - i);
            }
        } else {
            for (unsigned i = 0; i < 16; i++) {
                bits |= (uint32_t)(qbyte(spu, in.ra, i) & 1) << (15 - i);
            }
        }

        gpr_fill(spu, in.rt, bits);
        break;
    }

    /* ---- compares --------------------------------------------------- */
    case K_CEQ:
    case K_CGT:
    case K_CLGT:
        for (unsigned i = 0; i < 4; i++) {
            const uint32_t x = gpr_w(spu, in.ra, i);
            const uint32_t y = gpr_w(spu, in.rb, i);
            bool hit;

            if (in.op->kind == K_CEQ) {
                hit = x == y;
            } else if (in.op->kind == K_CGT) {
                hit = (int32_t)x > (int32_t)y;
            } else {
                hit = x > y;
            }
            gpr_set_w(spu, in.rt, i, hit ? 0xFFFFFFFF : 0);
        }
        break;

    case K_CEQH:
    case K_CGTH:
    case K_CLGTH:
        for (unsigned i = 0; i < 8; i++) {
            const uint16_t x = qhalf(spu, in.ra, i);
            const uint16_t y = qhalf(spu, in.rb, i);
            bool hit;

            if (in.op->kind == K_CEQH) {
                hit = x == y;
            } else if (in.op->kind == K_CGTH) {
                hit = (int16_t)x > (int16_t)y;
            } else {
                hit = x > y;
            }
            qhalf_set(spu, in.rt, i, hit ? 0xFFFF : 0);
        }
        break;

    case K_CEQB:
    case K_CGTB:
    case K_CLGTB:
        for (unsigned i = 0; i < 16; i++) {
            const uint8_t x = qbyte(spu, in.ra, i);
            const uint8_t y = qbyte(spu, in.rb, i);
            bool hit;

            if (in.op->kind == K_CEQB) {
                hit = x == y;
            } else if (in.op->kind == K_CGTB) {
                hit = (int8_t)x > (int8_t)y;
            } else {
                hit = x > y;
            }
            qbyte_set(spu, in.rt, i, hit ? 0xFF : 0);
        }
        break;

    /* ---- bit and byte munging --------------------------------------- */
    case K_CLZ:
        for (unsigned i = 0; i < 4; i++) {
            uint32_t v = gpr_w(spu, in.ra, i);
            uint32_t n = 0;

            while (n < 32 && !(v & 0x80000000u)) {
                v <<= 1;
                n++;
            }
            gpr_set_w(spu, in.rt, i, n);
        }
        break;

    case K_CNTB:
        for (unsigned i = 0; i < 4; i++) {
            uint32_t v = gpr_w(spu, in.ra, i);
            uint32_t r = 0;

            for (unsigned k = 0; k < 4; k++) {
                r |= (uint32_t)__builtin_popcount((v >> (8 * k)) & 0xFF)
                     << (8 * k);
            }
            gpr_set_w(spu, in.rt, i, r);
        }
        break;

    case K_XSBH:
        for (unsigned i = 0; i < 8; i++) {
            qhalf_set(spu, in.rt, i, (uint16_t)sext(qbyte(spu, in.ra, i), 8));
        }
        break;

    case K_XSHW:
        for (unsigned i = 0; i < 4; i++) {
            gpr_set_w(spu, in.rt, i,
                      (sext(qhalf(spu, in.ra, i * 2), 16) & 0xFFFF) |
                      (sext(qhalf(spu, in.ra, i * 2 + 1), 16) << 16));
        }
        break;

    case K_XSWD:
        /* Each doubleword: the odd word is sign-extended into the even one. */
        for (unsigned i = 0; i < 2; i++) {
            const uint32_t lo = gpr_w(spu, in.ra, i * 2 + 1);

            gpr_set_w(spu, in.rt, i * 2, (lo & 0x80000000u) ? ~0u : 0);
            gpr_set_w(spu, in.rt, i * 2 + 1, lo);
        }
        break;

    /* ---- channels --------------------------------------------------- */
    case K_RDCH:
        gpr_fill(spu, in.rt, ch_read(spu, in.ra));
        break;

    case K_WRCH:
        ch_write(spu, in.ra, scw(spu, in.rt));
        break;

    case K_RCHCNT:
        gpr_fill(spu, in.rt, ch_read_count(spu, in.ra));
        break;

    /* ---- multiply variants ------------------------------------------ */
    case K_MPYS:
        /* Low halfwords, signed; the high half of the 32-bit product, sign
         * extended into the word. */
        for (unsigned i = 0; i < 4; i++) {
            const int32_t p = (int32_t)(int16_t)(gpr_w(spu, in.ra, i) & 0xFFFF) *
                              (int32_t)(int16_t)(gpr_w(spu, in.rb, i) & 0xFFFF);

            gpr_set_w(spu, in.rt, i,
                      (uint32_t)(int32_t)(p >> 16));
        }
        break;

    case K_MPYH:
        for (unsigned i = 0; i < 4; i++) {
            const uint32_t x = gpr_w(spu, in.ra, i) >> 16;
            const uint32_t y = gpr_w(spu, in.rb, i) & 0xFFFF;

            gpr_set_w(spu, in.rt, i, (x * y) << 16);
        }
        break;

    case K_MPYHH:
    case K_MPYHHU:
    case K_MPYHHA:
    case K_MPYHHAU:
        for (unsigned i = 0; i < 4; i++) {
            const uint32_t x = gpr_w(spu, in.ra, i) >> 16;
            const uint32_t y = gpr_w(spu, in.rb, i) >> 16;
            uint32_t p;

            if (in.op->kind == K_MPYHH) {
                p = (uint32_t)((int32_t)(int16_t)x * (int32_t)(int16_t)y);
            } else if (in.op->kind == K_MPYHHU) {
                p = (uint32_t)(x * y);
            } else if (in.op->kind == K_MPYHHA) {
                p = (uint32_t)((int32_t)(int16_t)x * (int32_t)(int16_t)y) +
                    gpr_w(spu, in.rt, i);
            } else {
                p = (uint32_t)(x * y) + gpr_w(spu, in.rt, i);
            }
            gpr_set_w(spu, in.rt, i, p);
        }
        break;

    /* ---- borrow/link in the preferred slot -------------------------- */
    case K_BG:
    case K_BGX:
        for (unsigned i = 0; i < 4; i++) {
            const uint32_t x = gpr_w(spu, in.ra, i);
            const uint32_t y = gpr_w(spu, in.rb, i);
            const uint32_t cin = (in.op->kind == K_BGX)
                ? ((gpr_w(spu, in.rt, i) & 1) ? 0 : 1) : 0;
            uint32_t r;

            if (in.op->kind == K_BG) {
                /* 1 unless RB is strictly greater than RA (unsigned). */
                r = (y > x) ? 0 : 1;
            } else {
                const uint64_t sum = (uint64_t)y + cin;

                r = (sum < x) ? 0 : 1;
            }
            gpr_set_w(spu, in.rt, i, r);
        }
        break;

    case K_ORX: {
        const uint32_t v = gpr_w(spu, in.ra, 0) | gpr_w(spu, in.ra, 1) |
                           gpr_w(spu, in.ra, 2) | gpr_w(spu, in.ra, 3);

        gpr_set_w(spu, in.rt, 0, v);
        gpr_set_w(spu, in.rt, 1, 0);
        gpr_set_w(spu, in.rt, 2, 0);
        gpr_set_w(spu, in.rt, 3, 0);
        break;
    }

    /* ---- bit-count driven quadword shifts --------------------------- */
    case K_ROTQBYBI:
    case K_SHLQBYBI:
    case K_ROTMQBYBI: {
        const unsigned count = (scw(spu, in.rb) >> 3) & 0x1F;

        if (1) {
            fprintf(stderr, "isa: %s rt=%u ra=%u rb=%u rbval=0x%08X count=%u\n",
                    in.op->name, in.rt, in.ra, in.rb, scw(spu, in.rb), count);
        }

        gpr_get_bytes(spu, in.ra, a);
        if (in.op->kind == K_ROTMQBYBI) {
            qshr_bytes(out, a, (0u - count) & 0x1F);
        } else if (in.op->kind == K_SHLQBYBI) {
            qshl_bytes(out, a, count);
        } else {
            qrotl_bytes(out, a, count);
        }
        gpr_set_bytes(spu, in.rt, out);
        if (1) {
            fprintf(stderr, "isa: -> %02X %02X %02X %02X  lane0=0x%08X a0=%02X%02X%02X%02X\n",
                    out[0], out[1], out[2], out[3],
                    gpr_w(spu, in.rt, 0), a[0], a[1], a[2], a[3]);
        }
        break;
    }

    /* ---- special-purpose registers --------------------------------- */
    case K_MFSPR:
        /* The Cell SPRs are the local-store limit registers; this model has a
         * flat store, so they read back what was written (zero at reset). */
        for (unsigned i = 0; i < 4; i++) {
            gpr_set_w(spu, in.rt, i, i == SPU_PREFERRED
                      ? spu->spr[in.ra & 0x7F] : 0);
        }
        break;

    case K_MTSPR:
        spu->spr[in.ra & 0x7F] = scw(spu, in.rt);
        break;

    /* ---- single-precision floating point ---------------------------- */
    case K_FA:
    case K_FS:
    case K_FM:
        for (unsigned i = 0; i < 4; i++) {
            const uint32_t xb = gpr_w(spu, in.ra, i);
            const uint32_t yb = gpr_w(spu, in.rb, i);
            const long double x = spu_sf_value(xb);
            const long double y = spu_sf_value(yb);
            long double r;

            spu_sf_flags(spu, xb);
            spu_sf_flags(spu, yb);

            if (in.op->kind == K_FA) {
                r = x + y;
            } else if (in.op->kind == K_FS) {
                r = x - y;
            } else {
                r = x * y;
            }
            gpr_set_w(spu, in.rt, i, spu_sf_pack(r, &spu->fpscr));
        }
        break;

    case K_FMA:
    case K_FMS:
    case K_FNMS:
        for (unsigned i = 0; i < 4; i++) {
            const long double x = spu_sf_value(gpr_w(spu, in.ra, i));
            const long double y = spu_sf_value(gpr_w(spu, in.rb, i));
            const long double z = spu_sf_value(gpr_w(spu, in.rc, i));
            long double r;

            if (in.op->kind == K_FMA) {
                r = x * y + z;
            } else if (in.op->kind == K_FMS) {
                r = x * y - z;
            } else {
                r = z - x * y;
            }
            gpr_set_w(spu, in.rt, i, spu_sf_pack(r, &spu->fpscr));
        }
        break;

    case K_FREST:
    case K_FRSQEST:
        for (unsigned i = 0; i < 4; i++) {
            const uint32_t x = gpr_w(spu, in.ra, i);
            const unsigned exp = (x >> 23) & 0xFF;
            const unsigned sign = x & SPU_SF_SIGN;
            uint32_t frac, e;

            if (in.op->kind == K_FREST) {
                frac = spu_frest_fraction[(x >> 18) & 0x1F];
                e = spu_frest_exponent(exp);
            } else {
                frac = spu_frsqest_fraction[(x >> 18) & 0x3F];
                e = spu_frsqest_exponent(exp);
            }
            if (exp == 0) {
                spu->fpscr |= SPU_FP_DBZ;
            }
            gpr_set_w(spu, in.rt, i,
                      (in.op->kind == K_FREST ? sign : 0) | e | frac);
        }
        break;

    case K_FI:
        for (unsigned i = 0; i < 4; i++) {
            const uint32_t rb = gpr_w(spu, in.rb, i);
            const uint32_t ra = gpr_w(spu, in.ra, i);
            const long double base = 1.0L +
                (long double)((rb >> 10) & 0x1FFF) / 8192.0L;
            const long double step =
                (long double)(rb & 0x3FF) / 8192.0L;
            const long double y =
                (long double)(ra & 0x7FFFF) / 524288.0L;
            const long double v = base - step * y;
            uint32_t frac = (uint32_t)floorl((v - 1.0L) * 8388608.0L);

            if (frac > SPU_SF_FRAC) {
                frac = SPU_SF_FRAC;
            }
            gpr_set_w(spu, in.rt, i, (rb & 0xFF800000u) | frac);
        }
        break;

    case K_FESD:
        /* Each doubleword's left (preferred) word is extended to a double. */
        for (unsigned i = 0; i < 2; i++) {
            const long double v =
                spu_sf_value(gpr_w(spu, in.ra, i * 2));
            const uint64_t bits = spu_d_bits((double)v);

            gpr_set_d(spu, in.rt, i, bits);
        }
        break;

    case K_FRDS:
        /* Each double is rounded to single and placed in the left word; the
         * right word is zero. */
        for (unsigned i = 0; i < 2; i++) {
            const double d = spu_d_value(gpr_d(spu, in.ra, i));
            const uint32_t s = spu_sf_pack((long double)d, &spu->fpscr);

            gpr_set_w(spu, in.rt, i * 2, s);
            gpr_set_w(spu, in.rt, i * 2 + 1, 0);
        }
        break;

    case K_FSCRRD:
        for (unsigned i = 0; i < 4; i++) {
            gpr_set_w(spu, in.rt, i, i == SPU_PREFERRED ? spu->fpscr : 0);
        }
        break;

    case K_FSCRWR:
        spu->fpscr = scw(spu, in.ra);
        break;

    case K_CSFLT:
    case K_CUFLT:
        for (unsigned i = 0; i < 4; i++) {
            const uint32_t x = gpr_w(spu, in.ra, i);
            const unsigned scale = (155u - in.i8) & 0xFF;
            long double v;

            if (in.op->kind == K_CSFLT) {
                v = (long double)(int32_t)x;
            } else {
                v = (long double)x;
            }
            v = ldexpl(v, -(int)scale);
            gpr_set_w(spu, in.rt, i, spu_sf_pack(v, &spu->fpscr));
        }
        break;

    case K_CFLTS:
    case K_CFLTU:
        for (unsigned i = 0; i < 4; i++) {
            const long double x = spu_sf_value(gpr_w(spu, in.ra, i));
            const unsigned scale = (173u - in.i8) & 0xFF;
            const long double v = ldexpl(x, (int)scale);
            uint32_t r;

            if (in.op->kind == K_CFLTS) {
                if (v > 2147483647.0L) {
                    r = 0x7FFFFFFFu;
                } else if (v < -2147483648.0L) {
                    r = 0x80000000u;
                } else {
                    r = (uint32_t)(int32_t)v;
                }
            } else {
                if (v <= 0) {
                    r = 0;
                } else if (v >= 4294967295.0L) {
                    r = 0xFFFFFFFFu;
                } else {
                    r = (uint32_t)v;
                }
            }
            gpr_set_w(spu, in.rt, i, r);
        }
        break;

    case K_FCEQ:
    case K_FCGT:
    case K_FCMEQ:
    case K_FCMGT:
        for (unsigned i = 0; i < 4; i++) {
            const uint32_t xb = gpr_w(spu, in.ra, i);
            const uint32_t yb = gpr_w(spu, in.rb, i);
            long double x = spu_sf_value(xb);
            long double y = spu_sf_value(yb);
            bool hit;

            if (in.op->kind == K_FCMEQ || in.op->kind == K_FCMGT) {
                x = fabsl(x);
                y = fabsl(y);
            }
            if (in.op->kind == K_FCEQ || in.op->kind == K_FCMEQ) {
                hit = x == y;
            } else {
                hit = x > y;
            }
            gpr_set_w(spu, in.rt, i, hit ? 0xFFFFFFFFu : 0);
        }
        break;

    /* ---- double-precision floating point ---------------------------- */
    case K_DFA:
    case K_DFS:
    case K_DFM:
        for (unsigned i = 0; i < 2; i++) {
            const double x = spu_d_value(gpr_d(spu, in.ra, i));
            const double y = spu_d_value(gpr_d(spu, in.rb, i));
            double r;

            if (in.op->kind == K_DFA) {
                r = x + y;
            } else if (in.op->kind == K_DFS) {
                r = x - y;
            } else {
                r = x * y;
            }
            gpr_set_d(spu, in.rt, i, spu_d_bits(r));
        }
        break;

    case K_DFMA:
    case K_DFMS:
    case K_DFNMS:
    case K_DFNMA:
        for (unsigned i = 0; i < 2; i++) {
            const double x = spu_d_value(gpr_d(spu, in.ra, i));
            const double y = spu_d_value(gpr_d(spu, in.rb, i));
            const double z = spu_d_value(gpr_d(spu, in.rt, i));
            double r;

            if (in.op->kind == K_DFMA) {
                r = x * y + z;
            } else if (in.op->kind == K_DFMS) {
                r = x * y - z;
            } else if (in.op->kind == K_DFNMS) {
                r = -(x * y - z);
            } else {
                r = -(x * y + z);
            }
            gpr_set_d(spu, in.rt, i, spu_d_bits(r));
        }
        break;

    case K_DFCEQ:
    case K_DFCGT:
    case K_DFCMEQ:
    case K_DFCMGT:
        for (unsigned i = 0; i < 2; i++) {
            double x = spu_d_value(gpr_d(spu, in.ra, i));
            double y = spu_d_value(gpr_d(spu, in.rb, i));
            bool hit;

            if (in.op->kind == K_DFCMEQ || in.op->kind == K_DFCMGT) {
                x = fabs(x);
                y = fabs(y);
            }
            if (in.op->kind == K_DFCEQ || in.op->kind == K_DFCMEQ) {
                hit = x == y;
            } else {
                hit = x > y;
            }
            gpr_set_d(spu, in.rt, i, spu_d_mask(hit));
        }
        break;

    case K_DFTSV:
        for (unsigned i = 0; i < 2; i++) {
            const uint64_t bits = gpr_d(spu, in.ra, i);
            const unsigned sign = (bits >> 63) & 1;
            const unsigned exp = (bits >> 52) & 0x7FF;
            const uint64_t frac = bits & 0xFFFFFFFFFFFFFULL;
            const bool nan = exp == 0x7FF && frac != 0;
            const bool inf = exp == 0x7FF && frac == 0;
            const bool zero = exp == 0 && frac == 0;
            const bool denorm = exp == 0 && frac != 0;
            bool hit = false;

            if ((in.i7 & 0x40) && nan) hit = true;
            if ((in.i7 & 0x20) && denorm && !sign) hit = true;
            if ((in.i7 & 0x10) && inf && !sign) hit = true;
            if ((in.i7 & 0x08) && inf && sign) hit = true;
            if ((in.i7 & 0x04) && denorm && sign) hit = true;
            if ((in.i7 & 0x02) && zero && !sign) hit = true;
            if ((in.i7 & 0x01) && zero && sign) hit = true;

            gpr_set_d(spu, in.rt, i, spu_d_mask(hit));
        }
        break;

    /* ---- halts on condition (debug traps) --------------------------- */
    case K_HEQI:
    case K_HEQ:
    case K_HGT:
    case K_HGTI:
    case K_HLGT:
    case K_HLGTI: {
        const bool imm = (in.op->kind == K_HEQI || in.op->kind == K_HGTI ||
                          in.op->kind == K_HLGTI);
        const uint32_t x = scw(spu, in.ra);
        const uint32_t y = imm ? (uint32_t)sext(in.i10, 10) : scw(spu, in.rb);
        bool hit;

        if (in.op->kind == K_HEQ || in.op->kind == K_HEQI) {
            hit = x == y;
        } else if (in.op->kind == K_HGT || in.op->kind == K_HGTI) {
            hit = (int32_t)x > (int32_t)y;
        } else {
            hit = x > y;
        }

        if (hit) {
            spu->stop_code = 0x3FFF;
            spu->halted = true;
            snprintf(why, why_len, "conditional halt trap at 0x%X", pc);
            return false;
        }
        break;
    }

    default:
        return fault(spu, pc, word, why, why_len);
    }

    /*
     * Issue accounting.  Two instructions that use different pipes share a
     * cycle; a control transfer breaks the pair because the next fetch is not
     * known when the branch issues.  This is an estimate of issue slots, not a
     * cycle-accurate timing model (there are no stalls, hazards or latencies).
     */
    if (kind_is_branch(in.op->kind)) {
        spu->cycles++;
        spu->last_pipe_valid = false;
    } else {
        const bool even = kind_even_pipe(in.op->kind);

        if (spu->last_pipe_valid && even != spu->last_pipe_even) {
            spu->dual_issue_pairs++;
            spu->last_pipe_valid = false;
        } else {
            spu->cycles++;
            spu->last_pipe_valid = true;
            spu->last_pipe_even = even;
        }
    }

    spu->pc = next;
    return true;
}

static void report_hot(PS3SPU *spu, const char *what, char *why, size_t why_len)
{
    uint32_t best = 0, second = 0;
    uint32_t best_pc = 0, second_pc = 0;

    for (unsigned i = 0; i < ARRAY_SIZE(spu->hot); i++) {
        if (spu->hot[i].count > best) {
            second = best;
            second_pc = best_pc;
            best = spu->hot[i].count;
            best_pc = spu->hot[i].pc;
        } else if (spu->hot[i].count > second) {
            second = spu->hot[i].count;
            second_pc = spu->hot[i].pc;
        }
    }

    snprintf(why, why_len,
             "%s at 0x%X; hottest 0x%X (%u hits), next 0x%X (%u), "
             "%" PRIu64 " MFC gets/%" PRIu64 " puts",
             what, spu->pc, best_pc, best, second_pc, second,
             spu->mfc_gets, spu->mfc_puts);
}

static void run_reset(PS3SPU *spu)
{
    spu->tag_head = 0;
    spu->tag_count = 0;
    spu->stop_code = 0;
    spu->halted = false;
    spu->cycles = 0;
    spu->dual_issue_pairs = 0;
    spu->last_pipe_even = false;
    spu->last_pipe_valid = false;
    memset(spu->hot, 0, sizeof(spu->hot));

    for (unsigned i = 0; i < ARRAY_SIZE(spu->hist); i++) {
        spu->hist[i].pc = UINT32_MAX;
    }
}

int ps3_spu_run_to(PS3SPU *spu, uint32_t entry, uint32_t stop_pc,
                   uint64_t limit, char *why, size_t why_len)
{
    spu->pc = entry;
    spu->insns = 0;
    run_reset(spu);

    for (uint64_t i = 0; i < limit; i++) {
        const uint32_t pc = spu->pc;

        if (pc == stop_pc) {
            snprintf(why, why_len, "reached 0x%X after %" PRIu64
                     " instructions", stop_pc, spu->insns);
            return 0;
        }

        spu->insns++;

        if (!execute(spu, pc, why, why_len)) {
            return spu->halted ? 0 : 2;
        }
    }

    {
        char what[64];

        snprintf(what, sizeof(what),
                 "instruction limit (%" PRIu64 ") before 0x%X", limit,
                 stop_pc);
        report_hot(spu, what, why, why_len);
    }
    return 1;
}

int ps3_spu_run(PS3SPU *spu, uint32_t entry, uint64_t limit,
                char *why, size_t why_len)
{
    spu->pc = entry;
    spu->insns = 0;
    run_reset(spu);

    for (uint64_t i = 0; i < limit; i++) {
        const uint32_t pc = spu->pc;

        spu->insns++;

        if (!execute(spu, pc, why, why_len)) {
            return spu->halted ? 0 : 2;
        }
    }

    {
        char what[64];

        snprintf(what, sizeof(what),
                 "instruction limit (%" PRIu64 ")", limit);
        report_hot(spu, what, why, why_len);
    }
    return 1;
}
