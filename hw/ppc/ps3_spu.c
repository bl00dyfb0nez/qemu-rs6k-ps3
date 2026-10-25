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
    default:
        return 0;
    }
}

static uint32_t ch_read_count(PS3SPU *spu, unsigned ch)
{
    switch (ch) {
    case 0x18:                                  /* MFC_RdTagStat */
        return spu->tag_count;
    case 0x42:
        return (spu->has_ch66 && spu->ch66_pos < 8) ? 1 : 0;
    default:
        return 0;
    }
}

static void ch_write(PS3SPU *spu, unsigned ch, uint32_t value)
{
    switch (ch) {
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
    case 0x40:                                  /* SPU_IsoCntl */
        break;
    default:
        break;
    }
}

/* ---- decode ----------------------------------------------------------- */

typedef struct {
    const SpuOpcode *op;
    unsigned rt, ra, rb, rc;
    uint32_t i7, i10, i16, a18, bd;
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
        snprintf(why, why_len, "stop %u at 0x%X", spu->stop_code, pc);
        return false;

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

    /* ---- halts on condition (debug traps) --------------------------- */
    case K_HEQI:
    case K_HEQ: {
        const bool eq = (in.op->kind == K_HEQI)
            ? scw(spu, in.ra) == in.i10
            : scw(spu, in.ra) == scw(spu, in.rb);

        if (eq) {
            spu->stop_code = 0x3FFF;
            snprintf(why, why_len, "halt-if-equal trap at 0x%X", pc);
            return false;
        }
        break;
    }

    default:
        return fault(spu, pc, word, why, why_len);
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
            return 2;
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
            if (spu->stop_code) {
                snprintf(why, why_len,
                         "stop %u at 0x%X after %" PRIu64 " instructions",
                         spu->stop_code, pc, spu->insns);
                return 0;
            }
            return 2;
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
