/*
 * SELF stage decryption for the PS3 boot path.
 *
 * Local research model, not intended for upstream QEMU contributions.
 *
 * The modules below lv0ldr.2 are SELF containers: the metadata block is
 * AES-256-CBC over the loader ERK/RIV, and everything after it (the segment
 * descriptions, the section key table, and the sections themselves) is
 * AES-128-CTR under the key the metadata unwraps to.  Opening one is:
 *
 *   1. try each loader keyset on the 0x40-byte root header at meta + 0x20;
 *      the right one leaves both its padding fields zero;
 *   2. CTR-decrypt the 0x20-byte certification header at meta + 0x60 and the
 *      rest of the metadata at meta + 0x80 with the unwrapped key and the
 *      counter block that follows it;
 *   3. CTR-decrypt each section with the key/iv the metadata's key table names.
 *
 * That is the same sequence ps3tools' sce_decrypt_header/sce_decrypt_data do
 * (the form readself prints for lv2ldr.self), reimplemented here so the stage
 * tests run the console's own loader path inside the emulator rather than
 * shipping a PC tool next to it.
 *
 * One difference from the PC tools is deliberate: the carves of lv0 in this
 * tree are a mix, lv1ldr still sealed and lv2ldr/appldr/isoldr already
 * unselfed.  Those keep the "encrypted" flag in their section table, so before
 * decrypting anything the largest section is decoded twice, as it stands and
 * under its own key, and the reading that comes out as SPU instructions wins
 * for the whole file (self_sections_are_plaintext).  Without that, decrypting a
 * second time turns the carve's code into noise and the stage faults at its
 * entry word.
 */
#include "qemu/osdep.h"
#include "ps3_self.h"
#include "ps3_spu.h"

/* ---------------------------------------------------------------------- */
/* AES-128/256, CBC decrypt and CTR, self-contained                        */
/* ---------------------------------------------------------------------- */

static const uint8_t aes_sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16,
};

static uint8_t aes_inv_sbox[256];
static bool aes_tables_ready;

static uint8_t aes_xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0));
}

static uint8_t aes_mul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;

    while (b) {
        if (b & 1) {
            r ^= a;
        }
        a = aes_xtime(a);
        b >>= 1;
    }
    return r;
}

static void aes_init(void)
{
    unsigned i;

    if (aes_tables_ready) {
        return;
    }

    for (i = 0; i < 256; i++) {
        aes_inv_sbox[aes_sbox[i]] = i;
    }
    aes_tables_ready = true;
}

struct AesCtx {
    uint8_t rk[240];   /* up to 15 round keys of 16 bytes */
    int nr;            /* 10 for 128-bit, 14 for 256-bit */
};

static void aes_expand(struct AesCtx *ctx, const uint8_t *key, int bits)
{
    int nk = bits / 32;
    int total;
    uint8_t rcon = 0x01;
    int i;

    ctx->nr = (bits == 256) ? 14 : 10;
    total = 4 * (ctx->nr + 1);

    aes_init();
    memcpy(ctx->rk, key, nk * 4);

    for (i = nk; i < total; i++) {
        uint8_t t[4];

        memcpy(t, ctx->rk + (i - 1) * 4, 4);
        if (i % nk == 0) {
            uint8_t tmp = t[0];

            t[0] = aes_sbox[t[1]] ^ rcon;
            t[1] = aes_sbox[t[2]];
            t[2] = aes_sbox[t[3]];
            t[3] = aes_sbox[tmp];
            rcon = aes_xtime(rcon);
        } else if (nk > 6 && i % nk == 4) {
            t[0] = aes_sbox[t[0]];
            t[1] = aes_sbox[t[1]];
            t[2] = aes_sbox[t[2]];
            t[3] = aes_sbox[t[3]];
        }
        ctx->rk[i * 4 + 0] = ctx->rk[(i - nk) * 4 + 0] ^ t[0];
        ctx->rk[i * 4 + 1] = ctx->rk[(i - nk) * 4 + 1] ^ t[1];
        ctx->rk[i * 4 + 2] = ctx->rk[(i - nk) * 4 + 2] ^ t[2];
        ctx->rk[i * 4 + 3] = ctx->rk[(i - nk) * 4 + 3] ^ t[3];
    }
}

static void aes_add_round_key(uint8_t s[16], const uint8_t *rk)
{
    int i;

    for (i = 0; i < 16; i++) {
        s[i] ^= rk[i];
    }
}

static void aes_shift_rows(uint8_t s[16])
{
    uint8_t t[16];

    memcpy(t, s, 16);
    s[0] = t[0];  s[4] = t[4];  s[8]  = t[8];   s[12] = t[12];
    s[1] = t[5];  s[5] = t[9];  s[9]  = t[13];  s[13] = t[1];
    s[2] = t[10]; s[6] = t[14]; s[10] = t[2];   s[14] = t[6];
    s[3] = t[15]; s[7] = t[3];  s[11] = t[7];   s[15] = t[11];
}

static void aes_inv_shift_rows(uint8_t s[16])
{
    uint8_t t[16];

    memcpy(t, s, 16);
    s[0] = t[0];  s[4] = t[4];  s[8]  = t[8];   s[12] = t[12];
    s[1] = t[13]; s[5] = t[1];  s[9]  = t[5];   s[13] = t[9];
    s[2] = t[10]; s[6] = t[14]; s[10] = t[2];   s[14] = t[6];
    s[3] = t[7];  s[7] = t[11]; s[11] = t[15];  s[15] = t[3];
}

static void aes_mix_columns(uint8_t s[16])
{
    int c;

    for (c = 0; c < 4; c++) {
        uint8_t *p = s + c * 4;
        uint8_t a = p[0], b = p[1], d = p[2], e = p[3];

        p[0] = aes_mul(a, 2) ^ aes_mul(b, 3) ^ d ^ e;
        p[1] = a ^ aes_mul(b, 2) ^ aes_mul(d, 3) ^ e;
        p[2] = a ^ b ^ aes_mul(d, 2) ^ aes_mul(e, 3);
        p[3] = aes_mul(a, 3) ^ b ^ d ^ aes_mul(e, 2);
    }
}

static void aes_inv_mix_columns(uint8_t s[16])
{
    int c;

    for (c = 0; c < 4; c++) {
        uint8_t *p = s + c * 4;
        uint8_t a = p[0], b = p[1], d = p[2], e = p[3];

        p[0] = aes_mul(a, 14) ^ aes_mul(b, 11) ^ aes_mul(d, 13) ^ aes_mul(e, 9);
        p[1] = aes_mul(a, 9) ^ aes_mul(b, 14) ^ aes_mul(d, 11) ^ aes_mul(e, 13);
        p[2] = aes_mul(a, 13) ^ aes_mul(b, 9) ^ aes_mul(d, 14) ^ aes_mul(e, 11);
        p[3] = aes_mul(a, 11) ^ aes_mul(b, 13) ^ aes_mul(d, 9) ^ aes_mul(e, 14);
    }
}

static void aes_encrypt_block(const struct AesCtx *ctx, const uint8_t in[16],
                              uint8_t out[16])
{
    uint8_t s[16];
    int round, i;

    memcpy(s, in, 16);
    aes_add_round_key(s, ctx->rk);

    for (round = 1; round <= ctx->nr; round++) {
        for (i = 0; i < 16; i++) {
            s[i] = aes_sbox[s[i]];
        }
        aes_shift_rows(s);
        if (round != ctx->nr) {
            aes_mix_columns(s);
        }
        aes_add_round_key(s, ctx->rk + round * 16);
    }

    memcpy(out, s, 16);
}

static void aes_decrypt_block(const struct AesCtx *ctx, const uint8_t in[16],
                              uint8_t out[16])
{
    uint8_t s[16];
    int round, i;

    memcpy(s, in, 16);
    aes_add_round_key(s, ctx->rk + ctx->nr * 16);

    for (round = ctx->nr - 1; round >= 0; round--) {
        aes_inv_shift_rows(s);
        for (i = 0; i < 16; i++) {
            s[i] = aes_inv_sbox[s[i]];
        }
        aes_add_round_key(s, ctx->rk + round * 16);
        if (round != 0) {
            aes_inv_mix_columns(s);
        }
    }

    memcpy(out, s, 16);
}

/* AES-256-CBC decrypt of `len` bytes (a multiple of 16). */
static void aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                               const uint8_t *in, uint8_t *out, size_t len)
{
    struct AesCtx ctx;
    uint8_t prev[16], block[16];
    size_t off;

    aes_expand(&ctx, key, 256);
    memcpy(prev, iv, 16);

    for (off = 0; off + 16 <= len; off += 16) {
        aes_decrypt_block(&ctx, in + off, block);
        for (unsigned i = 0; i < 16; i++) {
            out[off + i] = block[i] ^ prev[i];
        }
        memcpy(prev, in + off, 16);
    }
}

/*
 * AES-128-CTR.  The counter block is encrypted, then the low 64 bits are
 * incremented big-endian (carrying into the high half), which is the console
 * tools' convention and mbedtls' for the block counts these containers use.
 */
static void aes128_ctr(const uint8_t key[16], const uint8_t iv[16],
                       const uint8_t *in, uint8_t *out, size_t len)
{
    struct AesCtx ctx;
    uint8_t ctr[16], stream[16];
    size_t off;

    aes_expand(&ctx, key, 128);
    memcpy(ctr, iv, 16);

    for (off = 0; off < len; off += 16) {
        size_t n = MIN((size_t)16, len - off);
        uint64_t lo, hi;

        aes_encrypt_block(&ctx, ctr, stream);
        for (size_t i = 0; i < n; i++) {
            out[off + i] = in[off + i] ^ stream[i];
        }

        lo = 0;
        hi = 0;
        for (int i = 0; i < 8; i++) {
            lo = (lo << 8) | ctr[8 + i];
            hi = (hi << 8) | ctr[i];
        }
        if (++lo == 0) {
            hi++;
        }
        for (int i = 0; i < 8; i++) {
            ctr[i] = (hi >> (56 - 8 * i)) & 0xFF;
            ctr[8 + i] = (lo >> (56 - 8 * i)) & 0xFF;
        }
    }
}

/* ---------------------------------------------------------------------- */
/* The loader keysets                                                      */
/* ---------------------------------------------------------------------- */

struct SelfKey {
    const char *erk;   /* 32 bytes, AES-256-CBC key over the root header */
    const char *riv;   /* 16-byte counter block */
};

static const struct SelfKey self_keys[] = {
    { "C0CEFE84C227F75BD07A7EB846509F93B238E770DACB9FF4A388F812482BE21B",
      "47EE7454E4774CC9B8960C7B59F4C14D" },
    { "CA7A24EC38BDB45B98CCD7D363EA2AF0C326E65081E0630CB9AB2D215865878A",
      "F9205F46F6021697E670F13DFA726212" },
    { "B9F3F9E6107CFF2680A91E118C2403CF4A6F18F3C7EFD7D13D1AC4DB760BD222",
      "B43661B9A79BAD9D8E2B046469CDA1E7" },
    { "53ABDF84BE08B0351B734F2B97D2BE1621BC6C889E4362E5C70F39D6C3ED9F23",
      "44E652661AC7584DBE08ECB810FB5FC0" },
    { "48793EBDDA1AF65D737DA2FDA2DD104447A698F8A82CAAEE992831711BA94E83",
      "15DCF3C67147A45D09DE7521EECA07A1" },
    { "5FF17D836E2C4AD69476E2614F64BDD05B9115389A9A6D055B5B544B1C34E3D5",
      "DF0F50EC3C4743C5B17839D7B49F24A4" },
    { "BD0621FA19383C3C72ECBC3B008F1CD55FFD7C3BB7510BF11AD0CF0FC2B70951",
      "569AF3745E1E02E3E288273CDE244CD8" },
    { "41A6E0039041E9D8AAF4EF2F2A2971248EDBD96A3985611ED7B4CE73EE4804FE",
      "C8C98D5A5CE23AF5607A352AECACB0DC" },
    { "557EDF6C063F3272B0D44EEC12F418DA774815B5415597CC5F75C21E048BAD74",
      "7144D7574937818517826227EF4AC0B4" },
    { "10CEA04973FCCC12EC19924510822D8D4C41F657FD3D7E73F415A8D687421BCD",
      "ED8699562C6AC65204FA166257E7FCF4" },
    { "94303F69513572AB5AE17C8C2A1839D2C24C28F65389D3BBB11894CE23E0798F",
      "9769BFD187B90990AE5FEA4E110B9CF5" },
    { "84015E90FA23139628A3C75CC09714E6427B527A82D18ABC3E91CD8D7DDAFF17",
      "5B240444D645F2038118F97FD5A145D5" },
    { "EAE15444048EFDE7A831BFA9F5D96F047C9FCFF50723E292CF50F5417D81E359",
      "9CA9282DC7FA9F315EF3156D970B7CD4" },
    { "88AD367EDEC2FEED3E2F99B1C685075C41BDEC90C84F526CAF588F89BBD1CBCC",
      "8D18E8E525230E63DE10291C9DD615BF" },
    { "688D5FCAC6F4EA35AC6AC79B10506007286131EE038116DB8AA2C0B0340D9FB0",
      "75E0239D18B0B669EAE650972F99726B" },
    { "E81C5B04C29FB079A4A2687A39D4EA97BFB49D80EF546CEB292979A5F77A6254",
      "15058FA7F2CAD7C528B5F605F6444EB0" },
    { "A1E4B86ED02BF7F1372A2C73FE02BC738907EB37CE3BA605FE783C999FAFDB97",
      "BBE7799B9A37CB272E386618FDFD4AEC" },
    { "0CAF212B6FA53C0DA7E2C575ADF61DBE68F34A33433B1B891ABF5C4251406A03",
      "9B79374722AD888EB6A35A2DF25A8B3E" },
    /*
     * The .2 SELF keys, added after the older loader table because those
     * entries are still the common case.  The first pair opens the .2 SPU
     * loader headers (lv1ldr.2, lv2ldr.2, appldr.2, isoldr.2).  The second
     * opens the 0x500-byte lv0.2 record in the CoreOS image, which is signed
     * metadata used by bootldr to check lv0, not a runnable image: its
     * section table points into lv0's body.  lv0.2 is not lv0ldr.2, metldr.2
     * or bootldr.2; those are separate containers with their own key paths.
     */
    { "5B548E7D5B375B9C43C1F1D80B77124BF4C2AE8019F918EEA2A7FC21459FDCA7",
      "3CAF87A6C0039BA20FF026C1C30BD666" },
    { "38417A8AA9E14E485E2BB0058F97D9F24C138CDB2A2EF3C14DF88700CE3AA8CD",
      "081A427E0231CA0C71CDB74805C2B147" },
};

unsigned ps3_self_key_count(void)
{
    return ARRAY_SIZE(self_keys);
}

/* ---------------------------------------------------------------------- */
/* Reading the container                                                   */
/* ---------------------------------------------------------------------- */

static uint32_t self_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t self_be64(const uint8_t *p)
{
    return ((uint64_t)self_be32(p) << 32) | self_be32(p + 4);
}

static bool hex_to_bytes(const char *hex, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;

        if (sscanf(hex + i * 2, "%2x", &v) != 1) {
            return false;
        }
        out[i] = v;
    }
    return true;
}

/*
 * Some carves carry the loader SELFs already unselfed: the section table still
 * says "encrypted" and names key/iv ids, but the bytes are the plaintext image
 * (every word decodes as an instruction, where ciphertext manages a little over
 * half by chance).  Decrypting such a section again turns its code into noise,
 * so decide from the largest section whether this file is one of them and then
 * treat every section the same way: a file that mixed the two would be a repack
 * this path has never seen, and guessing section by section would corrupt the
 * data sections, which never look like code in either reading.
 */
static bool self_sections_are_plaintext(const uint8_t *keys,
                                       const uint8_t *entry,
                                       const uint8_t *data, uint64_t size)
{
    uint8_t probe[4096];
    unsigned raw_known, raw_total, dec_known, dec_total;
    size_t n = MIN(size, sizeof(probe));
    uint32_t key_id = self_be32(entry + 0x24);
    uint32_t iv_id = self_be32(entry + 0x28);

    raw_known = ps3_spu_code_words(data, n, &raw_total);
    memcpy(probe, data, n);
    aes128_ctr(keys + 0x10 * key_id, keys + 0x10 * iv_id, probe, probe, n);
    dec_known = ps3_spu_code_words(probe, n, &dec_total);

    return raw_total && raw_known * 100 >= raw_total * 95 &&
           raw_known >= dec_known;
}

static const struct SelfKey self_app_keys[] = {
    /* application key revision 0x1C, the VSH key for the 4.xx firmware tree */
    { "CFF025375BA0079226BE01F4A31F346D79F62CFB643CA910E16CF60BD9092752",
      "FD40664E2EBBA01BF359B0DCDF543DA4" },
    /* revision 0x1D, used by the later 4.xx application builds */
    { "D202174EB65A62048F3674B59EF6FE72E1872962F3E1CD658DE8D7AF71DA1F3E",
      "ACB9945914EBB7B9A31ECE320AE09F2D" },
};

static bool self_decrypt_tables(uint8_t *img, size_t len,
                                const struct SelfKey *keys, unsigned key_count,
                                char *why, size_t why_len)
{
    uint8_t key[32], iv[16], root[0x40], ctr_iv[16];
    uint32_t meta_offset, section_count;
    uint64_t header_len;
    int opened = -1;

    if (len < 0x200 || memcmp(img, "SCE\0", 4)) {
        snprintf(why, why_len, "not a SCE container");
        return false;
    }

    meta_offset = self_be32(img + 0x0C);
    header_len  = self_be64(img + 0x10);

    if (meta_offset < 0x20 || header_len <= meta_offset ||
        header_len > len || meta_offset + 0xA0 > header_len) {
        snprintf(why, why_len, "metadata at 0x%X/0x%" PRIX64 " does not fit",
                 meta_offset, header_len);
        return false;
    }

    /* 1. The root header: the keyset whose key and iv padding are zero. */
    for (unsigned k = 0; k < key_count; k++) {
        if (!hex_to_bytes(keys[k].erk, key, sizeof(key)) ||
            !hex_to_bytes(keys[k].riv, iv, sizeof(iv))) {
            continue;
        }

        aes256_cbc_decrypt(key, iv, img + meta_offset + 0x20, root,
                           sizeof(root));
        if (memcmp(root + 0x10, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) ||
            memcmp(root + 0x30, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16)) {
            continue;
        }

        memcpy(img + meta_offset + 0x20, root, sizeof(root));
        opened = (int)k;
        break;
    }

    if (opened < 0) {
        snprintf(why, why_len, "no applicable keyset opened the root header "
                 "(%u candidates)", key_count);
        return false;
    }

    /*
     * 2. The certification header and the rest of the metadata, as one
     * continuous counter stream: the loader keeps the counter running across
     * the 0x20-byte header and the section table that follows it.
     */
    memcpy(ctr_iv, img + meta_offset + 0x40, 16);
    aes128_ctr(img + meta_offset + 0x20, ctr_iv,
               img + meta_offset + 0x60, img + meta_offset + 0x60,
               (size_t)(header_len - meta_offset - 0x60));

    section_count = self_be32(img + meta_offset + 0x60 + 0x0C);
    if (section_count > 0x40) {
        snprintf(why, why_len, "section count %u looks wrong", section_count);
        return false;
    }

    /*
     * 3. Is this file already unselfed?  Ask its largest encrypted section.
     */
    {
        uint8_t *key_table = img + meta_offset + 0x80 + 0x30 * section_count;
        uint64_t biggest = 0;
        bool plaintext = false;

        for (unsigned i = 0; i < section_count; i++) {
            uint8_t *entry = img + meta_offset + 0x80 + 0x30 * i;
            uint64_t offset = self_be64(entry);
            uint64_t size = self_be64(entry + 8);

            if (size <= biggest || size < 0x400 ||
                self_be32(entry + 0x24) == 0xFFFFFFFF ||
                self_be32(entry + 0x28) == 0xFFFFFFFF ||
                offset + size > len) {
                continue;
            }

            biggest = size;
            plaintext = self_sections_are_plaintext(key_table, entry,
                                                    img + offset, size);
        }

        if (plaintext) {
            snprintf(why, why_len, "opened with key %d, %u section(s), "
                     "already decrypted (left as is)", opened, section_count);
            return true;
        }
    }

    /*
     * 4. Each section.  The key table sits right after the section table and
     * is indexed by the key/iv ids the section header carries.
     */
    for (unsigned i = 0; i < section_count; i++) {
        uint8_t *entry = img + meta_offset + 0x80 + 0x30 * i;
        uint8_t *key_table = img + meta_offset + 0x80 + 0x30 * section_count;
        uint64_t offset = self_be64(entry);
        uint64_t size = self_be64(entry + 8);
        uint32_t key_id = self_be32(entry + 0x24);
        uint32_t iv_id = self_be32(entry + 0x28);

        if (key_id == 0xFFFFFFFF || iv_id == 0xFFFFFFFF || !size) {
            continue;
        }

        if (offset + size > len) {
            snprintf(why, why_len, "section %u (0x%" PRIX64 "/0x%" PRIX64
                     ") runs past the file", i, offset, size);
            return false;
        }

        aes128_ctr(key_table + 0x10 * key_id, key_table + 0x10 * iv_id,
                   img + offset, img + offset, (size_t)size);
    }

    snprintf(why, why_len, "opened with key %d, %u section(s)",
             opened, section_count);
    return true;
}

bool ps3_self_decrypt(uint8_t *img, size_t len, char *why, size_t why_len)
{
    return self_decrypt_tables(img, len, self_keys,
                               (unsigned)ARRAY_SIZE(self_keys), why, why_len);
}

bool ps3_self_decrypt_app(uint8_t *img, size_t len, char *why, size_t why_len)
{
    return self_decrypt_tables(img, len, self_app_keys,
                               (unsigned)ARRAY_SIZE(self_app_keys), why, why_len);
}

static void bytes_to_hex(const uint8_t *in, size_t n, char *out)
{
    static const char digits[] = "0123456789ABCDEF";

    for (size_t i = 0; i < n; i++) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 15];
    }
    out[n * 2] = 0;
}

/*
 * The .2 loaders do not hold their ERK in the clear: the 32-byte value is the
 * ERK wrapped under the console's per-console root key 2 (PCK2), the same
 * AES-256-CBC shape the HDD key sector uses.  Unwrap it and the following SELF
 * stages have the real per-console ERK they expect.
 */
void ps3_self_unwrap_erk(const uint8_t wrapped[32], const uint8_t pck2[48],
                         uint8_t erk[32])
{
    aes256_cbc_decrypt(pck2, pck2 + 32, wrapped, erk, 32);
}

bool ps3_self_decrypt_pck2(uint8_t *img, size_t len, const uint8_t pck2[48],
                           char *why, size_t why_len)
{
    unsigned count = ps3_self_key_count();
    unsigned first = count > 2 ? count - 2 : 0;   /* the .2 keysets */

    for (unsigned k = first; k < count; k++) {
        uint8_t wrapped[32], erk[32];
        char erk_hex[65], sub[160];
        struct SelfKey key;

        if (!hex_to_bytes(self_keys[k].erk, wrapped, sizeof(wrapped))) {
            continue;
        }

        ps3_self_unwrap_erk(wrapped, pck2, erk);
        bytes_to_hex(erk, sizeof(erk), erk_hex);
        key.erk = erk_hex;
        key.riv = self_keys[k].riv;

        if (self_decrypt_tables(img, len, &key, 1, sub, sizeof(sub))) {
            snprintf(why, why_len, "opened with the ERK unwrapped under "
                     "PCK2 (%s)", sub);
            return true;
        }
    }

    snprintf(why, why_len, "the ERK unwrapped under PCK2 opened no .2 "
             "keyset");
    return false;
}

bool ps3_self_decrypt_key(uint8_t *img, size_t len, const char *erk,
                          const char *riv, char *why, size_t why_len)
{
    const struct SelfKey key = { erk, riv };

    if (!erk || !riv || strlen(erk) != 64 || strlen(riv) != 32) {
        snprintf(why, why_len, "the explicit key must be 64 ERK and 32 RIV "
                 "hex digits");
        return false;
    }

    return self_decrypt_tables(img, len, &key, 1, why, why_len);
}

int ps3_self_load_ls(uint8_t *img, size_t len, uint8_t *ls, size_t ls_size,
                     uint32_t *entry_out, unsigned *segments, char *why,
                     size_t why_len)
{
    const uint8_t *elf = NULL;
    uint32_t entry, phnum, phoff, file_offset;
    unsigned loaded = 0;

    if (len < 0x200 || memcmp(img, "SCE\0", 4)) {
        snprintf(why, why_len, "not a SCE container");
        return 2;
    }

    if (!ps3_self_decrypt(img, len, why, why_len)) {
        return 1;
    }

    file_offset = (uint32_t)self_be64(img + 0x10);

    for (size_t i = 0x20; i + 0x40 < MIN(len, (size_t)0x400); i += 4) {
        if (!memcmp(img + i, "\177ELF", 4)) {
            elf = img + i;
            break;
        }
    }

    if (!elf) {
        snprintf(why, why_len, "no ELF header inside the SELF");
        return 2;
    }

    /*
     * The extended header names the program header table (0x38) and the
     * encapsulated file starts at header_len, so p_offset is relative to it.
     * The table's entry size follows the ELF class: 0x20 for the 32-bit form,
     * 0x38 for the 64-bit one.
     */
    phoff = (uint32_t)self_be64(img + 0x38);
    {
        bool wide = elf[4] == 2;
        uint32_t entsize = wide ? 0x38 : 0x20;

        phnum = wide ? ((elf[0x38] << 8) | elf[0x39])
                     : ((elf[0x2C] << 8) | elf[0x2D]);

        if (!phoff || phnum > 0x20 ||
            (uint64_t)phoff + (uint64_t)entsize * phnum > len) {
            snprintf(why, why_len, "program header table 0x%X/%u does not fit",
                     phoff, phnum);
            return 2;
        }

        entry = wide ? (uint32_t)self_be64(elf + 0x18) : self_be32(elf + 0x18);

        for (unsigned i = 0; i < phnum; i++) {
            const uint8_t *p = img + phoff + (size_t)entsize * i;
            uint32_t type = self_be32(p);
            uint32_t p_off = wide ? (uint32_t)self_be64(p + 8)
                                  : self_be32(p + 4);
            uint32_t vaddr = wide ? (uint32_t)self_be64(p + 0x10)
                                  : self_be32(p + 8);
            uint32_t filesz = wide ? (uint32_t)self_be64(p + 0x20)
                                   : self_be32(p + 16);
            uint32_t memsz = wide ? (uint32_t)self_be64(p + 0x28)
                                  : self_be32(p + 20);

            if (type != 1) {
                continue;
            }
            if ((uint64_t)vaddr + memsz > ls_size ||
                (filesz && (uint64_t)file_offset + p_off + filesz > len)) {
                snprintf(why, why_len, "segment %u (0x%X/0x%X) does not fit",
                         i, vaddr, memsz);
                return 3;
            }

            memset(ls + vaddr, 0, memsz);
            if (filesz) {
                memcpy(ls + vaddr, img + file_offset + p_off, filesz);
            }
            loaded++;
        }
    }

    *entry_out = entry;
    if (segments) {
        *segments = loaded;
    }
    return 0;
}
