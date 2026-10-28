/*
 * Seal (or open) a PS3 image's storage area with the model's own XTS layer.
 *
 * It sits beside the two files it shares with qemu-system-ppc64 - aes.c and
 * ps3_aes.c - and is compiled from them by scripts/ps3_emmc_create.py, so the
 * bytes this writes are the bytes the model's ps3_xts_crypt_sector reads back.
 * The keys are the console's: its 48-byte EID root key (PCK1, 32 key + 16 IV)
 * through the published encdec seeds, which is ps3_encdec_keys() and the ladder
 * lv1ldr runs.
 *
 *   ps3_encdec <image> <offset> <length> <erk-file|-> [decrypt]
 *
 * `offset` and `length` must be 512-byte aligned.  The tweak starts from
 * offset / 512, the sector's position in the image, which is what the model
 * folds into it.  `-` reads the 48-byte key from stdin, so a caller can hand
 * it over without putting it in a file.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#include "ps3_aes.h"

#define SECTOR 512u
#define CHUNK  (1024u * 1024u)          /* 2048 sectors per pass */

static int read_key(const char *path, uint8_t erk[48])
{
    FILE *f = !strcmp(path, "-") ? stdin : fopen(path, "rb");
    size_t n;

    if (!f) {
        fprintf(stderr, "ps3_encdec: cannot open %s: %s\n", strcmp(path, "-") ?
                path : "stdin", strerror(errno));
        return -1;
    }

    n = fread(erk, 1, 48, f);
    if (f != stdin) {
        fclose(f);
    }
    if (n != 48) {
        fprintf(stderr, "ps3_encdec: %s holds %zu byte(s), not 48\n",
                strcmp(path, "-") ? path : "stdin", n);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *path, *key_path;
    uint64_t off, len, done;
    uint8_t erk[48], data_key[32], tweak_key[32];
    uint8_t *buf;
    FILE *f;
    bool encrypt = true;

#ifdef _WIN32
    /* The key comes in over stdin, which the CRT would otherwise treat as
     * text: 0x1A would end it early and CRLF pairs would be folded. */
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif

    if (argc < 5) {
        fprintf(stderr, "usage: %s <image> <offset> <length> <erk-file|-> "
                        "[decrypt]\n", argv[0]);
        return 2;
    }

    path = argv[1];
    off = strtoull(argv[2], NULL, 0);
    len = strtoull(argv[3], NULL, 0);
    key_path = argv[4];
    if (argc > 5 && !strcmp(argv[5], "decrypt")) {
        encrypt = false;
    }

    if ((off % SECTOR) || (len % SECTOR)) {
        fprintf(stderr, "ps3_encdec: offset 0x%llx and length 0x%llx must be "
                        "512-byte aligned\n",
                (unsigned long long)off, (unsigned long long)len);
        return 2;
    }
    if (!len) {
        return 0;
    }
    if (read_key(key_path, erk)) {
        return 2;
    }

    ps3_encdec_keys(erk, data_key, tweak_key);

    f = fopen(path, "r+b");
    if (!f) {
        fprintf(stderr, "ps3_encdec: cannot open %s: %s\n", path,
                strerror(errno));
        return 2;
    }
    buf = malloc(CHUNK);
    if (!buf) {
        fclose(f);
        return 2;
    }

    for (done = 0; done < len; done += CHUNK) {
        size_t n = (len - done) < CHUNK ? (size_t)(len - done) : CHUNK;
        size_t i;

        if (fseeko(f, (off_t)(off + done), SEEK_SET) != 0 ||
            fread(buf, 1, n, f) != n) {
            fprintf(stderr, "ps3_encdec: cannot read 0x%llx bytes at 0x%llx\n",
                    (unsigned long long)n, (unsigned long long)(off + done));
            free(buf);
            fclose(f);
            return 2;
        }

        for (i = 0; i < n; i += SECTOR) {
            ps3_xts_crypt_sector(data_key, tweak_key,
                                 (off + done + i) / SECTOR, buf + i, SECTOR,
                                 encrypt);
        }

        if (fseeko(f, (off_t)(off + done), SEEK_SET) != 0 ||
            fwrite(buf, 1, n, f) != n) {
            fprintf(stderr, "ps3_encdec: cannot write 0x%llx bytes at 0x%llx\n",
                    (unsigned long long)n, (unsigned long long)(off + done));
            free(buf);
            fclose(f);
            return 2;
        }
    }

    free(buf);
    fclose(f);
    printf("%s 0x%llx byte(s) at 0x%llx (sector 0x%llx)\n",
           encrypt ? "sealed" : "opened",
           (unsigned long long)len, (unsigned long long)off,
           (unsigned long long)(off / SECTOR));
    return 0;
}
