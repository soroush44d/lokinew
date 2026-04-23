#include "loki97.h"
#include <stdio.h>
#include <string.h>

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *hex, BYTE *out, int out_len)
{
    int i;
    for (i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i] = (BYTE)((hi << 4) | lo);
    }
    return 1;
}

static int diff_count(const BYTE *a, const BYTE *b, int len)
{
    int i;
    int diff = 0;
    for (i = 0; i < len; i++) {
        if (a[i] != b[i]) {
            diff++;
        }
    }
    return diff;
}

int main(void)
{
    static const char *key_hex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    static const char *plain0_hex = "00000000000000000000000000000000";
    static const char *plain1_hex = "FF000000000000000000000000000000";

    BYTE plain0[BLOCK_SIZE], plain1[BLOCK_SIZE];
    BYTE out[BLOCK_SIZE];
    BYTE s1_a[0x2000], s2_a[0x800], p_a[0x100];
    BYTE s1_b[0x2000], s2_b[0x800], p_b[0x100];

    cipherInstance cipher;
    keyInstance key;
    int st;

    if (!parse_hex(plain0_hex, plain0, BLOCK_SIZE) || !parse_hex(plain1_hex, plain1, BLOCK_SIZE)) {
        printf("hex parse error\n");
        return 1;
    }

    st = cipherInit(&cipher, MODE_ECB, NULL);
    if (st != TRUE) {
        printf("cipherInit failed: %d\n", st);
        return 1;
    }

    st = makeKey(&key, DIR_ENCRYPT, 256, (char *)key_hex);
    if (st != TRUE) {
        printf("makeKey failed: %d\n", st);
        return 1;
    }

    loki97_sc_reset();
    st = blockEncrypt(&cipher, &key, plain0, BLOCK_SIZE * 8, out);
    if (st != TRUE) {
        printf("encrypt plain0 failed: %d\n", st);
        return 1;
    }
    loki97_sc_snapshot(s1_a, s2_a, p_a);

    loki97_sc_reset();
    st = blockEncrypt(&cipher, &key, plain1, BLOCK_SIZE * 8, out);
    if (st != TRUE) {
        printf("encrypt plain1 failed: %d\n", st);
        return 1;
    }
    loki97_sc_snapshot(s1_b, s2_b, p_b);

    printf("trace diff S1=%d S2=%d P=%d\n",
           diff_count(s1_a, s1_b, (int)sizeof(s1_a)),
           diff_count(s2_a, s2_b, (int)sizeof(s2_a)),
           diff_count(p_a, p_b, (int)sizeof(p_a)));

    return 0;
}
