#include "loki97.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    BYTE plain[BLOCK_SIZE] = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };
    BYTE enc[BLOCK_SIZE], dec[BLOCK_SIZE];
    keyInstance enc_key, dec_key;
    cipherInstance cipher;
    char key_hex[] = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    int st;

    st = cipherInit(&cipher, MODE_ECB, NULL);
    if (st != TRUE) return 1;

    st = makeKey(&enc_key, DIR_ENCRYPT, 256, key_hex);
    if (st != TRUE) return 2;
    st = blockEncrypt(&cipher, &enc_key, plain, BLOCK_SIZE * 8, enc);
    if (st != TRUE) return 3;

    st = makeKey(&dec_key, DIR_DECRYPT, 256, key_hex);
    if (st != TRUE) return 4;
    st = blockDecrypt(&cipher, &dec_key, enc, BLOCK_SIZE * 8, dec);
    if (st != TRUE) return 5;

    if (memcmp(plain, dec, BLOCK_SIZE) != 0) {
        printf("roundtrip mismatch\n");
        return 6;
    }

    printf("roundtrip ok\n");
    return 0;
}
