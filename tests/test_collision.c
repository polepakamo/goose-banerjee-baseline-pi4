/*
 * test_collision.c - what the ASSUMED baseline nonce costs, shown with the real
 * Ascon-AEAD128. Needs the Ascon objects, so build.sh builds it on the Pi:
 *
 *   gcc -O2 -Ilib -Ithird_party/ascon/asconaead128 tests/test_collision.c lib/goose_sec.c build/ascon_*.o
 *
 * Two different GOOSE states, (stNum=1, sqNum=512) and (stNum=258, sqNum=0), carry
 * different breaker commands. With the BER-concatenated nonce they get the SAME nonce;
 * with identical key and AAD the keystream of the first block is then identical and
 * C1 xor C2 == P1 xor P2, which leaks the plaintext relation without any key.
 *
 * IMPORTANT for the paper: the Banerjee paper does not state how its nonce is built.
 * This is a property of the nonce ASSUMED here, not a statement about their code.
 */
#include "goose_sec.h"
#include <stdio.h>
#include <string.h>

extern int crypto_aead_encrypt(unsigned char*, unsigned long long*, const unsigned char*,
                               unsigned long long, const unsigned char*, unsigned long long,
                               const unsigned char*, const unsigned char*, const unsigned char*);

int main(void)
{
    const uint8_t t[8] = {0x66, 0x1a, 0x2b, 0x3c, 0x00, 0x00, 0x00, 0x18};
    const uint8_t m1[20] = "BRK:OPEN-----------";
    const uint8_t m2[20] = "BRK:CLOSE----------";
    uint8_t na[16], nb[16], ad[16], c1[64], c2[64];
    unsigned long long l1, l2;
    int same, leak = 1, i;

    gs_nonce_ber(na, 1, 512, t);
    gs_nonce_ber(nb, 258, 0, t);
    same = memcmp(na, nb, 16) == 0;

    memset(ad, 0x42, sizeof ad);
    crypto_aead_encrypt(c1, &l1, m1, 20, ad, sizeof ad, NULL, na, GS_KEY);
    crypto_aead_encrypt(c2, &l2, m2, 20, ad, sizeof ad, NULL, nb, GS_KEY);
    /* first block only: later blocks absorb plaintext into the state */
    for (i = 0; i < 8; i++)
        if ((uint8_t)(c1[i] ^ c2[i]) != (uint8_t)(m1[i] ^ m2[i])) leak = 0;

    printf("assumed BER nonce: identical for (1,512) and (258,0): %s\n", same ? "YES" : "no");
    printf("C1^C2 == P1^P2 over the first block (keystream reuse): %s\n", leak ? "YES" : "no");
    printf(same && leak ? "PASS (property of the assumed nonce demonstrated)\n" : "FAIL\n");
    return same && leak ? 0 : 1;
}
