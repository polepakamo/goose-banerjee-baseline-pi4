/* test_sec.c - host-side unit tests for goose_sec.c (no libIEC61850, no Ascon needed).
 *   gcc -std=c99 -O2 -I../lib test_sec.c ../lib/goose_sec.c -o test_sec && ./test_sec
 */
#include "goose_sec.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)

static void test_nonce(void)
{
    uint8_t a[16], b[16], c[16], d[16], e[16];
    const uint8_t t[8] = {1,2,3,4,5,6,7,8};

    /* the assumed baseline nonce is deterministic ... */
    gs_nonce_ber(a, 7, 3, t);
    gs_nonce_ber(b, 7, 3, t);
    CHECK(memcmp(a, b, 16) == 0);
    /* ... layout: BER(7)=07, BER(3)=03, then the timestamp, zero padded */
    CHECK(a[0] == 0x07 && a[1] == 0x03 && a[2] == 1 && a[9] == 8 && a[10] == 0);
    /* a value with the top bit set needs a leading 0x00 in BER */
    gs_nonce_ber(e, 128, 0, t);
    CHECK(e[0] == 0x00 && e[1] == 0x80 && e[2] == 0x00 && e[3] == 1);

    /* the assumed nonce collides for different counters (documented property of the assumption) */
    gs_nonce_ber(a, 1, 512, t);
    gs_nonce_ber(b, 258, 0, t);
    CHECK(memcmp(a, b, 16) == 0);
    gs_nonce_ber(c, 1, 257, t);
    gs_nonce_ber(d, 257, 1, t);
    CHECK(memcmp(c, d, 16) == 0);
    /* and distinguishes counters whose encodings differ */
    gs_nonce_ber(a, 1, 2, t);
    gs_nonce_ber(b, 2, 1, t);
    CHECK(memcmp(a, b, 16) != 0);
}

static void test_ext(void)
{
    uint8_t nonce[16], tag[16], ext[128];
    const uint8_t *av, *iv, *mac;
    int avl, ivl, n, k;
    for (k = 0; k < 16; k++) { nonce[k] = (uint8_t)k; tag[k] = (uint8_t)(0xA0 + k); }

    n = gs_build_ext(ext, 16, nonce, tag);
    CHECK(n == 55 && n == gs_ext_len(16));
    CHECK(gs_parse_ext(ext, n, &av, &avl, &iv, &ivl, &mac) == 0);
    CHECK(ivl == 16 && memcmp(iv, nonce, 16) == 0 && memcmp(mac, tag, 16) == 0);
    CHECK(avl == 37 && av == ext);

    n = gs_build_ext(ext, 20, nonce, tag);
    CHECK(n == 59 && n == gs_ext_len(20));
    CHECK(gs_parse_ext(ext, n, &av, &avl, &iv, &ivl, &mac) == 0);
    CHECK(ivl == 20 && memcmp(iv, nonce, 16) == 0 && memcmp(mac, tag, 16) == 0);

    /* truncated extension must be rejected */
    CHECK(gs_parse_ext(ext, n - 5, &av, &avl, &iv, &ivl, &mac) != 0);
}

static void test_ber(void)
{
    uint8_t b[8]; int h, l;
    const uint8_t a[] = {0x61, 0x03, 1, 2, 3};
    const uint8_t c[] = {0x61, 0x81, 0xB0};
    CHECK(gs_ber_tl(a, 5, &h, &l) == 0 && h == 2 && l == 3);
    CHECK(gs_ber_tl(a, 4, &h, &l) != 0);               /* value would overrun */
    CHECK(gs_ber_tl(c, 3, &h, &l) != 0);               /* 176 bytes missing   */
    CHECK(gs_ber_put_len(b, 5) == 1 && b[0] == 5);
    CHECK(gs_ber_put_len(b, 200) == 2 && b[0] == 0x81 && b[1] == 200);
    CHECK(gs_ber_put_len(b, 300) == 3 && b[0] == 0x82 && b[1] == 1 && b[2] == 44);
}

static void test_log(void)
{
    gs_rec_t r, o; int i;
    memset(&r, 0, sizeof r);
    for (i = 0; i < 1000; i++) { r.st = (uint32_t)i; gs_log_push(&r); }
    for (i = 0; i < 1000; i++) { CHECK(gs_log_pop(&o) == 1 && o.st == (uint32_t)i); }
    CHECK(gs_log_pop(&o) == 0);
    CHECK(gs_log_dropped() == 0);
}

int main(void)
{
    test_nonce(); test_ext(); test_ber(); test_log();
    if (fails) { printf("%d check(s) FAILED\n", fails); return 1; }
    printf("all goose_sec tests passed\n");
    return 0;
}
