/*
 * ascon_bench.c - pure cipher cost, no networking.
 *
 * Built once per Ascon variant by build.sh against that variant's reference
 * code (they all export the same crypto_aead_encrypt/decrypt symbols, so each
 * variant is its own binary). Answers directly: how much of any latency
 * difference can the ASCON VARIANT explain?
 *
 * Reports median / mean ns per call for message lengths covering both schemes:
 *   5..40  small messages (reference points)
 *   176    the libIEC61850 sample PDU - Banerjee encrypts the whole PDU
 *   245, 512, 1024
 *
 *   ./ascon_bench_<variant> [iterations]      (default 200000)
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sched.h>

#include "api.h"       /* CRYPTO_KEYBYTES / NSECBYTES / NPUBBYTES / ABYTES of the linked variant */

extern int crypto_aead_encrypt(unsigned char*, unsigned long long*, const unsigned char*,
                               unsigned long long, const unsigned char*, unsigned long long,
                               const unsigned char*, const unsigned char*, const unsigned char*);
extern int crypto_aead_decrypt(unsigned char*, unsigned long long*, unsigned char*,
                               const unsigned char*, unsigned long long, const unsigned char*,
                               unsigned long long, const unsigned char*, const unsigned char*);

static uint64_t now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t) t.tv_sec * 1000000000ULL + (uint64_t) t.tv_nsec;
}

static int cmp_u(const void* a, const void* b)
{
    uint64_t x = *(const uint64_t*) a, y = *(const uint64_t*) b;
    return (x > y) - (x < y);
}

int main(int argc, char** argv)
{
    static const int lens[] = {5, 20, 40, 176, 245, 512, 1024};
    int iters = argc > 1 ? atoi(argv[1]) : 200000;
    unsigned char key[CRYPTO_KEYBYTES], npub[CRYPTO_NPUBBYTES];
    unsigned char ad[48], msg[1100], ct[1200], pt[1200];
    uint64_t* s = malloc((size_t) iters * sizeof(uint64_t));
    size_t li;
    cpu_set_t set;

    CPU_ZERO(&set); CPU_SET(3, &set);
    sched_setaffinity(0, sizeof(set), &set);

    memset(key, 0x2b, sizeof key);
    memset(npub, 0x11, sizeof npub);
    memset(ad, 0x55, sizeof ad);
    memset(msg, 0xA5, sizeof msg);

    printf("variant: key=%d nonce=%d tag=%d bytes   (%d iterations per length)\n",
           CRYPTO_KEYBYTES, CRYPTO_NPUBBYTES, CRYPTO_ABYTES, iters);
    printf("%8s  %14s  %14s  %14s  %14s\n", "len", "enc median ns", "enc mean ns", "dec median ns", "dec mean ns");

    for (li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
        int L = lens[li], i;
        unsigned long long clen = 0, plen = 0;
        double mean_e, mean_d;
        uint64_t med_e, med_d, sum;

        for (i = 0; i < 2000; i++) crypto_aead_encrypt(ct, &clen, msg, (unsigned long long) L, ad, 48, NULL, npub, key);

        sum = 0;
        for (i = 0; i < iters; i++) {
            uint64_t a = now_ns();
            crypto_aead_encrypt(ct, &clen, msg, (unsigned long long) L, ad, 48, NULL, npub, key);
            s[i] = now_ns() - a; sum += s[i];
        }
        qsort(s, (size_t) iters, sizeof(uint64_t), cmp_u);
        med_e = s[iters / 2]; mean_e = (double) sum / iters;

        sum = 0;
        for (i = 0; i < iters; i++) {
            uint64_t a = now_ns();
            crypto_aead_decrypt(pt, &plen, NULL, ct, clen, ad, 48, npub, key);
            s[i] = now_ns() - a; sum += s[i];
        }
        qsort(s, (size_t) iters, sizeof(uint64_t), cmp_u);
        med_d = s[iters / 2]; mean_d = (double) sum / iters;

        printf("%8d  %14llu  %14.1f  %14llu  %14.1f\n", L,
               (unsigned long long) med_e, mean_e, (unsigned long long) med_d, mean_d);
    }
    free(s);
    return 0;
}
