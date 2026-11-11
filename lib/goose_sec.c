/*
 * goose_sec.c - shared helpers for the Banerjee baseline implementation.
 * Pure C99, no libIEC61850 dependency, so it can be unit-tested on a PC.
 */
#include "goose_sec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

const uint8_t GS_KEY[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c   /* FIPS 197 App. B key, test use only */
};

volatile int gs_last_frame_size = 0;
volatile uint64_t gs_dbg[16];

/* ------------------------------------------------------------------------ */
/* configuration                                                             */
/* ------------------------------------------------------------------------ */
static int         s_init   = 0;
static gs_scheme_t s_scheme = GS_NONE;
static gs_replay_t s_replay = GS_REPLAY_NONE;
static int         s_iv_len = 16;

void gs_init(void)
{
    const char* e;
    if (s_init) return;
    s_init = 1;

    e = getenv("GOOSE_SCHEME");
    if (e && *e) {
        if (strcasecmp(e, "banerjee") == 0)      s_scheme = GS_BANERJEE;
        else if (strcasecmp(e, "proposed") == 0)
            fprintf(stderr, "goose_sec: the proposed scheme is not part of this build; using none\n");
        else if (strcasecmp(e, "none") == 0)     s_scheme = GS_NONE;
        else fprintf(stderr, "goose_sec: unknown GOOSE_SCHEME '%s', using none\n", e);
    }
    e = getenv("GOOSE_BANERJEE_REPLAY");
    if (e && strcasecmp(e, "strict") == 0) s_replay = GS_REPLAY_STRICT;

    e = getenv("GOOSE_IV_LEN");
    if (e && atoi(e) == 20) s_iv_len = 20;
}

gs_scheme_t gs_scheme(void)          { gs_init(); return s_scheme; }
gs_replay_t gs_banerjee_replay(void) { gs_init(); return s_replay; }
int         gs_iv_len(void)          { gs_init(); return s_iv_len; }

const char* gs_scheme_name(void)
{
    switch (gs_scheme()) {
    case GS_BANERJEE: return "banerjee";
    default:          return "none";
    }
}

/* ------------------------------------------------------------------------ */
/* BER helpers                                                               */
/* ------------------------------------------------------------------------ */
int gs_ber_tl(const uint8_t* p, int avail, int* hdr, int* len)
{
    if (avail < 2) return -1;
    if (p[1] < 0x80)                    { *hdr = 2; *len = p[1]; }
    else if (p[1] == 0x81 && avail >= 3) { *hdr = 3; *len = p[2]; }
    else if (p[1] == 0x82 && avail >= 4) { *hdr = 4; *len = (p[2] << 8) | p[3]; }
    else return -1;
    if (*hdr + *len > avail) return -1;
    return 0;
}

int gs_ber_put_len(uint8_t* out, int len)
{
    if (len < 0x80)  { out[0] = (uint8_t)len; return 1; }
    if (len < 0x100) { out[0] = 0x81; out[1] = (uint8_t)len; return 2; }
    out[0] = 0x82; out[1] = (uint8_t)(len >> 8); out[2] = (uint8_t)len;
    return 3;
}

/* minimal two's-complement BER integer value bytes, no tag/length */
static int ber_uint32_value(uint8_t* buf, uint32_t v)
{
    uint8_t tmp[4];
    int s = 0, n = 0, i;
    if (v == 0) { buf[0] = 0; return 1; }
    tmp[0] = (uint8_t)(v >> 24); tmp[1] = (uint8_t)(v >> 16);
    tmp[2] = (uint8_t)(v >> 8);  tmp[3] = (uint8_t)v;
    while (s < 3 && tmp[s] == 0) s++;
    if (tmp[s] & 0x80) buf[n++] = 0x00;
    for (i = s; i < 4; i++) buf[n++] = tmp[i];
    return n;
}

/* ------------------------------------------------------------------------ */
/* nonces                                                                    */
/* ------------------------------------------------------------------------ */
void gs_nonce_ber(uint8_t n[16], uint32_t st, uint32_t sq, const uint8_t t[8])
{
    uint8_t tmp[5];
    int np = 0, k, ts;
    memset(n, 0, 16);
    k = ber_uint32_value(tmp, st); memcpy(n + np, tmp, (size_t)k); np += k;
    k = ber_uint32_value(tmp, sq); memcpy(n + np, tmp, (size_t)k); np += k;
    ts = 16 - np; if (ts > 8) ts = 8;
    if (ts > 0) memcpy(n + np, t, (size_t)ts);
}

/* ------------------------------------------------------------------------ */
/* security extension                                                        */
/* ------------------------------------------------------------------------ */
int gs_ext_len(int iv_len)
{
    /* AV TLV: 2 + (3 + 6 + 4 + (2+iv) + 4) ; MAC TLV: 2 + 16 */
    return 2 + (3 + 6 + 4 + (2 + iv_len) + 4) + 2 + 16;
}

int gs_build_ext(uint8_t* ext, int iv_len, const uint8_t nonce[16], const uint8_t tag[16])
{
    int ep = 0, av_len_off, av_start;
    ext[ep++] = 0x80;
    av_len_off = ep++;
    av_start = ep;

    ext[ep++] = 0xA0; ext[ep++] = 0x01; ext[ep++] = 0x01;                 /* version        */
    ext[ep++] = 0xA1; ext[ep++] = 0x04;                                   /* time of cur key*/
    ext[ep++] = 0; ext[ep++] = 0; ext[ep++] = 0; ext[ep++] = 0;
    ext[ep++] = 0xA2; ext[ep++] = 0x02; ext[ep++] = 0; ext[ep++] = 0;     /* time of next   */
    ext[ep++] = 0xA3; ext[ep++] = (uint8_t)iv_len;                        /* IV / nonce     */
    memcpy(ext + ep, nonce, 16); ep += 16;
    if (iv_len > 16) { memset(ext + ep, 0, (size_t)(iv_len - 16)); ep += iv_len - 16; }
    ext[ep++] = 0xA4; ext[ep++] = 0x02; ext[ep++] = 0x00; ext[ep++] = 0x01; /* key id        */

    ext[av_len_off] = (uint8_t)(ep - av_start);

    ext[ep++] = 0x81; ext[ep++] = 0x10;                                   /* MAC            */
    memcpy(ext + ep, tag, 16); ep += 16;
    return ep;
}

int gs_parse_ext(const uint8_t* sec, int avail,
                 const uint8_t** av_tlv, int* av_tlv_len,
                 const uint8_t** iv, int* iv_len, const uint8_t** mac)
{
    int av_inner, pos = 0, mac_off;
    const uint8_t* av;
    *iv = NULL; *iv_len = 0;
    if (avail < 2 || sec[0] != 0x80) return -1;
    av_inner = sec[1];
    if (av_inner >= 0x80 || 2 + av_inner + 18 > avail) return -1;
    av = sec + 2;
    while (pos + 2 <= av_inner) {
        uint8_t st = av[pos]; int sl = av[pos + 1];
        pos += 2;
        if (pos + sl > av_inner) return -1;
        if (st == 0xA3) { *iv = av + pos; *iv_len = sl; }
        pos += sl;
    }
    if (*iv == NULL || *iv_len < 16) return -1;
    mac_off = 2 + av_inner;
    if (sec[mac_off] != 0x81 || sec[mac_off + 1] != 16) return -1;
    *av_tlv = sec;
    *av_tlv_len = 2 + av_inner;
    *mac = sec + mac_off + 2;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* receive log: single producer (receiver thread) / single consumer (app)    */
/* ------------------------------------------------------------------------ */
#define GS_LOG_SIZE (1u << 18)
static gs_rec_t          s_log[GS_LOG_SIZE];
static volatile uint32_t s_head = 0, s_tail = 0;
static volatile uint64_t s_dropped = 0;

void gs_log_push(const gs_rec_t* r)
{
    uint32_t h = s_head;
    if ((uint32_t)(h - s_tail) >= GS_LOG_SIZE) { s_dropped++; return; }
    s_log[h & (GS_LOG_SIZE - 1)] = *r;
    __sync_synchronize();
    s_head = h + 1;
}

int gs_log_pop(gs_rec_t* r)
{
    uint32_t t = s_tail;
    if (t == s_head) return 0;
    __sync_synchronize();
    *r = s_log[t & (GS_LOG_SIZE - 1)];
    __sync_synchronize();
    s_tail = t + 1;
    return 1;
}

uint64_t gs_log_dropped(void) { return s_dropped; }
