/*
 * goose_sec.h - shared helpers for the Banerjee & Banerjee baseline implementation.
 *
 * Scheme selected at run time with GOOSE_SCHEME:
 *
 *   none      stock libIEC61850 GOOSE (no security extension) - the reference run
 *   banerjee  Banerjee & Banerjee (IEEE FNWF 2025) AS DESCRIBED IN THEIR PAPER:
 *               - the whole PDU value is encrypted with Ascon-AEAD128 (NIST SP 800-232)
 *               - AAD = EtherType | AppID | Length | Res1 | Res2 | Authentication Value TLV
 *                 (their Fig. 5)
 *               - IEC 62351-6 extension: Authentication Value (version, key times,
 *                 Initialization Vector, key id) + MAC (their Fig. 3);
 *                 nonce travels in the IV field, tag in the MAC field
 *               - the subscriber decrypts the whole PDU BEFORE parsing it
 *             The paper does NOT say how the nonce is built or whether a replay filter
 *             exists, so those two points are explicit ASSUMPTIONS:
 *               nonce  = BER(stNum) | BER(sqNum) | timestamp, zero padded to 16 bytes
 *               replay = none  (GOOSE_BANERJEE_REPLAY=strict adds an sqNum == last+1
 *                              filter, used only by the security tests)
 *
 * The proposed scheme is deliberately NOT part of this code base; it is added later
 * as a separate step.
 */
#ifndef GOOSE_SEC_H_
#define GOOSE_SEC_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { GS_NONE = 0, GS_BANERJEE = 1 } gs_scheme_t;
typedef enum { GS_REPLAY_NONE = 0, GS_REPLAY_STRICT = 1 } gs_replay_t;

/* verdicts recorded per received frame */
enum { GS_V_DELIVERED = 0, GS_V_REJ_AUTH = 1, GS_V_REJ_REPLAY = 2, GS_V_REJ_PARSE = 3 };

/* ---- configuration (read once from the environment) -------------------- */
void         gs_init(void);
gs_scheme_t  gs_scheme(void);          /* GOOSE_SCHEME = none|banerjee                */
gs_replay_t  gs_banerjee_replay(void); /* GOOSE_BANERJEE_REPLAY = none|strict          */
int          gs_iv_len(void);          /* GOOSE_IV_LEN = 16 (default) or 20            */
const char*  gs_scheme_name(void);

extern const uint8_t GS_KEY[16];       /* fixed test key; real key via IEC 62351-9     */

#define GS_AAD_MAX 1600

/* ---- BER helpers -------------------------------------------------------- */
/* p points at a TAG byte. Fills header length (tag+length bytes) and value length. */
int gs_ber_tl(const uint8_t* p, int avail, int* hdr, int* len);
/* encode a BER length, returns bytes written */
int gs_ber_put_len(uint8_t* out, int len);

/* ---- baseline nonce (ASSUMPTION, see above) -------------------------------
 * BER(stNum) | BER(sqNum) | timestamp, zero padded to 16 bytes.
 * Variable-length fields without separators: distinct (stNum, sqNum) pairs can
 * give identical nonces, e.g. (1,512) and (258,0). */
void gs_nonce_ber(uint8_t n[16], uint32_t st, uint32_t sq, const uint8_t t[8]);

/* ---- IEC 62351-6 style security extension -------------------------------
 *   [0x80][AVlen] [A0 01 ver] [A1 04 ToCK] [A2 02 ToNK] [A3 ivlen IV] [A4 02 keyID]
 *   [0x81][16] tag
 * extension bytes = 39 + iv_len  (55 for a 16-byte IV, 59 for a 20-byte IV)      */
int gs_ext_len(int iv_len);
int gs_build_ext(uint8_t* ext, int iv_len, const uint8_t nonce[16], const uint8_t tag[16]);
/* returns 0 on success; pointers refer into sec */
int gs_parse_ext(const uint8_t* sec, int avail,
                 const uint8_t** av_tlv, int* av_tlv_len,
                 const uint8_t** iv, int* iv_len, const uint8_t** mac);

/* ---- per-frame receive log (lock-free SPSC ring) ------------------------- */
typedef struct {
    uint64_t t_proc_ns;   /* from after select() to delivery/reject (this frame) */
    uint32_t st, sq;
    uint32_t frame_len;
    uint32_t verdict;
} gs_rec_t;

void     gs_log_push(const gs_rec_t* r);   /* receiver thread */
int      gs_log_pop(gs_rec_t* r);          /* application thread; 1 if a record was read */
uint64_t gs_log_dropped(void);             /* records lost because the app was too slow */

/* ---- receiver stage counters (diagnostics, receiver thread writes, application reads)
 * 0 tick calls   1 packets read   2 parseGooseMessage entered   3 too short   4 not GOOSE ethertype
 * 5 bad length   6 no matching subscriber   7 subscriber matched   8 select ready   9 select timeout
 * 10 select error   11 numbytes at bad length   12 length field   13 header length   14 appId at no-match */
extern volatile uint64_t gs_dbg[16];

/* ---- publisher export ----------------------------------------------------- */
extern volatile int gs_last_frame_size;    /* bytes of the last frame handed to the NIC */

#ifdef __cplusplus
}
#endif
#endif
