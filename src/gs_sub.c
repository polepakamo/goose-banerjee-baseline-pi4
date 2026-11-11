/*
 * gs_sub.c - subscriber for the Banerjee baseline (GOOSE_SCHEME = none | banerjee).
 *
 * Uses the threaded libIEC61850 receiver (GooseReceiver_start), as the stock
 * sample subscriber does. The receiver thread (lib/goose_receiver.c) writes one
 * record per received frame into a lock-free ring; this program drains the ring
 * and writes every record to CSV, so no frame is missed or counted twice.
 *
 *   T_proc = from immediately after select() returns, to immediately after the
 *            subscriber callback returns (or to the reject point).
 *
 * Usage: sudo -E ./gs_sub <iface> [options]
 *   --count N         delivered frames to measure after warm-up   (default 50000)
 *   --warmup N        delivered frames to discard                 (default 1000)
 *   --duration S      run for S seconds instead of a frame count (security tests)
 *   --idle-timeout S  stop after S seconds without any frame      (default 8)
 *   --out FILE        per-frame CSV (all verdicts)
 *   --cpu N           receiver thread core                        (default 3)
 *   --cpu-main N      this (logging) thread core                  (default 2)
 *   --cbref S --appid HEX
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <math.h>

#include "goose_receiver.h"
#include "goose_subscriber.h"
#include "mms_value.h"
#include "goose_sec.h"

static volatile int g_run = 1;
static void on_sig(int s) { (void) s; g_run = 0; }

static volatile uint64_t g_flag_valid = 0, g_flag_invalid = 0;

static void listener(GooseSubscriber sub, void* param)
{
    (void) param;
    /* the stack already decoded the dataset. We only record the stock stateValid flag:
     * stock libIEC61850 delivers non-increasing sqNum frames too, flagged invalid */
    if (GooseSubscriber_isValid(sub)) g_flag_valid++; else g_flag_invalid++;
}

static void pin(int cpu)
{
    cpu_set_t set;
    if (cpu < 0) return;
    CPU_ZERO(&set); CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) perror("sched_setaffinity");
}

static double mono_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double) t.tv_sec + (double) t.tv_nsec * 1e-9;
}

static int cmp_d(const void* a, const void* b)
{
    double x = *(const double*) a, y = *(const double*) b;
    return (x > y) - (x < y);
}

int main(int argc, char** argv)
{
    const char* iface = NULL;
    const char* outfile = NULL;
    const char* cbref = "simpleIOGenericIO/LLN0$GO$gcbAnalogValues";
    int count = 50000, warmup = 1000, cpu = 3, cpu_main = 2, appid = 0x1000;
    double duration = 0, idle_timeout = 8;
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--count") && i + 1 < argc)        count = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--warmup") && i + 1 < argc)  warmup = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--duration") && i + 1 < argc) duration = atof(argv[++i]);
        else if (!strcmp(argv[i], "--idle-timeout") && i + 1 < argc) idle_timeout = atof(argv[++i]);
        else if (!strcmp(argv[i], "--out") && i + 1 < argc)     outfile = argv[++i];
        else if (!strcmp(argv[i], "--cpu") && i + 1 < argc)     cpu = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--cpu-main") && i + 1 < argc) cpu_main = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--cbref") && i + 1 < argc)   cbref = argv[++i];
        else if (!strcmp(argv[i], "--appid") && i + 1 < argc)   appid = (int) strtol(argv[++i], NULL, 16);
        else if (argv[i][0] != '-' && !iface)                   iface = argv[i];
        else { fprintf(stderr, "unknown option %s\n", argv[i]); return 1; }
    }
    if (!iface) { fprintf(stderr, "usage: %s <iface> [options]\n", argv[0]); return 1; }

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    gs_init();

    FILE* f = NULL;
    if (outfile) {
        f = fopen(outfile, "w");
        if (!f) { perror("fopen"); return 1; }
        fprintf(f, "idx,warmup,stNum,sqNum,frame_len,verdict,t_proc_us\n");
    }

    /* the receiver thread inherits this affinity */
    pin(cpu);

    GooseReceiver receiver = GooseReceiver_create();
    GooseReceiver_setInterfaceId(receiver, iface);
    GooseSubscriber sub = GooseSubscriber_create((char*) cbref, NULL);   /* NULL: as the stock sample */
    GooseSubscriber_setAppId(sub, (uint16_t) appid);
    {   /* with a destination MAC the receiver adds a real multicast membership. Without it the stock
         * ALL_MULTICAST path silently fails (uninitialised ifreq) and the NIC drops the frames. */
        uint8_t dst[6] = {0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01};
        GooseSubscriber_setDstMac(sub, dst);
    }
    GooseSubscriber_setListener(sub, listener, NULL);
    GooseReceiver_addSubscriber(receiver, sub);
    GooseReceiver_start(receiver);
    if (!GooseReceiver_isRunning(receiver)) {
        fprintf(stderr, "GooseReceiver_start failed on %s (run with sudo)\n", iface);
        return 1;
    }
    pin(cpu_main);          /* from here on only the logging thread runs on cpu_main */

    printf("gs_sub  scheme=%s  iface=%s  recv-cpu=%d  log-cpu=%d  %s\n",
           gs_scheme_name(), iface, cpu, cpu_main,
           duration > 0 ? "timed run" : "count run");

    size_t cap = 1u << 20, nd = 0;
    double* td = malloc(cap * sizeof(double));           /* delivered, after warm-up (us) */
    uint64_t verdicts[4] = {0, 0, 0, 0};
    uint64_t verdicts_measured[4] = {0, 0, 0, 0};
    uint64_t delivered = 0, idx = 0;
    uint32_t first_len = 0;
    double t_start = mono_s(), t_last = t_start;
    double sum_rej_replay = 0, sum_rej_auth = 0;
    uint64_t n_rej_replay = 0, n_rej_auth = 0;

    while (g_run) {
        gs_rec_t r;
        int got = 0;
        while (gs_log_pop(&r)) {
            int is_warm;
            double us = (double) r.t_proc_ns / 1e3;
            got = 1;
            if (r.verdict < 4) verdicts[r.verdict]++;
            is_warm = (r.verdict == GS_V_DELIVERED && delivered < (uint64_t) warmup);
            if (r.verdict == GS_V_DELIVERED) {
                delivered++;
                if (!is_warm) {
                    if (nd == cap) { cap *= 2; td = realloc(td, cap * sizeof(double)); }
                    td[nd++] = us;
                    if (first_len == 0) first_len = r.frame_len;
                }
            }
            if (!is_warm && r.verdict < 4) verdicts_measured[r.verdict]++;
            if (r.verdict == GS_V_REJ_REPLAY) { sum_rej_replay += us; n_rej_replay++; }
            if (r.verdict == GS_V_REJ_AUTH)   { sum_rej_auth += us;   n_rej_auth++; }
            if (f) fprintf(f, "%llu,%d,%u,%u,%u,%u,%.3f\n", (unsigned long long) idx, is_warm,
                           r.st, r.sq, r.frame_len, r.verdict, us);
            idx++;
        }
        if (got) t_last = mono_s();
        else usleep(500);

        if (duration > 0) { if (mono_s() - t_start >= duration) break; }
        else if (delivered >= (uint64_t)(warmup + count)) break;
        if (mono_s() - t_last > idle_timeout && idx > 0) { printf("idle timeout\n"); break; }
        if (mono_s() - t_start > idle_timeout + 60 && idx == 0) { printf("no frames seen\n"); break; }
    }

    GooseReceiver_stop(receiver);
    GooseReceiver_destroy(receiver);
    if (f) { fclose(f); printf("wrote %s\n", outfile); }

    printf("\nreceiver stages: select_ready=%llu select_timeout=%llu select_err=%llu | ticks=%llu packets=%llu | entered=%llu short=%llu not_goose=%llu badlen=%llu nosub=%llu matched=%llu\n",
           (unsigned long long) gs_dbg[8], (unsigned long long) gs_dbg[9], (unsigned long long) gs_dbg[10],
           (unsigned long long) gs_dbg[0], (unsigned long long) gs_dbg[1], (unsigned long long) gs_dbg[2],
           (unsigned long long) gs_dbg[3], (unsigned long long) gs_dbg[4], (unsigned long long) gs_dbg[5],
           (unsigned long long) gs_dbg[6], (unsigned long long) gs_dbg[7]);
    if (gs_dbg[5]) printf("  bad length: numbytes=%llu length-field=%llu header=%llu\n", (unsigned long long) gs_dbg[11], (unsigned long long) gs_dbg[12], (unsigned long long) gs_dbg[13]);
    if (gs_dbg[6]) printf("  no subscriber matched: frame appId=0x%llx\n", (unsigned long long) gs_dbg[14]);
    printf("\nverdict counts (whole run):  delivered=%llu  rej_auth=%llu  rej_replay=%llu  rej_parse=%llu\n",
           (unsigned long long) verdicts[0], (unsigned long long) verdicts[1],
           (unsigned long long) verdicts[2], (unsigned long long) verdicts[3]);
    printf("ring records dropped (app too slow): %llu\n", (unsigned long long) gs_log_dropped());
    printf("callback saw stock isValid flag: valid=%llu  invalid=%llu\n",
           (unsigned long long) g_flag_valid, (unsigned long long) g_flag_invalid);
    if (n_rej_replay) printf("mean cost of a replay reject: %.3f us\n", sum_rej_replay / (double) n_rej_replay);
    if (n_rej_auth)   printf("mean cost of an auth  reject: %.3f us\n", sum_rej_auth / (double) n_rej_auth);

    if (nd > 0) {
        double sum = 0, ss = 0, mean;
        size_t k;
        for (k = 0; k < nd; k++) sum += td[k];
        mean = sum / (double) nd;
        for (k = 0; k < nd; k++) ss += (td[k] - mean) * (td[k] - mean);
        qsort(td, nd, sizeof(double), cmp_d);
        printf("T_proc over %zu delivered frames (frame %u bytes):\n", nd, first_len);
        printf("  mean=%.3f  median=%.3f  std=%.3f  p99=%.3f  max=%.3f us\n",
               mean, td[nd / 2], sqrt(ss / (double) nd), td[(size_t)((double) nd * 0.99)], td[nd - 1]);
    }
    free(td);
    return 0;
}
