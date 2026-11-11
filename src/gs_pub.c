/*
 * gs_pub.c - publisher for the Banerjee baseline (GOOSE_SCHEME = none | banerjee).
 *
 * The scheme is applied inside GoosePublisher_publish() (lib/goose_publisher.c);
 * this program only drives it and times the call from outside, the same way for
 * every scheme.
 *
 *   T_gen = wall time of the GoosePublisher_publish() call (encode + [encrypt +
 *           extension] + sendto). Time of GoosePublisher_increaseStNum() is
 *           recorded separately (t_inc) and is NOT part of T_gen.
 *   T_tx  = frame_bytes * 8 / 100 Mbit/s   (calculated; the Pi 4B NIC has no
 *           hardware timestamping, so it cannot be measured on this hardware)
 *
 * Usage: sudo -E ./gs_pub <iface> [options]
 *   --count N        measured frames                         (default 50000)
 *   --warmup N       warm-up frames sent before them         (default 1000)
 *   --gap-us U       gap between frames in microseconds      (default 100)
 *   --burst K        frames per state: stNum++ every K frames, sqNum 0..K-1  (default 8)
 *   --dataset NAME   example | bool | four                   (default example)
 *   --out FILE       per-frame CSV
 *   --expect-size B  warn if the first frame is not B bytes (Banerjee Table II: none=202, aead=261)
 *   --cpu N          pin to core N                           (default 3)
 *   --rt             SCHED_FIFO priority 50
 *   --cbref/--datset/--goid S   GOOSE names (defaults: libIEC61850 example names, goID unset)
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
#include <math.h>

#include "goose_publisher.h"
#include "mms_value.h"
#include "linked_list.h"
#include "goose_sec.h"

#define LINK_BPS 100000000.0

static uint64_t now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t) t.tv_sec * 1000000000ULL + (uint64_t) t.tv_nsec;
}

static int cmp_d(const void* a, const void* b)
{
    double x = *(const double*) a, y = *(const double*) b;
    return (x > y) - (x < y);
}

static void stats(const char* label, const double* v, int n)
{
    double sum = 0, ss = 0, mean, *tmp;
    int i;
    if (n <= 0) { printf("  %-28s no data\n", label); return; }
    for (i = 0; i < n; i++) sum += v[i];
    mean = sum / n;
    for (i = 0; i < n; i++) ss += (v[i] - mean) * (v[i] - mean);
    tmp = malloc((size_t) n * sizeof(double));
    memcpy(tmp, v, (size_t) n * sizeof(double));
    qsort(tmp, (size_t) n, sizeof(double), cmp_d);
    printf("  %-28s mean=%8.3f  median=%8.3f  std=%7.3f  p99=%8.3f  max=%8.3f us\n",
           label, mean, tmp[n / 2], sqrt(ss / n), tmp[(int)(n * 0.99)], tmp[n - 1]);
    free(tmp);
}

int main(int argc, char** argv)
{
    const char* iface = NULL;
    int count = 50000, warmup = 1000, gap_us = 100, burst = 8, cpu = 3, rt = 0, expect = 0;
    const char* dataset = "example";
    const char* outfile = NULL;
    const char* cbref  = "simpleIOGenericIO/LLN0$GO$gcbAnalogValues";
    const char* datset = "simpleIOGenericIO/LLN0$AnalogValues";
    const char* goid   = NULL;     /* unset, as in the libIEC61850 example: goID defaults to the goCbRef */
    int i, total, errors = 0;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--count") && i + 1 < argc)       count = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--warmup") && i + 1 < argc) warmup = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--gap-us") && i + 1 < argc) gap_us = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--burst") && i + 1 < argc)  burst = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--dataset") && i + 1 < argc) dataset = argv[++i];
        else if (!strcmp(argv[i], "--out") && i + 1 < argc)    outfile = argv[++i];
        else if (!strcmp(argv[i], "--expect-size") && i + 1 < argc) expect = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--cpu") && i + 1 < argc)    cpu = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--rt"))                     rt = 1;
        else if (!strcmp(argv[i], "--cbref") && i + 1 < argc)  cbref = argv[++i];
        else if (!strcmp(argv[i], "--datset") && i + 1 < argc) datset = argv[++i];
        else if (!strcmp(argv[i], "--goid") && i + 1 < argc)   goid = argv[++i];
        else if (argv[i][0] != '-' && !iface)                  iface = argv[i];
        else { fprintf(stderr, "unknown option %s\n", argv[i]); return 1; }
    }
    if (!iface || burst < 1) { fprintf(stderr, "usage: %s <iface> [options]\n", argv[0]); return 1; }

    if (cpu >= 0) {
        cpu_set_t set; CPU_ZERO(&set); CPU_SET(cpu, &set);
        if (sched_setaffinity(0, sizeof(set), &set) != 0) perror("sched_setaffinity");
    }
    if (rt) {
        struct sched_param sp; sp.sched_priority = 50;
        if (sched_setscheduler(0, SCHED_FIFO, &sp) != 0) perror("sched_setscheduler");
    }

    gs_init();

    CommParameters params;
    memset(&params, 0, sizeof(params));
    params.dstAddress[0] = 0x01; params.dstAddress[1] = 0x0c; params.dstAddress[2] = 0xcd;
    params.dstAddress[3] = 0x01; params.dstAddress[4] = 0x00; params.dstAddress[5] = 0x01;
    params.vlanPriority = 4;
    params.vlanId = 0;
    params.appId = 0x1000;

    GoosePublisher pub = GoosePublisher_create(&params, iface);
    if (!pub) { fprintf(stderr, "GoosePublisher_create failed on %s (run with sudo)\n", iface); return 1; }
    GoosePublisher_setGoCbRef(pub, (char*) cbref);
    GoosePublisher_setDataSetRef(pub, (char*) datset);
    if (goid) GoosePublisher_setGoID(pub, (char*) goid);
    GoosePublisher_setConfRev(pub, 1);
    GoosePublisher_setTimeAllowedToLive(pub, 500);

    LinkedList ds = LinkedList_create();
    MmsValue* toggle = NULL;   /* value flipped on every state change */
    if (!strcmp(dataset, "bool")) {                 /* single boolean: the 5-byte allData case */
        toggle = MmsValue_newBoolean(false);
        LinkedList_add(ds, toggle);
    } else if (!strcmp(dataset, "four")) {          /* BOOLEAN + INT32 + FLOAT32 + BIT STRING */
        toggle = MmsValue_newBoolean(false);
        LinkedList_add(ds, toggle);
        LinkedList_add(ds, MmsValue_newIntegerFromInt32(0));
        LinkedList_add(ds, MmsValue_newFloat(0.0f));
        LinkedList_add(ds, MmsValue_newBitString(2));
    } else {                                        /* libIEC61850 example publisher dataset */
        LinkedList_add(ds, MmsValue_newIntegerFromInt32(1234));
        LinkedList_add(ds, MmsValue_newBinaryTime(false));
        toggle = MmsValue_newIntegerFromInt32(5678);
        LinkedList_add(ds, toggle);
    }

    total = warmup + count;
    double* t_pub = calloc((size_t) total, sizeof(double));
    double* t_inc = calloc((size_t) total, sizeof(double));
    int* flen = calloc((size_t) total, sizeof(int));
    char* newst = calloc((size_t) total, 1);

    printf("gs_pub  scheme=%s  dataset=%s  burst=%d  gap=%dus  iface=%s  cpu=%d  iv_len=%d\n",
           gs_scheme_name(), dataset, burst, gap_us, iface, cpu, gs_iv_len());

    for (i = 0; i < total; i++) {
        uint64_t a, b, c;
        int rc, ns = (i % burst) == 0;
        if (ns) {
            if (MmsValue_getType(toggle) == MMS_BOOLEAN)
                MmsValue_setBoolean(toggle, !MmsValue_getBoolean(toggle));
            else
                MmsValue_setInt32(toggle, MmsValue_toInt32(toggle) + 1);
        }
        a = now_ns();
        if (ns) GoosePublisher_increaseStNum(pub);
        b = now_ns();
        rc = GoosePublisher_publish(pub, ds);
        c = now_ns();
        if (rc != 0) { errors++; continue; }
        t_inc[i] = (double)(b - a) / 1e3;
        t_pub[i] = (double)(c - b) / 1e3;
        flen[i] = gs_last_frame_size;
        newst[i] = (char) ns;
        if (i == 0) {
            printf("first frame: %d bytes", flen[0]);
            if (expect > 0) printf("  (expected %d)%s", expect, flen[0] == expect ? "  OK" : "  <-- MISMATCH");
            printf("\n");
        }
        if (gap_us > 0) usleep((useconds_t) gap_us);
    }

    if (outfile) {
        FILE* f = fopen(outfile, "w");
        if (f) {
            fprintf(f, "idx,warmup,newstate,frame_len,t_inc_us,t_gen_us,t_tx_us\n");
            for (i = 0; i < total; i++)
                fprintf(f, "%d,%d,%d,%d,%.3f,%.3f,%.3f\n", i, i < warmup, newst[i], flen[i],
                        t_inc[i], t_pub[i], flen[i] * 8.0 / LINK_BPS * 1e6);
            fclose(f);
            printf("wrote %s\n", outfile);
        }
    }

    stats("T_gen (publish call)", t_pub + warmup, count - errors);
    printf("  frame bytes (first measured) = %d   T_tx = %.3f us (calculated)\n",
           flen[warmup], flen[warmup] * 8.0 / LINK_BPS * 1e6);
    printf("  errors = %d\n", errors);

    free(t_pub); free(t_inc); free(flen); free(newst);
    LinkedList_destroyDeep(ds, (LinkedListValueDeleteFunction) MmsValue_delete);
    GoosePublisher_destroy(pub);
    return errors ? 2 : 0;
}
