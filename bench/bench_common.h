/*
 * Shared timing for the implementation study.
 *
 * Every harness here times one operation the same way: 50 discarded warm-up
 * calls, then 1,000 timed calls against CLOCK_MONOTONIC_RAW, reported as
 * median, mean, interquartile range and 95th percentile. The mean is kept
 * alongside the median because ML-DSA signing uses rejection sampling and the
 * two statistics come apart, which Section 7 of the paper turns on.
 *
 * Each result goes to stdout as one JSON object per line, so the driver can
 * collect them without parsing anything clever.
 */
#ifndef BENCH_COMMON_H
#define BENCH_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define WARMUP 50
#define TRIALS 1000

static const unsigned char MSG[] = "line-a benchmark message";
#define MSGLEN (sizeof(MSG) - 1)

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static void report(const char *impl, const char *op, double *t, int n) {
    qsort(t, n, sizeof(double), cmp_double);
    double sum = 0;
    for (int i = 0; i < n; i++) sum += t[i];
    double median = (n % 2) ? t[n / 2] : 0.5 * (t[n / 2 - 1] + t[n / 2]);
    printf("{\"impl\": \"%s\", \"op\": \"%s\", \"n\": %d, "
           "\"median_ms\": %.5f, \"mean_ms\": %.5f, \"iqr_ms\": %.5f, "
           "\"p95_ms\": %.5f, \"min_ms\": %.5f}\n",
           impl, op, n, median, sum / n, t[3 * n / 4] - t[n / 4],
           t[(int)(0.95 * n)], t[0]);
    fflush(stdout);
}

/* Time `stmt` TRIALS times after WARMUP untimed runs; `ok` must stay nonzero. */
#define TIME_OP(impl, op, stmt)                                         \
    do {                                                                \
        static double t_[TRIALS];                                       \
        int ok_ = 1;                                                    \
        for (int i_ = 0; i_ < WARMUP; i_++) { stmt; }                   \
        for (int i_ = 0; i_ < TRIALS; i_++) {                           \
            double s_ = now_ms();                                       \
            stmt;                                                       \
            t_[i_] = now_ms() - s_;                                     \
        }                                                               \
        if (!ok_) { fprintf(stderr, "%s %s failed\n", impl, op); exit(1); } \
        report(impl, op, t_, TRIALS);                                   \
    } while (0)

#endif
