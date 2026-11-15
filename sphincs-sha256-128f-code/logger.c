/* Research-only logging. Disabled by default at compile time.
 * Enabling this writes SECRET-derived bytes to disk; use synthetic TEST KEYS ONLY.
 * No environment variables, credentials or hard-coded keys are used here. */
#include "logger.h"
#include "params.h"
#ifdef ENABLE_CPA_LOGGING
#include <stdio.h>
#include <stdlib.h>

static FILE *real_sk_file = NULL;
static FILE *leakage_file = NULL;
static FILE *sk_indices_file = NULL;
static uint8_t hamming_weight(uint8_t b) {
    uint8_t count = 0;
    while (b) { count += (uint8_t)(b & 1u); b >>= 1; }
    return count;
}
void init_logger(void) {
    if (!real_sk_file) real_sk_file = fopen("real_sk_FORS.bin", "ab");
    if (!leakage_file) leakage_file = fopen("leakage.bin", "ab");
    if (!sk_indices_file) sk_indices_file = fopen("sk_indices.bin", "ab");
    if (!real_sk_file || !leakage_file || !sk_indices_file) {
        fprintf(stderr, "Cannot open private FORS research log files\n");
        exit(EXIT_FAILURE);
    }
}
void close_logger(void) {
    if (real_sk_file) { fclose(real_sk_file); real_sk_file = NULL; }
    if (leakage_file) { fclose(leakage_file); leakage_file = NULL; }
    if (sk_indices_file) { fclose(sk_indices_file); sk_indices_file = NULL; }
}
void log_sk_and_leakage(const uint8_t *sk, uint16_t index) {
    uint8_t hw[SPX_N];
    unsigned int i;
    if (!real_sk_file || !leakage_file || !sk_indices_file) {
        fprintf(stderr, "Research logger not initialized\n");
        exit(EXIT_FAILURE);
    }
    /* Specify little endian rather than platform-native uint16 encoding. */
    uint8_t index_le[2] = {(uint8_t)(index & 0xffu), (uint8_t)(index >> 8)};
    for (i = 0; i < SPX_N; ++i) hw[i] = hamming_weight(sk[i]);
    if (fwrite(index_le,1,2,sk_indices_file) != 2 ||
        fwrite(sk,1,SPX_N,real_sk_file) != SPX_N ||
        fwrite(hw,1,SPX_N,leakage_file) != SPX_N) {
        fprintf(stderr,"Research logger write failed\n");
        exit(EXIT_FAILURE);
    }
}
#else
void init_logger(void) { }
void close_logger(void) { }
void log_sk_and_leakage(const uint8_t *sk, uint16_t index) {
    (void)sk; (void)index;
}
#endif
