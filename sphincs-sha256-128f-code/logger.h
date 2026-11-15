#ifndef FORS_RESEARCH_LOGGER_H
#define FORS_RESEARCH_LOGGER_H
#include <stdint.h>
/* Compile-time research logging requires -DENABLE_CPA_LOGGING.
 * WARNING: produces raw derived secret material. Never use production keys. */
void init_logger(void);
void close_logger(void);
void log_sk_and_leakage(const uint8_t *sk, uint16_t index);
#endif
