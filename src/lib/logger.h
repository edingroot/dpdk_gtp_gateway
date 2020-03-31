/**
 * logger.h
 *  reference: https://github.com/vipinpv85/GTP_PKT_DECODE
 */
#ifndef __LOGGER_H_
#define __LOGGER_H_

#include <stdarg.h>
#include <stdio.h>
#include <rte_common.h>

typedef enum {
    LOG_APP,
    LOG_ARP,
    LOG_ETHER,
    LOG_LIB,
    LOG_ALL_FEATURES,
} FEATURE;

typedef enum {
    L_CRITICAL,
    L_INFO,
    L_DEBUG,
    ALL,
} TRACE_LEVEL;

struct LoggerFeature {
    TRACE_LEVEL Level;
    uint8_t Enable;
};

extern struct LoggerFeature *LogFeature;
void logger_init(void);
void logger_enable_trace(FEATURE feature, TRACE_LEVEL Level);

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define logger printf("[Log] %s(%s:%d) :: ", __FILENAME__, __func__, __LINE__); log_print

void log_print(FEATURE feature, TRACE_LEVEL Level, const char *format, ...);

#endif /* __LOGGER_H_ */
