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
    LOG_ALL_FeatureS,
} Feature;

typedef enum {
    L_CRITICAL,
    L_WARN,
    L_INFO,
    L_DEBUG,
    L_ALL,
} TraceLevel;

struct LoggerFeature {
    TraceLevel level;
    uint8_t enable;
};

extern struct LoggerFeature *LogFeature;
void logger_init(void);
void logger_enable_trace(Feature feature, TraceLevel level);

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define logger printf("[Log] %s:%d(%s) :: ", __FILENAME__, __LINE__, __func__); log_print

void log_print(Feature feature, TraceLevel level, const char *format, ...);

#endif /* __LOGGER_H_ */
