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
    LOG_ALL_Features,
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

extern struct LoggerFeature *enable_feature;
void logger_init(void);
void logger_enable_trace(Feature feature, TraceLevel level);

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

void logger(Feature feature, TraceLevel level, const char *format, ...);
void logger_s(Feature feature, TraceLevel level, const char *format, ...);

#endif /* __LOGGER_H_ */
