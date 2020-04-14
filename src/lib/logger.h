/**
 * logger.h
 *  ref: https://github.com/rajneshrat/dpdk-tcpipstack
 */
#ifndef __LOGGER_H_
#define __LOGGER_H_

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

#ifdef DEBUG
#define printf_dbg(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define printf_dbg(fmt, ...)
#endif

typedef enum {
    LOG_APP,
    LOG_ARP,
    LOG_ETHER,
    LOG_GTP,
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

#define logger(_feature, _level, ...) \
    if (enable_feature[_feature].enable && enable_feature[_feature].level >= _level) { \
        printf("[Log] %s:%d(%s) :: ", __FILENAME__, __LINE__, __func__); \
        logger_s(_feature, _level, __VA_ARGS__); \
    }

void logger_s(Feature feature, TraceLevel level, const char *format, ...);

#endif /* __LOGGER_H_ */
