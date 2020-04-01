#include "logger.h"

#include <stdarg.h>

#define LOG_FILE "dpdkgtpv1.log"

// uint32_t LoggingFeatures = 0;
struct LoggerFeature *LogFeature;

void
logger_init(void)
{
    LogFeature = calloc(LOG_ALL_FeatureS, sizeof(struct LoggerFeature));
    logger_enable_trace(LOG_APP, L_ALL);
    logger_enable_trace(LOG_ARP, L_ALL);
    logger_enable_trace(LOG_ETHER, L_ALL);
    logger_enable_trace(LOG_LIB, L_ALL);
}

void
logger_enable_trace(Feature feature, TraceLevel level)
{
    LogFeature[feature].enable = 1;
    LogFeature[feature].level = level;
}

void
log_print(Feature feature, TraceLevel level, const char *format, ...)
{
    va_list(arglist);

    if ((LogFeature[feature].enable == 1) && (LogFeature[feature].level >= level)) {
        // FILE *fd = fopen(LOG_FILE, "a");
        FILE *fd = stdout;
        va_start(arglist, format);

        // vfprintf(fd, "Log feature %d ---- ", feature);
        vfprintf(fd, format, arglist);
        // fprintf(fd, "\n");

        va_end(arglist);
        // fclose(fd);
    }
}
