#include "logger.h"

#include <stdarg.h>

#define LOG_FILE "dpdkgtpv1.log"

// uint32_t LoggingFeatures = 0;
struct LoggerFeature *LogFeature;

void
logger_init(void)
{
    LogFeature = calloc(LOG_ALL_FEATURES, sizeof(struct LoggerFeature));
    logger_enable_trace(LOG_APP, ALL);
    logger_enable_trace(LOG_ARP, ALL);
    logger_enable_trace(LOG_ETHER, ALL);
    logger_enable_trace(LOG_LIB, ALL);
}

void
logger_enable_trace(FEATURE feature, TRACE_LEVEL Level)
{
    LogFeature[feature].Enable = 1;
    LogFeature[feature].Level = Level;
}

void
log_print(FEATURE feature, TRACE_LEVEL Level, const char *format, ...)
{
    va_list(arglist);

    if ((LogFeature[feature].Enable == 1) && (LogFeature[feature].Level >= Level)) {
        // FILE *fd = fopen(LOG_FILE, "a");
        FILE *fd = stdout;
        va_start(arglist, format);

        // vfprintf(fd, "Log feature %d ---- ", feature);
        vfprintf(fd, format, arglist);
        fprintf(fd, "\n");

        va_end(arglist);
        // fclose(fd);
    }
}
