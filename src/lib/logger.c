#include "logger.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#define LOG_FILE "dpdkgtpv1.log"

struct LoggerFeature *enable_feature;

void
logger_init(void)
{
    enable_feature = calloc(LOG_ALL_Features, sizeof(struct LoggerFeature));
    memset(enable_feature, 0, sizeof(struct LoggerFeature));

    logger_enable_trace(LOG_APP, L_ALL);
    logger_enable_trace(LOG_ARP, L_ALL);
    // logger_enable_trace(LOG_ETHER, L_ALL);
    logger_enable_trace(LOG_GTP, L_ALL);
    // logger_enable_trace(LOG_LIB, L_ALL);
}

void
logger_enable_trace(Feature feature, TraceLevel level)
{
    enable_feature[feature].enable = 1;
    enable_feature[feature].level = level;
}

void
logger_s(Feature feature, TraceLevel level, const char *format, ...)
{
    va_list(arglist);

    if (enable_feature[feature].enable && enable_feature[feature].level >= level) {
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
