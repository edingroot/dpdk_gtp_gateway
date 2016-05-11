#include <string.h>

#include "config.h"

uint8_t gtpConfigCount = 0;
port_gtpConfig_t gtpConfig [GTP_PKTGEN_MAXPORTS] = {{0}};

const uint8_t gtpC[GTPC_MAXCOUNT][800] = {GTPC_ECHOREQ, GTPC_ECHOREP, GTPC_CREATEPDU_REQ, GTPC_CREATEPDU_REP};
const uint8_t gtpU[GTPU_MAXCOUNT][1500] = {GTPU_ICMPREQ, GTPU_ICMPREP};

static inline int getInt(const char *string)
{
    int i, stringLength = strlen(string);

    for(i = 0; i < stringLength; i++)
    {
        if((isdigit(string [i]) == 0))
            return -1;

    }

    return (atoi(string));
}

int32_t loadGtpConfig(void)
{
    struct rte_cfgfile *file = NULL;
    char **section_names = NULL;
    struct rte_cfgfile_entry entries[32];
    int32_t sectCount = 0, entrCount = 0, i = 0, j = 0, ret = -1;

    file = rte_cfgfile_load(GTP_CONFIGFILE, 0);
    if (file == NULL) {
        printf("Cannot load configuration profile %s\n", GTP_CONFIGFILE);
        return -1;
    }

    sectCount = rte_cfgfile_num_sections(file, GTP_PKTGEN_INTFTAG, strlen(GTP_PKTGEN_INTFTAG));
    //printf("\n section starting with INTF are %d", sectCount);
    //sectCount = rte_cfgfile_num_sections(file, NULL, 0);

    if (sectCount <= GTP_PKTGEN_MAXPORTS) {
        section_names = malloc(sectCount * sizeof(char *));

        for (i = 0; i < sectCount; i++)
            section_names[i] = malloc(10);

        rte_cfgfile_sections(file, section_names, sectCount);
        for (i = 0; i < sectCount; i++) {
            //printf("\n\n section - %s", section_names[i]);

            entrCount = rte_cfgfile_section_num_entries(file, section_names[i]);
            //printf("\n - entries Count: %d", entrCount);
            //printf("\n - ENTRY : VALUE ");
            //printf("\n ----------------");

            if (entrCount < 4) {
                /* MAX sections are 3 per interface */
                ret = rte_cfgfile_section_entries(file, section_names[i], entries, entrCount);

                gtpConfig[i].prtIndex = getInt(section_names[i] + strlen(GTP_PKTGEN_INTFTAG));

                //printf("\n Before: Port: %d gtp type %d", i, gtpConfig[i].gtpType);
                for (j = 0; j < ret; j++) {
                    //printf("\n %15s : %-15s", 
                    //         entries[j].name, entries[j].value);

                    switch (strlen(entries[j].name)) {

                        case (4):
                            if (STRCMP("\n && type", entries[j].name))
                                gtpConfig[i].gtpType = 
                                      (STRCMP("GTPC",entries[j].value)==0)?GTPC:
                                      (STRCMP("GTPU",entries[j].value)==0)?GTPU:
                                      0xff;
                            break;

                        case (5):
                            if (STRCMP("index", entries[j].name))
                                gtpConfig[i].pktIndex = atoi(entries[j].value);
                            break;

                        case (7):
                            if (STRCMP("version", entries[j].name))
                                gtpConfig[i].gtpVersion = atoi(entries[j].value);
                            break;

                        default:
                            printf("\n ERROR: unexpected entry %s with value %s", \
                                   entries[j].name, entries[j].value);
                            ret = rte_cfgfile_close(file);
                            return -2;
                    } /* update per entry */
                } /* iterate entries */
                //printf("\n After: Port: %d gtp type %d", i, gtpConfig[i].gtpType);
            } /* entry count */
        } /* per section */
        gtpConfigCount = i;
    } /* section count*/

    ret = rte_cfgfile_close(file);
    return 0;
}

