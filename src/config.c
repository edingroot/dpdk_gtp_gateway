#include "config.h"

#include <string.h>
#include <assert.h>

app_confg_t app_config = {0};

static inline int
get_int(const char *string)
{
    int i, stringLength = strlen(string);

    for (i = 0; i < stringLength; i++) {
        if ((isdigit(string[i]) == 0))
            return -1;
    }

    return atoi(string);
}

static int 
load_global_entries(struct rte_cfgfile *file)
{
    const char *section_name = "Global";
    int32_t j = 0, ret = -1;
    struct rte_cfgfile_entry entries[32];

    ret = rte_cfgfile_section_entries(file, section_name, entries, 32);

    for (j = 0; j < ret; j++) {
        printf("\n %15s : %-15s", entries[j].name, entries[j].value);

        switch (strlen(entries[j].name)) {
            case 10:
                if (STRCMP("disp_stats", entries[j].name) == 0) {
                    app_config.disp_stats = STRCMP("1", entries[j].value) == 0;
                }
                break;

            default:
                printf("\n ERROR: unexpected entry %s with value %s",
                        entries[j].name, entries[j].value);
                return -1;
        } /* update per entry */
    } /* iterate entries */

    return 0;
}

static int 
load_intf_entries(struct rte_cfgfile *file, int32_t idx, const char *section_name)
{
    int32_t j = 0, ret = -1;
    struct rte_cfgfile_entry entries[32];
    
    ret = rte_cfgfile_section_entries(file, section_name, entries, 32);
    app_config.gtp_ports[idx].port_index = get_int(section_name + strlen(GTP_CFG_TAG_INTF));

    for (j = 0; j < ret; j++) {
        printf("\n %15s : %-15s", entries[j].name, entries[j].value);

        switch (strlen(entries[j].name)) {
            case 4:
                if (STRCMP("type", entries[j].name)) {
                    app_config.gtp_ports[idx].gtp_type = 
                        (STRCMP("GTPU", entries[j].value) == 0) ? CFG_VAL_GTPU : 0xff;
                }
                break;

            case 5:
                if (STRCMP("index", entries[j].name))
                    app_config.gtp_ports[idx].pkt_index = atoi(entries[j].value);
                break;

            default:
                printf("\n ERROR: unexpected entry %s with value %s",
                        entries[j].name, entries[j].value);
                return -1;
        } /* update per entry */
    } /* iterate entries */

    return 0;
}

int32_t load_gtp_config(void) {
    struct rte_cfgfile *file = NULL;
    int32_t i = 0, ret;
    char **section_names = NULL;

    file = rte_cfgfile_load(GTP_CFG_FILE, 0);
    if (file == NULL) {
        printf("Cannot load configuration profile %s\n", GTP_CFG_FILE);
        return -1;
    }

    printf("\n Loading config entries:");
    
    int32_t intf_count = rte_cfgfile_num_sections(file, GTP_CFG_TAG_INTF, strlen(GTP_CFG_TAG_INTF));
    // printf("\n Sections starting with INTF_ are %d", intf_count);
    if (intf_count > GTP_CFG_MAX_PORTS) {
        printf("Error: INTF count(%d) > GTP_CFG_MAX_PORTS(%d)\n", intf_count, GTP_CFG_MAX_PORTS);
    }
    app_config.gtp_ports_count = intf_count;

    const int32_t section_count = intf_count + 1; // "Global" + ("INTF_" * intf_count)
    section_names = malloc(section_count * sizeof(char *));
    for (i = 0; i < section_count; i++)
        section_names[i] = malloc(GTP_CFG_MAX_KEYLEN + 1);
    
    rte_cfgfile_sections(file, section_names, section_count);

    for (i = 0; i < section_count; i++) {
        printf("\n\n              [%s]", section_names[i]);
        printf("\n --------------------------------");

        if (STRCMP("Global", section_names[i]) == 0) {
            ret = load_global_entries(file);
            assert(ret == 0);
        } else if (STRNCMP(GTP_CFG_TAG_INTF, section_names[i], strlen(GTP_CFG_TAG_INTF)) == 0) {
            ret = load_intf_entries(file, i, section_names[i]);
            assert(ret == 0);
        }
    } /* per section */
    
    ret = rte_cfgfile_close(file);
    assert(ret == 0);

    printf("\n\n");
    fflush(stdout);
    return 0;
}
