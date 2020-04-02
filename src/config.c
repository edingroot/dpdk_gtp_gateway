#include "config.h"

#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <rte_common.h>

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
load_intf_entries(struct rte_cfgfile *file, const char *section_name)
{
    int32_t j = 0, idx, ret = -1;
    struct rte_cfgfile_entry entries[32];
    
    ret = rte_cfgfile_section_entries(file, section_name, entries, 32);
    idx = get_int(section_name + strlen(GTP_CFG_TAG_INTF));
    app_config.gtp_ports[idx].port_num = idx;

    for (j = 0; j < ret; j++) {
        printf("\n %15s : %-15s", entries[j].name, entries[j].value);

        switch (strlen(entries[j].name)) {
            case 4:
                if (STRCMP("ipv4", entries[j].name) == 0) {
                    app_config.gtp_ports[idx].ipv4 = inet_addr(entries[j].value);
                } else if (STRCMP("type", entries[j].name) == 0) {
                    app_config.gtp_ports[idx].gtp_type = 
                        (STRCMP("GTPU", entries[j].value) == 0) ? CFG_VAL_GTPU : 0xff;
                }
                break;

            case 5:
                if (STRCMP("index", entries[j].name) == 0)
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

static int 
load_tunnel_entries(struct rte_cfgfile *file, const char *section_name)
{
    int32_t j = 0, idx, ret = -1;
    struct rte_cfgfile_entry entries[32];
    
    ret = rte_cfgfile_section_entries(file, section_name, entries, 32);
    idx = get_int(section_name + strlen(GTP_CFG_TAG_TUNNEL));
    app_config.gtp_tunnels[idx].id = idx;

    for (j = 0; j < ret; j++) {
        printf("\n %15s : %-15s", entries[j].name, entries[j].value);

        if (STRCMP("teid_in", entries[j].name) == 0) {
            app_config.gtp_tunnels[idx].teid_in = atoi(entries[j].value);
        } else if (STRCMP("teid_out", entries[j].name) == 0) {
            app_config.gtp_tunnels[idx].teid_out = atoi(entries[j].value);
        } else if (STRCMP("ue_ipv4", entries[j].name) == 0) {
            app_config.gtp_tunnels[idx].ue_ipv4 = inet_addr(entries[j].value);
        } else if (STRCMP("ran_ipv4", entries[j].name) == 0) {
            app_config.gtp_tunnels[idx].ran_ipv4 = inet_addr(entries[j].value);
        } else {
            printf("\n ERROR: unexpected entry %s with value %s\n",
                entries[j].name, entries[j].value);
            return -1;
        }
    } /* iterate entries */

    return 0;
}

int32_t
load_gtp_config(void)
{
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
    assert(intf_count <= GTP_CFG_MAX_PORTS);
    app_config.gtp_port_count = intf_count;

    int32_t tunnel_count = rte_cfgfile_num_sections(file, GTP_CFG_TAG_TUNNEL, strlen(GTP_CFG_TAG_TUNNEL));
    assert(tunnel_count <= GTP_CFG_MAX_TUNNELS);
    app_config.gtp_tunnel_count = tunnel_count;

    const int32_t section_count = 1 + intf_count + tunnel_count; // "Global" + ...
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
            ret = load_intf_entries(file, section_names[i]);
            assert(ret == 0);
        } else if (STRNCMP(GTP_CFG_TAG_TUNNEL, section_names[i], strlen(GTP_CFG_TAG_TUNNEL)) == 0) {
            ret = load_tunnel_entries(file, section_names[i]);
            assert(ret == 0);
        }
    } /* per section */
    
    ret = rte_cfgfile_close(file);
    assert(ret == 0);

    printf("\n\n");
    fflush(stdout);
    return 0;
}

confg_gtp_tunnel_t*
find_tunnel_by_ue_ipv4(uint32_t ue_ipv4)
{
    uint8_t i;

    for (i = 0; i < app_config.gtp_tunnel_count; i++) {
        if (likely(app_config.gtp_tunnels[i].ue_ipv4 == ue_ipv4)) {
            return &app_config.gtp_tunnels[i];
        }
    }

    return NULL;
}
