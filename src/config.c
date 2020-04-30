#include "config.h"

#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <rte_common.h>
#include <rte_jhash.h>

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

static void
init_config_hash(int with_locks)
{
    struct rte_hash_parameters params = {0};

    // Initialize gtp_port_hash
    params.name = "gtp_port_hash";
    params.entries = GTP_CFG_MAX_PORTS;
    params.key_len = sizeof(uint8_t);
    params.hash_func = rte_jhash;
    params.hash_func_init_val = 0;
    params.socket_id = rte_socket_id();
    if (with_locks) {
        params.extra_flag =
            RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT
            | RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY;
    } else {
        params.extra_flag = 0;
    }

    assert(rte_hash_find_existing(params.name) == NULL);
    app_config.gtp_port_hash = rte_hash_create(&params);
    assert((intptr_t)app_config.gtp_port_hash > 0);

    // Initialize teid_in_hash
    params.name = "teid_in_hash";
    params.entries = GTP_CFG_MAX_TUNNELS;
    params.key_len = sizeof(uint32_t);
    params.hash_func = rte_jhash;
    params.hash_func_init_val = 0;
    params.socket_id = rte_socket_id();
    if (with_locks) {
        params.extra_flag =
            RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT
            | RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY;
    } else {
        params.extra_flag = 0;
    }

    assert(rte_hash_find_existing(params.name) == NULL);
    app_config.teid_in_hash = rte_hash_create(&params);
    assert((intptr_t)app_config.teid_in_hash > 0);

    // Initialize ue_ipv4_hash
    memset(&params, 0, sizeof(struct rte_hash_parameters));
    params.name = "ue_ipv4_hash";
    params.entries = GTP_CFG_MAX_TUNNELS;
    params.key_len = sizeof(uint32_t);
    params.hash_func = rte_jhash;
    params.hash_func_init_val = 0;
    params.socket_id = rte_socket_id();
    if (with_locks) {
        params.extra_flag =
            RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT
            | RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY;
    } else {
        params.extra_flag = 0;
    }

    assert(rte_hash_find_existing(params.name) == NULL);
    app_config.ue_ipv4_hash = rte_hash_create(&params);
    assert((intptr_t)app_config.ue_ipv4_hash > 0);
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
                printf("\n ERROR: unexpected entry %s with value %s\n",
                        entries[j].name, entries[j].value);
                fflush(stdout);
                return -1;
        } /* update per entry */
    } /* iterate entries */

    return 0;
}

static int
load_intf_entries(struct rte_cfgfile *file, const char *section_name, int32_t intf_idx)
{
    int32_t j = 0, port_num, ret = -1;
    struct rte_cfgfile_entry entries[32];

    ret = rte_cfgfile_section_entries(file, section_name, entries, 32);
    port_num = get_int(section_name + strlen(GTP_CFG_TAG_INTF));
    app_config.gtp_ports[intf_idx].port_num = port_num;

    for (j = 0; j < ret; j++) {
        printf("\n %15s : %-15s", entries[j].name, entries[j].value);

        if (STRCMP("ipv4", entries[j].name) == 0) {
            app_config.gtp_ports[intf_idx].ipv4 = inet_addr(entries[j].value);
        } else if (STRCMP("type", entries[j].name) == 0) {
            app_config.gtp_ports[intf_idx].gtp_type =
                (STRCMP("GTPU", entries[j].value) == 0) ? CFG_VAL_GTPU : 0xff;
        // } else if (STRCMP("index", entries[j].name) == 0) {
        //     app_config.gtp_ports[intf_idx].pkt_index = atoi(entries[j].value);
        } else {
            printf("\n ERROR: unexpected entry %s with value %s\n",
                    entries[j].name, entries[j].value);
            fflush(stdout);
            return -1;
        }
    } /* iterate entries */

    // Add to hash
    ret = rte_hash_add_key_data(app_config.gtp_port_hash,
            &app_config.gtp_ports[intf_idx].port_num,
            &app_config.gtp_ports[intf_idx]);
    assert(ret == 0);

    return 0;
}

static int
load_tunnel_entries(struct rte_cfgfile *file, const char *section_name)
{
    int32_t j = 0, idx, ret = -1;
    struct rte_cfgfile_entry entries[32];
    confg_gtp_tunnel_t *gtp_tunnel;

    ret = rte_cfgfile_section_entries(file, section_name, entries, 32);
    idx = get_int(section_name + strlen(GTP_CFG_TAG_TUNNEL));
    gtp_tunnel = &app_config.gtp_tunnels[idx];
    gtp_tunnel->id = idx;

    for (j = 0; j < ret; j++) {
        printf("\n %15s : %-15s", entries[j].name, entries[j].value);

        if (STRCMP("teid_in", entries[j].name) == 0) {
            gtp_tunnel->teid_in = atoi(entries[j].value);
        } else if (STRCMP("teid_out", entries[j].name) == 0) {
            gtp_tunnel->teid_out = atoi(entries[j].value);
        } else if (STRCMP("ue_ipv4", entries[j].name) == 0) {
            gtp_tunnel->ue_ipv4 = inet_addr(entries[j].value);
        } else if (STRCMP("ran_ipv4", entries[j].name) == 0) {
            gtp_tunnel->ran_ipv4 = inet_addr(entries[j].value);
        } else {
            printf("\n ERROR: unexpected entry %s with value %s\n",
                entries[j].name, entries[j].value);
            fflush(stdout);
            return -1;
        }
    } /* iterate entries */

    // Add tunnel pointer to hashes
    ret = rte_hash_add_key_data(app_config.teid_in_hash, &gtp_tunnel->teid_in, gtp_tunnel);
    assert(ret == 0);
    ret = rte_hash_add_key_data(app_config.ue_ipv4_hash, &gtp_tunnel->ue_ipv4, gtp_tunnel);
    assert(ret == 0);

    return 0;
}

int32_t
load_gtp_config(void)
{
    struct rte_cfgfile *file = NULL;
    int32_t i = 0, intf_idx = 0, ret;
    char **section_names = NULL;

    init_config_hash(0);

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
            ret = load_intf_entries(file, section_names[i], intf_idx++);
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
