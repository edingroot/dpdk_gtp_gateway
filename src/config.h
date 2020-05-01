#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include <rte_debug.h>
#include <rte_cfgfile.h>
#include <rte_malloc.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_ethdev.h>
#include <rte_errno.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_hash.h>

#include "netstack/arp.h"

/* DEFINES */
#define GTP_CFG_FILE        "gtp_config.ini"
#define GTP_CFG_MAX_KEYLEN  15
#define GTP_CFG_TAG_INTF    "INTF_"
#define GTP_CFG_MAX_PORTS   10
#define GTP_CFG_TAG_TUNNEL  "TUNNEL_"
#define GTP_CFG_MAX_TUNNELS 100
#define GTP_CFG_TAG_ARP  "ARP_"
#define GTP_CFG_MAX_ARPS 100

#define GTP_MAX_NUMANODE    4
#define GTP_MAX_LCORECOUNT  32
#define GTP_MAX_INTFCOUNT   4

#define CFG_VAL_GTPU        0x01

#define STRCPY(x, y) strcpy((char *)x, (const char *)y)
#define STRCMP(x, y) strcmp((const char *)x, (const char *)y)
#define STRNCMP(x, y, n) strncmp((const char *)x, (const char *)y, n)

typedef struct confg_gtp_port_s {
    uint8_t port_num;
    // char ipv4[INET_ADDRSTRLEN];
    uint32_t ipv4; // host format (before htonl)
    uint8_t gtp_type;
    uint8_t pkt_index;
} confg_gtp_port_t;

typedef struct confg_gtp_tunnel_s {
    uint8_t id;
    uint32_t teid_in;
    uint32_t teid_out;
    uint32_t ue_ipv4; // host format (before htonl)
    uint32_t ran_ipv4; // host format (before htonl)
} confg_gtp_tunnel_t;

typedef struct app_confg_s {
    uint8_t disp_stats;

    uint8_t gtp_port_count;
    confg_gtp_port_t gtp_ports[GTP_CFG_MAX_PORTS];
    struct rte_hash *gtp_port_hash; // [port_num] = *gtp_port

    uint8_t gtp_tunnel_count;
    confg_gtp_tunnel_t gtp_tunnels[GTP_CFG_MAX_TUNNELS];
    struct rte_hash *teid_in_hash; // [teid_in] = *gtp_tunnel
    struct rte_hash *ue_ipv4_hash; // [ue_ipv4] = *gtp_tunnel

    uint8_t static_arp_count;
    arp_entry_t static_arps[GTP_CFG_MAX_ARPS];
} app_confg_t;

int32_t load_config(void);

#endif /*__CONFIG_H__*/
