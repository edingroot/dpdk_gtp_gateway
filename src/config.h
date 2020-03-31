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

/* D E F I N E S */   
#define GTP_CFG_FILE        "gtp_config.ini"
#define GTP_CFG_MAX_KEYLEN  15
#define GTP_CFG_MAX_PORTS   8
#define GTP_CFG_TAG_INTF    "INTF_"

#define GTP_MAX_NUMANODE    4
#define GTP_MAX_LCORECOUNT  32
#define GTP_MAX_INTFCOUNT   4

#define CFG_VAL_GTPU        0x01

#define STRCPY(x, y) strpy((char *)x, (const char *)y)
#define STRCMP(x, y) strcmp((const char *)x, (const char *)y)
#define STRNCMP(x, y, n) strncmp((const char *)x, (const char *)y, n)

typedef struct confg_gtp_port_s {
    uint8_t port_index;
    uint8_t gtp_type;
    uint8_t pkt_index;
} confg_gtp_port_t;

typedef struct app_confg_s {
    uint8_t disp_stats;
    uint8_t gtp_ports_count;
    confg_gtp_port_t gtp_ports[GTP_CFG_MAX_PORTS];
} app_confg_t;

int32_t load_gtp_config(void);

#endif /*__CONFIG_H__*/
