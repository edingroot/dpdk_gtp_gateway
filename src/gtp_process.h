#ifndef __GTP_PROCESS__
#define __GTP_PROCESS__

#include <rte_ethdev.h>

#include "stats.h"

extern pkt_stats_t port_pkt_stats[GTP_CFG_MAX_PORTS];

typedef struct gtpv1_s {
    uint8_t nPduNF : 1;
    uint8_t seqNF : 1;
    uint8_t extHF : 1;
    uint8_t rv : 1;
    uint8_t pt : 1;
    uint8_t vr : 3;
    uint8_t msgType;
    uint16_t len;
    uint32_t teid;
    uint16_t seqNum;
    uint8_t nPduNum;
    uint8_t nxtExtHT;
} gtpv1_t;

static __rte_always_inline int32_t 
process_gtpv1(struct rte_mbuf *m, uint8_t port, 
              struct rte_ipv4_hdr *ip_hdr, struct rte_udp_hdr *udp_hdr)
{
    // TODO: is this correct??
    struct rte_ipv4_hdr *ue_ip_hdr = (struct rte_ipv4_hdr *)(((char *)udp_hdr) + 1);

    if (unlikely(ue_ip_hdr->version_ihl & 0x40 != 0x40)) {
        port_pkt_stats[port].rx_gptu_ipv6 += 1;
    } else {
        port_pkt_stats[port].rx_gptu_ipv4 += 1;
    }

    // Send the packet with another port
    uint16_t fwd_port_id = port ^ 1;
    int32_t ret = rte_eth_tx_burst(fwd_port_id, 0, &m, 1);
    if (likely(ret == 1)) {
        port_pkt_stats[fwd_port_id].tx_gptu += 1;
        return 1;
    }
    
    return 0;
}

#endif /*__GTP_PROCESS__*/
