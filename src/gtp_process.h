#ifndef __GTP_PROCESS__
#define __GTP_PROCESS__

#include <rte_ethdev.h>

#include "helper.h"
#include "stats.h"

extern pkt_stats_t port_pkt_stats[GTP_CFG_MAX_PORTS];

typedef struct gtpv1_s {
    uint8_t nPduNF : 1;
    uint8_t seqNF : 1;
    uint8_t extHF : 1;
    uint8_t rv : 1;
    uint8_t pt : 1;
    uint8_t vr : 3;
    uint8_t type;
    uint16_t length;
    uint32_t teid;
} gtpv1_t;

static __rte_always_inline int32_t 
process_gtpv1(struct rte_mbuf *m, uint8_t port, 
              struct rte_ether_hdr *eth_hdr,
              struct rte_ipv4_hdr *outer_ip_hdr, gtpv1_t *gtp_hdr)
{
    struct rte_ipv4_hdr *ue_ip_hdr = (struct rte_ipv4_hdr *)((char *)(gtp_hdr + 1));
    // print_rte_ipv4(ue_ip_hdr->src_addr);
    // printf(" -> ");
    // print_rte_ipv4(ue_ip_hdr->dst_addr);
    // fflush(stdout);

    if (unlikely((ue_ip_hdr->version_ihl & 0x40) != 0x40)) {
        port_pkt_stats[port].rx_gptu_ipv6 += 1;
    } else {
        port_pkt_stats[port].rx_gptu_ipv4 += 1;
    }

    // Remove outer headers
    const int outer_hdr_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + 
                              sizeof(struct rte_udp_hdr) + sizeof(gtpv1_t);
    rte_pktmbuf_adj(m, (uint16_t)outer_hdr_len);

    // Prepend ethernet header
    rte_pktmbuf_prepend(m, (uint16_t)sizeof(struct rte_ether_hdr));
    struct rte_ether_hdr *new_eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    memcpy(new_eth_hdr, eth_hdr, sizeof(struct rte_ether_hdr));

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
