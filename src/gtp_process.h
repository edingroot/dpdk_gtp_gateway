#ifndef __GTP_PROCESS__
#define __GTP_PROCESS__

#include<string.h>
#include <rte_ethdev.h>
#include <rte_memcpy.h>

#include "helper.h"
#include "stats.h"
#include "netstack/arp.h"
#include "netstack/ether.h"

extern unsigned char iface_hw_addr[MAX_INTERFACES][RTE_ETHER_ADDR_LEN];
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
} __attribute__((__packed__)) gtpv1_t;

static __rte_always_inline int32_t 
process_gtpv1(struct rte_mbuf *m, uint8_t port, 
              struct rte_ipv4_hdr *outer_ip_hdr, gtpv1_t *gtp_hdr)
{
    int32_t ret;
    struct rte_ipv4_hdr *inner_ip_hdr = (struct rte_ipv4_hdr *)((char *)(gtp_hdr + 1));
    // print_rte_ipv4(inner_ip_hdr->src_addr);
    // printf(" -> ");
    // print_rte_ipv4(inner_ip_hdr->dst_addr);

    if (unlikely((inner_ip_hdr->version_ihl & 0x40) != 0x40)) {
        port_pkt_stats[port].rx_gptu_ipv6 += 1;
    } else {
        port_pkt_stats[port].rx_gptu_ipv4 += 1;
    }

    // Remove outer headers
    const int outer_hdr_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + 
                              sizeof(struct rte_udp_hdr) + sizeof(gtpv1_t);
    rte_pktmbuf_adj(m, (uint16_t)outer_hdr_len);

    // Send to another port
    uint16_t outport_id = port ^ 1;
    
    // Prepend ethernet header
    rte_pktmbuf_prepend(m, (uint16_t)sizeof(struct rte_ether_hdr));
    struct rte_ether_hdr *new_eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    
    new_eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    memcpy(new_eth_hdr->s_addr.addr_bytes, iface_hw_addr[outport_id], RTE_ETHER_ADDR_LEN);
    
    ret = get_mac(inner_ip_hdr->dst_addr, (unsigned char *) new_eth_hdr->d_addr.addr_bytes);
    if (unlikely(ret != 1)) {
        // printf(" Inner dst ip not found in arp table: ");
        // print_rte_ipv4(inner_ip_hdr->dst_addr);
        // printf("\n");
        send_arp_request(outport_id, &inner_ip_hdr->dst_addr);
        return 0;
    }

    // Transmit
    // printf(" [tx]\n");
    ret = rte_eth_tx_burst(outport_id, 0, &m, 1);
    if (likely(ret == 1)) {
        port_pkt_stats[outport_id].tx_gptu += 1;
        return 1;
    }
    
    return 0;
}

static __rte_always_inline int32_t 
process_ipv4(struct rte_mbuf *m, uint8_t port, struct rte_ipv4_hdr *ip_hdr)
{
    // TODO
    return 0;
}

#endif /*__GTP_PROCESS__*/
