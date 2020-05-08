#ifndef __GTP_PROCESS__
#define __GTP_PROCESS__

#include <netinet/ip.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_memcpy.h>
#include <rte_hash.h>

#include "logger.h"
#include "helper.h"
#include "stats.h"
#include "netstack/arp.h"
#include "netstack/ether.h"

/* EXTERN */
extern app_confg_t app_config;
extern interface_t *iface_list;
extern interface_t *port_iface_map[MAX_INTERFACES];
extern pkt_stats_t port_pkt_stats[GTP_CFG_MAX_PORTS];

/* DEFINES */
#define GTP1U_PORT  2152
#define GTP_TPDU    255

// According to 3GPP TS 29.060
typedef struct gtpv1_header {
    uint8_t     flags;
    uint8_t     type;
    uint16_t    length;
    uint32_t    teid;
} __attribute__ ((packed)) gtpv1_t;

#define GTP1_F_NPDU     0x01
#define GTP1_F_SEQ      0x02
#define GTP1_F_EXTHDR   0x04
#define GTP1_F_MASK     0x07

/* FUNCTION DEFS */
static __rte_always_inline void
gtpv1_set_header(gtpv1_t *gtp_hdr, uint16_t payload_len, uint32_t teid);

/* FUNCTIONS */
static __rte_always_inline int32_t
process_gtpv1(struct rte_mbuf *m, uint8_t port, gtpv1_t *rx_gtp_hdr)
{
    int32_t ret;
    struct rte_ipv4_hdr *inner_ip_hdr = (struct rte_ipv4_hdr *)((char *)(rx_gtp_hdr + 1));
    print_rte_ipv4_dbg(inner_ip_hdr->src_addr);
    printf_dbg(" -> ");
    print_rte_ipv4_dbg(inner_ip_hdr->dst_addr);

    if (unlikely((inner_ip_hdr->version_ihl & 0x40) != 0x40)) {
        port_pkt_stats[port].rx_gptu_ipv6 += 1;
    } else {
        port_pkt_stats[port].rx_gptu_ipv4 += 1;
    }

    // Check whether there is a matched tunnel
    uint32_t teid_in = ntohl(rx_gtp_hdr->teid);
    if (unlikely(rte_hash_lookup(app_config.teid_in_hash, &teid_in) < 0)) {
        printf(" ERR(No matched tunnel found with teid_in: %d) ", teid_in);
        port_pkt_stats[port].dropped += 1;
        return 0;
    }

    // Outer header removal
    const int outer_hdr_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
                              sizeof(struct rte_udp_hdr) + sizeof(gtpv1_t);
    rte_pktmbuf_adj(m, (uint16_t)outer_hdr_len);

    // Send to another port
    // TODO: follow routing table
    uint16_t out_port = port ^ 1;

    // Prepend ethernet header
    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)
            rte_pktmbuf_prepend(m, (uint16_t)sizeof(struct rte_ether_hdr));

    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    rte_ether_addr_copy(
        (const struct rte_ether_addr *)port_iface_map[out_port]->hw_addr,
        (struct rte_ether_addr *)eth_hdr->s_addr.addr_bytes);

    ret = arp_get_mac(inner_ip_hdr->dst_addr, eth_hdr->d_addr.addr_bytes);
    if (unlikely(ret != 1)) {
        printf(" ERR(Inner dst ip not found in arp table: ");
        print_rte_ipv4(inner_ip_hdr->dst_addr);
        printf(") ");

        // TODO: queue the packet and wait for arp reply instead of dropping it
        port_pkt_stats[port].dropped += 1;

        arp_send_request(inner_ip_hdr->dst_addr, out_port);
        return 0;
    }

    // Transmit
    printf_dbg(" [decap TX#%d]", out_port);
    ret = rte_eth_tx_burst(out_port, 0, &m, 1);
    if (likely(ret == 1)) {
        return 1;
    } else {
        printf_dbg(" ERR(rte_eth_tx_burst=%d) ", ret);
        return 0;
    }
}

static __rte_always_inline int32_t
process_ipv4(struct rte_mbuf *m, uint8_t port, struct rte_ipv4_hdr *rx_ip_hdr)
{
    int32_t ret;
    confg_gtp_tunnel_t *gtp_tunnel;

    if (unlikely(rte_hash_lookup_data(app_config.ue_ipv4_hash,
            &rx_ip_hdr->dst_addr, (void **)&gtp_tunnel) < 0)) {
        printf(" ERR(No matched tunnel found by ue_ipv4: ");
        print_rte_ipv4(rx_ip_hdr->dst_addr);
        printf(") ");
        port_pkt_stats[port].dropped += 1;
        return 0;
    }

    // Outer header removal
    rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ether_hdr));

    // Outer header creation
    const int outer_hdr_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
                              sizeof(struct rte_udp_hdr) + sizeof(gtpv1_t);
    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)
            rte_pktmbuf_prepend(m, (uint16_t)outer_hdr_len);

    // Send to another port
    // TODO: follow routing table
    // TODO: fix for the odd first port number
    uint16_t out_port = port ^ 1;
    interface_t *out_iface = port_iface_map[out_port];

    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)((char *)(eth_hdr + 1));
    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((char *)(ip_hdr + 1));
    gtpv1_t *gtp1_hdr = (gtpv1_t *)((char *)(udp_hdr + 1));

    // Ethernet header
    eth_hdr->ether_type = 0x8; // IPv4
    rte_ether_addr_copy(
        (const struct rte_ether_addr *)out_iface->hw_addr,
        (struct rte_ether_addr *)eth_hdr->s_addr.addr_bytes);

    ret = arp_get_mac(gtp_tunnel->ran_ipv4, eth_hdr->d_addr.addr_bytes);
    if (unlikely(ret != 1)) {
        printf(" ERR(Dst ip not found in arp table: ");
        print_rte_ipv4(gtp_tunnel->ran_ipv4);
        printf(") ");

        // TODO: queue the packet and wait for arp reply instead of dropping it
        port_pkt_stats[port].dropped += 1;

        arp_send_request(gtp_tunnel->ran_ipv4, out_port);
        return 0;
    }

    // IP header
    ip_hdr->version_ihl = RTE_IPV4_VHL_DEF;
    ip_hdr->total_length = rte_cpu_to_be_16(m->pkt_len
                               - sizeof(struct rte_ether_hdr));
    ip_hdr->time_to_live = IPDEFTTL;
    ip_hdr->next_proto_id = IPPROTO_UDP;
    ip_hdr->src_addr = out_iface->ipv4_addr;
    ip_hdr->dst_addr = gtp_tunnel->ran_ipv4;
    ip_hdr->hdr_checksum = 0;

    // UDP header
    udp_hdr->src_port = 0x6808; // htons(2152)
    udp_hdr->dst_port = 0x6808; // htons(2152)
    udp_hdr->dgram_len = rte_cpu_to_be_16(m->pkt_len
                             - sizeof(struct rte_ether_hdr)
                             - sizeof(struct rte_ipv4_hdr));
    udp_hdr->dgram_cksum = 0;

    // GTP header
    uint16_t payload_len = m->pkt_len - sizeof(struct rte_ether_hdr)
                                      - sizeof(struct rte_ipv4_hdr)
                                      - sizeof(struct rte_udp_hdr);
    gtpv1_set_header(gtp1_hdr, payload_len, gtp_tunnel->teid_out);

    // Checksum offloads
    m->l2_len = sizeof(struct rte_ether_hdr);
    m->l3_len = sizeof(struct rte_ipv4_hdr);
    m->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;

    // Transmit
    printf_dbg(" [encap TX#%d]", out_port);
    ret = rte_eth_tx_burst(out_port, 0, &m, 1);
    if (likely(ret == 1)) {
        port_pkt_stats[out_port].tx_gptu += 1;
        return 1;
    } else {
        printf_dbg(" ERR(rte_eth_tx_burst=%d) ", ret);
        return 0;
    }
}

static __rte_always_inline void
gtpv1_set_header(gtpv1_t *gtp1_hdr, uint16_t payload_len, uint32_t teid)
{
    /* Bits 8  7  6  5  4  3  2  1
     *    +--+--+--+--+--+--+--+--+
     *    |version |PT| 0| E| S|PN|
     *    +--+--+--+--+--+--+--+--+
     *     0  0  1  1  0  0  0  0
     */
    gtp1_hdr->flags = 0x30; // v1, GTP-non-prime
    gtp1_hdr->type = GTP_TPDU;
    gtp1_hdr->length = htons(payload_len);
    gtp1_hdr->teid = htonl(teid);

    /* TODO: Suppport for extension header, sequence number and N-PDU.
     *  Update the length field if any of them is available.
     */
}

#endif /*__GTP_PROCESS__*/
