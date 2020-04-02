/**
 * arp.c
 *  ref: https://github.com/rajneshrat/dpdk-tcpipstack
 */
#include "arp.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#include "pktbuf.h"
#include "ether.h"

extern interface_t *iface_list;

static struct arp_map *arp_map_list = NULL;

int
arp_in(struct rte_mbuf *mbuf)
{
    assert(mbuf->buf_len >= sizeof(struct arp));
    assert(rte_pktmbuf_data_len(mbuf) >= (sizeof(struct arp) + sizeof(struct rte_ether_hdr)));

    struct arp *arp_pkt = 
        (struct arp *)(rte_pktmbuf_mtod(mbuf, unsigned char *) + sizeof(struct rte_ether_hdr));
    
    switch (ntohs(arp_pkt->opcode)) {
        case ARP_REQ: {
            logger_s(LOG_ARP, L_INFO, "\n");
            logger(LOG_ARP, L_INFO, "[ARP Request]\n");

            send_arp_reply(arp_pkt->src_hw_add, arp_pkt->dst_pr_add, arp_pkt->src_pr_add);

            // uint32_t ip_addr = int_addr_from_char(arp_pkt->src_pr_add, 0);
            // add_mac(ip_addr, arp_pkt->src_hw_add);
            // logger(LOG_ARP, L_INFO, "seen arp packet\n");
            break;
        }
        case ARP_REPLY: {
            logger(LOG_ARP, L_INFO, "[ARP Reply]\n");

            uint32_t ip_addr = int_addr_from_char(arp_pkt->src_pr_add, 1);
            add_mac(ip_addr, arp_pkt->src_hw_add);
            break;
        }
        default: {
            assert(0);
        }
    }

    rte_pktmbuf_free(mbuf);
    fflush(stdout);
    return 0;
}

// Performance critical
int
get_mac(uint32_t ipv4_addr, unsigned char *mac_addr)
{
    struct arp_map *temp = arp_map_list;
    // printf("Getting mac for ");
    // print_ipv4(ipv4_addr, L_ALL);

    while (temp) {
        if (temp->ipv4_addr == ipv4_addr) {
            memcpy(mac_addr, temp->mac_addr, RTE_ETHER_ADDR_LEN);
            
            // printf(": mac found ");
            // print_mac(mac_addr, L_ALL);
            // printf("\n");
            return 1;
        }
        temp = temp->next;
    }

    // printf(": no mac found\n");
    return 0;
}

int
add_mac(uint32_t ipv4_addr, unsigned char *mac_addr)
{
    struct arp_map *temp = NULL;
    struct arp_map *last = NULL;

    logger(LOG_ARP, L_INFO, "Adding to arp table IP ");
    print_ipv4(ipv4_addr, L_INFO);
    logger_s(LOG_ARP, L_INFO, " MAC ");
    print_mac(mac_addr, L_INFO);
    logger_s(LOG_ARP, L_INFO, "\n");

    temp = arp_map_list;
    while (temp) {
        last = temp;
        temp = temp->next;
    }

    temp = malloc(sizeof(struct arp_map));
    temp->next = NULL;
    if (last) {
        last->next = temp;
    } else {
        arp_map_list = temp;
        logger(LOG_ARP, L_INFO, "Creating a new arp list\n");
    }

    temp->ipv4_addr = ipv4_addr;
    memcpy(temp->mac_addr, mac_addr, 6);
    return 0;
}

int
get_arp_table(char *buffer, int total_len)
{
    struct arp_map *temp = NULL;
    int i;
    int len = 0;

    (void)total_len;
    temp = arp_map_list;
    
    logger(LOG_ARP, L_INFO, "printing arp table.\n");
    while (temp) {
        len += sprintf(buffer + len, "\n");
        len += sprintf(buffer + len, " IP = ");
        len += print_ipv4_in_buf(temp->ipv4_addr, buffer + len);
        len += sprintf(buffer + len, " mac = ");
        for (i = 0; i < 6; i++) {
            len += sprintf(buffer + len, "%x::", temp->mac_addr[i]);
        }
        len += sprintf(buffer + len, "\n");
        temp = temp->next;
    }

    return len;
}

int
send_arp_request(uint8_t iface_num, unsigned char *dst_pr_add)
{
    struct rte_mbuf *new_mbuf = get_mbuf();
    assert(likely(new_mbuf != NULL));
    
    struct arp *arp_req = (struct arp *)rte_pktmbuf_prepend(new_mbuf, sizeof(struct arp));

    // http://www.tcpipguide.com/free/t_ARPMessageFormat.htm
    arp_req->hw_type = htons(HW_TYPE_ETHERNET);
    arp_req->pr_type = htons(SW_TYPE_IPV4);
    arp_req->hw_len = RTE_ETHER_ADDR_LEN;
    arp_req->pr_len = PR_LEN_IPV4;
    arp_req->opcode = htons(1);

    unsigned char dest_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    interface_t *iface = iface_list;

    while (iface && iface_num != iface->iface_num) {
        iface = iface->next;
    }

    if (unlikely(iface == NULL)) {
        logger(LOG_ARP, L_CRITICAL, 
            "ARP request failed, iface_num(%d) not in interface list\n", 
            iface_num);
        return 0;
    }

    logger(LOG_ARP, L_DEBUG, "[ARP Request] for ");
    print_ipv4(iface->ipv4_addr, L_DEBUG);
    logger_s(LOG_ARP, L_DEBUG, "\n");

    memcpy(arp_req->src_hw_add, iface->hw_addr, RTE_ETHER_ADDR_LEN);
    memcpy(arp_req->dst_hw_add, dest_mac, RTE_ETHER_ADDR_LEN);
    memcpy(arp_req->src_pr_add, &iface->ipv4_addr, PR_LEN_IPV4);
    memcpy(arp_req->dst_pr_add, dst_pr_add, PR_LEN_IPV4);
    
    send_arp(arp_req, iface->iface_num);

    return 0;
}

int
send_arp_reply(unsigned char *src_hw_addr, unsigned char *src_pr_add, unsigned char *dst_pr_add)
{
    struct arp *arp_reply = (struct arp *)malloc(sizeof(struct arp));
    uint32_t ip_addr = int_addr_from_char(src_pr_add, 1);
    interface_t *iface = iface_list;

    logger(LOG_ARP, L_DEBUG, "Processing arp request for ");
    print_ipv4(ip_addr, L_DEBUG);
    logger_s(LOG_ARP, L_DEBUG, "\n");

    while (iface && ip_addr != iface->ipv4_addr) {
        // logger(LOG_ARP, L_DEBUG, "Checking for arp ip %d found %d\n", ip_addr, iface->ipv4_addr);
        iface = iface->next;
    }

    if (unlikely(iface == NULL)) {
        logger(LOG_ARP, L_INFO, "ARP request failed, address not hosted\n");
        return 0;
    }

    // http://www.tcpipguide.com/free/t_ARPMessageFormat.htm
    arp_reply->hw_type = htons(HW_TYPE_ETHERNET);
    arp_reply->pr_type = htons(SW_TYPE_IPV4);
    arp_reply->hw_len = RTE_ETHER_ADDR_LEN;
    arp_reply->pr_len = PR_LEN_IPV4;
    arp_reply->opcode = htons(2);
    memcpy(arp_reply->src_hw_add, iface->hw_addr, RTE_ETHER_ADDR_LEN);
    memcpy(arp_reply->dst_hw_add, src_hw_addr, RTE_ETHER_ADDR_LEN);
    memcpy(arp_reply->src_pr_add, src_pr_add, PR_LEN_IPV4);
    memcpy(arp_reply->dst_pr_add, dst_pr_add, PR_LEN_IPV4);

    print_arp_table(L_DEBUG);
    logger_s(LOG_ARP, L_DEBUG, "\n");

    logger(LOG_ARP, L_DEBUG, "[ARP Reply] Dst MAC ");
    print_mac(arp_reply->dst_hw_add, L_DEBUG);
    logger_s(LOG_ARP, L_DEBUG, "\n");

    send_arp(arp_reply, iface->iface_num);

    free(arp_reply);
    return 0;
}

int
send_arp(struct arp *arp_pkt, uint8_t port)
{
    // logger(LOG_ARP, L_DEBUG, "Sending arp packet\n");
    struct rte_mbuf *mbuf = get_mbuf();
    assert(likely(mbuf != NULL));

    int i;
    struct arp *arp_hdr = (struct arp *)rte_pktmbuf_prepend(mbuf, sizeof(struct arp));
    struct rte_ether_hdr *eth = 
        (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct rte_ether_hdr));

    memcpy(arp_hdr, arp_pkt, sizeof(struct arp));

    if (arp_pkt->opcode == ntohs(ARP_REQ)) {
        eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

        memcpy(&eth->s_addr.addr_bytes[0], arp_pkt->src_hw_add, sizeof(arp_pkt->src_hw_add));
        for (i = 0; i < 6; i++) {
            eth->d_addr.addr_bytes[i] = 0xff;
        }
    
    } else if (arp_pkt->opcode == ntohs(ARP_REPLY)) {
        eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

        memcpy(&eth->s_addr.addr_bytes[0], arp_pkt->src_hw_add, sizeof(arp_pkt->src_hw_add));
        memcpy(&eth->d_addr.addr_bytes[0], arp_pkt->dst_hw_add, sizeof(arp_pkt->dst_hw_add));

    } else {
        logger(LOG_ARP, L_CRITICAL, "Invalid opcode %d", arp_pkt->opcode);
        return -1;
    }

    // TODO: fix the below, port should be dfrom routing
    const int queue_id = 0;
    const uint16_t total_packets_sent = rte_eth_tx_burst(port, queue_id, &mbuf, 1);
    assert(likely(total_packets_sent == 1));
    return 0;
}

void
print_ipv4(uint32_t ip_addr, TraceLevel trace_level)
{
    int i;
    uint8_t ip;
    ip_addr = htonl(ip_addr);

    for (i = 0; i < 4; i++) {
        ip = ip_addr >> 24;
        ip_addr = ip_addr << 8;
        logger_s(LOG_ARP, trace_level, "%u", ip);
        if (i != 3) {
            logger_s(LOG_ARP, trace_level, ".");
        }
    }
}

int
print_ipv4_in_buf(uint32_t ip_addr, char *buffer)
{
    int i;
    uint8_t ip;
    int len = 0;

    for (i = 0; i < 4; i++) {
        ip = ip_addr >> 24;
        ip_addr = ip_addr << 8;
        len += sprintf(buffer + len, "%u", ip);
        if (i != 3) {
            len += sprintf(buffer + len, ".");
        }
    }
    buffer[len] = '\0';

    return len;
}

void
print_arp_table(TraceLevel trace_level)
{
    struct arp_map *temp = NULL;

    logger(LOG_ARP, trace_level, "<ARP Table>");
    temp = arp_map_list;
    while (temp) {
        logger_s(LOG_ARP, trace_level, "\n");
        logger(LOG_ARP, trace_level, " - IP = ");
        print_ipv4(temp->ipv4_addr, trace_level);
        logger_s(LOG_ARP, trace_level, "\n");
        
        logger(LOG_ARP, trace_level, " - MAC = ");
        print_mac(temp->mac_addr, trace_level);

        temp = temp->next;
    }
}

void
print_mac(unsigned char *mac_addr, TraceLevel trace_level)
{
    int i;
    for (i = 0; i < 6; i++) {
        logger_s(LOG_ARP, trace_level, "%x::", mac_addr[i]);
    }
}
