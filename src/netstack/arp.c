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
#include <rte_jhash.h>

#include "pktbuf.h"
#include "ether.h"

/* EXTERN */
extern interface_t *iface_list;

/* GLOBALS */
static struct rte_hash *arp_table = NULL; // [uint32_t ipv4_addr] = arp_entry

int
arp_init(int with_locks)
{
    struct rte_hash_parameters params = {0};

    params.name = "arp_table";
    params.entries = MAX_ARP_ENTRIES;
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
    arp_table = rte_hash_create(&params);

    return (intptr_t)arp_table > 0 ? 0 : -1;
}

int
arp_in(struct rte_mbuf *mbuf)
{
    int ret;
    assert(mbuf->buf_len >= sizeof(struct arp));
    assert(rte_pktmbuf_data_len(mbuf) >= (sizeof(struct arp) + sizeof(struct rte_ether_hdr)));

    struct arp *arp_pkt =
        (struct arp *)(rte_pktmbuf_mtod(mbuf, unsigned char *) + sizeof(struct rte_ether_hdr));

    switch (ntohs(arp_pkt->opcode)) {
        case ARP_REQ: {
            logger_s(LOG_ARP, L_INFO, "\n");
            logger(LOG_ARP, L_INFO, "[ARP Request]\n");

            send_arp_reply(arp_pkt->src_hw_add, arp_pkt->dst_pr_add, arp_pkt->src_pr_add);
            logger_s(LOG_ARP, L_DEBUG, "\n");

            // uint32_t ip_addr = int_addr_from_char(arp_pkt->src_pr_add, 0);
            // add_mac(ip_addr, arp_pkt->src_hw_add);
            // logger(LOG_ARP, L_INFO, "seen arp packet\n");
            break;
        }
        case ARP_REPLY: {
            logger_s(LOG_ARP, L_INFO, "\n");
            logger(LOG_ARP, L_INFO, "[ARP Reply]\n");

            uint32_t ip_addr = int_addr_from_char(arp_pkt->src_pr_add, 1);
            ret = add_mac(ip_addr, arp_pkt->src_hw_add);
            assert(ret == 0);

            print_arp_table(L_DEBUG);
            logger_s(LOG_ARP, L_DEBUG, "\n");
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
    // printf("Getting mac for ");
    // print_ipv4(ipv4_addr, L_ALL);

    arp_entry_t *arp_entry;
    int ret = rte_hash_lookup_data(arp_table, (const void *)&ipv4_addr, (void **)&arp_entry);
    if (ret >= 0) {
        rte_memcpy(mac_addr, arp_entry->mac_addr, RTE_ETHER_ADDR_LEN);
        // printf(": mac found ");
        // print_mac(mac_addr, L_ALL);
        // printf("\n");
        return 1;
    } else {
        // printf(": no mac found%d\n", ret);
        return 0;
    }
}

int
add_mac(uint32_t ipv4_addr, unsigned char *mac_addr)
{
    int ret;
    logger(LOG_ARP, L_INFO, "Adding to arp table IP ");
    print_ipv4(ipv4_addr, L_INFO);
    logger_s(LOG_ARP, L_INFO, " MAC ");
    print_mac(mac_addr, L_INFO);
    logger_s(LOG_ARP, L_INFO, "\n");

    arp_entry_t *arp_entry = malloc(sizeof(arp_entry_t));
    arp_entry->ipv4_addr = ipv4_addr;
    rte_memcpy(arp_entry->mac_addr, mac_addr, RTE_ETHER_ADDR_LEN);

    ret = rte_hash_add_key_data(arp_table, (const void *)&ipv4_addr, (void *)arp_entry);
    return ret == 0 ? 0 : -1;
}

int
send_arp_request(uint8_t iface_num, unsigned char *dst_pr_add)
{
    unsigned char dest_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    interface_t *iface = iface_list;

    logger_s(LOG_ARP, L_DEBUG, "\n");
    logger(LOG_ARP, L_DEBUG, "<ARP Request> for ");
    print_ipv4(iface->ipv4_addr, L_DEBUG);
    logger_s(LOG_ARP, L_DEBUG, "\n");

    while (iface && iface_num != iface->iface_num) {
        iface = iface->next;
    }

    if (unlikely(iface == NULL)) {
        logger(LOG_ARP, L_CRITICAL,
            "ARP request failed, iface_num(%d) not in interface list\n",
            iface_num);
        return 0;
    }

    struct rte_mbuf *mbuf = get_mbuf();
    assert(likely(mbuf != NULL));

    // http://www.tcpipguide.com/free/t_ARPMessageFormat.htm
    struct arp *arp_req = (struct arp *)rte_pktmbuf_prepend(mbuf, sizeof(struct arp));
    arp_req->hw_type = htons(HW_TYPE_ETHERNET);
    arp_req->pr_type = htons(SW_TYPE_IPV4);
    arp_req->hw_len = RTE_ETHER_ADDR_LEN;
    arp_req->pr_len = PR_LEN_IPV4;
    arp_req->opcode = htons(1);
    rte_memcpy(arp_req->src_hw_add, iface->hw_addr, RTE_ETHER_ADDR_LEN);
    rte_memcpy(arp_req->dst_hw_add, dest_mac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(arp_req->src_pr_add, &iface->ipv4_addr, PR_LEN_IPV4);
    rte_memcpy(arp_req->dst_pr_add, dst_pr_add, PR_LEN_IPV4);

    int ret = send_arp(mbuf, iface->iface_num);
    if (likely(ret == 0)) {
        return 0;
    } else {
        rte_pktmbuf_free(mbuf);
        return -1;
    }
}

int
send_arp_reply(unsigned char *src_hw_addr, unsigned char *src_pr_add, unsigned char *dst_pr_add)
{
    uint32_t ip_addr = int_addr_from_char(src_pr_add, 1);
    interface_t *iface = iface_list;

    logger(LOG_ARP, L_DEBUG, "Request IP ");
    print_ipv4(ip_addr, L_DEBUG);
    logger_s(LOG_ARP, L_DEBUG, "\n");

    while (iface && ip_addr != iface->ipv4_addr) {
        // logger(LOG_ARP, L_DEBUG, "Checking for arp ip %d found %d\n", ip_addr, iface->ipv4_addr);
        iface = iface->next;
    }

    if (unlikely(iface == NULL)) {
        logger(LOG_ARP, L_INFO, "ARP request failed, address not hosted\n");
        return -1;
    }

    struct rte_mbuf *mbuf = get_mbuf();
    assert(likely(mbuf != NULL));

    // http://www.tcpipguide.com/free/t_ARPMessageFormat.htm
    struct arp *arp_reply = (struct arp *)rte_pktmbuf_prepend(mbuf, sizeof(struct arp));
    arp_reply->hw_type = htons(HW_TYPE_ETHERNET);
    arp_reply->pr_type = htons(SW_TYPE_IPV4);
    arp_reply->hw_len = RTE_ETHER_ADDR_LEN;
    arp_reply->pr_len = PR_LEN_IPV4;
    arp_reply->opcode = htons(2);
    rte_memcpy(arp_reply->src_hw_add, iface->hw_addr, RTE_ETHER_ADDR_LEN);
    rte_memcpy(arp_reply->dst_hw_add, src_hw_addr, RTE_ETHER_ADDR_LEN);
    rte_memcpy(arp_reply->src_pr_add, src_pr_add, PR_LEN_IPV4);
    rte_memcpy(arp_reply->dst_pr_add, dst_pr_add, PR_LEN_IPV4);

    logger(LOG_ARP, L_DEBUG, "<ARP Reply> Dst MAC ");
    print_mac(arp_reply->dst_hw_add, L_DEBUG);
    logger_s(LOG_ARP, L_DEBUG, "\n");

    int ret = send_arp(mbuf, iface->iface_num);
    if (likely(ret == 0)) {
        return 0;
    } else {
        rte_pktmbuf_free(mbuf);
        return -1;
    }
}

int
send_arp(struct rte_mbuf *mbuf, uint8_t port)
{
    // logger(LOG_ARP, L_DEBUG, "Sending arp packet\n");

    int i;
    struct arp *arp_pkt = (struct arp *)rte_pktmbuf_mtod(mbuf, struct arp *);
    struct rte_ether_hdr *eth =
        (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct rte_ether_hdr));

    if (arp_pkt->opcode == ntohs(ARP_REQ)) {
        eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

        rte_memcpy(&eth->s_addr.addr_bytes[0], arp_pkt->src_hw_add, sizeof(arp_pkt->src_hw_add));
        for (i = 0; i < 6; i++) {
            eth->d_addr.addr_bytes[i] = 0xff;
        }
    } else if (arp_pkt->opcode == ntohs(ARP_REPLY)) {
        eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

        rte_memcpy(&eth->s_addr.addr_bytes[0], arp_pkt->src_hw_add, sizeof(arp_pkt->src_hw_add));
        rte_memcpy(&eth->d_addr.addr_bytes[0], arp_pkt->dst_hw_add, sizeof(arp_pkt->dst_hw_add));
    } else {
        logger(LOG_ARP, L_CRITICAL, "Invalid opcode %d", arp_pkt->opcode);
        return -1;
    }

    // TODO: fix the below, port should be dfrom routing
    const int queue_id = 0;
    const uint16_t total_packets_sent = rte_eth_tx_burst(port, queue_id, &mbuf, 1);
    if (unlikely(total_packets_sent != 1)) {
        logger(LOG_ARP, L_CRITICAL, "Error sending arp message\n");
        return -1;
    }

    rte_pktmbuf_free(mbuf);
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

void
print_arp_table(TraceLevel trace_level)
{
    uint32_t *ipv4_addr, iter = 0;
    arp_entry_t *arp_entry;

    logger(LOG_ARP, trace_level, "{ARP Table}\n");
    logger(LOG_ARP, trace_level, "There are %d entries in total:", rte_hash_count(arp_table));
    logger_s(LOG_ARP, trace_level, "\n");

    while (rte_hash_iterate(arp_table, (void *)&ipv4_addr, (void **)&arp_entry, &iter) >= 0) {
        logger(LOG_ARP, trace_level, " - IP = ");
        print_ipv4(*ipv4_addr, trace_level); // arp_entry->ipv4_addr
        logger_s(LOG_ARP, trace_level, "\n");

        logger(LOG_ARP, trace_level, "   MAC = ");
        print_mac(arp_entry->mac_addr, trace_level);
        logger_s(LOG_ARP, trace_level, "\n");
    }
}

void
print_mac(unsigned char *mac_addr, TraceLevel trace_level)
{
    int i;
    for (i = 0; i < RTE_ETHER_ADDR_LEN; i++) {
        logger_s(LOG_ARP, trace_level, "%x:", mac_addr[i]);
    }
}
