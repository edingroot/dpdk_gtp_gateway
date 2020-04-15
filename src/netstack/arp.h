/**
 * arp.h - arp data structure
 *  ref: https://github.com/rajneshrat/dpdk-tcpipstack
 */
#ifndef __ARP_H_
#define __ARP_H_

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_hash.h>

#include "logger.h"

#define MAX_ARP_ENTRIES 8192

#define HW_TYPE_ETHERNET 1
#define SW_TYPE_IPV4 0x0800
#define PR_LEN_IPV4 4

typedef enum {
    ARP_REQ = 1,
    ARP_REPLY,
    RARP_REQ,
    RARP_REPLY,
} arp_type;

// typedef enum {
//     FREE = 0,
//     PENDING,
//     RESOLVED,
// } arp_state;

// http://www.tcpipguide.com/free/t_ARPMessageFormat.htm
struct arp {
    uint16_t hw_type;
    uint16_t pr_type;
    uint8_t hw_len;
    uint8_t pr_len;
    uint16_t opcode;
    unsigned char src_hw_add[RTE_ETHER_ADDR_LEN];
    unsigned char src_pr_add[PR_LEN_IPV4];
    unsigned char dst_hw_add[RTE_ETHER_ADDR_LEN];
    unsigned char dst_pr_add[PR_LEN_IPV4];
} __attribute__((__packed__)) __attribute__((aligned(2)));

typedef struct arp_entry_s {
    uint32_t ipv4_addr; // host format (before htonl)
    unsigned char mac_addr[RTE_ETHER_ADDR_LEN];
} arp_entry_t;

int arp_init(int with_locks);

int arp_in(struct rte_mbuf *mbuf);
int send_arp_request(uint32_t dst_ip_addr, uint8_t port);

/**
 * @return
 *   - 0 if sent successfully
 *   - A negative number if error occurred
 */
int send_arp_reply(uint32_t src_ip_addr, unsigned char *dst_hw_addr,
                   unsigned char *dst_pr_add);

int send_arp(struct rte_mbuf *mbuf, uint8_t port);

int get_mac(uint32_t ipv4_addr, unsigned char *mac_addr);

/**
 * Add an IPv4-MAC pair into arp table.
 * If there is an arp entry with same IP existed, the mac addr will be updated.
 *
 * @return
 *   - 0 if added successfully
 *   - A negative number if error occurred
 */
int add_mac(uint32_t ipv4_addr, unsigned char *mac_addr);

void print_ipv4(uint32_t ip_addr, TraceLevel trace_level);
void print_arp_table(TraceLevel trace_level);
void print_mac(unsigned char *mac_addr, TraceLevel trace_level);

#endif /* __ARP_H_ */
