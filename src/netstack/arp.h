/**
 * arp.h - arp data structure
 *  TODO: thread safe
 */
#ifndef __ARP_H_
#define __ARP_H_

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_ring.h>

#include "logger.h"

#define MAX_ARP_ENTRIES 8192
#define MAX_EGRESS_Q_IP_ENTRIES 8192

#define HW_TYPE_ETHERNET 1
#define SW_TYPE_IPV4 0x0800
#define PR_LEN_IPV4 4

typedef enum {
    ARP_REQ = 1,
    ARP_REPLY,
    RARP_REQ,
    RARP_REPLY,
} arp_type_t;

// See also arp_state_str[] in arp.c
typedef enum {
    ARP_STATE_ANY = 0,
    ARP_STATE_INCOMPLETE,
    // states below are valid for arp_get_mac()
    ARP_STATE_REACHABLE,
    ARP_STATE_PERMANENT,
} arp_state_t;

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
    arp_state_t state;
} arp_entry_t;

int arp_init(int with_locks);
int arp_terminate(void);

int arp_in(struct rte_mbuf *mbuf);
int arp_send_request(uint32_t dst_ip_addr, uint8_t port);

/**
 * @return
 *   - 0 if sent successfully
 *   - A negative number if error occurred
 */
int arp_send_reply(uint32_t src_ip_addr, unsigned char *dst_hw_addr,
                   unsigned char *dst_pr_add);

int arp_get_mac(uint32_t ipv4_addr, unsigned char *mac_addr);

/**
 * Add an IPv4-MAC pair into arp table.
 * If there is an arp entry with same IP existed, the mac addr will be updated.
 *
 * @return
 *   - 0 if added successfully
 *   - A negative number if error occurred
 */
int arp_add_mac(uint32_t ipv4_addr, unsigned char *mac_addr, int permanent);

int arp_queue_egress_pkt(uint32_t ipv4_addr, struct rte_mbuf *m);

void arp_print_table(TraceLevel trace_level);
void print_ipv4(uint32_t ip_addr, TraceLevel trace_level);
void print_mac(unsigned char *mac_addr, TraceLevel trace_level);

#endif /* __ARP_H_ */
