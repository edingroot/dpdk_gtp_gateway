/**
 * ether.h
 *  ref: https://github.com/rajneshrat/dpdk-tcpipstack
 */
#ifndef __EHTER_H_
#define __EHTER_H_

#include <rte_common.h>
#include <rte_ether.h>

#define MAX_INTERFACES 10

typedef struct interface_s {
    uint8_t port;
    unsigned char hw_addr[RTE_ETHER_ADDR_LEN];
    uint32_t ipv4_addr; // host format (before htonl)
    struct interface_s *next;
} interface_t;

/**
 * @param address e.g. {"192", "168", "0", "1"}
 */
uint32_t int_addr_from_char(unsigned char *address, uint8_t order);

void add_interface(interface_t *iface);
void set_interface_hw(uint8_t port, uint8_t *mac_addr);

#endif /* __EHTER_H_ */
