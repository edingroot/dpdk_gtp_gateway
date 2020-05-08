/**
 * ether.c
 *  ref: https://github.com/rajneshrat/dpdk-tcpipstack
 */
#include "ether.h"

#include <stdio.h>
#include <string.h>
#include <rte_common.h>

#include "arp.h"

interface_t *iface_list = NULL;
interface_t *port_iface_map[MAX_INTERFACES] = {0};

uint32_t
int_addr_from_char(unsigned char *address, uint8_t order)
{
    uint32_t i, ip_add = 0;

    for (i = 0; i < 4; i++) {
        ip_add = ip_add << 8;
        ip_add |= order ? address[3 - i] : address[i];
    }

    return ip_add;
}

void
add_interface(interface_t *iface)
{
    interface_t *ptr = malloc(sizeof(interface_t));

    memcpy(ptr, iface, sizeof(interface_t));
    ptr->next = NULL;

    if (iface_list == NULL) {
        iface_list = ptr;
    } else {
        iface_list->next = ptr;
    }

    if (ptr->port + 1 < MAX_INTERFACES) {
        port_iface_map[ptr->port] = ptr;
    } else {
        printf("ERROR :: interface number more than max\n");
    }

    arp_add_mac(ptr->ipv4_addr, ptr->hw_addr, 1);
}
