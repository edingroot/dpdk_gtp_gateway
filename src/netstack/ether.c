/**
 * ether.c
 *  reference: https://github.com/vipinpv85/GTP_PKT_DECODE
 */
#include "ether.h"

#include <stdio.h>
#include <string.h>
#include <rte_common.h>

#include "arp.h"

interface_t *iface_list = NULL;
// unsigned char iface_hw_addr[MAX_INTERFACES][HW_ADDRESS_LEN];

uint32_t
int_addr_from_char(unsigned char *address, uint8_t order)
{
    uint32_t ip_add = 0;
    int i;
    
    // printf("Converting address for ");
    // for (i = 0; i < 4; i++) {
    //     printf("%d ", address[i]);
    // }

    for (i = 0; i < 4; i++) {
        ip_add = ip_add << 8;
        if (order == 1) {
            ip_add = ip_add | address[3 - i];
        }
        if (order == 0) {
            ip_add = ip_add | address[i];
        }
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

    add_mac(ptr->ipv4_addr, ptr->hw_addr);
}

uint8_t
get_interface_mac(uint8_t iface_num, uint8_t *mac)
{
    interface_t *temp = NULL;
    temp = iface_list;

    while (temp && (temp->iface_num != iface_num)) {
        temp = temp->next;
    }

    if (temp) {
        memcpy(mac, temp->hw_addr, 6);
        return 1;
    }

    return 0;
}

// void
// set_interface_hw(uint8_t *mac_addr, uint8_t interface)
// {
//     printf("Setting interface %u\n", interface);

//     if (interface < MAX_INTERFACES) {
//         memcpy(iface_hw_addr[interface], mac_addr, HW_ADDRESS_LEN);
//     } else {
//         printf("ERROR :: interfcae number more than max.\n");
//     }
// }
