/**
 * ether.h
 *  reference: https://github.com/vipinpv85/GTP_PKT_DECODE
 */
#ifndef __EHTER_H_
#define __EHTER_H_

#include <rte_common.h>
#define HW_ADDRESS_LEN 6
#define MAX_INTERFACES 10

struct Interface {
    unsigned char hw_addr[HW_ADDRESS_LEN];
    uint8_t iface_num;
    unsigned char ip[4];
    struct Interface *next;
};

unsigned char InterfaceHwAddr[MAX_INTERFACES][HW_ADDRESS_LEN];
uint32_t GetIntAddFromChar(unsigned char *address, uint8_t order);

uint8_t GetInterfaceMac(uint8_t iface_num, uint8_t *mac);
void AddInterface(struct Interface *Iface);
void SetInterfaceHW(uint8_t *MacAddr, uint8_t interface);
void InitInterface(struct Interface *IfList[], unsigned int Count);

extern struct Interface *InterfaceList;
#endif /* __EHTER_H_ */
