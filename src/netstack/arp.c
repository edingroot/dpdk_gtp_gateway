/**
 * arp.c
 *  reference: https://github.com/vipinpv85/GTP_PKT_DECODE
 */
#include "arp.h"

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <netinet/in.h>

#include "logger.h"
#include "mbuf.h"
#include "ether.h"

#define ARP_TABLE_SIZE 100

struct arp arp_table[ARP_TABLE_SIZE];

static struct arp_map *arp_map_list = NULL;

void
swapvalue(char *add1, char *add2, int len)
{
    char temp;
    int i;
    for (i = 0; i < len; i++) {
        temp = add1[i];
        add1[i] = add2[i];
        add2[i] = temp;
    }
}

int
send_arp_reply(unsigned char *src_pr_add, unsigned char *dst_pr_add)
{
    struct arp *arp_reply = (struct arp *)malloc(sizeof(struct arp));  //rte_pktmbuf_prepend (new_mbuf, sizeof(struct arp));
    char mac[6];

    // http://www.tcpipguide.com/free/t_ARPMessageFormat.htm
    arp_reply->hw_type = htons(HW_TYPE_ETHERNET);
    arp_reply->pr_type = htons(SW_TYPE_IPV4);
    arp_reply->hw_len = HW_LEN_ETHER;
    arp_reply->pr_len = PR_LEN_IPV4;
    arp_reply->opcode = htons(2);

    unsigned char dest_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};  // don't use broadcast address for arp reply.
    uint32_t ip_add = GetIntAddFromChar(src_pr_add, 1);

    struct Interface *temp = NULL;
    temp = InterfaceList;

    while (temp && ip_add != GetIntAddFromChar(temp->ip, 1)) {
        logger(LOG_ARP, L_DEBUG, "Checking for arp ip %d found %d", ip_add, GetIntAddFromChar(temp->ip, 1));
        temp = temp->next;
    }

    if (temp == NULL) {
        logger(LOG_ARP, L_NORMAL, "Arp request failed, address not hosted");
        return 0;
    }

    logger(LOG_ARP, L_NORMAL, "IP found in interface list");
    //printf("Arp request for %x\n", ip_add);
    //printf("arp reply status = %d and mac %x\n", status, mac[0]);
    memcpy(arp_reply->src_hw_add, mac, HW_LEN_ETHER);
    memcpy(arp_reply->dst_hw_add, dest_mac, HW_LEN_ETHER);
    memcpy(arp_reply->src_pr_add, src_pr_add, PR_LEN_IPV4);
    memcpy(arp_reply->dst_pr_add, dst_pr_add, PR_LEN_IPV4);
    send_arp(arp_reply);

    free(arp_reply);
    return 0;
}

int
send_arp_request(unsigned char *src_pr_add, unsigned char *dst_pr_add)
{
    struct rte_mbuf *new_mbuf = get_mbuf();
    assert(likely(new_mbuf != NULL));
    
    struct arp *arp_reply = (struct arp *)rte_pktmbuf_prepend(new_mbuf, sizeof(struct arp));
    char mac[6];

    // http://www.tcpipguide.com/free/t_ARPMessageFormat.htm
    arp_reply->hw_type = htons(HW_TYPE_ETHERNET);
    arp_reply->pr_type = htons(SW_TYPE_IPV4);
    arp_reply->hw_len = HW_LEN_ETHER;
    arp_reply->pr_len = PR_LEN_IPV4;
    arp_reply->opcode = htons(1);

    unsigned char dest_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint32_t ip_add = GetIntAddFromChar(src_pr_add, 1);

    struct Interface *temp = NULL;
    temp = InterfaceList;
    while (temp && ip_add != GetIntAddFromChar(temp->ip, 1)) {
        temp = temp->next;
    }

    if (temp == NULL) {
        logger(LOG_ARP, L_NORMAL, "Arp request failed, address not hosted");
        return 0;
    }

    logger(LOG_ARP, L_NORMAL, "IP found in interface list");
    memcpy(arp_reply->src_hw_add, mac, HW_LEN_ETHER);
    memcpy(arp_reply->dst_hw_add, dest_mac, HW_LEN_ETHER);
    memcpy(arp_reply->src_pr_add, src_pr_add, PR_LEN_IPV4);
    memcpy(arp_reply->dst_pr_add, dst_pr_add, PR_LEN_IPV4);
    send_arp(arp_reply);

    return 0;
}

void
dump_arp_pkt(struct arp *arp_pkt)
{
    printf("HW type =  %u\n", arp_pkt->hw_type);
    printf("PR type =  %u\n", arp_pkt->pr_type);
    printf("HW len =  %u\n", arp_pkt->hw_len);
    printf("PR len =  %u\n", arp_pkt->pr_len);
    printf("Opcode  %u\n", arp_pkt->opcode);
}

int
arp_in(struct rte_mbuf *mbuf)
{
    assert(mbuf->buf_len >= sizeof(struct arp));
    struct arp *arp_pkt;
    uint32_t ip_add = 0;

    assert(rte_pktmbuf_data_len(mbuf) >= (sizeof(struct arp) + sizeof(struct rte_ether_hdr)));
    arp_pkt = (struct arp *)(rte_pktmbuf_mtod(mbuf, unsigned char *) + sizeof(struct rte_ether_hdr));
    dump_arp_pkt(arp_pkt);
    // printf("arp packet with opcode %u %u\n", arp_pkt->opcode, ntohs(arp_pkt->opcode));
    
    switch (ntohs(arp_pkt->opcode)) {
        case ARP_REQ:
            printf("seen arp request\n");
            send_arp_reply(arp_pkt->dst_pr_add, arp_pkt->src_pr_add);
            break;
            // uint32_t ip_add = GetIntAddFromChar(arp_pkt->src_pr_add, 0);
            // add_mac((ip_add), arp_pkt->src_hw_add);
            // logger(LOG_ARP, L_NORMAL, "seen arp packet");
            // break;

        case ARP_REPLY:
            ip_add = GetIntAddFromChar(arp_pkt->src_pr_add, 0);
            add_mac((ip_add), arp_pkt->src_hw_add);
            break;
        
        default:
            assert(0);
    }

    return 0;
}

void
print_add(uint32_t ip_add)
{
    int i;
    uint8_t ip;

    for (i = 0; i < 4; i++) {
        ip = ip_add >> 24;
        ip_add = ip_add << 8;
        log_print(LOG_ARP, ALL, "%u", ip);
        if (i != 3) {
            log_print(LOG_ARP, ALL, ".");
        }
    }
}

int
print_add_in_buf(uint32_t ip_add, char *buffer)
{
    int i;
    uint8_t ip;
    int len = 0;

    for (i = 0; i < 4; i++) {
        ip = ip_add >> 24;
        ip_add = ip_add << 8;
        len += sprintf(buffer + len, "%u", ip);
        if (i != 3) {
            len += sprintf(buffer + len, ".");
        }
    }
    buffer[len] = '\0';

    return len;
}

void
send_arp(struct arp *arp_pkt)
{
    struct rte_mbuf *mbuf = NULL;
    struct arp *arp_hdr = NULL;
    struct rte_ether_hdr *eth = NULL;
    int i;

    mbuf = get_mbuf();
    assert(likely(mbuf != NULL));

    arp_hdr = (struct arp *)rte_pktmbuf_prepend(mbuf, sizeof(struct arp));
    eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct rte_ether_hdr));
    memcpy(arp_hdr, arp_pkt, sizeof(struct arp));

    logger(LOG_ARP, L_NORMAL, "Sending arp packet");

    if (arp_pkt->opcode == ntohs(ARP_REQ)) {
        logger(LOG_ARP, ALL, "Sending arp request");
        
        eth->ether_type = htons(RTE_ETHER_TYPE_ARP);
        for (i = 0; i < 6; i++) {
            eth->d_addr.addr_bytes[i] = 0xff;
        }

        memcpy(&eth->s_addr.addr_bytes[0], arp_pkt->src_hw_add, sizeof(arp_pkt->hw_len));
    }
    if (arp_pkt->opcode == ntohs(ARP_REPLY)) {
        logger(LOG_ARP, ALL, "Sending arp reply");

        eth->ether_type = htons(RTE_ETHER_TYPE_ARP);
        for (i = 0; i < 6; i++) {
            eth->d_addr.addr_bytes[i] = 0xff;  // should not be a brodcast ideally. fix it.
        }

        // memcpy(&eth->d_addr.addr_bytes[0], arp_pkt->src_hw_add, sizeof(arp_pkt->hw_len));
        memcpy(&eth->s_addr.addr_bytes[0], arp_pkt->src_hw_add, sizeof(arp_pkt->hw_len));
    }

    // fix the below, port should be dfrom routing.
    // send_packet_out(mbuf, 0, 0);
}

int
get_mac(uint32_t ipv4_addr, unsigned char *mac_addr)
{
    struct arp_map *temp = NULL;
    int i;

    logger(LOG_ARP, ALL, "Getting mac for ");
    print_add(ipv4_addr);
    temp = arp_map_list;
    while (temp) {
        if (temp->ipv4_addr == ipv4_addr) {
            memcpy(mac_addr, temp->mac_addr, 6);
            logger(LOG_ARP, L_NORMAL, "mac found");
            for (i = 0; i < 6; i++) {
                //logger(LOG_ARP, L_NORMAL, "%x", temp->mac_addr[i]);
                logger(LOG_ARP, L_NORMAL, "%x", mac_addr[i]);
            }
            return 1;
        }
        temp = temp->next;
    }
    logger(LOG_ARP, L_NORMAL, "No mac found");
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
    
    logger(LOG_ARP, L_NORMAL, "printing arp table.");
    while (temp) {
        len += sprintf(buffer + len, "\n");
        len += sprintf(buffer + len, " IP = ");
        len += print_add_in_buf(temp->ipv4_addr, buffer + len);
        len += sprintf(buffer + len, " mac = ");
        for (i = 0; i < 6; i++) {
            len += sprintf(buffer + len, "%x::", temp->mac_addr[i]);
        }
        len += sprintf(buffer + len, "\n");
        temp = temp->next;
    }

    return len;
}

void
print_arp_table(void)
{
    struct arp_map *temp = NULL;
    int i;

    logger(LOG_ARP, L_NORMAL, "printing arp table.");
    temp = arp_map_list;
    while (temp) {
        log_print(LOG_ARP, L_NORMAL, " IP = ");
        print_add(temp->ipv4_addr);
        log_print(LOG_ARP, L_NORMAL, " mac = ");
        for (i = 0; i < 6; i++) {
            log_print(LOG_ARP, L_NORMAL, "%x::", temp->mac_addr[i]);
        }
        log_print(LOG_ARP, L_NORMAL, "\n");
        temp = temp->next;
    }
}

int
add_mac(uint32_t ipv4_addr, unsigned char *mac_addr)
{
    struct arp_map *temp = NULL;
    struct arp_map *last = NULL;
    int i;

    logger(LOG_ARP, ALL, "Adding mac for ");
    print_add(ipv4_addr);
    for (i = 0; i < 6; i++) {
        log_print(LOG_ARP, ALL, " %x", mac_addr[i]);
    }
    log_print(LOG_ARP, ALL, "\n");

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
        logger(LOG_ARP, ALL, " creating a new arp list.");
    }

    temp->ipv4_addr = ipv4_addr;
    memcpy(temp->mac_addr, mac_addr, 6);
    for (i = 0; i < 6; i++) {
        //printf("%x ", mac_addr);
    }
    //printf("\n");

    return 1;
}
