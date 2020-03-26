#include "config.h"
#include "gtpProcess.h"
#include "node.h"
#include "stats.h"

/* DEFINES */
#define MAX_RX_BURST_COUNT 8
#define PREFETCH_OFFSET 4
#define CREATE_PDP_CONTEXT_REQ 16 /*Create PDP Context Request*/

#define DEBUG_INFO 0

/* GLOBALS */

/* EXTERN */
extern uint8_t gtpConfigCount;
extern port_gtpConfig_t gtpConfig[GTP_PKTGEN_MAXPORTS];
extern const char gtpU[GTPU_MAXCOUNT][1500];
extern numa_Info_t numaNodeInfo[GTP_MAX_NUMANODE];
extern pkt_stats_t prtPktStats[GTP_PKTGEN_MAXPORTS];

static int pktDecode_Handler(void *arg) {
    uint8_t port = *((uint8_t *)arg);
    unsigned lcore_id, socket_id;
    int32_t j, nb_rx, ret;

    struct rte_mbuf *ptr[MAX_RX_BURST_COUNT], *m = NULL;

    struct rte_ether_hdr *ethHdr = NULL;
    struct rte_ipv4_hdr *ipHdr = NULL;
    struct rte_udp_hdr *udpHdr = NULL;

    gtpv1_t *gtp1Hdr = NULL;
    struct rte_ipv4_hdr *ipUeHdr = NULL;

    lcore_id = rte_lcore_id();
    socket_id = rte_lcore_to_socket_id(lcore_id);

    /* ToDo: if mempool is per port ignore the below*/
    //mbuf_pool_tx = numaNodeInfo[socket_id].tx[0];
    //mbuf_pool_rx = numaNodeInfo[socket_id].rx[port];

    printf("\n Launched handler for port %d on socket %d \n", port, socket_id);
    fflush(stdout);

    while (1) {
        /* fetch MAX Burst RX Packets */
        nb_rx = rte_eth_rx_burst(port, 0, ptr, MAX_RX_BURST_COUNT);

        if (likely(nb_rx)) {
            //rte_pktmbuf_dump (stdout, ptr[0], 64);

            /* prefetch packets for pipeline */
            for (j = 0; ((j < PREFETCH_OFFSET) &&
                         (j < nb_rx));
                 j++) {
                rte_prefetch0(rte_pktmbuf_mtod(ptr[j], void *));
            } /* for loop till PREFETCH_OFFSET */

            for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
                /* Prefetch others packets */
                m = ptr[j];
                rte_prefetch0(rte_pktmbuf_mtod(ptr[j + PREFETCH_OFFSET], void *));

                ethHdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

                /* check for IPv4 */
                //printf("\n ether type : %x\n", ethHdr->ether_type);
                if (likely(ethHdr->ether_type == 0x8)) {
                    printf("\n dst MAC: %x:%x:%x:%x:%x:%x port %u ",
                        ethHdr->d_addr.addr_bytes[0], ethHdr->d_addr.addr_bytes[1],
                        ethHdr->d_addr.addr_bytes[2], ethHdr->d_addr.addr_bytes[3],
                        ethHdr->d_addr.addr_bytes[4], ethHdr->d_addr.addr_bytes[5],
                        m->port);

                    ipHdr = (struct rte_ipv4_hdr *)((char *)(ethHdr + 1));

                    /* check IP is fragmented */
                    if (unlikely(ipHdr->fragment_offset & 0xfffc)) {
                        prtPktStats[port].ipFrag += 1;
                        rte_free(m);
                        continue;
                    }

                    /* check for UDP */
                    //printf("\n protocol: %x\n", ipHdr->next_proto_id);
                    if (likely(ipHdr->next_proto_id == 0x11)) {
                        udpHdr = (struct rte_udp_hdr *)((char *)(ipHdr + 1));
                        //printf("\n Port src: %x dst: %x\n", udpHdr->src_port, udpHdr->dst_port);

                        /* GTPU LTE carries V1 only 2152*/
                        if (unlikely((udpHdr->src_port == 0x6808) ||
                                     (udpHdr->dst_port == 0x6808))) {
                            gtp1Hdr = (gtpv1_t *)((char *)(udpHdr + 1));

                            /* check if gtp version is 1 */
                            if (unlikely(gtp1Hdr->vr != 1)) {
                                prtPktStats[port].non_gtpVer += 1;
                                rte_free(m);
                                continue;
                            }

                            /* check if msg type is PDU */
                            if (unlikely(gtp1Hdr->msgType == 0xff)) {
                                prtPktStats[port].dropped += 1;
                                rte_free(m);
                                continue;
                            }

                            // TODO: check correctness
                            ipUeHdr = (struct rte_ipv4_hdr *)(((char *)(udpHdr + 1)));

                            if (unlikely(ipUeHdr->version_ihl & 0x40) != 0x40) {
                                prtPktStats[port].rx_gptu_ipv6 += 1;
                            } else {
                                prtPktStats[port].rx_gptu_ipv4 += 1;
                            }

                            ret = rte_eth_tx_burst(port, 0, &m, 1);
                            if (likely(ret == 1)) {
                                continue;
                            }
                        } else {
                            prtPktStats[port].non_gtp += 1;
                        } /* (unlikely(udpHdr->src|dst_port != 2123)) */
                    } else {
                        prtPktStats[port].non_udp += 1;
                    } /* (unlikely(ipHdr->next_proto_id != 0x11)) */

                } else {
                    prtPktStats[port].non_ipv4 += 1;
                } /* (unlikely(ethHdr->ether_type != 0x0008)) */

                rte_pktmbuf_free(m);
                continue;
            } /* end fo for loop for nb_rx - PREFETCH_OFFSET */

            for (; j < nb_rx; j++) {
                m = ptr[j];

                ethHdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

                /* check for IPv4 */
                //printf("\n ether type : %x\n", ethHdr->ether_type);
                if (likely(ethHdr->ether_type == 0x8)) {
                    /*
                    printf("\n dst MAC: %x:%x:%x:%x:%x:%x port %u ",
                        ethHdr->d_addr.addr_bytes[0], ethHdr->d_addr.addr_bytes[1],
                        ethHdr->d_addr.addr_bytes[2], ethHdr->d_addr.addr_bytes[3],
                        ethHdr->d_addr.addr_bytes[4], ethHdr->d_addr.addr_bytes[5],
                        m->port);
*/
                    ipHdr = (struct rte_ipv4_hdr *)((char *)(ethHdr + 1));

                    /* check IP is fragmented */
                    if (unlikely(ipHdr->fragment_offset & 0xfffc)) {
                        prtPktStats[port].ipFrag += 1;
                        rte_free(m);
                        continue;
                    }

                    /* check for UDP */
                    //printf("\n protocol: %x\n", ipHdr->next_proto_id);
                    if (likely(ipHdr->next_proto_id == 0x11)) {
                        udpHdr = (struct rte_udp_hdr *)((char *)(ipHdr + 1));
                        //printf("\n Port src: %x dst: %x\n", udpHdr->src_port, udpHdr->dst_port);

                        /* GTPU LTE carries V1 only 2152*/
                        if (unlikely((udpHdr->src_port == 0x6808) ||
                                     (udpHdr->dst_port == 0x6808))) {
                            prtPktStats[port].rx_gptu_ipv4 += 1;

                            gtp1Hdr = (gtpv1_t *)((char *)(udpHdr + 1));

                            /* check if gtp version is 1 */
                            if (unlikely(gtp1Hdr->vr != 1)) {
                                prtPktStats[port].non_gtpVer += 1;
                                rte_free(m);
                                continue;
                            }

                            /* check if msg type is PDU */
                            if (unlikely(gtp1Hdr->msgType == 0xff)) {
                                prtPktStats[port].dropped += 1;
                                rte_free(m);
                                continue;
                            }

                            // TODO: check correctness
                            ipUeHdr = (struct rte_ipv4_hdr *)(((char *)(udpHdr + 1)));

                            if (unlikely(ipUeHdr->version_ihl & 0x40) != 0x40) {
                                prtPktStats[port].rx_gptu_ipv6 += 1;
                            } else {
                                prtPktStats[port].rx_gptu_ipv4 += 1;
                            }

                            ret = rte_eth_tx_burst(port, 0, &m, 1);
                            if (likely(ret == 1)) {
                                continue;
                            }
                        } else {
                            prtPktStats[port].non_gtp += 1;
                        } /* (unlikely(udpHdr->src|dst_port != 2123)) */
                    } else {
                        prtPktStats[port].non_udp += 1;
                    } /* (unlikely(ipHdr->next_proto_id != 0x11)) */

                } else {
                    prtPktStats[port].non_ipv4 += 1;
                } /* (unlikely(ethHdr->ether_type != 0x0008)) */

                rte_pktmbuf_free(m);
                continue;
            } /* end of for loop */

        } /* end of packet count check */
    }

    return 0;
}

int main(int argc, char **argv) {
    int32_t i;
    int32_t ret;

    /* Load INI configuration for fetching GTP port details */
    ret = loadGtpConfig();
    if (unlikely(ret < 0)) {
        printf("\n ERROR: failed to load config\n");
        return -1;
    }

    /* Initialize DPDK EAL */
    ret = rte_eal_init(argc, argv);
    if (unlikely(ret < 0)) {
        printf("\n ERROR: cannot init EAL\n");
        return -2;
    }

    /* check Huge pages for memory buffers */
    ret = rte_eal_has_hugepages();
    if (unlikely(ret < 0)) {
        rte_panic("\n ERROR: no Huge Page\n");
        exit(EXIT_FAILURE);
    }

    ret = populateNodeInfo();
    if (unlikely(ret < 0)) {
        rte_panic("\n ERROR: in populating NUMA node Info\n");
        exit(EXIT_FAILURE);
    }

    /* launch functions for specified cores */
    if (interfaceSetup() < 0) {
        rte_panic("ERROR: interface setup Failed\n");
        exit(EXIT_FAILURE);
    }

    /*Launch thread lcores*/
    ret = rte_eth_dev_count_avail();
    for (i = 0; i < ret; i++) {
        rte_eal_remote_launch(pktDecode_Handler, (void *)&i, i + 1);
    }

    /* Register Signal */
    signal(SIGUSR1, sigExtraStats);
    signal(SIGUSR2, sigConfig);

    set_stats_timer();
    rte_delay_ms(2000);
    show_static_display();

    do {
        rte_delay_ms(1000);
        rte_timer_manage();
    } while (1);
}
