#include <assert.h>
#include <rte_ip_frag.h>
#include <rte_bus_pci.h>

#include "logger.h"
#include "pktbuf.h"
#include "netstack/arp.h"
#include "netstack/ether.h"

#include "config.h"
#include "node.h"
#include "stats.h"
#include "gtp_process.h"

/* DEFINES */
#define MAX_RX_BURST_COUNT 8
#define PREFETCH_OFFSET 4

/* GLOBALS */

/* EXTERN */
extern app_confg_t app_config;
extern numa_info_t numa_node_info[GTP_MAX_NUMANODE];
extern pkt_stats_t port_pkt_stats[GTP_CFG_MAX_PORTS];

static int add_interfaces(void);
static __rte_always_inline int pkt_handler(void *arg);
static __rte_always_inline void process_pkt_mbuf(struct rte_mbuf *m, uint8_t port);

int
main(int argc, char **argv) {
    int32_t i;
    int32_t ret;

    logger_init();

    // Initialize DPDK EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        printf("\n ERROR: cannot init EAL\n");
        return -2;
    }

    // Check Huge pages for memory buffers
    ret = rte_eal_has_hugepages();
    if (ret < 0) {
        rte_panic("\n ERROR: no Huge Page\n");
        exit(EXIT_FAILURE);
    }

    // Load ini config file
    ret = load_gtp_config();
    if (ret < 0) {
        printf("\n ERROR: failed to load config\n");
        return -1;
    }

    // Create packet buffer pool
    ret = mbuf_init();
    assert(ret == 0);

    ret = populate_node_info();
    if (ret < 0) {
        rte_panic("\n ERROR: in populating NUMA node Info\n");
        exit(EXIT_FAILURE);
    }
    printf("\n");

    // Init ARP table
    ret = arp_init(0);
    assert(ret == 0);

    // Add interface info to interface and arp table
    ret = add_interfaces();
    assert(ret == 0);

    // Set interface options and queues
    if (node_interface_setup() < 0) {
        rte_panic("ERROR: interface setup Failed\n");
        exit(EXIT_FAILURE);
    }

    // Launch thread lcores
    ret = rte_eth_dev_count_avail();
    for (i = 0; i < ret; i++) {
        rte_eal_remote_launch(pkt_handler, (void *)&i, i + 1);
    }

    // Register signals
    signal(SIGUSR1, sigExtraStats);
    signal(SIGUSR2, sigConfig);

    // Show stats
    printf("\n DISP_STATS=%s\n", app_config.disp_stats ? "ON" : "OFF");
    if (app_config.disp_stats) {
        set_stats_timer();
        rte_delay_ms(1000);
        show_static_display();
    }

    do {
        rte_delay_ms(1000);
        if (app_config.disp_stats) {
            show_static_display();
        }
        rte_timer_manage();
    } while (1);

    return 0;
}

static int
add_interfaces(void)
{
    int32_t i;
    struct rte_ether_addr addr;

    if (app_config.gtp_port_count != rte_eth_dev_count_avail()) {
        logger(LOG_APP, L_CRITICAL,
            "Number of interface in config (%d) does not match avail dpdk eth dev (%d)\n",
            app_config.gtp_port_count, rte_eth_dev_count_avail());

        if (app_config.gtp_port_count > rte_eth_dev_count_avail()) {
            logger(LOG_APP, L_CRITICAL, "Aborting.\n");
            return -1;
        }
    }

    for (i = 0; i < rte_eth_dev_count_avail(); i++) {
        interface_t iface;
        rte_eth_macaddr_get(i, &addr);

        iface.iface_num = i;
        iface.ipv4_addr = app_config.gtp_ports[i].ipv4;
        memcpy(iface.hw_addr, addr.addr_bytes, sizeof(iface.hw_addr));

        add_interface(&iface);
    }

    return 0;
}

static __rte_always_inline int
pkt_handler(void *arg)
{
    uint8_t port = *((uint8_t *)arg);
    int32_t j, nb_rx;
    unsigned lcore_id, socket_id;
    struct rte_mbuf *ptr[MAX_RX_BURST_COUNT], *m = NULL;

    lcore_id = rte_lcore_id();
    socket_id = rte_lcore_to_socket_id(lcore_id);

    // TODO: if mempool is per port ignore the below
    // mbuf_pool_tx = numa_node_info[socket_id].tx[0];
    // mbuf_pool_rx = numa_node_info[socket_id].rx[port];

    printf("\n Launched handler for port %d on socket %d \n", port, socket_id);
    fflush(stdout);

    while (1) {
        // Fetch MAX Burst RX packets
        nb_rx = rte_eth_rx_burst(port, 0, ptr, MAX_RX_BURST_COUNT);

        if (likely(nb_rx)) {
            // rte_pktmbuf_dump(stdout, ptr[0], 64);

            // Prefetch packets for pipeline
            for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++) {
                rte_prefetch0(rte_pktmbuf_mtod(ptr[j], void *));
            }

            // Prefetch others packets and process packets
            for (j = 0; j < nb_rx - PREFETCH_OFFSET; j++) {
                m = ptr[j];
                rte_prefetch0(rte_pktmbuf_mtod(ptr[j + PREFETCH_OFFSET], void *));
                process_pkt_mbuf(m, port);
            }

            // Process remaining packets
            for (; j < nb_rx; j++) {
                m = ptr[j];
                process_pkt_mbuf(m, port);
            }
        }
    }

    return 0;
}

static __rte_always_inline void
process_pkt_mbuf(struct rte_mbuf *m, uint8_t port)
{
    struct rte_ether_hdr *eth_hdr = NULL;
    struct rte_ipv4_hdr *ip_hdr = NULL;
    struct rte_udp_hdr *udp_hdr = NULL;
    gtpv1_t *gtp1_hdr = NULL;

    eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    // printf("\n [RX] Port#%u Ether(type:0x%x dst mac: %x:%x:%x:%x:%x:%x) ",
    //     m->port, eth_hdr->ether_type,
    //     eth_hdr->d_addr.addr_bytes[0], eth_hdr->d_addr.addr_bytes[1],
    //     eth_hdr->d_addr.addr_bytes[2], eth_hdr->d_addr.addr_bytes[3],
    //     eth_hdr->d_addr.addr_bytes[4], eth_hdr->d_addr.addr_bytes[5]);

    // Ether type: IPv4 (rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) = 0x8)
    if (likely(eth_hdr->ether_type == 0x8)) {
        ip_hdr = (struct rte_ipv4_hdr *)((char *)(eth_hdr + 1));
        // printf(" IPv4(");
        // print_rte_ipv4(ip_hdr->src_addr);
        // printf(" -> ");
        // print_rte_ipv4(ip_hdr->dst_addr);
        // printf(") ");

        // Check IP is fragmented
        if (unlikely(rte_ipv4_frag_pkt_is_fragmented(ip_hdr))) {
            port_pkt_stats[port].ipFrag += 1;
            rte_free(m);
            return;
        }

        // Check for UDP
        // printf(" protocol: %x ", ip_hdr->next_proto_id);
        if (likely(ip_hdr->next_proto_id == 0x11)) {
            udp_hdr = (struct rte_udp_hdr *)((char *)(ip_hdr + 1));
            // printf(" UDP(port src:%d dst:%d) ",
            //     rte_cpu_to_be_16(udp_hdr->src_port),
            //     rte_cpu_to_be_16(udp_hdr->dst_port));

            /* GTPU LTE carries V1 only 2152 (htons(2152) = 0x6808) */
            if (likely(udp_hdr->src_port == 0x6808 ||
                       udp_hdr->dst_port == 0x6808)) {
                gtp1_hdr = (gtpv1_t *)((char *)(udp_hdr + 1));
                // printf(" GTP-U(type:0x%x, teid:%d) ", gtp1_hdr->type, ntohl(gtp1_hdr->teid));

                // Check if gtp version is 1
                if (unlikely(gtp1_hdr->flags >> 5 != 1)) {
                    printf(" NonGTPVer(gtp1_hdr->ver:%d)\n", gtp1_hdr->flags >> 5);
                    port_pkt_stats[port].non_gtpVer += 1;
                    rte_pktmbuf_free(m);
                    return;
                }

                // Check if msg type is PDU
                if (unlikely(gtp1_hdr->type != 0xff)) {
                    printf(" DROP(gtp1_hdr->type:%d)\n", gtp1_hdr->type);
                    port_pkt_stats[port].dropped += 1;
                    rte_pktmbuf_free(m);
                    return;
                }

                // GTP decap / forward
                if (likely(process_gtpv1(m, port, ip_hdr, gtp1_hdr) > 0)) {
                    return;
                } else {
                    printf(" ERR(failed to TX)\n");
                }
            } else {
                port_pkt_stats[port].non_gtp += 1;
            } /* (unlikely(udp_hdr->src|dst_port != 2123)) */
        } else {
            port_pkt_stats[port].non_udp += 1;
        } /* (unlikely(ip_hdr->next_proto_id != 0x11)) */

        // GTP encap
        if (likely(process_ipv4(m, port, ip_hdr) > 0)) {
            return;
        }

    } else {
        port_pkt_stats[port].non_ipv4 += 1;

        // Ether type: ARP
        if (unlikely(eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP))) {
            arp_in(m);
            return;
        }
    } /* (likely(eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))) */

    // Test: forward all non-gtpu packets
    // int32_t ret = rte_eth_tx_burst(port ^ 1, 0, &m, 1);
    // if (likely(ret == 1)) {
    //     return;
    // }

    rte_pktmbuf_free(m);
}
