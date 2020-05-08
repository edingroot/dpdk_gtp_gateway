#include "stats.h"

/* GLOBAL */
pkt_stats_t port_pkt_stats[GTP_CFG_MAX_PORTS] = {0};

static struct rte_timer fetchStats;
static struct rte_timer displayStats;

uint8_t doStatsDisplay = 1;

/* EXTERN */
extern app_confg_t app_config;
extern numa_info_t numa_node_info[GTP_MAX_NUMANODE];

void
sig_extra_stats(__attribute__((unused)) int signo)
{
    int32_t i = 0, ports = rte_eth_dev_count_avail();

    doStatsDisplay = 0;

    /* clear screen */
    STATS_CLR_SCREEN;

    printf(YELLOW "\033[2;1H INTF " RESET);
    printf("\033[3;1H");
    printf(BLUE "*************************************************" RESET);
    printf("\033[10;5H");
    printf(YELLOW " ------------- TX PKT BUFF DETAILS --------" RESET);
    printf("\033[11;1H");
    printf(" +  Type:");
    printf("\033[12;1H");
    printf(" +   Ver:");
    printf("\033[13;1H");
    printf(" + Index:");
    printf("\033[18;1H");
    printf(YELLOW " NUMA " RESET);
    printf("\033[19;1H");
    printf(BLUE "*************************************************" RESET);
    printf("\033[20;1H");
    printf(" + LCORE in Use: ");
    printf("\033[21;1H");
    printf(" + INTF in Use: ");
    printf("\033[30;1H");
    printf(BLUE "*************************************************" RESET);

    for (; i < ports; i++) {
        printf("\033[2;%dH", (15 + 10 * i));
        printf(" %8u ", i);
        printf("\033[11;%dH", (15 + 10 * i));
        printf(" %8u ", app_config.gtp_ports[i].gtp_type);
        printf("\033[13;%dH", (15 + 10 * i));
        printf(" %8u ", app_config.gtp_ports[i].pkt_index); // not used
    }

    for (i = 0; i < GTP_MAX_NUMANODE; i++) {
        printf("\033[18;%dH", (15 + 10 * i));
        printf(" %8u ", i);
        printf("\033[20;%dH", (15 + 10 * i));
        printf(" %8u ", numa_node_info[i].lcoreUsed);
        printf("\033[21;%dH", (15 + 10 * i));
        printf(" %8u ", numa_node_info[i].intfUsed);
    }

    fflush(stdout);
    rte_delay_ms(10000);

    show_static_display();

    doStatsDisplay = 1;
    return;
}

void
sig_config(__attribute__((unused)) int signo)
{
}

void get_link_stats(__attribute__((unused)) struct rte_timer *t,
                    __attribute__((unused)) void *arg) {
    int32_t i, ports = rte_eth_dev_count_avail();
    static uint64_t rx_currStat[GTP_CFG_MAX_PORTS] = {0};
    static uint64_t tx_currStat[GTP_CFG_MAX_PORTS] = {0};
    // static uint64_t rx_prevStat[GTP_CFG_MAX_PORTS] = {0};
    // static uint64_t tx_prevStat[GTP_CFG_MAX_PORTS] = {0};

    /* get link status for DPDK ports */
    struct rte_eth_stats stats;

    for (i = 0; i < ports; i++) {
        /* ToDo: use numa info to identify the ports */
        if (likely(rte_eth_stats_get(i, &stats) == 0)) {
            rx_currStat[i] = stats.ipackets;
            tx_currStat[i] = stats.opackets;

            // port_pkt_stats[i].rxPkts = (rx_currStat[i] - rx_prevStat[i]);
            // port_pkt_stats[i].txPkts = (tx_currStat[i] - tx_prevStat[i]);
            port_pkt_stats[i].rxPkts = rx_currStat[i];
            port_pkt_stats[i].txPkts = tx_currStat[i];

            // rx_prevStat[i] = stats.ipackets;
            // tx_prevStat[i] = stats.opackets;

            port_pkt_stats[i].rxBytes = stats.ibytes / (1024 * 1024);
            port_pkt_stats[i].txBytes = stats.obytes / (1024 * 1024);
            port_pkt_stats[i].rxMissed = stats.imissed;
            port_pkt_stats[i].rxErr = stats.ierrors;
            port_pkt_stats[i].txErr = stats.oerrors;
            port_pkt_stats[i].rxNoMbuff = stats.rx_nombuf;
        }
    }

    return;
}

void get_process_stats(__attribute__((unused)) struct rte_timer *t,
                       __attribute__((unused)) void *arg) {
    int32_t i, ports = rte_eth_dev_count_avail();

    if (likely(doStatsDisplay)) {
        for (i = 0; i < ports; i++) {
            /* Display calculated stats */

            /*NUMA_SOCKET*/
            printf("\033[4;%dH", (15 + 10 * i));
            //printf("%-8d |", );

            /*PKTS_PER_SEC_RX*/
            printf("\033[5;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].rxPkts);

            /*PKTS_PER_SEC_TX*/
            printf("\033[6;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].txPkts);

            /*MB_RX*/
            printf("\033[7;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].rxBytes);

            /*MB_TX*/
            printf("\033[8;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].txBytes);

            /* INTF STATS */
            /* Drop */
            printf("\033[11;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].dropped);

            /* RX miss */
            printf("\033[12;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].rxMissed);

            /* RX err */
            printf("\033[13;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].rxErr);

            /* RX no mbuf */
            printf("\033[14;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].rxNoMbuff);

            /* TX err */
            printf("\033[15;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].txErr);

            /*GTPU_RX_IPV4*/
            printf("\033[18;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].rx_gptu_ipv4);

            /*GTPU_RX_IPV6*/
            printf("\033[19;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].rx_gptu_ipv6);

            /*ERR NON IPV4*/
            printf("\033[22;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].non_ipv4);

            /*ERR NON UDP*/
            printf("\033[23;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].non_udp);

            /*ERR NON GTP*/
            printf("\033[24;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].non_gtp);

            /*ERR GTP ver*/
            printf("\033[25;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].non_gtpVer);

            /*ERR IP FRAG*/
            printf("\033[26;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].ipFrag);

            /*ERR IP CSUM*/
            printf("\033[27;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].ipCsumErr);

            /*ERR UDP CSUM*/
            printf("\033[28;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].udpCsumErr);

            /*TX GTPU*/
            printf("\033[31;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].tx_gptu);

            /*ENCAP ERR*/
            printf("\033[32;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].encap_err);

            /*DECAP ERR*/
            printf("\033[33;%dH", (15 + 10 * i));
            printf("  %-12lu ", port_pkt_stats[i].decap_err);
        }
    }

    fflush(stdout);
    return;
}

void
show_static_display(void)
{
    struct rte_eth_link link;
    int32_t i, ports = rte_eth_dev_count_avail();

    /* clear screen */
    STATS_CLR_SCREEN;

    /* stats header */
    printf("\033[2;1H");
    printf(" %-10s | ", "Cat|Intf");
    printf("\033[3;1H");
    printf(BLUE "======================================================" RESET);

    /*NUMA_SOCKET*/
    /*LINK_SPEED_STATE*/
    printf("\033[4;1H");
    printf(BLUE " %-10s | ", "Speed-Dup");

    /*PKTS_PER_SEC_RX*/
    printf("\033[5;1H");
    printf(BLUE " %-10s | ", "RX pkts/s");

    /*PKTS_PER_SEC_TX*/
    printf("\033[6;1H");
    printf(BLUE " %-10s | ", "TX pkts/s");

    /*MB_RX*/
    printf("\033[7;1H");
    printf(BLUE " %-10s | ", "RX MB");

    /*MB_TX*/
    printf("\033[8;1H");
    printf(BLUE " %-10s | " RESET, "TX MB");

    /*PKT_INFO*/
    printf("\033[10;1H");
    printf(CYAN " %-25s " RESET, "---------- INTF STATS ----------");

    /* Dropped */
    printf("\033[11;1H");
    printf(RED " %-10s | ", "DROP");

    /* RX miss*/
    printf("\033[12;1H");
    printf(RED " %-10s | ", "RX MISS");

    /* RX Err */
    printf("\033[13;1H");
    printf(RED " %-10s | ", "RX ERR");

    /* RX no Mbuf */
    printf("\033[14;1H");
    printf(RED " %-10s | " RESET, "RX no MBUF");

    /* TX Err */
    printf("\033[15;1H");
    printf(RED " %-10s | " RESET, "TX ERR");

    printf("\033[17;1H");
    printf(CYAN " %-25s " RESET, "------- GTP PKT STATS -------");

    /*GTPU_RX_IPV4*/
    printf("\033[18;1H");
    printf(YELLOW " %-10s | ", "RX V1U-4");

    /*GTPU_RX_IPV6*/
    printf("\033[19;1H");
    printf(YELLOW " %-10s | " RESET, "RX V1U-6");

    printf("\033[21;1H");
    printf(CYAN " %-25s " RESET, "-------- PKT ERR STATS --------");

    /*NON IPv4*/
    printf("\033[22;1H");
    printf(MAGENTA " %-10s | ", "NON IPv4");

    /*NON UDP*/
    printf("\033[23;1H");
    printf(MAGENTA " %-10s | ", "NON UDP");

    /*NON GTP*/
    printf("\033[24;1H");
    printf(MAGENTA " %-10s | ", "NON GTP");

    /*NON GTP VER*/
    printf("\033[25;1H");
    printf(MAGENTA " %-10s | ", "GTP E_VER");

    /*IP FRAG*/
    printf("\033[26;1H");
    printf(MAGENTA " %-10s | ", "IP FRAG");

    /*IP CHECKSUM*/
    printf("\033[27;1H");
    printf(MAGENTA " %-10s | ", "IP CSUM");

    /*UDP CHECKSUM*/
    printf("\033[28;1H");
    printf(MAGENTA " %-10s | " RESET, "UDP CSUM");

    printf("\033[30;1H");
    printf(CYAN " %-25s " RESET, "-------- GTP PROC STATS --------");

    /*TX GTPU*/
    printf("\033[31;1H");
    printf(BOLDRED " %-10s | ", "TX GTPU");

    /*ENCAP ERR*/
    printf("\033[32;1H");
    printf(BOLDRED " %-10s | ", "ENCAP ERR");

    /*DECAP ERR*/
    printf("\033[33;1H");
    printf(BOLDRED " %-10s | ", "DECAP ERR");

    /* fetch port info and display */
    for (i = 0; i < ports; i++) {
        rte_eth_link_get_nowait(i, &link);

        /* DPDK port id - up|down */
        printf("\033[2;%dH", (15 + 10 * i));
        if (link.link_status)
            printf("  %d-" GREEN "up" RESET, i);
        else
            printf("  %d-" RED "down" RESET, i);

        /*LINK_SPEED_STATE*/
        printf("\033[4;%dH", (15 + 10 * i));
        printf(" %5d-%-2s ",
               ((link.link_speed == ETH_SPEED_NUM_10M) ? 10 :
                (link.link_speed == ETH_SPEED_NUM_100M) ? 100 :
                (link.link_speed == ETH_SPEED_NUM_1G) ? 1000 :
                (link.link_speed == ETH_SPEED_NUM_10G) ? 10000 : 0),
               ((link.link_duplex == ETH_LINK_HALF_DUPLEX) ? "HD" : "FD"));
    }

    fflush(stdout);
    return;
}

void
set_stats_timer(void)
{
    int32_t lcoreId = rte_get_master_lcore();

    rte_timer_subsystem_init();

    /* initialize the stats fetch and display timers */
    rte_timer_init(&fetchStats);
    rte_timer_init(&displayStats);

    /* periodic reload for every `period` sec for stats fetch and display */
    uint64_t hz = rte_get_timer_hz();
    double period = 0.5;
    rte_timer_reset(&fetchStats, hz * period, PERIODICAL, lcoreId, get_link_stats, NULL);
    rte_timer_reset(&displayStats, hz * period, PERIODICAL, lcoreId, get_process_stats, NULL);

    return;
}
