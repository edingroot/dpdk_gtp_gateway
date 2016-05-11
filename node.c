#include "node.h"

/* GLOBAL */
numa_Info_t numaNodeInfo[GTP_MAX_NUMANODE];

static const struct rte_eth_conf portConf = {
    .rxmode = {
        .split_hdr_size = 0,
        .header_split   = 0, /**< Header Split disabled */
        .hw_ip_checksum = 0, /**< IP checksum offload disabled */
        .hw_vlan_filter = 0, /**< VLAN filtering disabled */
        .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
        .hw_strip_crc   = 0, /**< CRC stripped by hardware */
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

int32_t populateNodeInfo (void)
{
    int32_t i = 0, socketId = -1, lcoreIndex = 0, enable = 0;
    uint8_t coreCount, portCount;
    struct rte_eth_dev_info devInfo;

    /* fetch total lcore count under DPDK */
    coreCount = rte_lcore_count();
    for (i = 0; i < coreCount; i++)
    {
       socketId = rte_lcore_to_socket_id(i);
       lcoreIndex = rte_lcore_index(i);
       enable = rte_lcore_is_enabled(i);

       //printf ("\n Logical %d Physical %d Socket %d Enabled %d \n",
       //        i, lcoreIndex, socketId, enable);

       if (likely(enable)) {
           /* classify the lcore info per NUMA node */
           numaNodeInfo[socketId].lcoreAvail = numaNodeInfo[socketId].lcoreAvail | (1 << lcoreIndex);
           numaNodeInfo[socketId].lcoreTotal += 1;
       }
       else {
            rte_panic("ERROR: Lcore %d Socket %d not enabled\n", lcoreIndex, socketId);
            exit(EXIT_FAILURE);
       }
    }

    /* Create mempool per numa node based on interface available */
    portCount = rte_eth_dev_count();
    for (i =0; i < portCount; i++)
    {
        rte_eth_dev_info_get(i, &devInfo);
        printf("\n Inteface %d", i);
        printf("\n - driver: %s", devInfo.driver_name);
        printf("\n - if_index: %d", devInfo.if_index);
        if (devInfo.pci_dev) {
            printf("\n - PCI INFO ");
            printf("\n -- ADDR - domain:bus:devid:function %x:%x:%x:%x",
                  devInfo.pci_dev->addr.domain,
                  devInfo.pci_dev->addr.bus,
                  devInfo.pci_dev->addr.devid,
                  devInfo.pci_dev->addr.function);
            printf("\n == PCI ID - vendor:device:sub-vendor:sub-device %x:%x:%x:%x",
                  devInfo.pci_dev->id.vendor_id,
                  devInfo.pci_dev->id.device_id,
                  devInfo.pci_dev->id.subsystem_vendor_id,
                  devInfo.pci_dev->id.subsystem_device_id);
            printf("\n -- numa node: %d", devInfo.pci_dev->numa_node);
        }

        socketId = (devInfo.pci_dev->numa_node == -1)?0:devInfo.pci_dev->numa_node;
        numaNodeInfo[socketId].intfAvail = numaNodeInfo[socketId].intfAvail | (1 << i);
        numaNodeInfo[socketId].intfTotal += 1;
    }

    /* allocate mempool for numa which has NIC interfaces */
    for (i = 0; i < GTP_MAX_NUMANODE; i++)
    {
        if (likely(numaNodeInfo[i].intfAvail)) {
            /* ToDo: per interface */
            uint8_t portIndex = 0;
            char mempoolName[25];

            /* create mempool for TX */
            sprintf(mempoolName, "mbuf_pool-%d-%d-tx", i, portIndex);
            numaNodeInfo[i].tx[portIndex] = rte_mempool_create(
                        mempoolName, NB_MBUF,
                        MBUF_SIZE, 64,
                        sizeof(struct rte_pktmbuf_pool_private),
                        rte_pktmbuf_pool_init, NULL,
                        rte_pktmbuf_init, NULL,
                        i,/*SOCKET_ID_ANY*/
                         0/*MEMPOOL_F_SP_PUT*/);
            if (unlikely(numaNodeInfo[i].tx[portIndex] == NULL)) {
                rte_panic("\n ERROR: failed to get mem-pool for tx on node %d intf %d\n", i, portIndex);
                exit(EXIT_FAILURE);
            }

            /* create mempool for RX */
            sprintf(mempoolName, "mbuf_pool-%d-%d-rx", i, portIndex);
            numaNodeInfo[i].rx[portIndex] = rte_mempool_create(
                        mempoolName, NB_MBUF,
                        MBUF_SIZE, 64,
                        sizeof(struct rte_pktmbuf_pool_private),
                        rte_pktmbuf_pool_init, NULL,
                        rte_pktmbuf_init, NULL,
                        i,/*SOCKET_ID_ANY*/
                         0/*MEMPOOL_F_SP_PUT*/);
            if (unlikely(numaNodeInfo[i].rx[portIndex] == NULL)) {
                rte_panic("\n ERROR: failed to get mem-pool for rx on node %d intf %d\n", i, portIndex);
                exit(EXIT_FAILURE);
            }

        }
    }

    return 0;
}

int32_t interfaceSetup(void)
{
    uint8_t portIndex = 0, portCount = rte_eth_dev_count();
    int32_t ret = 0, socket_id = -1;
    struct rte_eth_link link;

    for (portIndex = 0; portIndex < portCount; portIndex++)
    {
        /* fetch the socket Id to which the port the mapped */
        for (ret = 0; ret < GTP_MAX_NUMANODE; ret++)
        {
            if (numaNodeInfo[ret].intfTotal) {
                if (numaNodeInfo[ret].intfAvail & (1 << portIndex)) {
                    socket_id = ret;
                    break;
                }
            }
        }

        memset(&link, 0x00, sizeof(struct rte_eth_link));
        ret = rte_eth_dev_configure(portIndex, 1, 1, &portConf);
        if (unlikely(ret < 0))
        {
            rte_panic("ERROR: Dev Configure\n");
            return -1;
        }

        ret = rte_eth_rx_queue_setup(portIndex, 0, RTE_TEST_RX_DESC_DEFAULT,
                                     0, NULL, numaNodeInfo[socket_id].rx[0]);
        if (unlikely(ret < 0))
        {
            rte_panic("ERROR: Rx Queue Setup\n");
            return -2;
        }

        ret = rte_eth_tx_queue_setup(portIndex, 0, RTE_TEST_TX_DESC_DEFAULT,
                                     0, NULL);
        if (unlikely(ret < 0))
        {
            rte_panic("ERROR: Tx Queue Setup\n");
            return -3;
        }

        rte_eth_promiscuous_enable(portIndex);
        rte_eth_dev_start(portIndex);
    }

    return 0;
}


