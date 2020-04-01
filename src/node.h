#ifndef __NODE__
#define __NODE__

#include "config.h"

/* DEFINES */
#define RTE_TEST_TX_DESC_DEFAULT (4096)
#define RTE_TEST_RX_DESC_DEFAULT (1024)

/* STRUCTURES */
typedef struct numa_info_s {
    struct rte_mempool *tx[GTP_MAX_LCORECOUNT];
    struct rte_mempool *rx[GTP_MAX_LCORECOUNT];

    uint32_t lcoreAvail;
    uint32_t intfAvail;
    uint32_t lcoreUsed;
    uint32_t intfUsed;

    uint8_t lcoreTotal;
    uint8_t intfTotal;
    uint8_t lcoreInUse;
    uint8_t intfInUse;
} numa_info_t;

/* FUNCTION DECLARATION */
int32_t populate_node_info(void);
int32_t node_interface_setup(void);

#endif /* __NODE__ */
