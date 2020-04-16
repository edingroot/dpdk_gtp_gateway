#include "pktbuf.h"

#include <assert.h>

#include "logger.h"

static struct rte_mempool * pktmbuf_pool = NULL;

int
mbuf_init(void)
{
    if (pktmbuf_pool)
        return -1;

    pktmbuf_pool = rte_mempool_create("mbuf_pool", NB_MBUF,
                    MBUF_SIZE, 32,
                    sizeof(struct rte_pktmbuf_pool_private),
                    rte_pktmbuf_pool_init, NULL,
                    rte_pktmbuf_init, NULL,
                    SOCKET_ID_ANY, // rte_socket_id(),
                    0);

    if (!pktmbuf_pool) {
        logger(LOG_LIB, L_CRITICAL, "mbuf_init failed\n");
    }

    return pktmbuf_pool ? 0 : -1;
}

struct rte_mbuf*
get_mbuf(void)
{
    struct rte_mbuf* buf;
    assert(unlikely(pktmbuf_pool != NULL));

    if (unlikely((buf = rte_pktmbuf_alloc(pktmbuf_pool)) == NULL))
        return NULL;
    else
        return buf;
}
