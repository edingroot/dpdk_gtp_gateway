#ifndef __MBUF_H_
#define __MBUF_H_

#include <rte_mbuf.h>

#define NB_MBUF          24000
#define MBUF_BUFFER_LEN  2000
#define MBUF_SIZE        (MBUF_BUFFER_LEN + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

int
mbuf_init(void);

struct rte_mbuf*
get_mbuf(void);

#endif /* __MBUF_H_ */
