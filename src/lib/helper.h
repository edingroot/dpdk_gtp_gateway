#ifndef __HELPER_H_
#define __HELPER_H_

#include <rte_common.h>
#include <rte_ethdev.h>

static __rte_always_inline void
print_rte_ipv4(rte_be32_t addr4)
{
    struct in_addr addr = {.s_addr = addr4};
    printf("%s", inet_ntoa(addr));
}

#endif /* __HELPER_H_ */
