#ifndef __HELPER_H_
#define __HELPER_H_

#include <arpa/inet.h>
#include <rte_common.h>
#include <rte_ethdev.h>

static __rte_always_inline void
print_rte_ipv4(rte_be32_t addr4)
{
    struct in_addr addr = {.s_addr = addr4};
    printf("%s", inet_ntoa(addr));
}

static __rte_always_inline void
print_rte_ipv4_dbg(
#ifndef DEBUG
    __attribute__((unused))
#endif
    rte_be32_t addr4)
{
#ifdef DEBUG
    print_rte_ipv4(addr4);
#endif
}

#endif /* __HELPER_H_ */
