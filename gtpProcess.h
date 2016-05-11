#ifndef __GTP_PROCESS__
#define __GTP_PROCESS__

#include "config.h"
#include "node.h"
#include "stats.h"

#include <rte_common.h>

typedef struct gtpv1_s {
    uint8_t  nPduNF:1;
    uint8_t  seqNF:1;
    uint8_t  extHF:1;
    uint8_t  rv:1;
    uint8_t  pt:1;
    uint8_t  vr:3;
    uint8_t  msgType;
    uint16_t len;
    uint32_t teid;
    uint16_t seqNum;
    uint8_t  nPduNum;
    uint8_t  nxtExtHT;
} gtpv1_t;

typedef struct extHeader_s {
    uint8_t msgLen;
    char   *content;
} extHeader_t;

typedef struct gtpv2_s {
    uint8_t  spare:3;
    uint8_t  teidF:1;
    uint8_t  pbF:1;
    uint8_t  vr:3;
    uint8_t  msgType;
    uint16_t msgLen;
}__attribute__((__packed__)) gtpv2_t;

typedef struct gtpv2_withTeid_s {
    uint32_t teid;
    uint32_t seqNumSpare;
}__attribute__((__packed__)) gtpv2_withTeid_t;

typedef struct gtpv2_noTeid_s {
    uint32_t seqNumSpare;
}__attribute__((__packed__)) gtpv2_noTeid_t;

typedef struct gtpv2_tlv_s {
    uint32_t type:8;
    uint32_t len:16;
    uint32_t crFlag_Inst:8;
    uint8_t  data;
} gtpv2_tlv_t;

typedef struct fqtei_s {
    uint8_t intfType:6;
    uint8_t ipv6:1;
    uint8_t ipv4:1;
    uint32_t teid;
    uint32_t ip[4];
} __attribute__((__packed__)) fqtei_t;

typedef struct userInfo_s {
    char     req_apn[100];
    uint64_t req_msisdn;
    uint64_t req_imsi;

    uint32_t fteidIp[4];
    uint32_t fteidTeid;
    uint32_t seqNum;
    uint32_t rep_ip6[4];
    uint32_t rep_ip4;

    uint16_t cause;

    uint8_t  fteidIpType;
    uint8_t  fteidIntf;

    uint8_t  req_ipType;
    uint8_t  rep_ipType;
} __attribute__((__packed__)) userInfo_t;

int32_t process_gtpCv2(void);
int32_t process_gtpUv1(void);


#endif /*__GTP_PROCESS__*/

