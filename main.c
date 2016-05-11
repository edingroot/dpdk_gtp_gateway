#include "config.h"
#include "node.h"
#include "stats.h"
#include "gtpProcess.h"

/* DEFINES */
#define MAX_RX_BURST_COUNT 8
#define PREFETCH_OFFSET    4
#define CREATE_PDP_CONTEXT_REQ 16 /*Create PDP Context Request*/

#define DEBUG_INFO 0

/* GLOBALS */

/* EXTERN */
extern uint8_t gtpConfigCount;
extern port_gtpConfig_t gtpConfig [GTP_PKTGEN_MAXPORTS];
extern const char gtpC[GTPC_MAXCOUNT][1500];
extern const char gtpU[GTPU_MAXCOUNT][1500];
extern numa_Info_t numaNodeInfo[GTP_MAX_NUMANODE];
extern pkt_stats_t prtPktStats [GTP_PKTGEN_MAXPORTS];

static int pktDecode_Handler(void *arg)
{
    uint8_t port = *((uint8_t *)arg);
    unsigned lcore_id, socket_id;
    int32_t j, nb_rx, ret;
    int16_t actLen, tlvLen;
    uint16_t offset, fields;

    struct rte_mbuf *ptr[MAX_RX_BURST_COUNT], *m = NULL;

    struct ether_hdr *ethHdr = NULL;
    struct ipv4_hdr  *ipHdr  = NULL;
    struct udp_hdr   *udpHdr = NULL;

    gtpv1_t *gtp1Hdr    = NULL;
    gtpv2_t *gtp2Hdr    = NULL;
    gtpv2_tlv_t *tlv    = NULL;
    gtpv2_noTeid_t *seq = NULL;
    fqtei_t *details    = NULL;
#if 0
    extHeader_t *extHdr   = NULL;
    gtp_v2_withTeid_t *gtp2TeidHdr = NULL;
    gtp_v2_noTeid_t   *gtp2NoTeidHdr = NULL;
#endif
    struct ipv4_hdr *ipUeHdr = NULL;

    userInfo_t *usrData = NULL;

    lcore_id = rte_lcore_id();
    socket_id = rte_lcore_to_socket_id(lcore_id);

    /* ToDo: if mempool is per port ignore the below*/
    //mbuf_pool_tx = numaNodeInfo[socket_id].tx[0];
    //mbuf_pool_rx = numaNodeInfo[socket_id].rx[port];

    printf("\n arg %d port %d on socket %d \n", *(uint8_t *)arg, port, socket_id);
    fflush(stdout);

    while(1)
    {
        /* fetch MAX Burst RX Packets */
        nb_rx =  rte_eth_rx_burst(port, 0, ptr, MAX_RX_BURST_COUNT);

        if(likely(nb_rx)) {
            //rte_pktmbuf_dump (stdout, ptr[0], 64);

            /* prefetch packets for pipeline */
            for (j = 0; ((j < PREFETCH_OFFSET) &&
                         (j < nb_rx)); j++)
            {
                rte_prefetch0(rte_pktmbuf_mtod(ptr[j], void *));
            } /* for loop till PREFETCH_OFFSET */

            for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++)
            {
                /* Prefetch others packets */
                m = ptr[j];
                rte_prefetch0(rte_pktmbuf_mtod(ptr[j + PREFETCH_OFFSET], void *));

                ethHdr = rte_pktmbuf_mtod(m, struct ether_hdr*);

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
                    ipHdr = (struct ipv4_hdr *) ((char *)(ethHdr + 1));

                    /* check IP is fragmented */
                    if (unlikely(ipHdr->fragment_offset & 0xfffc)) {
                        prtPktStats[port].ipFrag+= 1;
                        rte_free(m);
                        continue;
                    }

                    /* check for UDP */
                    //printf("\n protocol: %x\n", ipHdr->next_proto_id);
                    if (likely(ipHdr->next_proto_id == 0x11)) {
                        udpHdr = (struct udp_hdr *) ((char *) (ipHdr+1));
                        //printf("\n Port src: %x dst: %x\n", udpHdr->src_port, udpHdr->dst_port);

                        /* GTPC LTE carries V2 only 2123*/
                        if (unlikely((udpHdr->src_port == 0x4B08) || 
                                     (udpHdr->dst_port == 0x4B08))) {

                            gtp2Hdr = (gtpv2_t *)((char *)(udpHdr + 1));

                            /* process only v2 */
                            if(unlikely(gtp2Hdr->vr != 2)) {
                                prtPktStats[port].non_gtpVer+= 1;
                                rte_free(m);
                                continue;
                            }

                            prtPktStats[port].rx_gtpc_v2_ipv4 += 1;

                            /* ToDo: save the sequence number for response*/
                            if (gtp2Hdr->teidF) {
                                seq = (gtpv2_noTeid_t *) (((char *)(gtp2Hdr + 1)) + 4);
                            }
                            else {
                                seq = (gtpv2_noTeid_t *) (((char *)(gtp2Hdr + 1)));
                            }

                            usrData = rte_malloc(NULL, sizeof(userInfo_t), 0);
                            if (unlikely(usrData == NULL)) {
                                printf("\n ERROR: failed to alloc usr data memory!!!\n");
                                rte_free(m);
                                continue;
                            }

                            usrData->seqNum = (rte_be_to_cpu_32(seq->seqNumSpare) >> 8);
                            //printf("\n gptv2 HDR type %x\n", gtp2Hdr->msgType);
                            //printf("\n Seq Number: %x\n", usrData->req_seqNum);

                            switch(gtp2Hdr->msgType)
                            {
                                case (32):/*Create Session Request*/
                                 fields = 0;
                                 tlv = (gtpv2_tlv_t *) ( ((char *)(seq + 1)));

                                 actLen = rte_be_to_cpu_16(gtp2Hdr->msgLen) - (3 + (gtp2Hdr->teidF)? 4:0);
                                 offset = 0;

                                 //printf("\n len actual: %d offset: %d tlv type %d len %d %p %p", 
                                 //actLen, offset, tlv->type, rte_be_to_cpu_16(tlv->len), seq, ethHdr);
                                 //printf("\n First TLV type %d len %d", tlv->type, tlv->len);

                                 do 
                                 {
                                     tlvLen = rte_be_to_cpu_16(tlv->len);

                                     if(tlv->type == 76) {/*MSISDN*/
                                         //printf("\n MSISDN Len %d", tlvLen);
                                         rte_memcpy(&usrData->req_msisdn,((char *)tlv + 4),tlvLen);
                                         fields |= 1;
                                     }
                                     else if (tlv->type == 1) {/*IMSI*/
                                         //printf("\n IMSI Len %d %d", tlvLen, tlv->data);
                                         rte_memcpy(&usrData->req_imsi,((char *)tlv + 4),tlvLen);
                                         fields |= 2;
                                     }
                                     else if (tlv->type == 99) {/*PDN Type*/
                                         //printf("\n PDN Len %d", tlvLen);
                                         rte_memcpy(&usrData->req_ipType,((char *)tlv + 4),tlvLen);
                                         fields |= 4;
                                     }
                                     else if (tlv->type == 71) {/*Access Point Name*/
                                         //printf("\n APN Len %d", tlvLen);
                                         rte_memcpy(&usrData->req_apn,((char *)tlv + 4),tlvLen);
                                         usrData->req_apn[99] = '\0';
                                         fields |= 8;
                                     }
                                     else if (tlv->type == 87) {/*FTQEI*/
                                         //printf("\n FTQEI Len %d %x", tlvLen, tlv->data);
                                         details = (fqtei_t *) &tlv->data;
                                         usrData->fteidIpType = (details->ipv4)?4:(details->ipv6)?6:0xff;
                                         usrData->fteidIntf   = details->intfType;
                                         usrData->fteidTeid   = details->teid;
                                         usrData->fteidIp[0]  = details->ip[0];
                                         if(usrData->fteidIpType == 6) {
                                           usrData->fteidIp[1] = details->ip[1];
                                           usrData->fteidIp[2] = details->ip[2];
                                           usrData->fteidIp[3] = details->ip[3];
                                         }
                                         fields |= 16;
                                     }

                                     offset = offset + 4 + tlvLen;
                                     tlv = (gtpv2_tlv_t *)(((char *)tlv) + 4 + tlvLen);

                                     //printf("\n len actual: %d offset: %d", actLen, offset);
                                     //printf("\n TLV type %d len %d", tlv->type, tlvLen);
                                 } while((offset < actLen) || (fields != 0x1f));
                                 break;

                                case (33):/*Create Session Response*/
                                 fields = 0;
                                 tlv = (gtpv2_tlv_t *) ( ((char *)(seq + 1)));

                                 actLen = rte_be_to_cpu_16(gtp2Hdr->msgLen) - (3 + (gtp2Hdr->teidF)? 4:0);
                                 offset = 0;

                                 do 
                                 {
                                     tlvLen = rte_be_to_cpu_16(tlv->len);

                                     if(tlv->type == 2) {/*Cause */
                                         //printf("\n MSISDN Len %d", tlvLen);
                                         rte_memcpy(&usrData->cause,((char *)tlv + 4),tlvLen);
                                         fields |= 1;
                                     }
                                     else if (tlv->type == 79) {/*PDN Address Allocation*/
                                         if(*((char *)tlv + 4)& 0x01){
                                             rte_memcpy(&usrData->rep_ipType,((char *)tlv + 4),1);
                                             rte_memcpy(&usrData->rep_ip4,((char *)tlv + 4),4);
                                             
                                         }
                                         else{
                                             rte_memcpy(&usrData->rep_ipType,((char *)tlv + 4),1);
                                             rte_memcpy(usrData->rep_ip6,((char *)tlv + 4),16);

                                         }
                                         fields |= 2;
                                     }
                                     else if (tlv->type == 87) {/*FTQEI*/
                                         //printf("\n FTQEI Len %d %x", tlvLen, tlv->data);
                                         details = (fqtei_t *) &tlv->data;
                                         usrData->fteidIpType = (details->ipv4)?4:(details->ipv6)?6:0xff;
                                         usrData->fteidIntf   = details->intfType;
                                         usrData->fteidTeid   = details->teid;
                                         usrData->fteidIp[0]  = details->ip[0];
                                         if(usrData->fteidIpType == 6) {
                                           usrData->fteidIp[1] = details->ip[1];
                                           usrData->fteidIp[2] = details->ip[2];
                                           usrData->fteidIp[3] = details->ip[3];
                                         }
                                         fields |= 4;
                                     }


                                     offset = offset + 4 + tlvLen;
                                     tlv = (gtpv2_tlv_t *)(((char *)tlv) + 4 + tlvLen);

                                     //printf("\n len actual: %d offset: %d", actLen, offset);
                                     //printf("\n TLV type %d len %d", tlv->type, tlvLen);
                                 } while((offset < actLen) || (fields != 0x07));
                                 break;

                                case (34): /*Modify Bearer Request*/
                                 fields = 0;
                                 tlv = (gtpv2_tlv_t *) ( ((char *)(seq + 1)));

                                 actLen = rte_be_to_cpu_16(gtp2Hdr->msgLen) - (3 + (gtp2Hdr->teidF)? 4:0);
                                 offset = 0;

                                 do 
                                 {
                                     tlvLen = rte_be_to_cpu_16(tlv->len);

                                     if(tlv->type == 87) {
                                         //printf("\n FTQEI Len %d %x", tlvLen, tlv->data);
                                         details = (fqtei_t *) &tlv->data;
                                         usrData->fteidIpType = (details->ipv4)?4:(details->ipv6)?6:0xff;
                                         usrData->fteidIntf   = details->intfType;
                                         usrData->fteidTeid   = details->teid;
                                         usrData->fteidIp[0]  = details->ip[0];
                                         if(usrData->fteidIpType == 6) {
                                           usrData->fteidIp[1] = details->ip[1];
                                           usrData->fteidIp[2] = details->ip[2];
                                           usrData->fteidIp[3] = details->ip[3];
                                         }
                                         fields |= 1;
                                     } 

                                     offset = offset + 4 + tlvLen;
                                     tlv = (gtpv2_tlv_t *)(((char *)tlv) + 4 + tlvLen);

                                     //printf("\n len actual: %d offset: %d", actLen, offset);
                                     //printf("\n TLV type %d len %d", tlv->type, tlvLen);
                                 } while((offset < actLen) || (fields != 0x01));
                                 break;

                                case (35): /*Modify Bearer Response*/
                                 fields = 0;
                                 tlv = (gtpv2_tlv_t *) ( ((char *)(seq + 1)));

                                 actLen = rte_be_to_cpu_16(gtp2Hdr->msgLen) - (3 + (gtp2Hdr->teidF)? 4:0);
                                 offset = 0;

                                 do 
                                 {
                                     tlvLen = rte_be_to_cpu_16(tlv->len);

                                     if(tlv->type == 16) { /*CAUSE*/
                                         rte_memcpy(&usrData->cause,((char *)tlv + 4),tlvLen);
                                         fields |= 1;
                                     } 

                                     offset = offset + 4 + tlvLen;
                                     tlv = (gtpv2_tlv_t *)(((char *)tlv) + 4 + tlvLen);

                                     //printf("\n len actual: %d offset: %d", actLen, offset);
                                     //printf("\n TLV type %d len %d", tlv->type, tlvLen);
                                 } while((offset < actLen) || (fields != 0x01));
                                 break;

                                case (36): /*Delete Session Request*/
                                 fields = 0;
                                 tlv = (gtpv2_tlv_t *) ( ((char *)(seq + 1)));

                                 actLen = rte_be_to_cpu_16(gtp2Hdr->msgLen) - (3 + (gtp2Hdr->teidF)? 4:0);
                                 offset = 0;

                                 do 
                                 {
                                     tlvLen = rte_be_to_cpu_16(tlv->len);

                                     if(tlv->type == 87) {
                                         //printf("\n FTQEI Len %d %x", tlvLen, tlv->data);
                                         details = (fqtei_t *) &tlv->data;
                                         usrData->fteidIpType = (details->ipv4)?4:(details->ipv6)?6:0xff;
                                         usrData->fteidIntf   = details->intfType;
                                         usrData->fteidTeid   = details->teid;
                                         usrData->fteidIp[0]  = details->ip[0];
                                         if(usrData->fteidIpType == 6) {
                                           usrData->fteidIp[1] = details->ip[1];
                                           usrData->fteidIp[2] = details->ip[2];
                                           usrData->fteidIp[3] = details->ip[3];
                                         }
                                         fields |= 1;
                                     } 

                                     offset = offset + 4 + tlvLen;
                                     tlv = (gtpv2_tlv_t *)(((char *)tlv) + 4 + tlvLen);

                                     //printf("\n len actual: %d offset: %d", actLen, offset);
                                     //printf("\n TLV type %d len %d", tlv->type, tlvLen);
                                 } while((offset < actLen) || (fields != 0x01));
                                 break;

                                case (37): /*Delete Session Response*/
                                 fields = 0;
                                 tlv = (gtpv2_tlv_t *) ( ((char *)(seq + 1)));

                                 actLen = rte_be_to_cpu_16(gtp2Hdr->msgLen) - (3 + (gtp2Hdr->teidF)? 4:0);
                                 offset = 0;

                                 do 
                                 {
                                     tlvLen = rte_be_to_cpu_16(tlv->len);

                                     if(tlv->type == 16) { /*CAUSE*/
                                         rte_memcpy(&usrData->cause,((char *)tlv + 4),tlvLen);
                                         fields |= 1;
                                     } 

                                     offset = offset + 4 + tlvLen;
                                     tlv = (gtpv2_tlv_t *)(((char *)tlv) + 4 + tlvLen);

                                     //printf("\n len actual: %d offset: %d", actLen, offset);
                                     //printf("\n TLV type %d len %d", tlv->type, tlvLen);
                                 } while((offset < actLen) || (fields != 0x01));
                                 break;

                                default:
                                    rte_free(usrData);
                                    rte_pktmbuf_free(m);
                                    continue;
                            }

#if 0
                            printf("\n %-15s: %lx", "MSISDN", (usrData->req_msisdn));
                            printf("\n %-15s: %lx", "IMSI",   (usrData->req_imsi));
                            printf("\n %-15s: %x", "IP Type", (usrData->req_ipType));
                            printf("\n %-15s: %s", "APN",     (usrData->req_apn));
                            printf("\n %-15s: %d", "CAUSE",   (usrData->cause));
                            printf("\n %-15s: %x", "IP Type", (usrData->rep_ipType));
                            printf("\n %-15s: %d", "IP Value",(usrData->rep_ip4));
                            printf("\n --- FTEID ---");
                            printf("\n %-15s: %s", "IP",   (usrData->fteidIpType == 4)?"4":
                                                           (usrData->fteidIpType == 6)?"6":"NA");
                            printf("\n %-15s: %d", "INTF", usrData->fteidIntf);
                            printf("\n %-15s: %x", "TEID", usrData->fteidTeid);
                            if (usrData->fteidIpType == 4)
                              printf("\n %-15s: %x", "IP", usrData->fteidIp[0]);
                            else if (usrData->fteidIpType == 6)
                              printf("\n %-15s: %x:%x:%x:%x", "IP",
                                usrData->fteidIp[0], usrData->fteidIp[1],
                                usrData->fteidIp[2], usrData->fteidIp[3]);
                            printf("\n ------------------------------- \n");
                            fflush(stdout);
#endif

                            rte_free(usrData);

                            ret =  rte_eth_tx_burst(port, 0, &m, 1);
                            if (likely(ret == 1)) {
                                continue;
                            }

                        }
                        /* GTPU LTE carries V1 only 2152*/
                        else if (unlikely((udpHdr->src_port == 0x6808) || 
                                         (udpHdr->dst_port == 0x6808))) {

                            gtp1Hdr = (gtpv1_t *)((char *)(udpHdr + 1));

                            /* check if gtp version is 1 */
                            if (unlikely(gtp1Hdr->vr != 1)) {
                                prtPktStats[port].non_gtpVer+= 1;
                                rte_free(m);
                                continue;
                            }

                            /* check if msg type is PDU */
                            if (unlikely(gtp1Hdr->msgType == 0xff)) {
                                prtPktStats[port].dropped+= 1;
                                rte_free(m);
                                continue;
                            }

                            /*parse header till data*/
                            if (gtp2Hdr->teidF) {
                                seq = (gtpv2_noTeid_t *) (((char *)(gtp2Hdr + 1)) + 4);
                            }
                            else {
                                seq = (gtpv2_noTeid_t *) (((char *)(gtp2Hdr + 1)));
                            }

                            //usrData->seqNum = (rte_be_to_cpu_32(seq->seqNumSpare) >> 8);
                            ipUeHdr = (struct ipv4_hdr *) (((char *)(seq + 1)));

                            if (unlikely(ipUeHdr->version_ihl & 0x40) != 0x40) {
                              prtPktStats[port].rx_gptu_ipv6 += 1;
                            }
                            else {
                              prtPktStats[port].rx_gptu_ipv4 += 1;
                            }

                            ret =  rte_eth_tx_burst(port, 0, &m, 1);
                            if (likely(ret == 1)) {
                                continue;
                            }
                        }
                        else {
                            prtPktStats[port].non_gtp += 1;
                        } /* (unlikely(udpHdr->src|dst_port != 2123)) */
                    }
                    else {
                        prtPktStats[port].non_udp += 1;
                    } /* (unlikely(ipHdr->next_proto_id != 0x11)) */

                }
                else {
                    prtPktStats[port].non_ipv4 += 1;
                } /* (unlikely(ethHdr->ether_type != 0x0008)) */

                rte_pktmbuf_free(m);
                continue;
            } /* end fo for loop for nb_rx - PREFETCH_OFFSET */

            for (; j < nb_rx; j++)
            {
                m = ptr[j];

                ethHdr = rte_pktmbuf_mtod(m, struct ether_hdr*);

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
                    ipHdr = (struct ipv4_hdr *) ((char *)(ethHdr + 1));

                    /* check IP is fragmented */
                    if (unlikely(ipHdr->fragment_offset & 0xfffc)) {
                        prtPktStats[port].ipFrag+= 1;
                        rte_free(m);
                        continue;
                    }

                    /* check for UDP */
                    //printf("\n protocol: %x\n", ipHdr->next_proto_id);
                    if (likely(ipHdr->next_proto_id == 0x11)) {
                        udpHdr = (struct udp_hdr *) ((char *) (ipHdr+1));
                        //printf("\n Port src: %x dst: %x\n", udpHdr->src_port, udpHdr->dst_port);

                        /* GTPC LTE carries V2 only 2123*/
                        if (unlikely((udpHdr->src_port == 0x4B08) || 
                                     (udpHdr->dst_port == 0x4B08))) {

                            gtp2Hdr = (gtpv2_t *)((char *)(udpHdr + 1));

                            /* process only v2 */
                            if(unlikely(gtp2Hdr->vr != 2)) {
                                prtPktStats[port].rx_gtpc_v1_ipv4+= 1;
                                rte_free(m);
                                continue;
                            }

                            prtPktStats[port].rx_gtpc_v2_ipv4 += 1;

                            /* ToDo: save the sequence number for response*/
                            if (gtp2Hdr->teidF) {
                                seq = (gtpv2_noTeid_t *) (((char *)(gtp2Hdr + 1)) + 4);
                            }
                            else {
                                seq = (gtpv2_noTeid_t *) (((char *)(gtp2Hdr + 1)));
                            }

                            usrData = rte_malloc(NULL, sizeof(userInfo_t), 0);
                            if (unlikely(usrData == NULL)) {
                                printf("\n ERROR: failed to alloc usr data memory!!!\n");
                                rte_free(m);
                                continue;
                            }

                            usrData->seqNum = (rte_be_to_cpu_32(seq->seqNumSpare) >> 8);
                            //printf("\n gptv2 HDR type %x\n", gtp2Hdr->msgType);
                            //printf("\n Seq Number: %x\n", usrData->req_seqNum);

                            switch(gtp2Hdr->msgType)
                            {
                                case (32):/*Create Session Request*/
                                 fields = 0;
                                 tlv = (gtpv2_tlv_t *) ( ((char *)(seq + 1)));

                                 actLen = rte_be_to_cpu_16(gtp2Hdr->msgLen) - (3 + (gtp2Hdr->teidF)? 4:0);
                                 offset = 0;

                                 //printf("\n len actual: %d offset: %d tlv type %d len %d %p %p", 
                                 //actLen, offset, tlv->type, rte_be_to_cpu_16(tlv->len), seq, ethHdr);
                                 //printf("\n First TLV type %d len %d", tlv->type, tlv->len);

                                 do 
                                 {
                                     tlvLen = rte_be_to_cpu_16(tlv->len);

                                     if(tlv->type == 76) {/*MSISDN*/
                                         //printf("\n MSISDN Len %d", tlvLen);
                                         rte_memcpy(&usrData->req_msisdn,((char *)tlv + 4),tlvLen);
                                         fields |= 1;
                                     }
                                     else if (tlv->type == 1) {/*IMSI*/
                                         //printf("\n IMSI Len %d %d", tlvLen, tlv->data);
                                         rte_memcpy(&usrData->req_imsi,((char *)tlv + 4),tlvLen);
                                         fields |= 2;
                                     }
                                     else if (tlv->type == 99) {/*PDN Type*/
                                         //printf("\n PDN Len %d", tlvLen);
                                         rte_memcpy(&usrData->req_ipType,((char *)tlv + 4),tlvLen);
                                         fields |= 4;
                                     }
                                     else if (tlv->type == 71) {/*Access Point Name*/
                                         //printf("\n APN Len %d", tlvLen);
                                         rte_memcpy(&usrData->req_apn,((char *)tlv + 4),tlvLen);
                                         usrData->req_apn[99] = '\0';
                                         fields |= 8;
                                     }
                                     else if (tlv->type == 87) {/*FTQEI*/
                                         //printf("\n FTQEI Len %d %x", tlvLen, tlv->data);
                                         details = (fqtei_t *) &tlv->data;
                                         usrData->fteidIpType = (details->ipv4)?4:(details->ipv6)?6:0xff;
                                         usrData->fteidIntf   = details->intfType;
                                         usrData->fteidTeid   = details->teid;
                                         usrData->fteidIp[0]  = details->ip[0];
                                         if(usrData->fteidIpType == 6) {
                                           usrData->fteidIp[1] = details->ip[1];
                                           usrData->fteidIp[2] = details->ip[2];
                                           usrData->fteidIp[3] = details->ip[3];
                                         }
                                         fields |= 16;
                                     }

                                     offset = offset + 4 + tlvLen;
                                     tlv = (gtpv2_tlv_t *)(((char *)tlv) + 4 + tlvLen);

                                     //printf("\n len actual: %d offset: %d", actLen, offset);
                                     //printf("\n TLV type %d len %d", tlv->type, tlvLen);
                                 } while((offset < actLen) || (fields != 0x1f));
                                 break;

                                case (33):/*Create Session Response*/
                                 fields = 0;
                                 tlv = (gtpv2_tlv_t *) ( ((char *)(seq + 1)));

                                 actLen = rte_be_to_cpu_16(gtp2Hdr->msgLen) - (3 + (gtp2Hdr->teidF)? 4:0);
                                 offset = 0;

                                 do 
                                 {
                                     tlvLen = rte_be_to_cpu_16(tlv->len);

                                     if(tlv->type == 2) {/*Cause */
                                         //printf("\n MSISDN Len %d", tlvLen);
                                         rte_memcpy(&usrData->cause,((char *)tlv + 4),tlvLen);
                                         fields |= 1;
                                     }
                                     else if (tlv->type == 79) {/*PDN Address Allocation*/
                                         if(*((char *)tlv + 4)& 0x01){
                                             rte_memcpy(&usrData->rep_ipType,((char *)tlv + 4),1);
                                             rte_memcpy(&usrData->rep_ip4,((char *)tlv + 4),4);
                                             
                                         }
                                         else{
                                             rte_memcpy(&usrData->rep_ipType,((char *)tlv + 4),1);
                                             rte_memcpy(usrData->rep_ip6,((char *)tlv + 4),16);

                                         }
                                         fields |= 2;
                                     }
                                     else if (tlv->type == 87) {/*FTQEI*/
                                         //printf("\n FTQEI Len %d %x", tlvLen, tlv->data);
                                         details = (fqtei_t *) &tlv->data;
                                         usrData->fteidIpType = (details->ipv4)?4:(details->ipv6)?6:0xff;
                                         usrData->fteidIntf   = details->intfType;
                                         usrData->fteidTeid   = details->teid;
                                         usrData->fteidIp[0]  = details->ip[0];
                                         if(usrData->fteidIpType == 6) {
                                           usrData->fteidIp[1] = details->ip[1];
                                           usrData->fteidIp[2] = details->ip[2];
                                           usrData->fteidIp[3] = details->ip[3];
                                         }
                                         fields |= 4;
                                     }


                                     offset = offset + 4 + tlvLen;
                                     tlv = (gtpv2_tlv_t *)(((char *)tlv) + 4 + tlvLen);

                                     //printf("\n len actual: %d offset: %d", actLen, offset);
                                     //printf("\n TLV type %d len %d", tlv->type, tlvLen);
                                 } while((offset < actLen) || (fields != 0x07));
                                 break;

                                case (34): /*Modify Bearer Request*/
                                 fields = 0;
                                 tlv = (gtpv2_tlv_t *) ( ((char *)(seq + 1)));

                                 actLen = rte_be_to_cpu_16(gtp2Hdr->msgLen) - (3 + (gtp2Hdr->teidF)? 4:0);
                                 offset = 0;

                                 do 
                                 {
                                     tlvLen = rte_be_to_cpu_16(tlv->len);

                                     if(tlv->type == 87) {
                                         //printf("\n FTQEI Len %d %x", tlvLen, tlv->data);
                                         details = (fqtei_t *) &tlv->data;
                                         usrData->fteidIpType = (details->ipv4)?4:(details->ipv6)?6:0xff;
                                         usrData->fteidIntf   = details->intfType;
                                         usrData->fteidTeid   = details->teid;
                                         usrData->fteidIp[0]  = details->ip[0];
                                         if(usrData->fteidIpType == 6) {
                                           usrData->fteidIp[1] = details->ip[1];
                                           usrData->fteidIp[2] = details->ip[2];
                                           usrData->fteidIp[3] = details->ip[3];
                                         }
                                         fields |= 1;
                                     } 

                                     offset = offset + 4 + tlvLen;
                                     tlv = (gtpv2_tlv_t *)(((char *)tlv) + 4 + tlvLen);

                                     //printf("\n len actual: %d offset: %d", actLen, offset);
                                     //printf("\n TLV type %d len %d", tlv->type, tlvLen);
                                 } while((offset < actLen) || (fields != 0x01));
                                 break;

                                case (35): /*Modify Bearer Response*/
                                 fields = 0;
                                 tlv = (gtpv2_tlv_t *) ( ((char *)(seq + 1)));

                                 actLen = rte_be_to_cpu_16(gtp2Hdr->msgLen) - (3 + (gtp2Hdr->teidF)? 4:0);
                                 offset = 0;

                                 do 
                                 {
                                     tlvLen = rte_be_to_cpu_16(tlv->len);

                                     if(tlv->type == 16) { /*CAUSE*/
                                         rte_memcpy(&usrData->cause,((char *)tlv + 4),tlvLen);
                                         fields |= 1;
                                     } 

                                     offset = offset + 4 + tlvLen;
                                     tlv = (gtpv2_tlv_t *)(((char *)tlv) + 4 + tlvLen);

                                     //printf("\n len actual: %d offset: %d", actLen, offset);
                                     //printf("\n TLV type %d len %d", tlv->type, tlvLen);
                                 } while((offset < actLen) || (fields != 0x01));
                                 break;

                                case (36): /*Delete Session Request*/
                                 fields = 0;
                                 tlv = (gtpv2_tlv_t *) ( ((char *)(seq + 1)));

                                 actLen = rte_be_to_cpu_16(gtp2Hdr->msgLen) - (3 + (gtp2Hdr->teidF)? 4:0);
                                 offset = 0;

                                 do 
                                 {
                                     tlvLen = rte_be_to_cpu_16(tlv->len);

                                     if(tlv->type == 87) {
                                         //printf("\n FTQEI Len %d %x", tlvLen, tlv->data);
                                         details = (fqtei_t *) &tlv->data;
                                         usrData->fteidIpType = (details->ipv4)?4:(details->ipv6)?6:0xff;
                                         usrData->fteidIntf   = details->intfType;
                                         usrData->fteidTeid   = details->teid;
                                         usrData->fteidIp[0]  = details->ip[0];
                                         if(usrData->fteidIpType == 6) {
                                           usrData->fteidIp[1] = details->ip[1];
                                           usrData->fteidIp[2] = details->ip[2];
                                           usrData->fteidIp[3] = details->ip[3];
                                         }
                                         fields |= 1;
                                     } 

                                     offset = offset + 4 + tlvLen;
                                     tlv = (gtpv2_tlv_t *)(((char *)tlv) + 4 + tlvLen);

                                     //printf("\n len actual: %d offset: %d", actLen, offset);
                                     //printf("\n TLV type %d len %d", tlv->type, tlvLen);
                                 } while((offset < actLen) || (fields != 0x01));
                                 break;

                                case (37): /*Delete Session Response*/
                                 fields = 0;
                                 tlv = (gtpv2_tlv_t *) ( ((char *)(seq + 1)));

                                 actLen = rte_be_to_cpu_16(gtp2Hdr->msgLen) - (3 + (gtp2Hdr->teidF)? 4:0);
                                 offset = 0;

                                 do 
                                 {
                                     tlvLen = rte_be_to_cpu_16(tlv->len);

                                     if(tlv->type == 16) { /*CAUSE*/
                                         rte_memcpy(&usrData->cause,((char *)tlv + 4),tlvLen);
                                         fields |= 1;
                                     } 

                                     offset = offset + 4 + tlvLen;
                                     tlv = (gtpv2_tlv_t *)(((char *)tlv) + 4 + tlvLen);

                                     //printf("\n len actual: %d offset: %d", actLen, offset);
                                     //printf("\n TLV type %d len %d", tlv->type, tlvLen);
                                 } while((offset < actLen) || (fields != 0x01));
                                 break;

                                default:
                                    rte_free(usrData);
                                    rte_pktmbuf_free(m);
                                    continue;
                            }

#if 0
                            printf("\n %-15s: %lx", "MSISDN", (usrData->req_msisdn));
                            printf("\n %-15s: %lx", "IMSI",   (usrData->req_imsi));
                            printf("\n %-15s: %x", "IP Type", (usrData->req_ipType));
                            printf("\n %-15s: %s", "APN",     (usrData->req_apn));
                            printf("\n %-15s: %d", "CAUSE",   (usrData->cause));
                            printf("\n %-15s: %x", "IP Type", (usrData->rep_ipType));
                            printf("\n %-15s: %d", "IP Value",(usrData->rep_ip4));
                            printf("\n --- FTEID ---");
                            printf("\n %-15s: %s", "IP",   (usrData->fteidIpType == 4)?"4":
                                                           (usrData->fteidIpType == 6)?"6":"NA");
                            printf("\n %-15s: %d", "INTF", usrData->fteidIntf);
                            printf("\n %-15s: %x", "TEID", usrData->fteidTeid);
                            if (usrData->fteidIpType == 4)
                              printf("\n %-15s: %x", "IP", usrData->fteidIp[0]);
                            else if (usrData->fteidIpType == 6)
                              printf("\n %-15s: %x:%x:%x:%x", "IP",
                                usrData->fteidIp[0], usrData->fteidIp[1],
                                usrData->fteidIp[2], usrData->fteidIp[3]);
                            printf("\n ------------------------------- \n");
                            fflush(stdout);
#endif

                            rte_free(usrData);

                            ret =  rte_eth_tx_burst(port, 0, &m, 1);
                            if (likely(ret != 1)) {
                                continue;
                            }

                        }
                        /* GTPU LTE carries V1 only 2152*/
                        else if (unlikely((udpHdr->src_port == 0x6808) || 
                                         (udpHdr->dst_port == 0x6808))) {
                            prtPktStats[port].rx_gptu_ipv4 += 1;

                            gtp1Hdr = (gtpv1_t *)((char *)(udpHdr + 1));

                            /* check if gtp version is 1 */
                            if (unlikely(gtp1Hdr->vr != 1)) {
                                prtPktStats[port].non_gtpVer+= 1;
                                rte_free(m);
                                continue;
                            }

                            /* check if msg type is PDU */
                            if (unlikely(gtp1Hdr->msgType == 0xff)) {
                                prtPktStats[port].dropped+= 1;
                                rte_free(m);
                                continue;
                            }

                            /*parse header till data*/
                            if (gtp2Hdr->teidF) {
                                seq = (gtpv2_noTeid_t *) (((char *)(gtp2Hdr + 1)) + 4);
                            }
                            else {
                                seq = (gtpv2_noTeid_t *) (((char *)(gtp2Hdr + 1)));
                            }

                            //usrData->seqNum = (rte_be_to_cpu_32(seq->seqNumSpare) >> 8);
                            ipUeHdr = (struct ipv4_hdr *) (((char *)(seq + 1)));

                            if (unlikely(ipUeHdr->version_ihl & 0x40) != 0x40) {
                              prtPktStats[port].rx_gptu_ipv6 += 1;
                            }
                            else {
                              prtPktStats[port].rx_gptu_ipv4 += 1;
                            }

                            ret =  rte_eth_tx_burst(port, 0, &m, 1);
                            if (likely(ret == 1)) {
                                continue;
                            }
                        }
                        else {
                            prtPktStats[port].non_gtp += 1;
                        } /* (unlikely(udpHdr->src|dst_port != 2123)) */
                    }
                    else {
                        prtPktStats[port].non_udp += 1;
                    } /* (unlikely(ipHdr->next_proto_id != 0x11)) */

                }
                else {
                    prtPktStats[port].non_ipv4 += 1;
                } /* (unlikely(ethHdr->ether_type != 0x0008)) */

                rte_pktmbuf_free(m);
                continue;
            } /* end of for loop */

        } /* end of packet count check */
    }

    return 0;
}


int main(int argc, char **argv)
{
    int32_t ret = 0;

    argc -= ret;
    argv += ret;

    /* Load INI configuration for fetching GTP port details */
    ret = loadGtpConfig();
    if (unlikely(ret < 0))
    {
        printf("\n ERROR: failed to load config\n");
        return -1;
    }

    /* Initialize DPDK EAL */
    ret =  rte_eal_init(argc, argv);
    if (unlikely(ret < 0))
    {
        printf("\n ERROR: Cannot init EAL\n");
        return -2;
    }

    /* check Huge pages for memory buffers */
    ret = rte_eal_has_hugepages();
    if (unlikely(ret < 0))
    {
        rte_panic("\n ERROR: No Huge Page\n");
        exit(EXIT_FAILURE);
    }

    ret = populateNodeInfo();
    if (unlikely(ret < 0))
    {
        rte_panic("\n ERROR: in populating NUMA node Info\n");
        exit(EXIT_FAILURE);
    }

    /* launch functions for specified cores */
    if (interfaceSetup() < 0)
    {
        rte_panic("ERROR: interface setup Failed\n");
        exit(EXIT_FAILURE);

    }

    /*Launch thread in core 1*/
    ret = 0;
    rte_eal_remote_launch(pktDecode_Handler, (void *)&ret, 1);

    /*Launch thread in core 2*/
    ret = 1;
    rte_eal_remote_launch(pktDecode_Handler, (void *)&ret, 2);

    /*Launch thread in core 3*/
    ret = 2;
    rte_eal_remote_launch(pktDecode_Handler, (void *)&ret, 3);

    /* Register Signal */
    signal(SIGUSR1, sigExtraStats);
    signal(SIGUSR2, sigConfig);

    set_stats_timer();
    rte_delay_ms(5000);
    show_static_display();

    do {
        rte_delay_ms(1000);
        rte_timer_manage();
    }while(1);
}

