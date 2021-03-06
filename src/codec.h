/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  PPP_CODEC.H

  Designed by THE on Jan 14, 2019
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#ifndef _PPP_CODEC_H_
#define _PPP_CODEC_H_

#include "pppoeclient.h"
#include <ip_codec.h>
#include "fsm.h"

#define PPP_MAX_MSG_LEN			512
#define DEF_TTL					120 //secs
#define	DEF_MSG_NUM_PER_SEC		1   //packets

typedef enum {
	CHASSIS_ID_SUBT_RESERVED,
	CHASSIS_ID_SUBT_CHASSIS_COMPONENT,
	CHASSIS_ID_SUBT_IF_ALIAS,
	CHASSIS_ID_SUBT_PORT_COMPONENT,
	CHASSIS_ID_SUBT_MAC_ADDR,
	CHASSIS_ID_SUBT_NET_ADDR,
	CHASSIS_ID_SUBT_IF_NAME,
	CHASSIS_ID_SUBT_LOC_ASSIGN
} CHASSIS_ID_SUBTYPE;

typedef enum {
	PORT_ID_SUBT_RESERVED,
	PORT_ID_SUBT_IF_ALIAS,
	PORT_ID_SUBT_PORT_COMPONENT,
	PORT_ID_SUBT_MAC_ADDR,
	PORT_ID_SUBT_NET_ADDR,
	PORT_ID_SUBT_IF_NAME,
	PORT_ID_SUBT_AGENT_ID,
	PORT_ID_SUBT_LOC_ASSIGN
} PORT_ID_SUBTYPE;

typedef enum {
	ADDR_FAMILY_NUM_IP_OTHER,
	ADDR_FAMILY_NUM_IP_V4,
	ADDR_FAMILY_NUM_IP_V6,
} ADDR_FAMILY_TYPE;

typedef enum {
	IF_SUBT_UNKNOWN=1,	
	IF_SUBT_IFNDX,
	IF_SUBT_SYS_PORT_NO
} IF_SUBTYPE;

/**********************************************************************
 * _PPP_GET_TBL_NDX4() : 4 arguments
 *
 * purpose : find out the specific entry from table
 * input   : t - type, table, max table entries
 *           Don't change 't' to 'type', otherwise syntax error.
 * output  : entry
 **********************************************************************/
#define  _PPP_GET_TBL_NDX4(entry, t, table, max_type) \
{ \
    for((entry)=0; (table)[(entry)].type!=(max_type) && (t)!=(table)[(entry)].type; (entry)++); \
}
 
extern STATUS PPP_decode_frame(tPPP_MBX *mail, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t **ppp_lcp_options, uint16_t *event);
extern STATUS decode_ipcp(struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t total_lcp_length, uint16_t *event);

extern void   DECODE_OBJID(U8 *vp, U8 vlen, U32 *oids, U8 *oids_len);

extern STATUS build_config_request(int cp, unsigned char* buffer, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t *mulen);
extern STATUS build_config_ack(int cp, unsigned char* buffer, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t *mulen);
extern STATUS build_config_nak_rej(int cp, unsigned char* buffer, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t *mulen);
extern STATUS build_terminate_ack(int cp, unsigned char* buffer, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t *mulen);
extern STATUS build_code_reject(int cp, unsigned char* buffer, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t *mulen);
extern STATUS build_terminate_request(int cp, unsigned char* buffer, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t *mulen);
extern STATUS build_echo_reply(unsigned char* buffer, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t *mulen);
extern STATUS build_auth_request_pap(unsigned char* buffer, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t *mulen);

STATUS check_nak_reject(uint8_t flag,struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t total_lcp_length);
STATUS check_ipcp_nak_rej(uint8_t flag,struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t total_lcp_length);

STATUS pppoe_recv(tPPP_MBX *mail, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header);
STATUS build_padi(void);
STATUS build_padr(struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, pppoe_header_tag_t *pppoe_header_tag);
STATUS build_padt(struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header);

extern  U8		ppp_802_1_oui[];
extern  U8  	ppp_da_mac[];
extern  char	cts_port_id[];
extern  char	cts_port_desc[];
extern  U32		ppp_ttl;

extern unsigned char *src_mac;
extern unsigned char *dst_mac;
extern uint16_t		 session_id;
extern unsigned char *user_id;
extern unsigned char *passwd;

#endif
