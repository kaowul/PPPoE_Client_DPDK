/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  PPPD.C

    - purpose : for ppp detection
	
  Designed by THE on Jan 14, 2019
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#include        	<common.h>
#include 			<rte_eal.h>
#include 			<rte_ethdev.h>
#include 			<rte_cycles.h>
#include 			<rte_lcore.h>
#include 			<rte_timer.h>
#include 			<rte_ether.h>
#include			"fsm.h"
#include 			"dpdk_send_recv.h"

#define 			RING_SIZE 		16384
#define 			NUM_MBUFS 		8191
#define 			MBUF_CACHE_SIZE 512

BOOL				ppp_testEnable = FALSE;
U32					ppp_ttl;
U32					ppp_interval;
U16					ppp_init_delay;
uint8_t				ppp_max_msg_per_query;

U8 					PORT_BIT_MAP(tPPP_PORT ports[]);
tPPP_PORT			ppp_ports[2]; //port is 1's based

tIPC_ID 			pppQid = -1;
tIPC_ID 			pppQid_main = -1;

struct rte_mempool 		*mbuf_pool;
struct rte_ring 		*rte_ring;

extern int timer_loop();

uint16_t 				session_id;
unsigned char 			*src_mac;
unsigned char 			*dst_mac;
unsigned char 			*user_id;
unsigned char 			*passwd;
uint8_t					data_plane_start;
struct rte_timer		pppoe;
struct rte_timer 		ppp;

int main(int argc, char **argv)
{
	uint16_t portid;
	uint16_t user_id_length, passwd_length;
	
	if (argc < 7) {
		puts("Too less parameter.");
		puts("Type ./pppoeclient <username> <password> <eal_options>");
		return ERROR;
	}

	int ret = rte_eal_init(argc-3,argv+3);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte initlize fail.");

	if (rte_lcore_count() < 5)
		rte_exit(EXIT_FAILURE, "We need at least 5 cores.\n");

	src_mac = (unsigned char *)malloc(ETH_ALEN);
	dst_mac = (unsigned char *)malloc(ETH_ALEN);
	user_id_length = strlen(argv[1]);
	passwd_length = strlen(argv[2]);
	user_id = (unsigned char *)malloc(user_id_length+1);
	passwd = (unsigned char *)malloc(passwd_length+1);
	memcpy(user_id,argv[1],user_id_length);
	memcpy(passwd,argv[2],passwd_length);
	user_id[user_id_length] = '\0';
	passwd[passwd_length] = '\0';
	
	rte_eth_macaddr_get(1,(struct ether_addr *)src_mac);

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
	rte_ring = rte_ring_create("state_machine",RING_SIZE,rte_socket_id(),0);

	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid) {
		if (PPP_PORT_INIT(portid) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",portid);
	}

	signal(SIGTERM,PPP_bye);
	data_plane_start = FALSE;

	/* init RTE timer library */
	rte_timer_subsystem_init();

	/* init timer structures */
	rte_timer_init(&pppoe);
	rte_timer_init(&ppp);

	rte_eal_remote_launch(ppp_recvd,NULL,1);
	rte_eal_remote_launch(encapsulation,NULL,2);
	rte_eal_remote_launch(control_plane,NULL,3);
	rte_eal_remote_launch(timer_loop,NULL,4);
	//rte_eal_remote_launch(gateway,NULL,5);

	rte_eal_mp_wait_lcore();
    return 0;
}

int control_plane(void)
{
	if (pppdInit() == ERROR)
		return ERROR;
	if (ppp_init() == ERROR)
		return ERROR;
	kill(getpid(), SIGTERM);
	return 0;
}

/*---------------------------------------------------------
 * ppp_bye : signal handler for INTR-C only
 *--------------------------------------------------------*/
void PPP_bye(void)
{
    printf("bye!\n");
    free(src_mac);
    free(dst_mac);
    free(user_id);
    free(passwd);
    rte_ring_free(rte_ring);
    exit(0);
}

/**************************************************************
 * pppdInit: 
 *
 **************************************************************/
int pppdInit(void)
{	
	ppp_interval = (uint32_t)(3*SEC);
    
    //--------- default of all ports ----------
	ppp_ports[0].enable = TRUE;
	ppp_ports[0].query_cnt = 1;
	ppp_ports[0].state = S_INIT;
	ppp_ports[0].port = 0;
		
	ppp_ports[0].imsg_cnt =
	ppp_ports[0].err_imsg_cnt =
	ppp_ports[0].omsg_cnt = 0;

	ppp_ports[1].enable = TRUE;
	ppp_ports[1].query_cnt = 1;
	ppp_ports[1].state = S_INIT;
	ppp_ports[1].port = 0;
		
	ppp_ports[1].imsg_cnt =
	ppp_ports[1].err_imsg_cnt =
	ppp_ports[1].omsg_cnt = 0;
    
	sleep(1);
	ppp_testEnable = TRUE; //to let driver ppp msg come in ...
	puts("============ pppoe init successfully ==============");
	return 0;
}
            
/***************************************************************
 * pppd : 
 *
 ***************************************************************/
int ppp_init(void)
{
	extern STATUS		PPP_FSM(struct rte_timer *ppp, tPPP_PORT *port_ccb, U16 event);
    tPPP_MBX			*mail;
	tPPP_PORT			*ccb;
	int 				cp;
	uint16_t			event;
	uint16_t			burst_size, max_retransmit = MAX_RETRAN;
	uint16_t			recv_type;
	struct ethhdr 		eth_hdr;
	pppoe_header_t 		pppoe_header;
	ppp_payload_t		ppp_payload;
	ppp_lcp_header_t	ppp_lcp;
	ppp_lcp_options_t	*ppp_lcp_options = (ppp_lcp_options_t *)malloc(40*sizeof(char));
	
    if (build_padi(&pppoe,&max_retransmit) == FALSE) {
    	free(ppp_lcp_options);
    	return ERROR;
    }
    rte_timer_reset(&pppoe,rte_get_timer_hz(),PERIODICAL,4,build_padi,&max_retransmit);
    for(;;) {
    	mail = control_plane_dequeue(mail);
		if (PPP_decode_frame(mail,&eth_hdr,&pppoe_header,&ppp_payload,&ppp_lcp,&ppp_lcp_options,&event,&pppoe) == FALSE)
			continue;
		pppoe_phase_t pppoe_phase;
		pppoe_phase.eth_hdr = &eth_hdr;
		pppoe_phase.pppoe_header = &pppoe_header;
		pppoe_phase.pppoe_header_tag = (pppoe_header_tag_t *)((pppoe_header_t *)((struct ethhdr *)mail->refp + 1) + 1);
		pppoe_phase.max_retransmit = MAX_RETRAN;

		switch(pppoe_header.code) {
		case PADO:
			rte_timer_stop(&pppoe);
			memcpy(src_mac,eth_hdr.h_dest,6);
			memcpy(dst_mac,eth_hdr.h_source,6);
			if (build_padr(&pppoe,&pppoe_phase) == FALSE)
				return ERROR;
			rte_timer_reset(&pppoe,rte_get_timer_hz(),PERIODICAL,4,build_padr,&pppoe_phase);
			continue;
		case PADS:
			rte_timer_stop(&pppoe);
			session_id = pppoe_header.session_id;
			break;
		case PADT:
			puts("Connection disconnected.");
			return ERROR;
		case PADM:
			puts("recv active discovery message");
			continue;
		default:
			puts("Unknown PPPoE discovery type.");
			return ERROR;
		}
		break;
    }
    ppp_ports[0].cp = 0;
    for (int i=0; i<2; i++) {
    	ppp_ports[i].ppp_phase.eth_hdr = &eth_hdr;
    	ppp_ports[i].ppp_phase.pppoe_header = &pppoe_header;
    	ppp_ports[i].ppp_phase.ppp_payload = &ppp_payload;
    	ppp_ports[i].ppp_phase.ppp_lcp = &ppp_lcp;
    	ppp_ports[i].ppp_phase.ppp_lcp_options = ppp_lcp_options;
    }
    PPP_FSM(&ppp,&ppp_ports[0],E_OPEN);
    mail = NULL;
    
	for(;;){
	    mail = control_plane_dequeue(mail);
	    recv_type = *(uint16_t *)mail;
		
		switch(recv_type){
		case IPC_EV_TYPE_TMR:
			break;
		
		case IPC_EV_TYPE_DRV:
			if (PPP_decode_frame(mail,&eth_hdr,&pppoe_header,&ppp_payload,&ppp_lcp,&ppp_lcp_options,&event,&ppp) == FALSE) {
				ppp_ports[0].err_imsg_cnt++;
				continue;
			}
			ppp_ports[0].ppp_phase.ppp_lcp_options = ppp_lcp_options;
			ppp_ports[1].ppp_phase.ppp_lcp_options = ppp_lcp_options;
			if (ppp_payload.ppp_protocol == htons(AUTH_PROTOCOL)) {
				if (ppp_lcp.code == AUTH_NAK) {
					free(ppp_lcp_options);
					return ERROR;
				}
				else if (ppp_lcp.code == AUTH_ACK) {
					ppp_ports[1].cp = 1;
					PPP_FSM(&ppp,&ppp_ports[1],E_OPEN);
					continue;
				}
			}
			if (pppoe_header.code != SESSION_DATA) {
				if (is_padt(mail,&eth_hdr,&pppoe_header) == FALSE) {
					if (build_padt(&eth_hdr,&pppoe_header) == FALSE) {
						free(ppp_lcp_options);
						return ERROR;
					}
					goto out;
				}
				continue;
			}
			cp = (ppp_payload.ppp_protocol == htons(IPCP_PROTOCOL)) ? 1 : 0;
			ppp_ports[cp].cp = cp;
			PPP_FSM(&ppp,&ppp_ports[cp],event);
			break;
		case IPC_EV_TYPE_CLI:
			break;
		case IPC_EV_TYPE_MAP:
			break;
		default:
		    ;
		}
    }
out:
    free(ppp_lcp_options);
    return 0;
}
