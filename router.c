#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
struct ether_header build_ether_header(uint8_t *source_mac, uint8_t *dest_mac,uint16_t type) {
	struct ether_header new_eth_hdr;
	new_eth_hdr.ether_type = htons(type);
	memcpy(new_eth_hdr.ether_shost,source_mac,6);
	memcpy(new_eth_hdr.ether_dhost,dest_mac,6);
	return new_eth_hdr;
}
struct iphdr build_ip_header(uint32_t source_addr, uint32_t dest_addr, uint8_t protocol){
	struct iphdr new_ip_hdr;
	new_ip_hdr.ihl = 5;
	new_ip_hdr.version = 4;
	new_ip_hdr.tos = 0;
	new_ip_hdr.id = 1;
	new_ip_hdr.frag_off = 0;
	new_ip_hdr.ttl = 64;
	new_ip_hdr.protocol = protocol;
	new_ip_hdr.saddr = source_addr;
	new_ip_hdr.daddr = dest_addr;
	new_ip_hdr.check = 0;
	new_ip_hdr.check = checksum((u_int16_t *)&new_ip_hdr,sizeof(struct iphdr));
	return new_ip_hdr;
}
struct icmphdr build_icmp_header(uint8_t type,uint8_t code,uint16_t id,uint16_t sequence){
	struct icmphdr new_icmphdr;
	new_icmphdr.type = type;
	new_icmphdr.code = code;
	new_icmphdr.un.echo.id = id;
	new_icmphdr.un.echo.sequence = sequence;
	new_icmphdr.checksum = 0;
	new_icmphdr.checksum = checksum((u_int16_t *)&new_icmphdr,sizeof(struct icmphdr));
	return new_icmphdr;
}
struct arp_table_entry *get_next_hop(struct arp_table_entry *arp_table, int arp_table_len, uint32_t ip){
	for(int i = 0; i < arp_table_len; i++){
		if(arp_table[i].ip == ip){
			return &arp_table[i];
		}
	}
	return NULL;
}
struct arp_header build_arp_header(uint16_t op, u_int8_t *sha,uint32_t spa,uint8_t *tha,uint32_t tpa){
	struct arp_header new_arp;
	new_arp.htype = htons(1);
	new_arp.ptype = htons(2048);
	new_arp.hlen = 6;
	new_arp.plen = 4;
	new_arp.op = htons(op);
	memcpy(new_arp.sha,sha,6);
	memcpy(new_arp.tha,tha,6);
	new_arp.spa = spa;
	new_arp.tpa = tpa;
	return new_arp;
}
struct route_table_entry *get_best_route_binary(uint32_t ip_dest, int left, int right, struct route_table_entry *rtable) {
    struct route_table_entry *res = NULL;
	while(left <=right){
		int mid  = (left + right) / 2;
		uint32_t prefix = rtable[mid].mask & ip_dest;
		if(prefix == rtable[mid].prefix  && !res)
			res = &rtable[mid];
		//daca gasesc o varianta mai buna decat cea initiala o iau pe aceea cu masca mai mare
		if(prefix == rtable[mid].prefix  && res)
			if(ntohl(rtable[mid].mask) > ntohl(res->mask))
				res = &rtable[mid];
		if (ntohl(rtable[mid].prefix) <= ntohl(ip_dest))
			left = mid + 1;
		else
			right = mid - 1;	
	}
	return res;
	
}
int compare(const void *x, const void *y) {
	struct route_table_entry rtable1 = *(struct route_table_entry *)x;
	struct route_table_entry rtable2 = *(struct route_table_entry *)y;

	if (ntohl(rtable1.prefix) > ntohl(rtable2.prefix))
		return ntohl(rtable1.prefix) - ntohl(rtable2.prefix);

	if (ntohl(rtable1.prefix) == ntohl(rtable2.prefix))
		if (ntohl(rtable1.mask) > ntohl(rtable2.mask))
			return ntohl(rtable1.mask) - ntohl(rtable2.mask);

	return ntohl(rtable1.prefix) - ntohl(rtable2.prefix);
}
int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	char buf[MAX_PACKET_LEN];
	// Do not modify this line
	init(argc - 2, argv + 2);

	struct arp_table_entry *arp_table;
	arp_table = (struct arp_table_entry *)calloc(256, sizeof(struct arp_table_entry));
	int arp_table_len = 0;

	struct route_table_entry *route_table = (struct route_table_entry *)calloc(100000 , sizeof(struct route_table_entry));
	int rtable_len = read_rtable(argv[1],route_table);
	qsort(route_table,rtable_len,sizeof(struct route_table_entry), compare);
	queue packet_queue = queue_create();
	queue length_queue = queue_create();
	queue interface_queue = queue_create();
	while (1) {
		int interface;
		size_t len;
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
		if(ntohs(eth_hdr->ether_type) == 0x0800){
			char *r_ip_chr = get_interface_ip(interface);
			struct in_addr router_ip;
			u_int8_t r_ip;
			hwaddr_aton(r_ip_chr,&r_ip);
			inet_aton(r_ip_chr,&router_ip);

			if(router_ip.s_addr == ip_hdr->daddr){
				//trimit mesaj ICMP 
				struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
				if(icmp_hdr->type == 8 && icmp_hdr->code == 0){
					//am primit echo request
					//trimit mesaj de tip ICMP echo reply
					char reply[MAX_PACKET_LEN];
					int reply_len = 0;

					//NEW ETHERNET HEADER
					uint8_t *mac = (uint8_t *) calloc(6, sizeof(uint8_t));
					get_interface_mac(interface,mac);
					struct ether_header new_eth_hdr = build_ether_header(mac,eth_hdr->ether_shost,0x0800);
					memcpy(reply + reply_len,&new_eth_hdr,sizeof(struct ether_header));
					reply_len += sizeof(struct ether_header);

					//NEW IPV4 HEADER
					struct iphdr new_ip_hdr = build_ip_header(ip_hdr->daddr,ip_hdr->saddr,ip_hdr->protocol);
					memcpy(reply + reply_len,&new_ip_hdr,sizeof(struct iphdr));
					reply_len += sizeof(struct iphdr);

					//NEW ECHO REPLAY HEADER
					struct icmphdr new_icmphdr = build_icmp_header(0,0,icmp_hdr->un.echo.id,icmp_hdr->un.echo.sequence);
					memcpy(reply + reply_len,&new_icmphdr,sizeof(struct icmphdr));
					reply_len += sizeof(struct icmphdr);
					send_to_link(interface,reply,reply_len);
					continue;
				}
			}
			if(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != 0)
				continue;	
			if(ip_hdr->ttl <= 1){ //Time exedeed type 11 code 0
					char reply[MAX_PACKET_LEN];
					int reply_len = 0;
					uint8_t *mac = (uint8_t *) calloc(6, sizeof(uint8_t));
					get_interface_mac(interface,mac);
					//NEW ETHERNET HEADER
					struct ether_header new_eth_hdr = build_ether_header(mac,eth_hdr->ether_shost,0x0800);
					memcpy(reply + reply_len,&new_eth_hdr,sizeof(struct ether_header));
					reply_len += sizeof(struct ether_header);

					//NEW IPV4 HEADER
					struct iphdr new_ip_hdr = build_ip_header(ip_hdr->daddr,ip_hdr->saddr,IPPROTO_ICMP);
					memcpy(reply + reply_len,&new_ip_hdr,sizeof(struct iphdr));
					reply_len += sizeof(struct iphdr);

					//NEW ICMP HEADER
					struct icmphdr new_icmphdr = build_icmp_header(11,0,0,0);
					memcpy(reply + reply_len,&new_icmphdr,sizeof(struct icmphdr));
					reply_len += sizeof(struct icmphdr);
					//precum și primii 64 de biți din payload-ul pachetului original
					memcpy(reply + reply_len,buf + sizeof(struct iphdr) + sizeof(struct ether_header),64);
					reply_len += 64 * sizeof(uint8_t);
					send_to_link(interface,reply,reply_len);
					continue;
				}
			ip_hdr->ttl--;
			//cautare eficienta tabela de rutare
			struct route_table_entry *res = get_best_route_binary(ip_hdr->daddr,0,rtable_len - 1,route_table);
			if(res == NULL){ //Destination unreacheable type 3 code 0
				//NEW ETHERNET HEADER
				char reply[MAX_PACKET_LEN];
				int reply_len = 0;
				uint8_t *mac = (uint8_t *) calloc(6, sizeof(uint8_t));
				get_interface_mac(interface,mac);
				struct ether_header new_eth_hdr = build_ether_header(mac,eth_hdr->ether_shost,0x800);
				memcpy(reply + reply_len,&new_eth_hdr,sizeof(struct ether_header));
				reply_len += sizeof(struct ether_header);

				//NEW IPV4 HEADER
				struct iphdr new_ip_hdr = build_ip_header(ip_hdr->daddr,ip_hdr->saddr,IPPROTO_ICMP);
				memcpy(reply + reply_len,&new_ip_hdr,sizeof(struct iphdr));
				reply_len += sizeof(struct iphdr);
				//NEW ICMP HEADER
				struct icmphdr new_icmphdr = build_icmp_header(3,0,0,0);
				memcpy(reply + reply_len,&new_icmphdr,sizeof(struct icmphdr));
				reply_len += sizeof(struct icmphdr);

				//precum și primii 64 de biți din payload-ul pachetului original
				memcpy(reply + reply_len,buf + sizeof(struct iphdr) + sizeof(struct ether_header),64);
				reply_len += 64 * sizeof(uint8_t);
				send_to_link(interface,reply,reply_len);
				continue;
			}
			u_int16_t old_check = ip_hdr->check;
			uint8_t old_ttl = ip_hdr->ttl + 1;
			ip_hdr->check = 0;
			ip_hdr->check = ~(~old_check + ~((uint16_t) old_ttl) + ((uint16_t)ip_hdr->ttl)) - 1;
			struct arp_table_entry *arp_res = NULL;
			arp_res = get_next_hop(arp_table,arp_table_len,res->next_hop);
			
			if(arp_res == NULL){
				char buf_help[MAX_PACKET_LEN];
				memcpy(buf_help,buf,len);
				queue_enq(packet_queue,buf_help);
				queue_enq(length_queue,&len);
				queue_enq(interface_queue,&res->interface);
				char reply[MAX_PACKET_LEN];
				int reply_len = 0;
				uint8_t *mac = (uint8_t*)calloc(6, sizeof(uint8_t));
				get_interface_mac(res->interface,mac);
				
				uint8_t *broadcast = (uint8_t*)calloc(6, sizeof(uint8_t));
				for(int i = 0; i < 6; i++) {
					broadcast[i] = 0xff;
				}
				//NEW ETHERNET HEADER
				struct ether_header new_eth_hdr = build_ether_header(mac,broadcast,0x0806);
				memcpy(reply + reply_len,&new_eth_hdr,sizeof(struct ether_header));
				reply_len += sizeof(struct ether_header);

				//NEW ARP HEADER
				char *my_ip = get_interface_ip(res->interface);
				struct in_addr my_ip_struct;
				inet_aton(my_ip,&my_ip_struct);
				struct arp_header new_arp_hdr = build_arp_header(0x0001,mac,my_ip_struct.s_addr,broadcast,res->next_hop);
				memcpy(reply + reply_len,&new_arp_hdr,sizeof(struct arp_header));
				reply_len += sizeof(struct arp_header);

				send_to_link(res->interface,reply,reply_len);
				continue;
			}
			get_interface_mac(res->interface,eth_hdr->ether_shost);
			memcpy(eth_hdr->ether_dhost,arp_res->mac,sizeof(arp_res->mac)); 
			send_to_link(res->interface,buf,len);
			continue;
		} else if(ntohs(eth_hdr->ether_type) == 0x0806){ //ARP
					struct arp_header *arp_head = (struct arp_header *)(buf + sizeof(struct ether_header));
					if(ntohs(arp_head->op) == 0x0001){ //Arp request
						uint8_t *mac = (uint8_t *) calloc(6, sizeof(uint8_t));
						get_interface_mac(interface,mac);
						char reply[MAX_PACKET_LEN];
						int reply_len = 0; 
						//NEW ETHERNET HEADER
						struct ether_header new_eth_hdr = build_ether_header(mac,eth_hdr->ether_shost,0x0806);
						memcpy(reply + reply_len,&new_eth_hdr,sizeof(struct ether_header));
						reply_len += sizeof(struct ether_header);

						//NEW ARP HEADER
						struct arp_header new_arp = build_arp_header(0x0002,mac,arp_head->tpa,arp_head->sha,arp_head->spa);
						memcpy(reply + reply_len,&new_arp,sizeof(struct arp_header));
						reply_len += sizeof(struct arp_header);

						send_to_link(interface,reply,reply_len);
						continue;
					}
					else if(ntohs(arp_head->op) == 0x0002){//Arp reply	
						memcpy(arp_table[arp_table_len].mac,arp_head->sha,6);
						arp_table[arp_table_len].ip = arp_head->spa;
						arp_table_len++;

						if(!queue_empty(packet_queue)){
							char *q_buff = queue_deq(packet_queue);
							struct ether_header *q_eth_head = (struct ether_header *)q_buff;
							int *q_interface = queue_deq(interface_queue);
							get_interface_mac(*q_interface,q_eth_head->ether_shost);
							memcpy(q_eth_head->ether_dhost,arp_head->sha,6);
							size_t *q_len = queue_deq(length_queue);
							send_to_link(*q_interface,q_buff,*q_len);
							continue;
						}
					}
				}
				else
					return 0; 

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
	}
}

