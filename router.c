// SERBOI FLOREA-DAN 325CB
#include "skel.h"

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	packet m;
	int rc;
	init();
	// vom crea un trie pentru a cauta in O(1) cea mai potrivita intrare din tabela de rutare pentru un ip destinatie
	struct Trie* head = getNewTrieNode();
	// vom parsa tabela de rutare si in acelasi timp vom stoca in trie intrarile
	struct route_table_entry * rtable = parse_rtable(head);
	// alocam dinamic tabela ARP
	int arp_table_len = 0;
	struct arp_entry * arp_table = calloc(100, sizeof(struct arp_entry));
	// in aceasta coada retinem pachetele pe care nu stim sa le forwardam la un moment dat deoarece nu cunoastem adresa MAC a next-hop-ului
	queue queue = queue_create();
	
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		
		// tratam cazul cand avem packet IP
		if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
			
			if(ip_hdr->protocol == IPPROTO_ICMP){
				struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

				// daca pachetul este icmp echo request si imi este destinat, arunc pachetul si raspund cu un echo reply, altfel incerc sa forwardez
				if(icmp_hdr->type == ICMP_ECHO){	
					// verificam daca ip-ul destinatie coincide ip-ul vreunei interfete
					uint32_t * interface_ip = NULL;
					for(int i = 0; i < ROUTER_NUM_INTERFACES; i++){
						uint32_t current_interface_ip = inet_addr(get_interface_ip(i));
						if(current_interface_ip == ip_hdr->daddr)
							interface_ip = &ip_hdr->daddr;				
					}

					// daca da, arunc pachetul original si raspund cu un echo reply la acest echo request
					// altfel incerc sa forwardez acest pachet IP
					if(interface_ip != NULL){
						packet reply;
						init_packet(&reply, m.len, m.interface);
						struct ether_header *eth_hdr_reply = (struct ether_header *)reply.payload;
						struct iphdr *ip_hdr_reply = (struct iphdr *)(reply.payload + sizeof(struct ether_header));
						struct icmphdr *icmp_hdr_reply = (struct icmphdr *)(reply.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
						// completez header-ul de Ethernet
						uint8_t interface_mac[6]; 
						get_interface_mac(m.interface, interface_mac);
						memcpy(eth_hdr_reply->ether_dhost, eth_hdr->ether_shost, 6);
						memcpy(eth_hdr_reply->ether_shost, interface_mac, 6);
						eth_hdr_reply->ether_type = htons(ETHERTYPE_IP);
						// completez header-ul de IPv4
						ip_hdr_reply->version = 4;
						ip_hdr_reply->ihl = 5;
						ip_hdr_reply->tos = 0;
						ip_hdr_reply->tot_len = htons(reply.len - sizeof(struct ether_header));
						ip_hdr_reply->id = htons(getpid() & 0xFF);
						ip_hdr_reply->frag_off = htons(0);
						ip_hdr_reply->ttl = 64;
						ip_hdr_reply->protocol = IPPROTO_ICMP;
						ip_hdr_reply->saddr = ip_hdr->daddr;
						ip_hdr_reply->daddr = ip_hdr->saddr;
						ip_hdr_reply->check = 0;
						ip_hdr_reply->check = checksum(ip_hdr_reply, sizeof(struct iphdr));
						// completez header-ul de ICMP
						icmp_hdr_reply->type = ICMP_ECHOREPLY;
						icmp_hdr_reply->code = 0;
						icmp_hdr_reply->un.echo.id = htons(getpid() & 0xFF);
						icmp_hdr_reply->un.echo.sequence = htons(0);
						icmp_hdr_reply->checksum = 0;
						icmp_hdr_reply->checksum = checksum(icmp_hdr_reply, sizeof(struct icmphdr));
						// trimit pachetul si astept packet nou
						int s = send_packet(reply.interface, &reply);	
						DIE(s == -1, "Sending error !");								
						continue;
					}
				}
			}

			// raspund cu un packet ICMP de tip TIME EXCEEDED daca timpul a expirat
			if(ip_hdr->ttl <= 1){
				packet reply;
				init_packet(&reply, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), m.interface);
				struct ether_header *eth_hdr_reply = (struct ether_header *)reply.payload;
				struct iphdr *ip_hdr_reply = (struct iphdr *)(reply.payload + sizeof(struct ether_header));
				struct icmphdr *icmp_hdr_reply = (struct icmphdr *)(reply.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
				// completez header-ul de Ethernet
				uint8_t interface_mac[6]; 
				get_interface_mac(m.interface, interface_mac);
				memcpy(eth_hdr_reply->ether_dhost, eth_hdr->ether_shost, 6);
				memcpy(eth_hdr_reply->ether_shost, interface_mac, 6);
				eth_hdr_reply->ether_type = htons(ETHERTYPE_IP);
				// completez header-ul de IPv4
				ip_hdr_reply->version = 4;
				ip_hdr_reply->ihl = 5;
				ip_hdr_reply->tos = 0;
				ip_hdr_reply->tot_len = htons(reply.len - sizeof(struct ether_header));
				ip_hdr_reply->id = htons(getpid() & 0xFF);
				ip_hdr_reply->frag_off = htons(0);
				ip_hdr_reply->ttl = 64;
				ip_hdr_reply->protocol = IPPROTO_ICMP;
				ip_hdr_reply->saddr = *(int32_t *)(get_interface_ip(m.interface));
				ip_hdr_reply->daddr = ip_hdr->saddr;
				ip_hdr_reply->check = 0;
				ip_hdr_reply->check = checksum(ip_hdr_reply, sizeof(struct iphdr));
				// completez header-ul de ICMP
				icmp_hdr_reply->type = ICMP_TIME_EXCEEDED;
				icmp_hdr_reply->code = 0;
				icmp_hdr_reply->un.echo.id = htons(getpid() & 0xFF);
				icmp_hdr_reply->un.echo.sequence = htons(0);
				icmp_hdr_reply->checksum = 0;
				icmp_hdr_reply->checksum = checksum(icmp_hdr_reply, sizeof(struct icmphdr));
				// trimit pachetul si astept packet nou
				int s = send_packet(reply.interface, &reply);
				DIE(s == -1, "Sending error !");								
				continue;
			}

			// cautam cea mai buna ruta pentru packetul IP care se doreste forwardat
			struct route_table_entry * best_route = best_route_from_trie(head, ip_hdr->daddr);			
			// daca nu am ruta
			if(best_route == NULL){
				packet reply;
				init_packet(&reply, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), m.interface);
				struct ether_header *eth_hdr_reply = (struct ether_header *)reply.payload;
				struct iphdr *ip_hdr_reply = (struct iphdr *)(reply.payload + sizeof(struct ether_header));
				struct icmphdr *icmp_hdr_reply = (struct icmphdr *)(reply.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
				// completez header-ul de Ethernet
				uint8_t my_mac[6]; 
				get_interface_mac(m.interface, my_mac);
				memcpy(eth_hdr_reply->ether_dhost, eth_hdr->ether_shost, 6);
				memcpy(eth_hdr_reply->ether_shost, my_mac, 6);
				eth_hdr_reply->ether_type = htons(ETHERTYPE_IP);
				// completez header-ul de IPv4
				ip_hdr_reply->version = 4;
				ip_hdr_reply->ihl = 5;
				ip_hdr_reply->tos = 0;
				ip_hdr_reply->tot_len = htons(reply.len - sizeof(struct ether_header));
				ip_hdr_reply->id = htons(getpid() & 0xFF);
				ip_hdr_reply->frag_off = htons(0);
				ip_hdr_reply->ttl = 64;
				ip_hdr_reply->protocol = IPPROTO_ICMP;
				ip_hdr_reply->saddr = *(int32_t *)(get_interface_ip(m.interface));
				ip_hdr_reply->daddr = ip_hdr->saddr;
				ip_hdr_reply->check = 0;
				ip_hdr_reply->check = checksum(ip_hdr_reply, sizeof(struct iphdr));
				// completez header-ul de ICMP
				icmp_hdr_reply->type = ICMP_DEST_UNREACH;
				icmp_hdr_reply->code = 0;
				icmp_hdr_reply->un.echo.id = htons(getpid() & 0xFF);
				icmp_hdr_reply->un.echo.sequence = htons(0);
				icmp_hdr_reply->checksum = 0;
				icmp_hdr_reply->checksum = checksum(icmp_hdr_reply, sizeof(struct icmphdr));
				// trimit pachetul si astept packet nou
				int s = send_packet(reply.interface, &reply);
				DIE(s == -1, "Sending error !");								
				continue;
			}

			// daca nu am probleme cu TTL sau cu ruta, iar checksum-ul este bun, atunci incerc sa forwardez
			if(checksum(ip_hdr, sizeof(struct iphdr)) == 0){
				// decrementez ttl
				ip_hdr->ttl--;
				ip_hdr->check = 0;
				// calculez checksum
				ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));
				// actualizez mac-ul sursa = mac-ul interfetei pe care o sa trimit packetul
				uint8_t best_mac[6];
				get_interface_mac(best_route->interface, best_mac);
				memcpy(eth_hdr->ether_shost, best_mac, 6);
				// completez si campul interface
				m.interface = best_route->interface;
				// singurul lucru care ramane de completat e mac-ul next hop-ului 
				struct arp_entry * matching_arp_entry = NULL;
				matching_arp_entry = get_arp_entry(best_route->next_hop, arp_table, arp_table_len);
				// daca am gasit intrare in tabela arp, forwardam packetul
				if(matching_arp_entry != NULL){
					//actualizez mac-ul destinatie, trimit packetul si astept packet nou
					memcpy(eth_hdr->ether_dhost, matching_arp_entry->mac, 6);
					int s = send_packet(best_route->interface, &m);
					DIE(s == -1, "Sending error !");								
					continue;
				}
				// altfel, trebuie sa punem in coada pachetul si sa trimitem un arp request
				else{
					packet* packet_on_hold = calloc(1, sizeof(packet));
					memcpy(packet_on_hold, &m, sizeof(packet));
					queue_enq(queue, packet_on_hold);
					// construiesc arp request-ul
					packet request;
					init_packet(&request, sizeof(struct ether_header) + sizeof(struct ether_arp), best_route->interface);
					struct ether_header *eth_hdr_request = (struct ether_header *)request.payload;
					struct ether_arp* arp_request = (struct ether_arp*)(request.payload + sizeof(struct ether_header));
					// completez header-ul de Ethernet
					// ca mac destinatie, am 255:255:255:255:255:255 = broadcast
					memset(eth_hdr_request->ether_dhost, 255, 6);
					// ca mac sursa, am mac-ul interfetei corespunzatoare celei mai bune rute
					memcpy(eth_hdr_request->ether_shost, best_mac, 6);
					eth_hdr_request->ether_type = htons(ETHERTYPE_ARP);
					// completez header-ul de ARP
					arp_request->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
					arp_request->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
					arp_request->ea_hdr.ar_hln = 6;
					arp_request->ea_hdr.ar_pln = 4;
					arp_request->ea_hdr.ar_op = htons(ARPOP_REQUEST);
					// arp_sha = adresa mac a celui care cere = eu, router-ul(de pe best interface)
					memcpy(arp_request->arp_sha, best_mac, 6);
					// arp_spa = adresa ip a celui care cere = ip-ul pentru best interface
					*(uint32_t*)(arp_request->arp_spa) = inet_addr(get_interface_ip(best_route->interface));
					// arp_tha = nu e nimic, fiindca aici ar fi trebuit sa fie mac-ul cautat(pe care nu il stiu)
					memset(arp_request->arp_tha, 0, 6);
					// arp_tpa = adresa ip a host-ului pe care il caut = next_hop
					*(uint32_t*)(arp_request->arp_tpa) = best_route->next_hop;
					int s = send_packet(best_route->interface, &request);
					DIE(s == -1, "Sending error !");								
					continue;
				}
			}
		}
		
		// tratam cazul cand avem packet ARP
		else if(ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP){
			struct ether_arp* arp = (struct ether_arp*)(m.payload + sizeof(struct ether_header));
			
			// verfic daca am ARP REQUEST
			if(ntohs(arp->ea_hdr.ar_op) == ARPOP_REQUEST){
				packet reply;
				init_packet(&reply, sizeof(struct ether_header) + sizeof(struct ether_arp), m.interface);
				struct ether_header *eth_hdr_reply = (struct ether_header *)reply.payload;
				struct ether_arp* arp_reply = (struct ether_arp*)(reply.payload + sizeof(struct ether_header));
				// completez header-ul de Ethernet
				uint8_t my_mac[6]; 
				get_interface_mac(m.interface, my_mac);
				// pur si simplu se inverseaza adresele de MAC
				memcpy(eth_hdr_reply->ether_dhost, eth_hdr->ether_shost, 6);
				memcpy(eth_hdr_reply->ether_shost, my_mac, 6);
				eth_hdr_reply->ether_type = htons(ETHERTYPE_ARP);
				// completez header-ul de ARP
				arp_reply->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
				arp_reply->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
				arp_reply->ea_hdr.ar_hln = 6;
				arp_reply->ea_hdr.ar_pln = 4;
				arp_reply->ea_hdr.ar_op = htons(ARPOP_REPLY);
				// arp_reply->arp_sha = adresa mac pe care o cauta(adresa MAC a interfetei pe care a venit mesajul)
				memcpy(arp_reply->arp_sha, my_mac, 6);
				// arp_reply->arp_spa = adresa ip a host-ului pe care il cauta
				memcpy(arp_reply->arp_spa, arp->arp_tpa, 4);
				// arp_reply->arp_tha = adresa mac a celui care cere
				memcpy(arp_reply->arp_tha, arp->arp_sha, 6);
				// arp_reply->arp_tpa = adresa ip a celui care cere
				memcpy(arp_reply->arp_tpa, arp->arp_spa, 4);
				// trimit packetul si astept alt packet
				int s = send_packet(reply.interface, &reply);
				DIE(s == -1, "Sending error !");								
				continue;
			}
			
			// verific daca am ARP REPLY
			if(ntohs(arp->ea_hdr.ar_op) == ARPOP_REPLY){
				// adaugam in tabela ARP adresa cautata
				arp_table[arp_table_len].ip = *(uint32_t *)arp->arp_spa;
				memcpy(arp_table[arp_table_len].mac, arp->arp_sha, 6);
				arp_table_len++;
				// scoatem din coada pachetul pe care doream sa il forwardam
				do {
					packet* pkt = queue_deq(queue);
					struct ether_header *eth_hdr = (struct ether_header *)pkt->payload;
					struct iphdr *ip_hdr = (struct iphdr *)(pkt->payload + sizeof(struct ether_header));
					// daca am gasit pachetul, doar adaug adresa mac lipsa si forwardez pachetul
					if(ip_hdr->daddr == *(uint32_t * )(arp->arp_spa)){
						memcpy(eth_hdr->ether_dhost, arp->arp_sha, 6);
						//pun pe stiva pachetul cautat ca sa pot elibera memoria de pe heap si apoi trimit
						packet pkt_to_be_send = *pkt;
						free(pkt);
						int s = send_packet(pkt_to_be_send.interface, &pkt_to_be_send);
						DIE(s == -1, "Sending error !");								
						break;
					}
					// altfel bag la loc pachetul in coada
					else{
						queue_enq(queue, pkt);
					}
				} while(!queue_empty(queue));
			}
		}
	}
	free_trie(head);
	free(rtable);
	free(arp_table);
	return 0;
}