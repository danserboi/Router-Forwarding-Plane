#include "utils.h"

int main(int argc, char *argv[]) {
	setvbuf(stdout, NULL, _IONBF, 0);
	packet m;
	int rc;
	init();
	// vom crea un trie pentru a cauta in O(1) cea mai potrivita intrare din tabela de rutare pentru un ip destinatie
	struct Trie* head = getNewTrieNode();
	// vom parsa tabela de rutare si in acelasi timp vom stoca in trie intrarile
	struct route_table_entry * rtable = parse_rtable(head);
	// alocam dinamic tabela ARP
	struct arp_entry * arp_table = calloc(100, sizeof(struct arp_entry));
	int arp_table_len = 0;
	// in aceasta coada retinem pachetele pe care nu stim sa le forwardam la un moment dat deoarece nu cunoastem adresa MAC a next-hop-ului
	queue queue = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;

		// tratam cazul cand avem packet IP
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

			if (ip_hdr->protocol == IPPROTO_ICMP) {
				struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

				// daca pachetul este icmp echo request si imi este destinat, arunc pachetul si raspund cu un echo reply, altfel incerc sa forwardez
				if (icmp_hdr->type == ICMP_ECHO) {
					// verificam daca ip-ul destinatie coincide ip-ul vreunei interfete
					uint32_t * interface_ip = NULL;
					for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
						uint32_t current_interface_ip = inet_addr(get_interface_ip(i));
						if (current_interface_ip == ip_hdr->daddr)
							interface_ip = &ip_hdr->daddr;
					}

					// daca da, arunc pachetul original si raspund cu un echo reply la acest echo request
					// altfel incerc sa forwardez acest pachet IP
					if (interface_ip != NULL) {
						echo_reply(m, eth_hdr, ip_hdr);
						continue;
					}
				}
			}

			// raspund cu un packet ICMP de tip TIME EXCEEDED daca timpul a expirat
			if (ip_hdr->ttl <= 1) {
				time_exceeded_reply(m, eth_hdr, ip_hdr);
				continue;
			}

			// cautam cea mai buna ruta pentru packetul IP care se doreste forwardat
			struct route_table_entry * best_route = best_route_from_trie(head, ip_hdr->daddr);
			// daca nu am ruta
			if (best_route == NULL) {
				dest_unreachable_reply(m, eth_hdr, ip_hdr);
				continue;
			}

			// daca nu am probleme cu TTL sau cu ruta, iar checksum-ul este bun, atunci incerc sa forwardez
			if (checksum(ip_hdr, sizeof(struct iphdr)) == 0) {
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
				if (matching_arp_entry != NULL) {
					//actualizez mac-ul destinatie, trimit packetul si astept packet nou
					memcpy(eth_hdr->ether_dhost, matching_arp_entry->mac, 6);
					int s = send_packet(best_route->interface, &m);
					DIE(s == -1, "Sending error !");
					continue;
				}
				// altfel, trebuie sa punem in coada pachetul si sa trimitem un arp request
				else {
					packet* packet_on_hold = calloc(1, sizeof(packet));
					memcpy(packet_on_hold, &m, sizeof(packet));
					queue_enq(queue, packet_on_hold);
					arp_request(best_mac, best_route);
					continue;
				}
			}
		}

		// tratam cazul cand avem packet ARP
		else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			struct ether_arp* arp = (struct ether_arp*)(m.payload + sizeof(struct ether_header));

			// verfic daca am ARP REQUEST si raspund cu ARP REPLY
			if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REQUEST) {
				arp_reply(m, eth_hdr, arp);
				continue;
			}

			// verific daca am ARP REPLY
			if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REPLY) {
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
					if (ip_hdr->daddr == *(uint32_t * )(arp->arp_spa)) {
						memcpy(eth_hdr->ether_dhost, arp->arp_sha, 6);
						//pun pe stiva pachetul cautat ca sa pot elibera memoria de pe heap si apoi trimit
						packet pkt_to_be_send = *pkt;
						free(pkt);
						int s = send_packet(pkt_to_be_send.interface, &pkt_to_be_send);
						DIE(s == -1, "Sending error !");
						break;
					}
					// altfel bag la loc pachetul in coada
					else {
						queue_enq(queue, pkt);
					}
				} while (!queue_empty(queue));
			}
		}
	}
	free_trie(head);
	free(rtable);
	free(arp_table);
	return 0;
}
