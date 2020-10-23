#include "utils.h"

int interfaces[ROUTER_NUM_INTERFACES];

int get_sock(const char *if_name) {
	int res;
	int s = socket(AF_PACKET, SOCK_RAW, 768);
	DIE(s == -1, "socket");

	struct ifreq intf;
	strcpy(intf.ifr_name, if_name);
	res = ioctl(s, SIOCGIFINDEX, &intf);
	DIE(res, "ioctl SIOCGIFINDEX");

	struct sockaddr_ll addr;
	memset(&addr, 0x00, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = intf.ifr_ifindex;

	res = bind(s , (struct sockaddr *)&addr , sizeof(addr));
	DIE(res == -1, "bind");
	return s;
}

packet* socket_receive_message(int sockfd, packet *m) {
	// "buffer-ul" trebuie sa aiba cel putin 1500 bytes(MTU)
	m->len = read(sockfd, m->payload, MAX_LEN);
	DIE(m->len == -1, "read");
	return m;
}

int send_packet(int sockfd, packet *m) {
	// "buffer-ul" trebuie sa aiba cel putin 1500 bytes(MTU)
	int ret;
	ret = write(interfaces[sockfd], m->payload, m->len);
	DIE(ret == -1, "write");
	return ret;
}

int get_packet(packet *m) {
	int res;
	fd_set set;

	FD_ZERO(&set);
	while (1) {
		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			FD_SET(interfaces[i], &set);
		}

		res = select(interfaces[ROUTER_NUM_INTERFACES - 1] + 1, &set, NULL, NULL, NULL);
		DIE(res == -1, "select");

		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			if (FD_ISSET(interfaces[i], &set)) {
				socket_receive_message(interfaces[i], m);
				m->interface = i;
				return 0;
			}
		}
	}
	return -1;
}

char *get_interface_ip(int interface) {
	struct ifreq ifr;
	sprintf(ifr.ifr_name, "r-%u", interface);
	ioctl(interfaces[interface], SIOCGIFADDR, &ifr);
	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

int get_interface_mac(int interface, uint8_t *mac) {
	struct ifreq ifr;
	sprintf(ifr.ifr_name, "r-%u", interface);
	ioctl(interfaces[interface], SIOCGIFHWADDR, &ifr);
	memcpy(mac, ifr.ifr_addr.sa_data, 6);
	return 1;
}

void init() {
	int s0 = get_sock("r-0");
	int s1 = get_sock("r-1");
	int s2 = get_sock("r-2");
	int s3 = get_sock("r-3");
	interfaces[0] = s0;
	interfaces[1] = s1;
	interfaces[2] = s2;
	interfaces[3] = s3;
}

static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}
int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}

uint16_t checksum(void *vdata, size_t length) {
	// facem cast pointer-ului pentru a putea fi indexat
	char* data = (char*)vdata;

	// initializam acumulatorul
	uint64_t acc = 0xffff;

	// manuim orice bloc partial de la inceputul datelor
	unsigned int offset = ((uintptr_t)data) & 3;
	if (offset) {
		size_t count = 4 - offset;
		if (count > length) count = length;
		uint32_t word = 0;
		memcpy(offset + (char*)&word, data, count);
		acc += ntohl(word);
		data += count;
		length -= count;
	}

	// manuim orice block complet de 32 bits
	char* data_end = data + (length & ~3);
	while (data != data_end) {
		uint32_t word;
		memcpy(&word, data, 4);
		acc += ntohl(word);
		data += 4;
	}
	length &= 3;

	// manuim orice bloc partial de la sfarsitul datelor
	if (length) {
		uint32_t word = 0;
		memcpy(&word, data, length);
		acc += ntohl(word);
	}

	acc = (acc & 0xffffffff) + (acc >> 32);
	while (acc >> 16) {
		acc = (acc & 0xffff) + (acc >> 16);
	}

	// daca datele au inceput de la o adresa impara
	// inversam ordinea bytes-ilor pentru a compensa
	if (offset & 1) {
		acc = ((acc & 0xff00) >> 8) | ((acc & 0x00ff) << 8);
	}

	// returnam checksum-ul in ordinea de retea a bytes-ilor.
	return htons(~acc);
}

// functia initializeaza campurile unui packet
void init_packet(packet* pkt, int length, int interface)
{
	pkt->len = length;
	memset(pkt->payload, 0, sizeof(pkt->payload));
	pkt->interface = interface;
}

// returneaza intrarea din tabela arp pentru un ip dat sau NULL daca nu exista
struct arp_entry *get_arp_entry(uint32_t ip, struct arp_entry * arp_table, int arp_table_len) {
	struct arp_entry * matching_arp_entry = NULL;
	for (int i = 0; i < arp_table_len; i++) {
		if (ip == arp_table[i].ip) {
			matching_arp_entry = & arp_table[i];
		}
	}
	return matching_arp_entry;
}

// aceasta functie parseaza tabela de rutare si introduce intr-un trie intrarile pentru a cauta in O(1)
struct route_table_entry * parse_rtable(struct Trie * trie)
{
	struct route_table_entry * rtable = NULL;
	FILE *f = NULL;
	f = fopen("rtable.txt", "r");
	DIE(f == NULL, "Failed to open rtable.txt");
	// intai numar cate linii are fisierul
	// pentru a afla numarul de intrari care trebuie alocate dinamic
	char ch;
	int no_lines = 0;
	// citim caracter cu caracter si verificam daca avem avem newline
	while ((ch = fgetc(f)) != EOF) {
		if (ch == '\n')
			no_lines++;
	}
	// alocam dinamic tabela de rutare
	rtable = calloc(no_lines, sizeof(struct route_table_entry));
	// ne pozitionam din nou la inceputul fisierului pentru a adauga intrarile in tabela
	fseek(f, 0, SEEK_SET);
	char line[80];
	for (int i = 0; fgets(line, sizeof(line), f); i++) {
		char prefix[20], next_hop[20], mask[20], interface[20];
		sscanf(line, "%s %s %s %s", prefix, next_hop, mask, interface);
		rtable[i].prefix = inet_addr(prefix);
		rtable[i].next_hop = inet_addr(next_hop);
		rtable[i].mask = inet_addr(mask);
		rtable[i].interface = atoi(interface);
		// introducem in trie intrarea curenta
		insert(trie, &rtable[i]);
	}
	fclose(f);
	return rtable;
}

// functia returneaza valoarea bit-ului i din numarul N
int bit(uint32_t N, int i)
{
	if (N & (1 << i))
		return 1;
	else
		return 0;
}

// functia aloca memorie si construieste un nod nou al unui Trie
struct Trie* getNewTrieNode()
{
	struct Trie* node = (struct Trie*)malloc(sizeof(struct Trie));
	node->r_entry = NULL;

	for (int i = 0; i < BITS; i++)
		node->bit[i] = NULL;

	return node;
}

// functia insereaza o intrare din tabela de rutare in Trie
void insert(struct Trie *head, struct route_table_entry* entry)
{
	// pornesc de la radacina arborelui
	struct Trie* curr = head;
	int i = 0;
	// cat timp bit-ul de masca e 1
	// inserez bit-ul prefixului in trie, daca nu exista
	// si la sfarsit marchez intrarea in tabela de rutare
	int mask_bit = bit(entry->mask, i);
	int prefix_bit = bit(entry->prefix, i);

	while (mask_bit) {
		// creez un nod nou daca acest bit nu este in componenta altor intregi din arbore
		if (curr->bit[prefix_bit] == NULL)
			curr->bit[prefix_bit] = getNewTrieNode();
		// ma deplasez pe acest nod
		curr = curr->bit[prefix_bit];
		//trec la urmatorul bit din masca/prefix
		i++;
		mask_bit = bit(entry->mask, i);
		prefix_bit = bit(entry->prefix, i);
	}

	// la sfarsit marchez intrarea
	curr->r_entry = entry;
}

// functia returneaza cea mai specifica intrare pentru un ip dat sau NULL daca nu exista
struct route_table_entry* best_route_from_trie(struct Trie* head, uint32_t dest_ip)
{
	struct route_table_entry* res = NULL;
	// daca arborele e gol, evident ca nu exista nimic
	if (head == NULL)
		return NULL;

	// pornesc de la radacina trie-ului
	struct Trie* curr = head;

	// incep cu primul bit din prefix
	int i = 0;
	int dest_ip_bit = bit(dest_ip, i);
	while (curr->bit[dest_ip_bit]) {
		// ma deplasez pe acel bit
		curr = curr->bit[dest_ip_bit];
		// daca exista intrare, o retin
		if (curr->r_entry)
			res = curr->r_entry;
		// trec la bit-ul urmator din ip-ul destinatie
		i++;
		dest_ip_bit = bit(dest_ip, i);
	}

	// ultima intrare va fi si cea mai specifica (daca nu exista, rezultatul va fi NULL)
	return res;
}

// functia dezaloca memoria Trie-ului
void free_trie(struct Trie * current)
{
	// daca e null, ma opresc, nu eliberez nimic
	if (!current)
		return;

	// ma duc recursiv pe toate nodurile
	for (int i = 0; i < BITS; i++)
		free_trie(current->bit[i]);

	// eliberez nodul
	free(current);
}

// functia construieste si trimite un raspuns ICMP de tip echo reply
void echo_reply(packet m, struct ether_header *eth_hdr, struct iphdr *ip_hdr) {
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
}

// functia construieste si trimite un raspuns ICMP de tip time exceeded
void time_exceeded_reply(packet m, struct ether_header *eth_hdr, struct iphdr *ip_hdr) {
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
}

// functia construieste si trimite un raspuns ICMP de tip destination unreachable
void dest_unreachable_reply(packet m, struct ether_header *eth_hdr, struct iphdr *ip_hdr) {
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
}

// functia construieste si trimite un ARP request
void arp_request(uint8_t* best_mac, struct route_table_entry * best_route) {
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
}

// functia construieste si trimite un ARP reply
void arp_reply(packet m, struct ether_header *eth_hdr, struct ether_arp* arp) {
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
}
