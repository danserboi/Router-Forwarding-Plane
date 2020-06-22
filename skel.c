// SERBOI FLOREA-DAN 325CB
#include "skel.h"

int interfaces[ROUTER_NUM_INTERFACES];

int get_sock(const char *if_name)
{
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

packet* socket_receive_message(int sockfd, packet *m)
{        
	/* 
	 * Note that "buffer" should be at least the MTU size of the 
	 * interface, eg 1500 bytes 
	 * */
	m->len = read(sockfd, m->payload, MAX_LEN);
	DIE(m->len == -1, "read");
	return m;
}

int send_packet(int sockfd, packet *m)
{        
	/* 
	 * Note that "buffer" should be at least the MTU size of the 
	 * interface, eg 1500 bytes 
	 * */
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

char *get_interface_ip(int interface)
{
	struct ifreq ifr;
	sprintf(ifr.ifr_name, "r-%u", interface);
	ioctl(interfaces[interface], SIOCGIFADDR, &ifr);
	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

int get_interface_mac(int interface, uint8_t *mac)
{
	struct ifreq ifr;
	sprintf(ifr.ifr_name, "r-%u", interface);
	ioctl(interfaces[interface], SIOCGIFHWADDR, &ifr);
	memcpy(mac, ifr.ifr_addr.sa_data, 6);
	return 1;
}

void init()
{
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
/**
 * hwaddr_aton - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
int hwaddr_aton(const char *txt, uint8_t *addr)
{
	int i;
	for (i = 0; i < 6; i++) {
		int a, b;
		a = hex2num(*txt++);
		if (a < 0)
			return -1;
		b = hex2num(*txt++);
		if (b < 0)
			return -1;
		*addr++ = (a << 4) | b;
		if (i < 5 && *txt++ != ':')
			return -1;
	}
	return 0;
}

uint16_t checksum(void *vdata, size_t length) {
	// Cast the data pointer to one that can be indexed.
	char* data=(char*)vdata;

	// Initialise the accumulator.
	uint64_t acc=0xffff;

	// Handle any partial block at the start of the data.
	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	// Handle any complete 32-bit blocks.
	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;

	// Handle any partial block at the end of the data.
	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}

	// Handle deferred carries.
	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	// If the data began at an odd byte address
	// then reverse the byte order to compensate.
	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	// Return the checksum in network byte order.
	return htons(~acc);
}

//----------------------------ADAUGATE DE MINE-------------------------------

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
	for(int i = 0; i < arp_table_len; i++){
		if(ip == arp_table[i].ip){
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
	while((ch=fgetc(f))!=EOF) {
      if(ch=='\n')
			no_lines++;
	}
	// alocam dinamic tabela de rutare
	rtable = calloc(no_lines, sizeof(struct route_table_entry));
	// ne pozitionam din nou la inceputul fisierului pentru a adauga intrarile in tabela
	fseek(f, 0, SEEK_SET);
	char line[80];
	for(int i = 0; fgets(line, sizeof(line), f); i++) {
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
    if(N & (1<<i))
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
	
	while(mask_bit){
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
	while(curr->bit[dest_ip_bit]){
		// ma deplasez pe acel bit
		curr = curr->bit[dest_ip_bit];
		// daca exista intrare, o retin
		if(curr->r_entry)
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
    if(!current)
        return;

    // ma duc recursiv pe toate nodurile
    for (int i = 0; i < BITS; i++)
       free_trie(current->bit[i]);
    
	// eliberez nodul
    free(current);
}