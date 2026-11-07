#include<string.h>
#include<arpa/inet.h>

#include "include/protocols.h"
#include "include/queue.h"
#include "include/lib.h"

// Structura pentru nodurile trie ului de rutare
struct nod_trie_rutare {
	struct nod_trie_rutare *copil[2];
	struct route_table_entry *ruta;
};

// Trie ce contine rutele din route table
struct trie_rutare {
	struct nod_trie_rutare *radacina;
};

// Structura de vector dinamic pt cache ARP
struct cache_arp {
	struct arp_table_entry *intrari;
	size_t nr_intrari;
	size_t capacitate;
};

// Structura pentru pachetele in asteptare de raspuns ARP
struct pachet_in_asteptare_arp {
	char frame[MAX_PACKET_LEN];
	size_t lungime;
	size_t interfata_iesire;
	uint32_t ip_next_hop;
};

// Structura finala a routerului
struct context_router {
	struct route_table_entry *rtable;
	int rtable_len;
	struct trie_rutare trie;
	struct cache_arp cache_pt_arp;
	queue coada_arp;
};

void insert_in_trie(struct trie_rutare *trie, struct route_table_entry *ruta) {
	// Transformam prefixul si masca in host order
	uint32_t prefix_host_order = ntohl(ruta->prefix);
	uint32_t mask_host_order = ntohl(ruta->mask);

	int lungime_prefix = 0;
	uint32_t aux_mask = mask_host_order;

	// Cat timp masca are bitul de la stanga 1, crestem lungimea prefixului
	while ((aux_mask & 0x80000000) != 0) {
		lungime_prefix++;
		aux_mask <<= 1;
	}

	struct nod_trie_rutare *nod_curent = trie->radacina;

	// Parcurgem trie ul conform bitilor din prefix
	for (int i = 0; i < lungime_prefix; i++) {
		// Luam pe rand cel mai din stanga bit din prefix
		int bit = (prefix_host_order >> (31 - i)) & 1;

		// Daca nu exista copil pentru bitul curent, il cream
		if (nod_curent->copil[bit] == NULL) {
			nod_curent->copil[bit] = calloc(1, sizeof(struct nod_trie_rutare));
		}

		nod_curent = nod_curent->copil[bit];
	}

	// La finalul prefixului, salvam ruta in nodul curent
	nod_curent->ruta = ruta;
}

void initializare_router(struct context_router *router, char *cale_rtable) {	
	// Alocam memorie pentru route table si citim rutele din fisier cu read_rtable
	router->rtable = malloc(sizeof(struct route_table_entry) * 100000);
	router->rtable_len = read_rtable(cale_rtable, router->rtable);

	// Construim trie ul de rutare pe baza route table ului
	router->trie.radacina = calloc(1, sizeof(struct nod_trie_rutare));
	for (int i = 0; i < router->rtable_len; i++) {
		insert_in_trie(&router->trie, &router->rtable[i]);
	}

	// Initializam cache ul ARP
	router->cache_pt_arp.nr_intrari = 0;
	router->cache_pt_arp.capacitate = 100;
	router->cache_pt_arp.intrari = malloc(sizeof(struct arp_table_entry) * router->cache_pt_arp.capacitate);

	// Cream coada pentru pachetele in asteptare de raspuns ARP
	router->coada_arp = create_queue();
}

struct route_table_entry *find_lpm(struct trie_rutare *trie, uint32_t ip_dest) {
	uint32_t ip_host_order = ntohl(ip_dest);

	struct nod_trie_rutare *nod_curent = trie->radacina;
	struct route_table_entry *lpm = NULL;

	// Parcurgem trie ul conform bitilor din ip_dest in host order
	for (int i = 0; i < 32; i++) {
		// Daca nodul curent are o ruta, o salvam ca potential lpm
		if (nod_curent->ruta != NULL) {
			lpm = nod_curent->ruta;
		}

		// Luam pe rand cel mai din stanga bit din ip_dest in host order
		int bit = (ip_host_order >> (31 - i)) & 1;

		// Daca nu exista copilul pt bitul extras, ne oprim si returnam lpm ul gasit pana acm
		if (nod_curent->copil[bit] == NULL) {
			return lpm;
		}

		nod_curent = nod_curent->copil[bit];
	}

	// Daca am ajuns la finalul trie ului, returnam lpm ul gasit pana acm
	if (nod_curent != NULL && nod_curent->ruta != NULL) {
		lpm = nod_curent->ruta;
	}

	return lpm;
}

uint8_t *cauta_mac_in_cache(struct cache_arp *cache, uint32_t ip) {
	// Cautam in cache adresa MAC corespunzatoare adresei IP
	for (size_t i = 0; i < cache->nr_intrari; i++) {
		if (cache->intrari[i].ip == ip) {
			return cache->intrari[i].mac;
		}

	}

	// Daca nu o gasim, returnam NULL
	return NULL;
}

void actualizeaza_cache_arp(struct cache_arp *cache, uint32_t ip, uint8_t mac[6]) {
	// Cautam sa vedem daca exista deja in cache IP ul
	for (size_t i = 0; i < cache->nr_intrari; i++) {
		// Daca da, suprascriem adresa MAC coresp si dam return
		if (cache->intrari[i].ip == ip) {
			memcpy(cache->intrari[i].mac, mac, 6);
			return;
		}

	}

	// Daca nu exista si mai avem loc in vectorul dinamic, o adaugam
	if (cache->nr_intrari < cache->capacitate) {
		cache->intrari[cache->nr_intrari].ip = ip;
		memcpy(cache->intrari[cache->nr_intrari].mac, mac, 6);
		cache->nr_intrari++;
	} else {
		// Altfel, dublam capacitatea vectorului dinamic, il realocam cu noua capacit si adaugam noua intrare
		cache->capacitate *= 2;
		cache->intrari = realloc(cache->intrari, sizeof(struct arp_table_entry) * cache->capacitate);

		cache->intrari[cache->nr_intrari].ip = ip;
		memcpy(cache->intrari[cache->nr_intrari].mac, mac, 6);

		cache->nr_intrari++;
	}

}

void proceseaza_frame_arp(struct context_router *router, char *buf, size_t len, size_t interfata_intrare) {
	// Extragem din buf, header ul Ethernet si header ul ARP
	struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
	struct arp_hdr *arp_hdr = (struct arp_hdr *) (buf + sizeof(struct ether_hdr));

	// Daca este un req ARP, mai vedem si daca IP ul pt care s a facut este chiar al interfetei de intrare
	if (arp_hdr->opcode == htons(1)) {
        uint32_t ip_interfata = inet_addr(get_interface_ip(interfata_intrare));
        if (arp_hdr->tprotoa == ip_interfata) {
			// Schmbam opcode ul in cel de reply
            arp_hdr->opcode = htons(2);

			// Punemm in adresele hardware si IP de destinatie pe cele ale sursei, ca sa i trimitem ei reply ul
            memcpy(arp_hdr->thwa, arp_hdr->shwa, 6);
            arp_hdr->tprotoa = arp_hdr->sprotoa;

			// Punem in adresele hardware si IP de sursa pe cele ale interfetei de intrare
            get_interface_mac(interfata_intrare, arp_hdr->shwa);
            arp_hdr->sprotoa = ip_interfata;

			// Punem in adresa hardware de destinatie pe cea a sursei, iar in adresa hardware de sursa pe cea a interfetei de intrare
            memcpy(eth_hdr->ethr_dhost, arp_hdr->thwa, 6);
            get_interface_mac(interfata_intrare, eth_hdr->ethr_shost);

			// In final , trimitem reply ul pe link si dam return
            send_to_link(len, buf, interfata_intrare);
            return;
        }

	} else if (arp_hdr->opcode == htons(2)) {
		// Daca este un reply ARP

		// Adaugam in cache ARP adresa MAC si IP ul din reply
		actualizeaza_cache_arp(&router->cache_pt_arp, arp_hdr->sprotoa, arp_hdr->shwa);

		queue aux_coada = create_queue();

		// Parcurgem toate pachetele din coada de asteptare ARP
		while (!queue_empty(router->coada_arp)) {
			struct pachet_in_asteptare_arp *pachet = queue_deq(router->coada_arp);

			// Daca pachetul are next_hop egal cu IP ul tocmai primit in reply
			if (pachet->ip_next_hop == arp_hdr->sprotoa) {
				// Punem in adresa hardware de destinatie pe cea primita in reply
				struct ether_hdr *eth_hdr_pachet = (struct ether_hdr *)pachet->frame;

				// Si in adresa hardware de sursa pe cea a interfetei de iesire
				memcpy(eth_hdr_pachet->ethr_dhost, arp_hdr->shwa, 6);

				// Il trimitem pe link si nu il mai adaugam in coada de asteptare ARP
				send_to_link(pachet->lungime, pachet->frame, pachet->interfata_iesire);

				free(pachet);
			} else {
				// Altfel, il adaugam in coada auxiliara, ca sa il adaugam inapoi in coada de asteptare ARP
				queue_enq(aux_coada, pachet);
			}

		}

		// Actualizam coada de asteptare ARP cu cea auxiliara (chiar daca am modificat cv la ea sau nu)
		free(router->coada_arp);
		router->coada_arp = aux_coada;
	}

}

void trimite_icmp_echo_reply(char *buf_original, size_t len_original, size_t interfata_intrare) {
	// Extragem din buf, header ul Ethernet, header ul IP si header ul ICMP
	struct ether_hdr *eth_hdr_original = (struct ether_hdr *) buf_original;
	struct ip_hdr *ip_hdr_original = (struct ip_hdr *) (buf_original + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp_hdr_original = (struct icmp_hdr *) (buf_original + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

	// Interschimbam intre ele adresele mac de la sursa la destinatie
	uint8_t aux_mac[6];
	memcpy(aux_mac, eth_hdr_original->ethr_dhost, 6);
	memcpy(eth_hdr_original->ethr_dhost, eth_hdr_original->ethr_shost, 6);
	memcpy(eth_hdr_original->ethr_shost, aux_mac, 6);

	// Interschimbam intre ele adresele IP de la sursa la destinatie
	uint32_t aux_ip = ip_hdr_original->source_addr;
	ip_hdr_original->source_addr = ip_hdr_original->dest_addr;
	ip_hdr_original->dest_addr = aux_ip;

	// Modificam tipul si codul ICMP in 0
	icmp_hdr_original->mtype = 0;
	icmp_hdr_original->mcode = 0;

	// Recalculam checksum ul pentru header ul IP, dupa ce am modificat campurile relevante
	ip_hdr_original->checksum = 0;
	ip_hdr_original->checksum = htons(checksum((uint16_t *)ip_hdr_original, sizeof(struct ip_hdr)));

	// Facem lfl si pt checksum ul ICMP, dupa ce am modificat tipul si codul
	icmp_hdr_original->check = 0;
	icmp_hdr_original->check = htons(checksum((uint16_t *)icmp_hdr_original, len_original - sizeof(struct ether_hdr) - sizeof(struct ip_hdr)));

	// Trimitem frame ul modificat pe link ul pe care a venit
	send_to_link(len_original, buf_original, interfata_intrare);
}

void trimite_icmp_eroare(char *buf_original, size_t len_original, uint8_t tip, uint8_t cod, size_t interfata_intrare) {
	// Extragem din buf, header ul Ethernet si header ul IP
	struct ether_hdr *eth_hdr_original = (struct ether_hdr *) buf_original;
	struct ip_hdr *ip_hdr_original = (struct ip_hdr *) (buf_original + sizeof(struct ether_hdr));

	// Construim un nou frame pt reply ul ICMP de err
	char buf_reply[MAX_PACKET_LEN];
	struct ether_hdr *eth_hdr_reply = (struct ether_hdr *) buf_reply;
	struct ip_hdr *ip_hdr_reply = (struct ip_hdr *) (buf_reply + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp_hdr_reply = (struct icmp_hdr *) (buf_reply + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

	// Punem in adresa hardware de destinatie pe cea a sursei, iar in adresa hardware de sursa pe cea a interfetei de intrare
	memcpy(eth_hdr_reply->ethr_dhost, eth_hdr_original->ethr_shost, 6);
	get_interface_mac(interfata_intrare, eth_hdr_reply->ethr_shost);
	eth_hdr_reply->ethr_type = htons(0x0800);

	// Setam versiunea la 4, pentru IPv4
	ip_hdr_reply->ver = 4;

	// Ihl ul este 5, pentru ca nu avem optiuni in header ul IP
	ip_hdr_reply->ihl = 5;
	ip_hdr_reply->tos = 0;

	// Lungimea totala va fi de dimensiunea header ului IP + header ului ICMP + header ului IP original + 8 bytes din payload ul original
	ip_hdr_reply->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
	ip_hdr_reply->id = htons(0);
	ip_hdr_reply->frag = htons(0);

	// Setam TTL ul la 64, iar protocolul la 1, pentru ICMP
	ip_hdr_reply->ttl = 64;
	ip_hdr_reply->proto = 1;

	// Punem in adresa IP de sursa pe cea a interfetei de intrare, iar in adresa IP de destinatie pe cea a sursei
	ip_hdr_reply->source_addr = inet_addr(get_interface_ip(interfata_intrare));
	ip_hdr_reply->dest_addr = ip_hdr_original->source_addr;

	icmp_hdr_reply->mtype = tip;
	icmp_hdr_reply->mcode = cod;

	// Copiem in payload ul ICMP, header ul IP original + 8 bytes din payload ul original
	memcpy(buf_reply + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), ip_hdr_original, sizeof(struct ip_hdr) + 8);

	// Recalculam checksum ul pentru header ul IP, dupa ce am modificat campurile relevante
	ip_hdr_reply->checksum = 0;
	ip_hdr_reply->checksum = htons(checksum((uint16_t *)ip_hdr_reply, sizeof(struct ip_hdr)));

	// Facem lfl si pt checksum ul ICMP, dupa ce am modificat tipul, codul si payload ul
	icmp_hdr_reply->check = 0;
	icmp_hdr_reply->check = htons(checksum((uint16_t *)icmp_hdr_reply, sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8));

	// Trimitem frame ul de err pe link ul pe care a venit
	send_to_link(sizeof(struct ether_hdr) + ntohs(ip_hdr_reply->tot_len), buf_reply, interfata_intrare);
}

void proceseaza_frame_ipv4(struct context_router *router, char *buf, size_t len, size_t interfata_intrare) {
	// Extragem din buf, header ul Ethernet si header ul IP
	struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
	struct ip_hdr *ip_hdr = (struct ip_hdr *) (buf + sizeof(struct ether_hdr));

	uint16_t checksum_primit = ip_hdr->checksum;
	ip_hdr->checksum = 0;

	// Calculam checksum ul pentru header ul IP primit, ca sa vedem daca e lfl cu cel primit deja in header
	uint16_t calculated = checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr));

	// Daca nu e lfl, dam return si nu procesam frame ul
	if (ntohs(calculated) != checksum_primit) {
		return;
	}

	ip_hdr->checksum = checksum_primit;

	// Verificam daca pachetul are IP ul destinatie chiar cel al unei interfete a routerului
	int pachet_pt_router = 0;
    for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
        if (ip_hdr->dest_addr == inet_addr(get_interface_ip(i))) {
            pachet_pt_router = 1;
            break;
        }

    }

	// Daca da, vedem daca e un pachet ICMP de tip echo request, caz in care ii trimitem un echo reply inapoi
    if (pachet_pt_router) {
        if (ip_hdr->proto == 1) {
            struct icmp_hdr *icmp_hdr = (struct icmp_hdr *) (buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

            if (icmp_hdr->mtype == 8) {
                trimite_icmp_echo_reply(buf, len, interfata_intrare);
            }

        }

        return;
    }

	// Verificam si daca ttl ul pachetului e invalid (adica 0 sau 1)
	if (ip_hdr->ttl <= 1) {
		// Daca da, trimitem un msj de eroare ICMP inapoi sursei cu tipul si codul aferent
		trimite_icmp_eroare(buf, len, 11, 0, interfata_intrare);
		return;
	}

	// Daca nu e pt router si ttl ul e valid, cautam in trie ruta lpm pt adresa IP destinatie
	struct route_table_entry *lpm = find_lpm(&router->trie, ip_hdr->dest_addr);

	// Daca nu gasim, trimitem un msj de eroare ICMP inapoi sursei cu tipul si codul aferent
	if (lpm == NULL) {
		trimite_icmp_eroare(buf, len, 3, 0, interfata_intrare);
		return;
	}

	// Daca am ajuns aici inseamna ca trb sa facem forwarding la pachet, deci decrementam ttl ul
	ip_hdr->ttl--;

	// Recalculam checksum ul pentru header ul IP (pt ca am modificat ttl ul)
	ip_hdr->checksum = 0;
	ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

	uint32_t next_hop = lpm->next_hop;

	// Daca next_hop ul din ruta lpm e 0, inseamna ca destinatia e in aceeasi retea cu interfata de iesire
	if (next_hop == 0) {
		// In cazul asta, next_hop este IP ul destinatie din header ul IP
		next_hop = ip_hdr->dest_addr;
	}

	uint8_t *mac_destinatie = cauta_mac_in_cache(&router->cache_pt_arp, next_hop);

	// Daca gasim in cache ARP adresa MAC corespunzatoare next_hop ului
	if (mac_destinatie != NULL) {
		// Copiem in adresa hardware de destinatie pe cea gasita in cache
		memcpy(eth_hdr->ethr_dhost, mac_destinatie, 6);

		// Si in adresa hardware de sursa pe cea a interfetei de iesire
		get_interface_mac(lpm->interface, eth_hdr->ethr_shost);

		// Trimitem frame ul modificat pe link ul de iesire din ruta lpm
		send_to_link(len, buf, lpm->interface);
	} else {
		// Daca nu gasim adresa MAC in cache ARP

		int arp_req_dat_deja = 0;
        queue aux_coada = create_queue();

		// Verificam daca s a mai dat vreun ARP req pt acelasi next_hop
        while (!queue_empty(router->coada_arp)) {
            struct pachet_in_asteptare_arp *pachet_din_coada = queue_deq(router->coada_arp);
            
            if (pachet_din_coada->ip_next_hop == next_hop) {
                arp_req_dat_deja = 1;
            }
            
            queue_enq(aux_coada, pachet_din_coada);
        }
        
        free(router->coada_arp);
        router->coada_arp = aux_coada;

		struct pachet_in_asteptare_arp *pachet = malloc(sizeof(struct pachet_in_asteptare_arp));
		memcpy(pachet->frame, buf, len);
		pachet->lungime = len;
		pachet->interfata_iesire = lpm->interface;
		pachet->ip_next_hop = next_hop;

		// Punem pachetul in coada de asteptare ARP, pt ca inca nu avem adresa MAC a next_hop ului
		queue_enq(router->coada_arp, pachet);

		// Daca nu s a mai dat vreun ARP req pt acelasi next_hop
		if (arp_req_dat_deja == 0) {
			// Construim un buf pt frame ul de ARP req, cu header ul Ethernet si header ul ARP
			char buf_arp[MAX_PACKET_LEN];
			struct ether_hdr *eth_hdr_arp = (struct ether_hdr *) buf_arp;
			struct arp_hdr *arp_hdr_arp = (struct arp_hdr *) (buf_arp + sizeof(struct ether_hdr));

			// Punem in adresa hardware de destinatie adresa de broadcast, iar in adresa hardware de sursa pe cea a interfetei de iesire
			memset(eth_hdr_arp->ethr_dhost, 0xff, 6);
			get_interface_mac(lpm->interface, eth_hdr_arp->ethr_shost);
			eth_hdr_arp->ethr_type = htons(0x0806);

			// Setam campurile relevante din header ul ARP
			arp_hdr_arp->hw_type = htons(1);
			arp_hdr_arp->proto_type = htons(0x0800);
			arp_hdr_arp->hw_len = 6;
			arp_hdr_arp->proto_len = 4;
			arp_hdr_arp->opcode = htons(1);

			// Punem in adresa hardware si cea IP a sursei pe cele ale interfetei de iesire
			get_interface_mac(lpm->interface, arp_hdr_arp->shwa);
			arp_hdr_arp->sprotoa = inet_addr(get_interface_ip(lpm->interface));

			// Punem in adresa hardware de destinatie pe 0 (pt ca nu o stim) si in adresa IP de destinatie pe next_hop ul din ruta lpm
			memset(arp_hdr_arp->thwa, 0, 6);
			arp_hdr_arp->tprotoa = next_hop;

			// Trimitem frame ul de ARP req pe link ul de iesire din ruta lpm
			send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), buf_arp, lpm->interface);
		}

	}

}

int main(int argc, char *argv[]) {
	char buf[MAX_PACKET_LEN];
	struct context_router router;

	// Do not modify this line
	init(argv + 2, argc - 2);

	// Initializam structura routerului, citind rutele din fisierul dat ca argument in main
	memset(&router, 0, sizeof(router));
	initializare_router(&router, argv[1]);

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

    // TODO: Implement the router forwarding logic

		// Verificam daca lungimea pachetului primit e suficienta pentru a contine un header Ethernet
		if (len < sizeof(struct ether_hdr)) {
			continue;
		}

		struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;

		uint8_t mac_interfata[6];
        get_interface_mac(interface, mac_interfata);

        uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        
        int pt_router = 1;
        int pt_broadcast = 1;

		// Verificam daca adresa MAC de destinatie din header ul Ethernet e adresa MAC a interfetei de intrare sau adresa de broadcast
        for (int i = 0; i < 6; i++) {
            if (eth_hdr->ethr_dhost[i] != mac_interfata[i]) {
                pt_router = 0;
            }
            if (eth_hdr->ethr_dhost[i] != broadcast_mac[i]) {
                pt_broadcast = 0;
            }
        }

		// Daca nu e nici pt router, nici de broadcast, nu il prelucram
        if (!pt_router && !pt_broadcast) {
            continue;
        }

		// In functie de tipul din header ul Ethernet, apelam functia corespunzatoare pt procesarea frame ului
		if (ntohs(eth_hdr->ethr_type) == 0x0806) {
			proceseaza_frame_arp(&router, buf, len, interface);
		} else if (ntohs(eth_hdr->ethr_type) == 0x0800) {
			proceseaza_frame_ipv4(&router, buf, len, interface);
		}

    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */


	}

}