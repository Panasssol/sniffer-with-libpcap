#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h> // arp
#include <string.h>

#define COUNT -1
#define TIMEOUT -1
#define MODE 1  // modo promíscuo

void print_ipv4_header(const struct ip *ip_hdr);
void print_ipv6_header(const struct ip6_hdr *ip6_hdr);
void print_tcp_header(const struct tcphdr *tcp_hdr);
void print_udp_header(const struct udphdr *udp_hdr);

void callback(u_char *user, const struct pcap_pkthdr *p_hdr, const u_char *packet);

int main() {
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if ((dev = pcap_lookupdev(errbuf)) == NULL) {
        fprintf(stderr, "Erro: %s\n", errbuf);
        return 1;
    }

    printf("Dispositivo: %s\n", dev);

    handle = pcap_open_live(dev, BUFSIZ, MODE, TIMEOUT, errbuf);
    if (!handle) {
        fprintf(stderr, "Erro: %s\n", errbuf);
        return 1;
    }

    if (pcap_loop(handle, COUNT, callback, NULL) < 0) {
        fprintf(stderr, "Não foi possível capturar pacotes\n");
        pcap_close(handle);
        return 1;
    }

    pcap_close(handle);
    return 0;
}

void callback(u_char *user, const struct pcap_pkthdr *p_hdr, const u_char *packet) {
    if (p_hdr->len < sizeof(struct ether_header)) {
        puts("Pacote defeituoso");
        return;
    }

    const struct ether_header *eth = (const struct ether_header *)packet;

    u_short eth_type = ntohs(eth->ether_type);
    const u_char *payload = packet + sizeof(struct ether_header);
    u_int payload_len = p_hdr->len - sizeof(struct ether_header);

    if (eth_type == ETHERTYPE_IP) {
        if (payload_len < sizeof(struct ip)) {
            puts("Pacote IPv4 incompleto");
            return;
        }

        const struct ip *ip_hdr = (const struct ip *)payload;

        if (ip_hdr->ip_v != 4) {
            puts("Versão IPv4 inválida");
            return;
        }

        print_ipv4_header(ip_hdr);

        int ip_header_len = ip_hdr->ip_hl * 4;
        if (payload_len < ip_header_len) {
            puts("Cabeçalho IPv4 incompleto");
            return;
        }

        const u_char *transport_payload = payload + ip_header_len;
        int transport_len = payload_len - ip_header_len;

        if (ip_hdr->ip_p == IPPROTO_TCP) {
            if (transport_len < sizeof(struct tcphdr)) {
                puts("Cabeçalho TCP incompleto");
                return;
            }
            const struct tcphdr *tcp_hdr = (const struct tcphdr *)transport_payload;
            print_tcp_header(tcp_hdr);
        }
        else if (ip_hdr->ip_p == IPPROTO_UDP) {
            if (transport_len < sizeof(struct udphdr)) {
                puts("Cabeçalho UDP incompleto");
                return;
            }
            const struct udphdr *udp_hdr = (const struct udphdr *)transport_payload;
            print_udp_header(udp_hdr);
        }
        else {
            printf("Protocolo IPv4 não suportado para parsing detalhado: %u\n\n", ip_hdr->ip_p);
        }
    }
    else if (eth_type == ETHERTYPE_IPV6) {
        if (payload_len < sizeof(struct ip6_hdr)) {
            puts("Pacote IPv6 incompleto");
            return;
        }

        const struct ip6_hdr *ip6_hdr = (const struct ip6_hdr *)payload;
        print_ipv6_header(ip6_hdr);

        const u_char *transport_payload = payload + sizeof(struct ip6_hdr);
        int transport_len = payload_len - sizeof(struct ip6_hdr);

        if (ip6_hdr->ip6_nxt == IPPROTO_TCP) {
            if (transport_len < sizeof(struct tcphdr)) {
                puts("Cabeçalho TCP incompleto");
                return;
            }
            const struct tcphdr *tcp_hdr = (const struct tcphdr *)transport_payload;
            print_tcp_header(tcp_hdr);
        }
        else if (ip6_hdr->ip6_nxt == IPPROTO_UDP) {
            if (transport_len < sizeof(struct udphdr)) {
                puts("Cabeçalho UDP incompleto");
                return;
            }
            const struct udphdr *udp_hdr = (const struct udphdr *)transport_payload;
            print_udp_header(udp_hdr);
        }
        else {
            printf("Protocolo IPv6 não suportado para parsing detalhado: %u\n\n", ip6_hdr->ip6_nxt);
        }
    }
    // Não exibe ARP nem Ethernet
}

void print_ipv4_header(const struct ip *ip_hdr) {
    printf("----- IPv4 Header -----\n");
    printf("Version: %u\n", ip_hdr->ip_v);
    printf("Header Length: %u (bytes)\n", ip_hdr->ip_hl * 4);
    printf("TOS: 0x%02x\n", ip_hdr->ip_tos);
    printf("Total Length: %u\n", ntohs(ip_hdr->ip_len));
    printf("Identification: %u\n", ntohs(ip_hdr->ip_id));
    printf("Fragment Offset: 0x%04x\n", ntohs(ip_hdr->ip_off));
    printf("TTL: %u\n", ip_hdr->ip_ttl);
    printf("Protocol: %u\n", ip_hdr->ip_p);
    printf("Checksum: 0x%04x\n", ntohs(ip_hdr->ip_sum));
    printf("Src IP: %s\n", inet_ntoa(ip_hdr->ip_src));
    printf("Dst IP: %s\n\n", inet_ntoa(ip_hdr->ip_dst));
}

void print_ipv6_header(const struct ip6_hdr *ip6_hdr) {
    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6_hdr->ip6_src, src, sizeof(src));
    inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, dst, sizeof(dst));

    uint32_t vtcfl = ntohl(*(const uint32_t *)ip6_hdr);
    uint8_t version = (vtcfl >> 28) & 0xF;
    uint8_t traffic_class = (vtcfl >> 20) & 0xFF;
    uint32_t flow_label = vtcfl & 0xFFFFF;

    printf("----- IPv6 Header -----\n");
    printf("Version: %u\n", version);
    printf("Traffic Class: 0x%02x\n", traffic_class);
    printf("Flow Label: 0x%05x\n", flow_label);
    printf("Payload Length: %u\n", ntohs(ip6_hdr->ip6_plen));
    printf("Next Header: %u\n", ip6_hdr->ip6_nxt);
    printf("Hop Limit: %u\n", ip6_hdr->ip6_hlim);
    printf("Src IP: %s\n", src);
    printf("Dst IP: %s\n\n", dst);
}

void print_tcp_header(const struct tcphdr *tcp_hdr) {
    printf("----- TCP Header -----\n");
    printf("Source port: %u\n", ntohs(tcp_hdr->source));
    printf("Destination port: %u\n", ntohs(tcp_hdr->dest));
    printf("Sequence number: %u\n", ntohl(tcp_hdr->seq));
    printf("Ack number: %u\n", ntohl(tcp_hdr->ack_seq));
    printf("Data offset: %u (bytes)\n", tcp_hdr->doff * 4);
    printf("Flags: urg=%u ack=%u psh=%u rst=%u syn=%u fin=%u\n",
           tcp_hdr->urg, tcp_hdr->ack, tcp_hdr->psh,
           tcp_hdr->rst, tcp_hdr->syn, tcp_hdr->fin);
    printf("Window size: %u\n", ntohs(tcp_hdr->window));
    printf("Checksum: 0x%04x\n", ntohs(tcp_hdr->check));
    printf("Urgent pointer: %u\n\n", ntohs(tcp_hdr->urg_ptr));
}

void print_udp_header(const struct udphdr *udp_hdr) {
    printf("----- UDP Header -----\n");
    printf("Source port: %u\n", ntohs(udp_hdr->source));
    printf("Destination port: %u\n", ntohs(udp_hdr->dest));
    printf("Length: %u\n", ntohs(udp_hdr->len));
    printf("Checksum: 0x%04x\n\n", ntohs(udp_hdr->check));
}

