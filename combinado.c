#include <stdio.h>



#include <pcap.h>



#include <arpa/inet.h>



#include <net/ethernet.h>



#include <netinet/ip.h>



#include <netinet/ip6.h>



#include <netinet/tcp.h>



#include <netinet/udp.h>



#include <netinet/icmp6.h>



#include <netinet/if_ether.h>



#include <string.h>







#define COUNT -1



#define TIMEOUT -1



#define MODE 1







void print_ipv4_header(const struct ip *ip_hdr);



void print_ipv6_header(const struct ip6_hdr *ip6_hdr);



void print_tcp_header(const struct tcphdr *tcp_hdr);



void print_udp_header(const struct udphdr *udp_hdr);



void print_icmpv6_header(const struct icmp6_hdr *icmp6_hdr);



void print_ipv6_ext_header(uint8_t hdr_type, const u_char *ext_hdr, int ext_len);



const u_char* ipv6_extensions(const u_char *ptr, u_int remaining_len, uint8_t *out_next_header);



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







        const u_char *next_hdr_ptr = payload + sizeof(struct ip6_hdr);



        int remaining_len = payload_len - sizeof(struct ip6_hdr);



        uint8_t next_header = ip6_hdr->ip6_nxt;







        const u_char *final_payload = ipv6_extensions(next_hdr_ptr, remaining_len, &next_header);



        if (final_payload == NULL) {



            puts("Erro ao processar headers de extensão IPv6");



            return;



        }







        int final_payload_len = remaining_len - (final_payload - next_hdr_ptr);







        if (next_header == IPPROTO_TCP) {



            if (final_payload_len < sizeof(struct tcphdr)) {



                puts("Cabeçalho TCP incompleto");



                return;



            }



            const struct tcphdr *tcp_hdr = (const struct tcphdr *)final_payload;



            print_tcp_header(tcp_hdr);



        }



        else if (next_header == IPPROTO_UDP) {



            if (final_payload_len < sizeof(struct udphdr)) {



                puts("Cabeçalho UDP incompleto");



                return;



            }



            const struct udphdr *udp_hdr = (const struct udphdr *)final_payload;



            print_udp_header(udp_hdr);



        }



        else if (next_header == IPPROTO_ICMPV6) {



            if (final_payload_len < sizeof(struct icmp6_hdr)) {



                puts("Cabeçalho ICMPv6 incompleto");



                return;



            }



            const struct icmp6_hdr *icmp6_hdr = (const struct icmp6_hdr *)final_payload;



            print_icmpv6_header(icmp6_hdr);



        }



        else {



            printf("Protocolo IPv6 não suportado para parsing detalhado: %u\n\n", next_header);



        }



    }



}







const u_char* ipv6_extensions(const u_char *ptr, u_int remaining_len, uint8_t *out_next_header) {



    uint8_t next = *out_next_header;



    const u_char *current = ptr;







    while (1) {



        if (next == IPPROTO_TCP || next == IPPROTO_UDP || next == IPPROTO_ICMPV6) {



            *out_next_header = next;



            return current;



        }







        // 0=Hop-by-Hop, 43=Routing, 44=Fragment, 50=ESP, 51=AH, 60=Destination Options



        if (next == 0 || next == 43 || next == 50 || next == 51 || next == 60) {



            if (remaining_len < 2) return NULL;







            uint8_t ext_next = current[0];



            uint8_t ext_len = current[1];



            size_t ext_header_len = (ext_len + 1) * 8;







            if (remaining_len < ext_header_len) return NULL;







            print_ipv6_ext_header(next, current, ext_header_len);







            current += ext_header_len;



            remaining_len -= ext_header_len;



            next = ext_next;



        }



        else if (next == 44) {



            if (remaining_len < 8) return NULL;







            print_ipv6_ext_header(next, current, 8);







            next = current[0];



            current += 8;



            remaining_len -= 8;



        }



        else {



            *out_next_header = next;



            return current;



        }



    }



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







void print_ipv6_ext_header(uint8_t hdr_type, const u_char *ext_hdr, int ext_len) {



    printf("----- IPv6 Extension Header -----\n");



    switch (hdr_type) {



        case 0: printf("Hop-by-Hop Options Header\n"); break;



        case 43: printf("Routing Header\n"); break;



        case 44: printf("Fragment Header\n"); break;



        case 50: printf("Encapsulating Security Payload (ESP) Header\n"); break;



        case 51: printf("Authentication Header (AH)\n"); break;



        case 60: printf("Destination Options Header\n"); break;



        default: printf("Header desconhecido (Tipo %u)\n", hdr_type);



    }



    printf("Length: %d bytes\n\n", ext_len);



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







void print_icmpv6_header(const struct icmp6_hdr *icmp6_hdr) {



    printf("----- ICMPv6 Header -----\n");



    printf("Type: %u\n", icmp6_hdr->icmp6_type);



    printf("Code: %u\n", icmp6_hdr->icmp6_code);



}



