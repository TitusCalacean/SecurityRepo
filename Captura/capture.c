#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define MAX_INTERFACES 64
#define SNAPLEN 65536

typedef struct ethernet_header {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;
} ethernet_header;

typedef struct ipv4_header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
} ipv4_header;

typedef struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} tcp_header;

typedef struct udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_header;

typedef struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
} icmp_header;

typedef struct capture_context {
    FILE *csv;
    unsigned long packet_count;
} capture_context;

static void format_ip(uint32_t ip_net_order, char *buffer, size_t buffer_size) {
    struct in_addr addr;
    addr.s_addr = ip_net_order;
    inet_ntop(AF_INET, &addr, buffer, (DWORD)buffer_size);
}

static const char *protocol_to_string(uint8_t proto) {
    switch (proto) {
        case 1:  return "ICMP";
        case 6:  return "TCP";
        case 17: return "UDP";
        default: return "OTHER";
    }
}

static void tcp_flags_to_string(uint8_t flags, char *buffer, size_t buffer_size) {
    buffer[0] = '\0';

    if (flags & 0x01) strncat(buffer, "FIN|", buffer_size - strlen(buffer) - 1);
    if (flags & 0x02) strncat(buffer, "SYN|", buffer_size - strlen(buffer) - 1);
    if (flags & 0x04) strncat(buffer, "RST|", buffer_size - strlen(buffer) - 1);
    if (flags & 0x08) strncat(buffer, "PSH|", buffer_size - strlen(buffer) - 1);
    if (flags & 0x10) strncat(buffer, "ACK|", buffer_size - strlen(buffer) - 1);
    if (flags & 0x20) strncat(buffer, "URG|", buffer_size - strlen(buffer) - 1);
    if (flags & 0x40) strncat(buffer, "ECE|", buffer_size - strlen(buffer) - 1);
    if (flags & 0x80) strncat(buffer, "CWR|", buffer_size - strlen(buffer) - 1);

    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '|') {
        buffer[len - 1] = '\0';
    }

    if (buffer[0] == '\0') {
        strncpy(buffer, "NONE", buffer_size - 1);
        buffer[buffer_size - 1] = '\0';
    }
}

static void write_csv_header(FILE *csv) {
    fprintf(csv,
            "packet_no,timestamp_sec,timestamp_usec,src_ip,dst_ip,src_port,dst_port,protocol,packet_len,ttl,tcp_flags,icmp_type,icmp_code\n");
    fflush(csv);
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    capture_context *ctx = (capture_context *)user;
    ctx->packet_count++;

    if (header->caplen < sizeof(ethernet_header)) {
        return;
    }

    const ethernet_header *eth = (const ethernet_header *)packet;
    uint16_t eth_type = ntohs(eth->type);

    // 0x0800 = IPv4
    if (eth_type != 0x0800) {
        return;
    }

    const u_char *ip_ptr = packet + sizeof(ethernet_header);
    size_t ip_available = header->caplen - sizeof(ethernet_header);

    if (ip_available < sizeof(ipv4_header)) {
        return;
    }

    const ipv4_header *ip = (const ipv4_header *)ip_ptr;
    uint8_t version = (ip->version_ihl >> 4) & 0x0F;
    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;

    if (version != 4 || ihl < 20 || ip_available < ihl) {
        return;
    }

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    format_ip(ip->src_addr, src_ip, sizeof(src_ip));
    format_ip(ip->dst_addr, dst_ip, sizeof(dst_ip));

    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    char tcp_flags[64] = "NONE";
    int icmp_type = -1;
    int icmp_code = -1;

    const u_char *transport_ptr = ip_ptr + ihl;
    size_t transport_available = ip_available - ihl;

    if (ip->protocol == 6) {
        if (transport_available >= sizeof(tcp_header)) {
            const tcp_header *tcp = (const tcp_header *)transport_ptr;
            src_port = ntohs(tcp->src_port);
            dst_port = ntohs(tcp->dst_port);
            tcp_flags_to_string(tcp->flags, tcp_flags, sizeof(tcp_flags));
        }
    } else if (ip->protocol == 17) {
        if (transport_available >= sizeof(udp_header)) {
            const udp_header *udp = (const udp_header *)transport_ptr;
            src_port = ntohs(udp->src_port);
            dst_port = ntohs(udp->dst_port);
        }
    } else if (ip->protocol == 1) {
        if (transport_available >= sizeof(icmp_header)) {
            const icmp_header *icmp = (const icmp_header *)transport_ptr;
            icmp_type = icmp->type;
            icmp_code = icmp->code;
        }
    }

    fprintf(ctx->csv,
            "%lu,%ld,%ld,%s,%s,%u,%u,%s,%u,%u,%s,%d,%d\n",
            ctx->packet_count,
            (long)header->ts.tv_sec,
            (long)header->ts.tv_usec,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol_to_string(ip->protocol),
            header->len,
            ip->ttl,
            tcp_flags,
            icmp_type,
            icmp_code);

    fflush(ctx->csv);

    printf("[%lu] %s -> %s | proto=%s | sport=%u | dport=%u | len=%u | ttl=%u | flags=%s",
           ctx->packet_count,
           src_ip,
           dst_ip,
           protocol_to_string(ip->protocol),
           src_port,
           dst_port,
           header->len,
           ip->ttl,
           tcp_flags);

    if (icmp_type != -1) {
        printf(" | icmp_type=%d | icmp_code=%d", icmp_type, icmp_code);
    }

    printf("\n");
}

int main(void) {
    pcap_if_t *alldevs = NULL;
    pcap_if_t *dev = NULL;
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int device_index = 0;
    int selected_index = 0;
    capture_context ctx;
    FILE *csv = NULL;

    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        return 1;
    }

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuf);
        WSACleanup();
        return 1;
    }

    if (alldevs == NULL) {
        fprintf(stderr, "No interfaces found.\n");
        WSACleanup();
        return 1;
    }

    printf("Available interfaces:\n\n");
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        device_index++;
        printf("%d. %s", device_index, dev->name);
        if (dev->description) {
            printf(" (%s)", dev->description);
        }
        printf("\n");
    }

    if (device_index == 0) {
        fprintf(stderr, "No capture interfaces available.\n");
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    printf("\nSelect interface number: ");
    if (scanf("%d", &selected_index) != 1 || selected_index < 1 || selected_index > device_index) {
        fprintf(stderr, "Invalid selection.\n");
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    dev = alldevs;
    for (int i = 1; i < selected_index; i++) {
        dev = dev->next;
    }

    printf("Opening interface: %s\n", dev->name);
    if (dev->description) {
        printf("Description: %s\n", dev->description);
    }

    handle = pcap_open_live(
        dev->name,
        SNAPLEN,
        1,      // promiscuous mode
        1000,   // read timeout in ms
        errbuf
    );

    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Unsupported link layer. This code expects Ethernet.\n");
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    csv = fopen("dataset.csv", "w");
    if (!csv) {
        fprintf(stderr, "Failed to create dataset.csv\n");
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    write_csv_header(csv);

    ctx.csv = csv;
    ctx.packet_count = 0;

    printf("\nCapturing packets... Press Ctrl+C to stop.\n\n");

    
    pcap_loop(handle, 0, packet_handler, (u_char *)&ctx);

    fclose(csv);
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    WSACleanup();

    return 0;
}