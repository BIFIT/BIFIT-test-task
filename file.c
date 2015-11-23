/* Тестовое задание на вакансию Разработчик C.
 * Для приведенного ниже кода ответьте на следующие вопросы:
 * * Что делает данный код?
 * * Какие ошибки в нем есть? Поясните и предложите варианты решения.
 * Напишите test case.
 * Решение и резюме высылайте на hohlov@bifit.com
*/

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#define ERR(format, ...)                                                  \
    fprintf(stderr, "ERROR: %s:%d: " format "\n", __FUNCTION__, __LINE__, \
            ## __VA_ARGS__)

/**
 * protocols
 */
struct ether_addr {
    uint8_t addr_bytes[6];
};

struct ether_hdr {
    struct ether_addr d_addr;
    struct ether_addr s_addr;
    uint16_t          ether_type;
};

struct ipv4_hdr {
    uint8_t  version_ihl;
    uint8_t  type_of_service;
    uint16_t total_length;
    uint16_t packet_id;
    uint16_t fragment_offset;
    uint8_t  time_to_live;
    uint8_t  next_proto_id;
    uint16_t hdr_checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
};

struct udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t dgram_len;
    uint16_t dgram_cksum;
};

void
usage() {
    ERR("usage: nat <src-net> <src-mask> <ext-addr> <ext-port> <int-addr> <int-port>");
}

uint16_t
ipv4_checksum(struct ipv4_hdr *ipv4) {
    uint32_t  sum = 0;
    uint16_t *raw = (uint16_t *)ipv4;

    for (int i = 0; i < 10; i++) {
        if (i == 5) continue;
        sum += raw[i];
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t) ~sum;
}

uint16_t
udp_checksum(struct ipv4_hdr *ipv4, struct udp_hdr *udp) {
    uint32_t sum = 0;

    // pseudoheader
    uint16_t *raw_ipv4 = (uint16_t *)ipv4;
    sum =
        // src
        raw_ipv4[6] + raw_ipv4[7] +
        // dst
        raw_ipv4[8] + raw_ipv4[9] +
        // proto + udp_len
        0x11 + udp->dgram_len;

    // udp
    uint16_t *raw_udp   = (uint16_t *)udp;
    uint16_t  dgram_len = ntohs(udp->dgram_len);
    uint16_t  nw        = dgram_len / 2;

    for (uint16_t i = 0; i < nw; i++) {
        if (i == 3) continue;
        sum += raw_udp[i];
    }

    if (dgram_len % 2) {
        sum += ((uint8_t *)(udp))[dgram_len - 1];
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t) ~sum;
}

int
ord(char c) {
    if ('A' <= c && c <= 'F') return c - 'A' + 0xA;
    if ('a' <= c && c <= 'f') return c - 'a' + 0xa;
    if ('0' <= c && c <= '9') return c - '0';
    return -1;
}

int
unhexlify(uint8_t *dst, char *src, int len) {
    for (int i = 0; i < len; i += 2) {
        int h = ord(src[i]);
        int l = ord(src[i + 1]);

        if (h == -1 || l == -1) {
            return -1;
        }
        dst[i / 2] = h << 4 | l;
    }
    return len / 2;
}

int
main(int argc, char *argv[]) {
    if (argc != 7) {
        usage();
        return 127;
    }

    uint32_t srcnet, srcmask, extaddr, intaddr;
    uint16_t extport, intport;

    {
        long l;

        l = strtol(argv[2], NULL, 0);
        if (errno != 0 || l < 0 || l > 32) {
            ERR("invalid src-mask");
            return 127;
        }
        srcmask = ~((1 << (32 - l)) - 1);

        l = strtol(argv[4], NULL, 0);
        if (errno != 0 || l <= 0 || l > 65535) {
            ERR("invalid ext-port");
            return 127;
        }
        extport = l;

        l = strtol(argv[6], NULL, 0);
        if (errno != 0 || l <= 0 || l > 65535) {
            ERR("invalid int-port");
            return 127;
        }
        intport = l;
    }

    if (!inet_pton(AF_INET, argv[1], &srcnet)) {
        ERR("invalid src-net");
        return 127;
    }

    if (!inet_pton(AF_INET, argv[3], &extaddr)) {
        ERR("invalid ext-addr");
        return 127;
    }

    if (!inet_pton(AF_INET, argv[5], &intaddr)) {
        ERR("invalid int-addr");
        return 127;
    }

    char    buf[512];
    uint8_t pkt[255];
    int     pktlen;

mainloop:
    while (fgets(buf, sizeof(buf), stdin)) {
        // check if data is terminated with '\n'
        char *nl = strchr(buf, '\n');
        if (nl == NULL) {
            ERR("error reading packet");
            return 1;
        }
        // skip empty strings
        if (nl == buf) continue;

        pktlen = unhexlify(pkt, buf, nl - buf);
        if (pktlen == -1) {
            ERR("unhexlify error");
            continue;
        }

        // deal with packet
        struct ipv4_hdr *ipv4 = (struct ipv4_hdr *)(pkt + sizeof(struct ether_hdr));
        struct udp_hdr * udp  = (struct udp_hdr *)(pkt + sizeof(struct ether_hdr) + (ipv4->version_ihl & 0x0f)*4);

        if ((ipv4->src_addr & srcmask) != srcnet) continue;
        if (ipv4->dst_addr != extaddr) continue;
        if (udp->dst_port != extport) continue;

        ipv4->dst_addr     = intaddr;
        ipv4->hdr_checksum = ipv4_checksum(ipv4);
        udp->dst_port      = htons(intport);
        udp->dgram_cksum   = udp_checksum(ipv4, udp);

        // write packet
        for (int i = 0; i < pktlen; i++) {
            printf("%02x", pkt[i]);
        }
        printf("\n");
    }

    if (!feof(stdin)) {
        ERR("error reading packet");
        return 1;
    }
    return 0;
}

