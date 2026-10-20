#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

struct ipv6_hdr { uint32_t vtcfl; uint16_t plen; uint8_t nh, hop; struct in6_addr src, dst; } __attribute__((packed));
struct udp_hdr { uint16_t sport, dport, len, check; } __attribute__((packed));

int main(int argc, char **argv) {
    if (argc != 4) { fprintf(stderr, "usage: %s IF SRC DST\n", argv[0]); return 2; }
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
    if (fd < 0) { perror("socket"); return 1; }
    int ifindex = if_nametoindex(argv[1]);
    if (!ifindex) { perror("if_nametoindex"); return 1; }
    unsigned char frame[14 + sizeof(struct ipv6_hdr) + sizeof(struct udp_hdr) + 4];
    memset(frame, 0, sizeof(frame));
    memset(frame, 0xff, 6);
    frame[6] = 0x02; frame[7] = 0; frame[8] = 0; frame[9] = 0; frame[10] = 0; frame[11] = 1;
    frame[12] = 0x86; frame[13] = 0xdd;
    struct ipv6_hdr *ip = (struct ipv6_hdr *)(frame + 14);
    ip->vtcfl = htonl(6u << 28); ip->plen = htons(sizeof(struct udp_hdr) + 4); ip->nh = 17; ip->hop = 64;
    if (inet_pton(AF_INET6, argv[2], &ip->src) != 1 || inet_pton(AF_INET6, argv[3], &ip->dst) != 1) { fprintf(stderr, "bad address\n"); return 2; }
    struct udp_hdr *udp = (struct udp_hdr *)(ip + 1);
    udp->sport = htons(40000); udp->dport = htons(40001); udp->len = htons(sizeof(*udp) + 4); udp->check = htons(1);
    memcpy(udp + 1, "TEST", 4);
    struct sockaddr_ll sa = {0}; sa.sll_family = AF_PACKET; sa.sll_ifindex = ifindex; sa.sll_halen = ETH_ALEN; memset(sa.sll_addr, 0xff, 6);
    for (int i = 0; i < 5; i++) { if (sendto(fd, frame, sizeof(frame), 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("sendto"); return 1; } usleep(200000); }
    puts("sent 5 IPv6 Ethernet frames");
    return 0;
}