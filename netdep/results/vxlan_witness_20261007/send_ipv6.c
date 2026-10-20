#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct ip6wire {
    uint32_t vtcfl;
    uint16_t plen;
    uint8_t nh;
    uint8_t hop;
    struct in6_addr src;
    struct in6_addr dst;
} __attribute__((packed));

struct frame {
    unsigned char eth[14];
    struct ip6wire ip;
    unsigned char payload[8];
} __attribute__((packed));

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s IF\n", argv[0]);
        return 2;
    }

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    int idx = if_nametoindex(argv[1]);
    if (!idx) {
        perror("if_nametoindex");
        return 1;
    }

    struct frame f;
    memset(&f, 0, sizeof(f));

    unsigned char dst[6] = {2, 0, 0, 0, 0, 2};
    unsigned char src[6] = {2, 0, 0, 0, 0, 1};

    memcpy(f.eth, dst, 6);
    memcpy(f.eth + 6, src, 6);
    f.eth[12] = 0x86;
    f.eth[13] = 0xdd;

    f.ip.vtcfl = htonl(6u << 28);
    f.ip.plen = htons(sizeof(f.payload));
    f.ip.nh = 59;
    f.ip.hop = 64;
    inet_pton(AF_INET6, "2001:db8::10", &f.ip.src);
    inet_pton(AF_INET6, "2001:db8::2", &f.ip.dst);

    struct sockaddr_ll sa = {0};
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = idx;
    sa.sll_halen = 6;
    memcpy(sa.sll_addr, dst, 6);

    for (int i = 0; i < 5; i++) {
        if (sendto(fd, &f, sizeof(f), 0, (struct sockaddr *)&sa,
                   sizeof(sa)) < 0) {
            perror("sendto");
            return 1;
        }

        usleep(200000);
    }

    puts("sent 5 IPv6 route-shortcircuit frames");
    return 0;
}
