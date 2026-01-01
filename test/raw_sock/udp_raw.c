#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define BUFFER_SIZE 1024
#define SRC_PORT 12345
#define DST_PORT 54321
#define SRC_IP "192.168.1.100"
#define DST_IP "192.168.1.1"
#define DST_MAC "02:00:00:00:01:00"  // 广播地址，或目标MAC

// 计算 IP 校验和
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// 获取接口 MAC 地址
void get_if_mac(int sock, const char *ifname, unsigned char *mac) {
    struct ifreq ifr;
    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        exit(1);
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
}

// 获取接口索引
int get_if_index(int sock, const char *ifname) {
    struct ifreq ifr;
    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        exit(1);
    }
    return ifr.ifr_ifindex;
}

#define IF_NAME "wlan0"

int main() {
    int sock_raw;
    struct sockaddr_ll saddr;
    unsigned char buffer[BUFFER_SIZE];
    int total_len = 0;
    
    // 1. 创建原始套接字
    sock_raw = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (sock_raw < 0) {
        perror("socket");
        return 1;
    }
    
    // 2. 获取接口信息
    unsigned char src_mac[6];
    get_if_mac(sock_raw, IF_NAME, src_mac);
    
    // 解析目标MAC（这里用广播）
    unsigned char dst_mac[6];
    sscanf(DST_MAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &dst_mac[0], &dst_mac[1], &dst_mac[2],
           &dst_mac[3], &dst_mac[4], &dst_mac[5]);
    
    // 3. 构建以太网帧头
    struct ethhdr *eth = (struct ethhdr *)buffer;
    memcpy(eth->h_dest, dst_mac, 6);
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETH_P_IP);  // 0x0800 = IP协议
    total_len += sizeof(struct ethhdr);
    
    // 4. 构建 IP 头部
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iph->version = 4;
    iph->ihl = 5;  // IP头部长度（5 * 4字节 = 20字节）
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 10); // 总长度
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;  // 先置0，后面计算
    inet_pton(AF_INET, SRC_IP, &iph->saddr);
    inet_pton(AF_INET, DST_IP, &iph->daddr);
    
    // 计算IP校验和
    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));
    total_len += sizeof(struct iphdr);
    
    // 5. 构建 UDP 头部
    struct udphdr *udph = (struct udphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    udph->source = htons(SRC_PORT);
    udph->dest = htons(DST_PORT);
    udph->len = htons(sizeof(struct udphdr) + 10);  // UDP头+数据长度
    udph->check = 0;  // UDP校验和可选，这里置0
    
    total_len += sizeof(struct udphdr);
    
    // 6. 添加 UDP 数据
    char *data = (char *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
    strcpy(data, "Hello UDP!");
    total_len += 10;
    
    // 更新IP总长度
    iph->tot_len = htons(total_len - sizeof(struct ethhdr));
    
    // 7. 设置发送地址结构
    memset(&saddr, 0, sizeof(struct sockaddr_ll));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_IP);
    saddr.sll_ifindex = get_if_index(sock_raw, IF_NAME);
    saddr.sll_halen = ETH_ALEN;
    memcpy(saddr.sll_addr, dst_mac, 6);
    
    // 8. 发送数据包
    int send_len = sendto(sock_raw, buffer, total_len, 0,
                         (struct sockaddr *)&saddr, sizeof(struct sockaddr_ll));
    if (send_len < 0) {
        perror("sendto");
    } else {
        printf("Packet sent, length: %d\n", send_len);
        
        // 打印发送的帧内容（前64字节）
        printf("Frame content (first 64 bytes):\n");
        for (int i = 0; i < 64 && i < total_len; i++) {
            printf("%02x ", buffer[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n");
    }
    
    close(sock_raw);
    return 0;
}