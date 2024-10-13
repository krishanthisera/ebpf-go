//go:build ignore

#include "xdp_lb_kern.h"

#define DEST_IP  ((192U << 24) | (168U << 16) | (0U << 8) | 169U)
#define DEST_MAC {0x60, 0x3e, 0x5f, 0x66, 0xdd, 0xab}

static __always_inline void set_dest_addresses(struct ethhdr *eth, struct iphdr *iph) {
    // Set static IP address for destination address to 192.168.0.169
    iph->daddr = DEST_IP;

    // Set destination MAC address to 60:3e:5f:66:dd:ab
    unsigned char dest_mac[] = DEST_MAC;
    __builtin_memcpy(eth->h_dest, dest_mac, ETH_ALEN);
}

SEC("xdp_lb")
int xdp_load_balancer(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    // bpf_printk("Hey it's load balancer");

    // Check if this is an ethernet frame
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // Check if this is an IP packet
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;
    
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Set destination IP and MAC addresses
    set_dest_addresses(eth, iph);

    // Recalculate IP checksum
    iph->check = iph_csum(iph);

    

    // bpf_printk("lb: got a TCP packet from %x", iph->saddr);
    return XDP_TX;
}

//

char _license[] SEC("license") = "GPL";
