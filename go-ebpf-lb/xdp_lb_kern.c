//go:build ignore

#include "xdp_lb_kern.h"

#define IP_ADDRESS(x) (unsigned int)(172 + (17 << 8) + (0 << 16) + (x << 24))
#define BACKEND 3 
#define CLIENT 4
#define LB 2

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
    
    // If this is returning packet we should send it the client
    if (iph->saddr == IP_ADDRESS(CLIENT))
    {
        iph->daddr = IP_ADDRESS(BACKEND);
        eth->h_dest[5] = BACKEND;
    }
    else
    {
        iph->daddr = IP_ADDRESS(CLIENT);
        eth->h_dest[5] = CLIENT;
    }

    // Always set source IP and MAC
    iph->saddr = IP_ADDRESS(LB);
    eth->h_source[5] = LB;
    // Recalculate IP checksum
    iph->check = iph_csum(iph);

    bpf_printk("lb: routing packets %x mac %x", iph->daddr, eth->h_dest);
    return XDP_TX;
}

//

char _license[] SEC("license") = "GPL";
