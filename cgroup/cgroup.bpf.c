//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/socket.h>


char __license[] SEC("license") = "Dual MIT/GPL";

// SEC("cgroup_skb/egress")
// int egress_packet_info(struct __sk_buff *skb) {

//     char comm[16];
//     bpf_get_current_comm(&comm, sizeof(comm)); // CANNOT USE
//     bpf_printk("'%s' sending packet", comm);
	
// 	return 1; // pass
// }

// struct bpf_sock_addr {
//     __u32 user_family;
//     __u32 user_ip4; // Stored in network byte order.
//     __u32 user_ip6[4]; // Stored in network byte order.
//     __u32 user_port; // Stored in network byte order
//     __u32 family; 2-> AF_INET, 10 -> AF_INET6
//     __u32 type; // Socket Type, 1 -> SOCK_STREAM, 2 -> SOCK_DGRAM
//     __u32 protocol; 6 -> IPPROTO_TCP, 17 -> IPPROTO_UDP
//     __u32 msg_src_ip4; // Stored in network byte order.
//     __u32 msg_src_ip6[4]; // Stored in network byte order.
//     __bpf_md_ptr(struct bpf_sock *, sk);
// };

SEC("cgroup/bind4")
int cgroup_bind(struct bpf_sock_addr *ctx)
{
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    __u32 ip = bpf_ntohl(ctx->user_ip4);
    __u16 port = bpf_ntohs(ctx->user_port);

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    bpf_printk(
        "bind4 comm=%s pid=%d "
        "user_family=%d family=%d type=%d proto=%d "
        "dst=%d.%d.%d.%d:%d",
        comm,
        pid,
        ctx->user_family,
        ctx->family,
        ctx->type,
        ctx->protocol,
        (ip >> 24) & 0xff,
        (ip >> 16) & 0xff,
        (ip >> 8) & 0xff,
        ip & 0xff,
        port
    );
	
	return 1; // pass
}

SEC("cgroup/connect4")
int cgroup_connect(struct bpf_sock_addr *ctx)
{
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    __u32 ip = bpf_ntohl(ctx->user_ip4);
    __u16 port = bpf_ntohs(ctx->user_port);

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    bpf_printk(
        "connect4 comm=%s pid=%d "
        "user_family=%d family=%d type=%d proto=%d "
        "addr=%d.%d.%d.%d:%d",
        comm,
        pid,
        ctx->user_family,
        ctx->family,
        ctx->type,
        ctx->protocol,
        (ip >> 24) & 0xff,
        (ip >> 16) & 0xff,
        (ip >> 8) & 0xff,
        ip & 0xff,
        port
    );
	
	return 1; // pass
}

