//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define AF_INET 2
#define AF_INET6 10

// SEC("lsm/socket_create")
// int socket_create(int family, int type, int protocol, int kern) {
//     // only family, type, protocol
// }

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) { // local socket, remote address
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    int sock_type = BPF_CORE_READ(sock, type);
    struct sock *sk = BPF_CORE_READ(sock, sk);
    int ifindex = BPF_CORE_READ(sk, __sk_common.skc_bound_dev_if); // will be 0 unless requested explicitly

    sa_family_t family = BPF_CORE_READ(address, sa_family);

    if (family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
        
        // Extract dest IP and port, are in network byte order
        u32 dest_ip = BPF_CORE_READ(addr_in, sin_addr.s_addr);
        u16 dest_port = BPF_CORE_READ(addr_in, sin_port);

        // create a byte view of the IP for printing
        unsigned char *ip = (unsigned char *)&dest_ip;

        bpf_printk("'%s': Connecting to IP: %d.%d.%d.%d Port: %d from interface: %d", comm, ip[0], ip[1], ip[2], ip[3], bpf_ntohs(dest_port), ifindex);
    }

    return 0;
}

// SEC("lsm/socket_accept")
// int BPF_PROG(socket_accept, struct socket *sock, struct socket *newsock) {
//     char comm[16];
//     bpf_get_current_comm(&comm, sizeof(comm));

//     struct sock *sk = BPF_CORE_READ(newsock, sk);


// }