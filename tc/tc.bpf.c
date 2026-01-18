//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

enum tc_action {
    TC_ACT_OK,    // pass
    TC_ACT_SHOT   // drop
};

// CANNOT USE bpf_get_current_comm()
// CAN USE bpf_get_current_task();

SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
	
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("'%s' tc/ingress", comm);

	return TC_ACT_OK;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
	
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("'%s' tc/egress", comm);

	return TC_ACT_OK;
}