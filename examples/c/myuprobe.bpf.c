#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

enum counters{
    CNT_ENTRY_ADD = 0,
    CNT_EXIT_ADD,
    CNT_NUM    
};

// TYPE_ARRAY 
// https://elixir.bootlin.com/linux/latest/source/samples/bpf/sockex1_kern.c
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key,   unsigned int);
	__type(value, unsigned int);
	__uint(max_entries, CNT_NUM); 
} my_cnt SEC(".maps");

SEC("uprobe//proc/self/exe:myuprobed_add")
int BPF_KPROBE(myuprobe_add, int a, int b)
{
    unsigned int *value;
    int cnt_idx = CNT_ENTRY_ADD;
    value = bpf_map_lookup_elem(&my_cnt, &cnt_idx);
	if (value)
		__sync_fetch_and_add(value, 1);

    // bpf_printk("myuprobe_add ENTRY: a = %d, b= %d", a, b);
    return 0;
}

SEC("uretprobe//proc/self/exe:myuprobed_add")
int BPF_KRETPROBE(myuretprobe_add, int ret)
{
    unsigned int *value;
    int cnt_idx = CNT_EXIT_ADD;
    value = bpf_map_lookup_elem(&my_cnt, &cnt_idx);
	if (value)
		__sync_fetch_and_add(value, 1);
    // bpf_printk("myuprobed_add EXIT: return = %d", ret);
    return 0;
}

