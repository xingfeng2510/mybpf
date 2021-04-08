#!/usr/bin/python

from bcc import BPF
from socket import inet_ntop, AF_INET
from struct import pack

bpf_text = """ 
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <bcc/proto.h>

struct info_t {
    u64 ts;
    u32 pid;
    char task[TASK_COMM_LEN];
};
BPF_HASH(start, struct sock *, struct info_t);

struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 dport;
    u64 delta_us;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

int trace_connect(struct pt_regs *ctx, struct sock *sk)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct info_t info = { .pid = pid };
    info.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&info.task, sizeof(info.task));
    start.update(&sk, &info);
    return 0;
};

int trace_tcp_rcv_state_process(struct pt_regs *ctx, struct sock *skp)
{
    if (skp->__sk_common.skc_state != TCP_SYN_SENT) {
        return 0;
    }

    struct info_t *infop = start.lookup(&skp);
    if (infop == 0) {
        return 0;
    }

    u64 ts = infop->ts;
    u64 now = bpf_ktime_get_ns();
    u64 delta_us = (now - ts) / 1000ul;
    u16 dport = skp->__sk_common.skc_dport;
    
    if (skp->__sk_common.skc_family == AF_INET) {
        struct ipv4_data_t data4 = { .pid = infop->pid };
        data4.ts_us = now / 1000;
        data4.saddr = skp->__sk_common.skc_rcv_saddr;
        data4.daddr = skp->__sk_common.skc_daddr;
        data4.dport = ntohs(dport);
        data4.delta_us = delta_us;
        __builtin_memcpy(&data4.task, infop->task, sizeof(data4.task));
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    }

    start.delete(&skp);

    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")
b.attach_kprobe(event="tcp_rcv_state_process", fn_name="trace_tcp_rcv_state_process")

def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    print("%-6d %-12s %-16s %-16s %-5d %.2f" % (event.pid, event.task, 
        inet_ntop(AF_INET, pack("I", event.saddr)),
        inet_ntop(AF_INET, pack("I", event.daddr)),
        event.dport, float(event.delta_us) / 1000)) 

print("%-6s %-12s %-16s %-16s %-5s %s" % ("PID", "COMM", "SADDR", "DADDR", 
    "DPORT", "LAT(ms)")) 

b["ipv4_events"].open_perf_buffer(print_ipv4_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
