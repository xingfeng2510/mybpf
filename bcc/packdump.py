#!/usr/bin/env python

from __future__ import print_function
from bcc import BPF
import argparse
from socket import inet_ntop, inet_aton, AF_INET
from struct import pack, unpack

examples = """examples:
    ./packdump             # trace all TCP packets
    ./packdump -t          # include timestamps
    ./packdump -a 1.2.3.4  # only trace ip address 1.2.3.4
    ./packdump -p 80       # only trace port 80
"""

parser = argparse.ArgumentParser(
    description="Trace TCP packets",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--timestamp", action="store_true", help="include timestamp on output")
parser.add_argument("-a", "--address", type=str, help="trace this ip address only")
parser.add_argument("-p", "--port", type=int, help="trace this port only.")
args = parser.parse_args()

ROUTE_EVENT_IF = 1
ROUTE_EVENT_IPT = 2

NF_VERDICT_NAME = [
    'DROP',
    'ACCEPT',
    'STOLEN',
    'QUEUE',
    'REPEAT',
    'STOP',
]

HOOKNAMES = [
    "PREROUTING",
    "INPUT",
    "FORWARD",
    "OUTPUT",
    "POSTROUTING",
]

bpf_text = """
#include <bcc/proto.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <net/inet_sock.h>
#include <linux/netfilter/x_tables.h>

#define ROUTE_EVENT_IF  1
#define ROUTE_EVENT_IPT 2

#define TRACE_SKB_DONE    0
#define TRACE_SKB_IGNORED 1

struct route_event_t {
    u64 flags;
    u64 ts_us;

    char ifname[IFNAMSIZ];
    u64 netns;

    u32 saddr;
    u32 daddr;

    u16 sport;
    u16 dport;

    u64 hook;
    u64 verdict;
    char tablename[XT_TABLE_MAXNAMELEN];
};
BPF_PERF_OUTPUT(route_events);

struct ipt_do_table_args
{
    struct sk_buff *skb;
    const struct nf_hook_state *state;
    struct xt_table *table;
};
BPF_HASH(ipt_do_table_args_map, u32, struct ipt_do_table_args);

#define member_of(ptr, member)  \
    ({                                                               \
        void *ret = ((char *)ptr) + offsetof(typeof(*ptr), member);  \
        ret;                                                         \
    })

#define member_read(dst, ptr, member)  \
    do {  \
        bpf_probe_read_kernel(dst, sizeof(ptr->member), member_of(ptr, member));  \
    } while (0)

#define copy_read(dst, src) \
    do {  \
        bpf_probe_read_kernel(dst, sizeof(*(dst)), src);  \
    } while (0)

static inline int do_trace_skb(struct route_event_t *evt, void *ctx, struct sk_buff *skb)
{
    char *head, *ip_header_address, *tcp_header_address;
    u16 network_header, transport_header;
    u8 ip_version;
    struct iphdr iph;
    struct tcphdr tcph;
    struct net_device *dev;
    possible_net_t *pnet;
    struct net *net;
    struct ns_common *ns;

    member_read(&head, skb, head);
    member_read(&network_header, skb, network_header);
    member_read(&transport_header, skb, transport_header);

    tcp_header_address = head + transport_header;
    copy_read(&tcph, tcp_header_address);
    evt->sport = ntohs(tcph.source);
    evt->dport = ntohs(tcph.dest);

    FILTER_PORT

    ip_header_address = head + network_header;
    copy_read(&ip_version, ip_header_address);
    if ((ip_version >> 4 & 0xf) != 4) { // IPv4 only
        return TRACE_SKB_IGNORED;
    }

    copy_read(&iph, ip_header_address);
    if (iph.protocol != IPPROTO_TCP) { // TCP protocol only
        return TRACE_SKB_IGNORED;
    }
    evt->saddr = iph.saddr;
    evt->daddr = iph.daddr;

    FILTER_IPADDR

    if ((evt->flags & ROUTE_EVENT_IPT) == 0) {
        member_read(&dev, skb, dev);
        copy_read(&evt->ifname, dev->name);

        pnet = &dev->nd_net;
        member_read(&net, pnet, net);
        ns = member_of(net, ns);
        member_read(&evt->netns, ns, inum);
    }

    evt->flags |= ROUTE_EVENT_IF;
    evt->ts_us = bpf_ktime_get_ns() / 1000;

    return TRACE_SKB_DONE;
}

static inline int do_trace(void *ctx, struct sk_buff *skb)
{
    struct route_event_t evt = {};
    int ret = do_trace_skb(&evt, ctx, skb);
    if (ret == TRACE_SKB_DONE) {
        route_events.perf_submit(ctx, &evt, sizeof(evt));
    }
    return ret;
}

TRACEPOINT_PROBE(net, netif_rx)
{
    return do_trace(args, (struct sk_buff *)args->skbaddr);
}

TRACEPOINT_PROBE(net, net_dev_queue)
{
    return do_trace(args, (struct sk_buff *)args->skbaddr);
}

TRACEPOINT_PROBE(net, napi_gro_receive_entry)
{
    return do_trace(args, (struct sk_buff *)args->skbaddr);
}

TRACEPOINT_PROBE(net, netif_receive_skb_entry)
{
    return do_trace(args, (struct sk_buff *)args->skbaddr);
}

static inline int __ipt_do_table_in(struct pt_regs *ctx, struct sk_buff *skb,
    const struct nf_hook_state *state, struct xt_table *table)
{
    u32 pid = bpf_get_current_pid_tgid();

    struct ipt_do_table_args args = {
        .skb = skb,
        .state = state,
        .table = table,
    };
    ipt_do_table_args_map.update(&pid, &args);

    return 0;
};

static inline int __ipt_do_table_out(struct pt_regs * ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct ipt_do_table_args *args;
    struct net_device *dev;
    struct net *net;
    struct ns_common *ns;
    int ret;

    args = ipt_do_table_args_map.lookup(&pid);
    if (args == 0) {
        return 0; // missed entry
    }
    ipt_do_table_args_map.delete(&pid);

    struct route_event_t evt = {
        .flags = ROUTE_EVENT_IPT,
    };

    ret = do_trace_skb(&evt, ctx, args->skb);
    if (ret == TRACE_SKB_DONE) {
        member_read(&evt.hook, args->state, hook);
        if (evt.hook > NF_INET_LOCAL_IN) {
            member_read(&dev, args->state, out);
        } else {
            member_read(&dev, args->state, in);
        }
        member_read(&evt.ifname, dev, name);

        member_read(&net, args->state, net);
        ns = member_of(net, ns);
        member_read(&evt.netns, ns, inum);

        member_read(&evt.tablename, args->table, name);
        evt.verdict = PT_REGS_RC(ctx);

        route_events.perf_submit(ctx, &evt, sizeof(evt));
    }
    return ret;
}

int kprobe__ipt_do_table(struct pt_regs *ctx, struct sk_buff *skb,
    const struct nf_hook_state *state, struct xt_table *table)
{
    return __ipt_do_table_in(ctx, skb, state, table);
};

int kretprobe__ipt_do_table(struct pt_regs *ctx)
{
    return __ipt_do_table_out(ctx);
}
"""

def print_route_event(cpu, data, size):
    evt = b["route_events"].event(data)

    global start_ts

    saddr = inet_ntop(AF_INET, pack("=I", evt.saddr))
    daddr = inet_ntop(AF_INET, pack("=I", evt.daddr))

    flow = "%s:%-5d -> %s:%-5d" % (saddr, evt.sport, daddr, evt.dport)

    iptables = ""
    if evt.flags & ROUTE_EVENT_IPT == ROUTE_EVENT_IPT:
        verdict = NF_VERDICT_NAME[evt.verdict]
        hook = HOOKNAMES[evt.hook]
        iptables = " %7s.%-12s:%s" % (evt.tablename, hook, verdict)

    if args.timestamp:
        if start_ts == 0:
            start_ts = evt.ts_us
        delta_s = (float(evt.ts_us) - start_ts) / 1000000
        print("%-9.6f " % delta_s, end="")

    print("[%10s] %16s %-46s %s" % (evt.netns, evt.ifname, flow, iptables))

if args.port:
    bpf_text = bpf_text.replace('FILTER_PORT',
        'if (evt->sport != %d && evt->dport != %d) { return TRACE_SKB_IGNORED; }' % (args.port, args.port))

if args.address:
    address = unpack("=I", inet_aton(args.address))[0]
    bpf_text = bpf_text.replace('FILTER_IPADDR',
        'if (evt->saddr != %d && evt->daddr != %d) { return TRACE_SKB_IGNORED; }' % (address, address))

bpf_text = bpf_text.replace('FILTER_PORT', '')
bpf_text = bpf_text.replace('FILTER_IPADDR', '')

b = BPF(text=bpf_text)

if args.timestamp:
    print("%-9s " % "TIME(s)", end="")

print("%12s %16s %-46s %s" % ('NETWORK NS', 'INTERFACE', 'ADDRESSES', 'IPTABLES'))

start_ts = 0

b["route_events"].open_perf_buffer(print_route_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
