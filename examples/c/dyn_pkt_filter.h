#ifndef __DYN_PKT_FILTER_H
#define __DYN_PKT_FILTER_H

struct filter_event {
    __be32 src_addr;
    __be32 dst_addr;
    union {
        __be32 ports;
        __be16 port16[2];
    };
    __u32 ip_proto;
    __u32 pkt_type;
    __u32 ifindex;
};

#endif
