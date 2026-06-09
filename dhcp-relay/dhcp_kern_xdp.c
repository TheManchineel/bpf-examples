/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>
#include <xdp/context_helpers.h>
#include "dhcp-relay.h"

#ifdef NBPF_DHCP_RELAY_BPF_DEBUG_STOP
#define NBPF_DEBUG_ACTION_BASE 128
#define NBPF_DEBUG_STOP(STAGE)                                                \
	do {                                                                  \
		if (NBPF_DHCP_RELAY_BPF_DEBUG_STOP == (STAGE))                \
			return NBPF_DEBUG_ACTION_BASE + (STAGE);              \
	} while (0)
#else
#define NBPF_DEBUG_STOP(STAGE)                                                \
	do {                                                                  \
	} while (0)
#endif

#ifdef NBPF_NPU
#define NBPF_ETH_P_IP ((__u16)0x0800)
#define NBPF_ETH_P_8021Q ((__u16)0x8100)
#define NBPF_ETH_P_8021AD ((__u16)0x88a8)

static __always_inline __u16 nbpf_load_be16(const void *p)
{
	const __u8 *b = (const __u8 *)p;
	return ((__u16)b[0] << 8) | b[1];
}

static __always_inline int nbpf_parse_ethhdr_vlan(void *data, void *data_end,
						  struct ethhdr **ethhdr,
						  struct collect_vlans *vlans,
						  void **next_pos)
{
	struct ethhdr *eth = (struct ethhdr *)data;
	uintptr_t pos = (uintptr_t)data;
	uintptr_t end = (uintptr_t)data_end;
	__u16 h_proto;
	struct vlan_hdr *vlh;

	if (pos + sizeof(*eth) > end)
		return -1;

	pos += sizeof(*eth);
	*ethhdr = eth;
	h_proto = eth->h_proto;

	if (proto_is_vlan(h_proto)) {
		if (pos + sizeof(struct vlan_hdr) > end)
			goto done;
		vlh = (struct vlan_hdr *)pos;
		h_proto = vlh->h_vlan_encapsulated_proto;
		vlans->id[0] = bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK;
		pos += sizeof(struct vlan_hdr);
	}

	if (proto_is_vlan(h_proto)) {
		if (pos + sizeof(struct vlan_hdr) > end)
			goto done;
		vlh = (struct vlan_hdr *)pos;
		h_proto = vlh->h_vlan_encapsulated_proto;
		vlans->id[1] = bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK;
		pos += sizeof(struct vlan_hdr);
	}

done:
	*next_pos = (void *)pos;
	return h_proto;
}
#endif

/*
 * This map is for storing the DHCP relay server
 * IP address configured by user. It is received
 * as an argument by user program.
*/
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} dhcp_server SEC(".maps");

/* Inserts DHCP option 82 into the received dhcp packet
 * at the specified offset.
*/
static __always_inline int write_dhcp_option(void *ctx, int offset,
					     struct collect_vlans *vlans)
{
	struct dhcp_option_82 option;

	option.t = DHO_DHCP_AGENT_OPTIONS;
	option.len = 8;
	option.circuit_id.option_id = RAI_CIRCUIT_ID;
	option.circuit_id.len = RAI_OPTION_LEN;
	option.circuit_id.val = bpf_htons(vlans->id[0]);
	option.remote_id.option_id = RAI_REMOTE_ID;
	option.remote_id.len = RAI_OPTION_LEN;
	option.remote_id.val = bpf_htons(vlans->id[1]);

	return xdp_store_bytes(ctx, offset, &option, sizeof(option), 0);
}

/* Calculates the IP checksum */
static __always_inline int calc_ip_csum(struct iphdr *oldip, struct iphdr *ip,
					__u32 oldcsum)
{
	__u32 size = sizeof(struct iphdr);
	__u32 csum = bpf_csum_diff((__be32 *)oldip, size, (__be32 *)ip, size,
				   ~oldcsum);
	__u32 sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return sum;
}

/* Offset to DHCP Options part of the packet */
#define static_offset                                                          \
	sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + \
		offsetof(struct dhcp_packet, options)

/* Delta value to be adjusted at xdp head*/
#define delta sizeof(struct dhcp_option_82)

/* buf needs to be a static global var because the verifier won't allow
 * unaligned stack accesses
*/
static __u8 buf[static_offset + VLAN_MAX_DEPTH * sizeof(struct vlan_hdr)];

/* XDP program for parsing the DHCP packet and inserting the option 82*/
SEC(XDP_PROG_SEC)
int xdp_dhcp_relay(struct xdp_md *ctx)
{
	NBPF_DEBUG_STOP(1);

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	NBPF_DEBUG_STOP(2);

	struct collect_vlans vlans = { 0 };
	struct ethhdr *eth;
	struct iphdr *ip;
	struct iphdr oldip;
	struct udphdr *udp;
	__u32 *dhcp_srv;
	int rc = XDP_PASS;
	__u16 offset = static_offset;
	__u16 ip_offset = 0;
	int i = 0;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int ether_type;
	int h_proto = 0;
	int key = 0;
	int len = 0;
#ifdef NBPF_NPU
	int npu_vlan_depth = 0;
#endif

	NBPF_DEBUG_STOP(3);

	if (ctx->data + 1 > ctx->data_end)
		return XDP_ABORTED;

	NBPF_DEBUG_STOP(4);

#ifdef NBPF_NPU
	{
		uintptr_t pos = ctx->data;
		uintptr_t end = ctx->data_end;

		if (pos + sizeof(*eth) > end) {
			rc = XDP_ABORTED;
			goto out;
		}

		eth = (struct ethhdr *)pos;
		pos += sizeof(*eth);
		ether_type = nbpf_load_be16((const __u8 *)eth + 12);
		nh.pos = (void *)pos;

		if (ether_type == NBPF_ETH_P_8021Q ||
		    ether_type == NBPF_ETH_P_8021AD) {
			if (pos + sizeof(struct vlan_hdr) > end)
				goto npu_eth_done;
			vlans.id[0] = nbpf_load_be16((const void *)pos) &
				       VLAN_VID_MASK;
			ether_type = nbpf_load_be16((const void *)(pos + 2));
			pos += sizeof(struct vlan_hdr);
			nh.pos = (void *)pos;
			npu_vlan_depth = 1;
		}

		if (ether_type == NBPF_ETH_P_8021Q ||
		    ether_type == NBPF_ETH_P_8021AD) {
			if (pos + sizeof(struct vlan_hdr) > end)
				goto npu_eth_done;
			vlans.id[1] = nbpf_load_be16((const void *)pos) &
				       VLAN_VID_MASK;
			ether_type = nbpf_load_be16((const void *)(pos + 2));
			pos += sizeof(struct vlan_hdr);
			nh.pos = (void *)pos;
			npu_vlan_depth = 2;
		}

npu_eth_done:
		;
	}
#else
	nh.pos = data;
	ether_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);
#endif
	NBPF_DEBUG_STOP(5);

	/* check for valid ether type */
	if (ether_type < 0) {
		rc = XDP_ABORTED;
		goto out;
	}
	NBPF_DEBUG_STOP(6);

#ifdef NBPF_NPU
	if (0)
#else
	if (ether_type != bpf_htons(ETH_P_IP))
#endif
		goto out;
	NBPF_DEBUG_STOP(7);

	/* Check at least two vlan tags are present */
#ifdef NBPF_NPU
	if (npu_vlan_depth < 2)
#else
	if (vlans.id[1] == 0)
#endif
		goto out;
	NBPF_DEBUG_STOP(8);

	/* Read dhcp relay server IP from map */
	dhcp_srv = bpf_map_lookup_elem(&dhcp_server, &key);
	if (dhcp_srv == NULL)
		goto out;
	NBPF_DEBUG_STOP(9);

	h_proto = parse_iphdr(&nh, data_end, &ip);
	NBPF_DEBUG_STOP(10);

	/* only handle fixed-size IP header due to static copy */
	if (h_proto != IPPROTO_UDP || ip->ihl > 5) {
		goto out;
	}
	NBPF_DEBUG_STOP(11);

	/*old ip hdr backup for re-calculating the checksum later*/
	oldip = *ip;
	ip_offset = ((__u8 *)ip - (__u8 *)data) & 0x3fff;
	len = parse_udphdr(&nh, data_end, &udp);
	if (len < 0)
		goto out;
	NBPF_DEBUG_STOP(12);

	if (udp->dest != bpf_htons(DEST_PORT))
		goto out;
	NBPF_DEBUG_STOP(13);

	if (xdp_load_bytes(ctx, 0, buf, static_offset))
		goto out;
	NBPF_DEBUG_STOP(14);

	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (vlans.id[i]) {
			if (xdp_load_bytes(ctx, offset, buf + offset, 4))
				goto out;
			offset += 4;
		}
	}

	/* adjusting the packet head by delta size to insert option82 */
	if (bpf_xdp_adjust_head(ctx, 0 - delta) < 0)
		return XDP_ABORTED;

	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;

	if ((uintptr_t)data + offset > (uintptr_t)data_end)
		return XDP_ABORTED;

	if (xdp_store_bytes(ctx, 0, buf, static_offset, 0))
		return XDP_ABORTED;

	if (offset > static_offset) {
		offset = static_offset;
		for (i = 0; i < VLAN_MAX_DEPTH; i++) {
			if (vlans.id[i]) {
				if (xdp_store_bytes(ctx, offset, buf + offset,
						    4, 0))
					return XDP_ABORTED;
				offset += 4;
			}
		}
	}

	if (write_dhcp_option(ctx, offset, &vlans))
		return XDP_ABORTED;

	ip = (struct iphdr *)((__u8 *)data + ip_offset);
	if ((uintptr_t)(ip + 1) > (uintptr_t)data_end)
		return XDP_ABORTED;

	/* overwrite the destination IP in IP header */
	ip->daddr = *dhcp_srv;

	//re-calc ip checksum
	__u32 sum = calc_ip_csum(&oldip, ip, oldip.check);
	ip->check = ~sum;
	rc = XDP_PASS;
	goto out;

out:
	return rc;
}
