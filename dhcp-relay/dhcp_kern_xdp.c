/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>
#include <xdp/context_helpers.h>
#include "dhcp-relay.h"

#ifndef NBPF_DHCP_RELAY_TRACE_STAGE
#define NBPF_DHCP_RELAY_TRACE_STAGE 0
#endif

#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 1
#define NBPF_TRACE_STAGE_1() (ctx->rx_queue_index = 1)
#else
#define NBPF_TRACE_STAGE_1() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 2
#define NBPF_TRACE_STAGE_2() (ctx->rx_queue_index = 2)
#else
#define NBPF_TRACE_STAGE_2() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 3
#define NBPF_TRACE_STAGE_3() (ctx->rx_queue_index = 3)
#else
#define NBPF_TRACE_STAGE_3() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 4
#define NBPF_TRACE_STAGE_4() (ctx->rx_queue_index = 4)
#else
#define NBPF_TRACE_STAGE_4() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 5
#define NBPF_TRACE_STAGE_5() (ctx->rx_queue_index = 5)
#else
#define NBPF_TRACE_STAGE_5() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 6
#define NBPF_TRACE_STAGE_6() (ctx->rx_queue_index = 6)
#else
#define NBPF_TRACE_STAGE_6() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 7
#define NBPF_TRACE_STAGE_7() (ctx->rx_queue_index = 7)
#else
#define NBPF_TRACE_STAGE_7() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 8
#define NBPF_TRACE_STAGE_8() (ctx->rx_queue_index = 8)
#else
#define NBPF_TRACE_STAGE_8() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 9
#define NBPF_TRACE_STAGE_9() (ctx->rx_queue_index = 9)
#else
#define NBPF_TRACE_STAGE_9() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 10
#define NBPF_TRACE_STAGE_10() (ctx->rx_queue_index = 10)
#else
#define NBPF_TRACE_STAGE_10() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 11
#define NBPF_TRACE_STAGE_11() (ctx->rx_queue_index = 11)
#else
#define NBPF_TRACE_STAGE_11() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 12
#define NBPF_TRACE_STAGE_12() (ctx->rx_queue_index = 12)
#else
#define NBPF_TRACE_STAGE_12() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 13
#define NBPF_TRACE_STAGE_13() (ctx->rx_queue_index = 13)
#else
#define NBPF_TRACE_STAGE_13() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 14
#define NBPF_TRACE_STAGE_14() (ctx->rx_queue_index = 14)
#else
#define NBPF_TRACE_STAGE_14() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 15
#define NBPF_TRACE_STAGE_15() (ctx->rx_queue_index = 15)
#else
#define NBPF_TRACE_STAGE_15() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 16
#define NBPF_TRACE_STAGE_16() (ctx->rx_queue_index = 16)
#else
#define NBPF_TRACE_STAGE_16() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 17
#define NBPF_TRACE_STAGE_17() (ctx->rx_queue_index = 17)
#else
#define NBPF_TRACE_STAGE_17() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 18
#define NBPF_TRACE_STAGE_18() (ctx->rx_queue_index = 18)
#else
#define NBPF_TRACE_STAGE_18() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 19
#define NBPF_TRACE_STAGE_19() (ctx->rx_queue_index = 19)
#else
#define NBPF_TRACE_STAGE_19() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 20
#define NBPF_TRACE_STAGE_20() (ctx->rx_queue_index = 20)
#else
#define NBPF_TRACE_STAGE_20() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 21
#define NBPF_TRACE_STAGE_21() (ctx->rx_queue_index = 21)
#else
#define NBPF_TRACE_STAGE_21() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 22
#define NBPF_TRACE_STAGE_22() (ctx->rx_queue_index = 22)
#else
#define NBPF_TRACE_STAGE_22() ((void)0)
#endif
#if defined(NBPF_NPU) && NBPF_DHCP_RELAY_TRACE_STAGE == 23
#define NBPF_TRACE_STAGE_23() (ctx->rx_queue_index = 23)
#else
#define NBPF_TRACE_STAGE_23() ((void)0)
#endif

#define NBPF_TRACE_STAGE_SELECT(STAGE) NBPF_TRACE_STAGE_##STAGE()
#define NBPF_TRACE_STAGE(STAGE) NBPF_TRACE_STAGE_SELECT(STAGE)

#ifdef NBPF_DHCP_RELAY_BPF_DEBUG_STOP
#define NBPF_DEBUG_ACTION_BASE 128
#define NBPF_DEBUG_STOP(STAGE)                                                \
	NBPF_TRACE_STAGE(STAGE);                                               \
	if (NBPF_DHCP_RELAY_BPF_DEBUG_STOP == (STAGE))                        \
		return NBPF_DEBUG_ACTION_BASE + (STAGE)
#else
#define NBPF_DEBUG_STOP(STAGE) NBPF_TRACE_STAGE(STAGE)
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

static __always_inline void nbpf_store_be16(void *p, __u16 v)
{
	__u8 *b = (__u8 *)p;
	b[0] = (__u8)(v >> 8);
	b[1] = (__u8)(v & 0xff);
}

static __always_inline __u16 nbpf_ipv4_csum_20(const __u8 *ip)
{
	__u32 sum = 0;
	int i;

	for (i = 0; i < 20; i += 2) {
		if (i == 10)
			continue;
		sum += nbpf_load_be16(ip + i);
	}

	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__u16)(~sum);
}

static __always_inline int write_dhcp_option_npu(void *ctx, int offset,
						 struct collect_vlans *vlans)
{
	__u8 option[sizeof(struct dhcp_option_82)];

	option[0] = DHO_DHCP_AGENT_OPTIONS;
	option[1] = 8;
	option[2] = RAI_CIRCUIT_ID;
	option[3] = RAI_OPTION_LEN;
	nbpf_store_be16(option + 4, vlans->id[0]);
	option[6] = RAI_REMOTE_ID;
	option[7] = RAI_OPTION_LEN;
	nbpf_store_be16(option + 8, vlans->id[1]);

	return xdp_store_bytes(ctx, offset, option, sizeof(option), 0);
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

	struct collect_vlans vlans;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct iphdr oldip;
	struct udphdr *udp;
	__u32 *dhcp_srv;
	int rc;
	__u16 offset;
	__u16 ip_offset;
	int i;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int ether_type;
	int h_proto;
	int key;
	int len;
#ifdef NBPF_NPU
	int npu_vlan_depth;
	__u16 npu_ip_header_len;
	__u16 npu_udp_offset;
#endif

	NBPF_DEBUG_STOP(3);

	vlans.id[0] = 0;
	vlans.id[1] = 0;
	rc = XDP_PASS;
	offset = static_offset;
	ip_offset = 0;
	i = 0;
	h_proto = 0;
	key = 0;
	len = 0;
#ifdef NBPF_NPU
	npu_vlan_depth = 0;
	npu_ip_header_len = 0;
	npu_udp_offset = 0;
#endif

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
	if (ether_type != NBPF_ETH_P_IP)
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

#ifdef NBPF_NPU
	{
		uintptr_t ip_pos = (uintptr_t)nh.pos;
		uintptr_t end = (uintptr_t)data_end;
		__u8 ver_ihl;

		if (ip_pos + sizeof(struct iphdr) > end)
			goto out;

		ver_ihl = *(__u8 *)ip_pos;
		if ((ver_ihl >> 4) != 4)
			goto out;

		npu_ip_header_len = (__u16)((ver_ihl & 0x0f) * 4);
		if (npu_ip_header_len < sizeof(struct iphdr))
			goto out;

		if (ip_pos + npu_ip_header_len > end)
			goto out;

		h_proto = *(__u8 *)(ip_pos + 9);
		ip_offset = (__u16)((ip_pos - (uintptr_t)data) & 0x3fff);
		nh.pos = (void *)(ip_pos + npu_ip_header_len);
	}
#else
	h_proto = parse_iphdr(&nh, data_end, &ip);
#endif
	NBPF_DEBUG_STOP(10);

	/* only handle fixed-size IP header due to static copy */
#ifdef NBPF_NPU
	if (h_proto != IPPROTO_UDP || npu_ip_header_len > sizeof(struct iphdr)) {
		goto out;
	}
#else
	if (h_proto != IPPROTO_UDP || ip->ihl > 5) {
		goto out;
	}
#endif
	NBPF_DEBUG_STOP(11);

	/*old ip hdr backup for re-calculating the checksum later*/
#ifdef NBPF_NPU
	{
		uintptr_t udp_pos = (uintptr_t)nh.pos;
		uintptr_t end = (uintptr_t)data_end;
		int udp_payload_len;

		if (udp_pos + sizeof(struct udphdr) > end)
			goto out;

		udp_payload_len = (int)nbpf_load_be16((const void *)(udp_pos + 4)) -
				  (int)sizeof(struct udphdr);
		if (udp_payload_len < 0)
			goto out;

		npu_udp_offset = (__u16)((udp_pos - (uintptr_t)data) & 0x3fff);
		nh.pos = (void *)(udp_pos + sizeof(struct udphdr));
		len = udp_payload_len;
	}
#else
	oldip = *ip;
	ip_offset = ((__u8 *)ip - (__u8 *)data) & 0x3fff;
	len = parse_udphdr(&nh, data_end, &udp);
	if (len < 0)
		goto out;
#endif
	NBPF_DEBUG_STOP(12);

#ifdef NBPF_NPU
	if (nbpf_load_be16((const __u8 *)data + npu_udp_offset + 2) != DEST_PORT)
		goto out;
#else
	if (udp->dest != bpf_htons(DEST_PORT))
		goto out;
#endif
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
	NBPF_DEBUG_STOP(15);

	/* adjusting the packet head by delta size to insert option82 */
	if (bpf_xdp_adjust_head(ctx, 0 - delta) < 0)
		return XDP_ABORTED;
	NBPF_DEBUG_STOP(16);

	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;

	if ((uintptr_t)data + offset > (uintptr_t)data_end)
		return XDP_ABORTED;
	NBPF_DEBUG_STOP(17);

	if (xdp_store_bytes(ctx, 0, buf, static_offset, 0))
		return XDP_ABORTED;
	NBPF_DEBUG_STOP(18);

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
	NBPF_DEBUG_STOP(19);

#ifdef NBPF_NPU
	if (write_dhcp_option_npu(ctx, offset, &vlans))
#else
	if (write_dhcp_option(ctx, offset, &vlans))
#endif
		return XDP_ABORTED;
	NBPF_DEBUG_STOP(20);

#ifdef NBPF_NPU
	{
		__u8 *ip_bytes = (__u8 *)data + ip_offset;
		__u8 *server = (__u8 *)dhcp_srv;
		__u16 csum;

		if ((uintptr_t)(ip_bytes + sizeof(struct iphdr)) >
		    (uintptr_t)data_end)
			return XDP_ABORTED;
		NBPF_DEBUG_STOP(21);

		ip_bytes[16] = server[0];
		ip_bytes[17] = server[1];
		ip_bytes[18] = server[2];
		ip_bytes[19] = server[3];
		NBPF_DEBUG_STOP(22);

		ip_bytes[10] = 0;
		ip_bytes[11] = 0;
		csum = nbpf_ipv4_csum_20(ip_bytes);
		nbpf_store_be16(ip_bytes + 10, csum);
	}
#else
	ip = (struct iphdr *)((__u8 *)data + ip_offset);
	if ((uintptr_t)(ip + 1) > (uintptr_t)data_end)
		return XDP_ABORTED;
	NBPF_DEBUG_STOP(21);

	/* overwrite the destination IP in IP header */
	ip->daddr = *dhcp_srv;
	NBPF_DEBUG_STOP(22);

	//re-calc ip checksum
	__u32 sum = calc_ip_csum(&oldip, ip, oldip.check);
	ip->check = ~sum;
#endif
	NBPF_DEBUG_STOP(23);
	rc = XDP_PASS;
	goto out;

out:
	return rc;
}
