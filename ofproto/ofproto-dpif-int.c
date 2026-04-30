/*
 * Copyright (c) 2024 The Open vSwitch Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * ofproto-dpif-int.c – INT (In-band Network Telemetry) sink role.
 *
 * This module implements the "sink" role of INT-MD (Metadata) as described in
 * the P4.org INT Specification (v2.1).  When enabled on a bridge, every
 * packet that carries an INT shim header on the configured destination UDP
 * port (INT_DST_PORT = 8090) is processed as follows:
 *
 *   1. The INT shim and INT MD headers, together with the per-hop metadata
 *      stack, are parsed.
 *   2. A UDP telemetry report is generated and sent to the configured
 *      collector endpoint.
 *   3. The INT headers and metadata are stripped from the packet in-place so
 *      that a clean copy of the original payload can be forwarded normally.
 *
 * Packet format (INT-MD over UDP):
 *
 *   [Ethernet][IPv4][UDP dst=8090]
 *     [INT Shim 4B]        ← type=1, length in 4-byte words
 *     [INT MD Hdr 12B]     ← ver, hop_metadata_len, remaining_hop_cnt, ...
 *     [Hop N metadata]     ← most recent hop first
 *     ...
 *     [Original payload]
 *
 * The telemetry report sent to the collector uses the following structure:
 *
 *   [Ethernet][IPv4][UDP]
 *     [INT Report Fixed Header  16B]
 *     [INT Report Individual Hdr 12B]
 *     [Original packet headers  ≤ 64B]
 *     [INT metadata stack (verbatim copy)]
 */

#include <config.h>
#include "ofproto-dpif-int.h"

#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "csum.h"
#include "dp-packet.h"
#include "flow.h"
#include "openvswitch/vlog.h"
#include "ovs-atomic.h"
#include "packets.h"
#include "socket-util.h"
#include "timeval.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(int_sink);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* Maximum number of bytes of the original packet headers to copy into the
 * telemetry report (Ethernet + IPv4 + UDP = 42 bytes typical; cap at 64). */
#define INT_REPORT_HDR_COPY_LEN 64

/* Default UDP source port used when sending reports. */
#define INT_REPORT_SRC_PORT 32766

/* Interval in seconds at which the collector socket is re-opened when it
 * has been lost. */
#define INT_RECONNECT_INTERVAL 5

struct dpif_int_sink {
    struct ovs_refcount ref_cnt;

    /* Configuration (protected by the GIL / single-writer model of OVS). */
    struct dpif_int_sink_options *options;

    /* UDP socket to the telemetry collector, or -1 if not connected. */
    int collector_fd;

    /* Sequence number included in every report. */
    uint32_t seq_num;

    /* Timestamp of the last reconnect attempt. */
    time_t next_reconnect;
};

/* -----------------------------------------------------------------------
 * Life-cycle helpers
 * ----------------------------------------------------------------------- */

struct dpif_int_sink *
dpif_int_sink_create(void)
{
    struct dpif_int_sink *sink = xzalloc(sizeof *sink);
    ovs_refcount_init(&sink->ref_cnt);
    sink->options = NULL;
    sink->collector_fd = -1;
    sink->seq_num = 0;
    sink->next_reconnect = 0;
    return sink;
}

struct dpif_int_sink *
dpif_int_sink_ref(const struct dpif_int_sink *sink_)
{
    struct dpif_int_sink *sink = CONST_CAST(struct dpif_int_sink *, sink_);
    if (sink) {
        ovs_refcount_ref(&sink->ref_cnt);
    }
    return sink;
}

static void
dpif_int_sink_options_destroy(struct dpif_int_sink_options *opts)
{
    if (opts) {
        free(opts->collector_ip);
        free(opts);
    }
}

static void
dpif_int_sink_close_fd(struct dpif_int_sink *sink)
{
    if (sink->collector_fd >= 0) {
        close(sink->collector_fd);
        sink->collector_fd = -1;
    }
}

static void
dpif_int_sink_destroy(struct dpif_int_sink *sink)
{
    dpif_int_sink_close_fd(sink);
    dpif_int_sink_options_destroy(sink->options);
    free(sink);
}

void
dpif_int_sink_unref(struct dpif_int_sink *sink)
{
    if (sink && ovs_refcount_unref_relaxed(&sink->ref_cnt) == 1) {
        dpif_int_sink_destroy(sink);
    }
}

/* -----------------------------------------------------------------------
 * Configuration
 * ----------------------------------------------------------------------- */

bool
dpif_int_sink_is_enabled(const struct dpif_int_sink *sink)
{
    return sink && sink->options && sink->options->collector_ip;
}

void
dpif_int_sink_set_options(struct dpif_int_sink *sink,
                          const struct dpif_int_sink_options *options)
{
    if (!sink) {
        return;
    }

    /* Tear down the old collector socket whenever the configuration changes
     * so that it is re-created with the new parameters in dpif_int_sink_run().
     */
    dpif_int_sink_close_fd(sink);
    dpif_int_sink_options_destroy(sink->options);
    sink->options = NULL;

    if (!options || !options->collector_ip) {
        return;
    }

    sink->options = xmemdup(options, sizeof *options);
    sink->options->collector_ip = xstrdup(options->collector_ip);
    sink->next_reconnect = 0;  /* reconnect immediately */
}

/* -----------------------------------------------------------------------
 * Socket management
 * ----------------------------------------------------------------------- */

static void
dpif_int_sink_connect(struct dpif_int_sink *sink)
{
    const struct dpif_int_sink_options *opts = sink->options;
    struct sockaddr_in sa;
    int fd;
    int err;

    if (sink->collector_fd >= 0) {
        return;  /* already connected */
    }

    if (time_now() < sink->next_reconnect) {
        return;  /* back-off period not yet elapsed */
    }

    sink->next_reconnect = time_now() + INT_RECONNECT_INTERVAL;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        VLOG_WARN_RL(&rl, "INT sink: failed to create UDP socket: %s",
                     ovs_strerror(errno));
        return;
    }

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(opts->collector_port ? opts->collector_port
                                                : INT_REPORT_SRC_PORT);
    err = inet_pton(AF_INET, opts->collector_ip, &sa.sin_addr);
    if (err != 1) {
        VLOG_WARN_RL(&rl, "INT sink: invalid collector IP '%s'",
                     opts->collector_ip);
        close(fd);
        return;
    }

    if (connect(fd, (struct sockaddr *) &sa, sizeof sa) < 0) {
        VLOG_WARN_RL(&rl, "INT sink: connect to %s:%u failed: %s",
                     opts->collector_ip, opts->collector_port,
                     ovs_strerror(errno));
        close(fd);
        return;
    }

    sink->collector_fd = fd;
    VLOG_INFO("INT sink: connected to collector %s:%u",
              opts->collector_ip, opts->collector_port);
}

/* -----------------------------------------------------------------------
 * Run / wait
 * ----------------------------------------------------------------------- */

void
dpif_int_sink_run(struct dpif_int_sink *sink)
{
    if (!dpif_int_sink_is_enabled(sink)) {
        return;
    }
    dpif_int_sink_connect(sink);
}

void
dpif_int_sink_wait(struct dpif_int_sink *sink OVS_UNUSED)
{
    /* Nothing to wait on beyond what poll_block() already provides. */
}

/* -----------------------------------------------------------------------
 * Telemetry report helpers
 * ----------------------------------------------------------------------- */

/* Compute a simple IPv4 header checksum. */
static ovs_be16
ipv4_csum(const struct ip_header *ip)
{
    return csum_finish(csum_continue(0, ip, IP_HEADER_LEN));
}

/* Compute a UDP checksum over pseudo-header + UDP header + data.
 * Returns 0xffff if the result would be zero (per RFC 768). */
static ovs_be16
udp_csum_compute(ovs_be32 src, ovs_be32 dst, const struct udp_header *udp,
                 const void *data, size_t data_len)
{
    /* IPv4 pseudo-header: src, dst, zero, proto=17, UDP length */
    uint32_t partial = 0;
    ovs_be16 proto_and_len[2];
    ovs_be32 src_be = src;
    ovs_be32 dst_be = dst;
    ovs_be16 udp_len = udp->udp_len;

    proto_and_len[0] = htons(IPPROTO_UDP);
    proto_and_len[1] = udp_len;

    partial = csum_continue(partial, &src_be, 4);
    partial = csum_continue(partial, &dst_be, 4);
    partial = csum_continue(partial, proto_and_len, sizeof proto_and_len);
    partial = csum_continue(partial, udp, UDP_HEADER_LEN);
    partial = csum_continue(partial, data, data_len);

    ovs_be16 result = csum_finish(partial);
    return result ? result : htons(0xffff);
}

/* Send the collected INT metadata to the telemetry collector.
 *
 * 'pkt_hdr'        – pointer to the start of the original packet
 *                    (Ethernet header), used for the report.
 * 'pkt_hdr_len'    – bytes to copy from the original packet headers.
 * 'int_data'       – pointer to the INT shim + MD header + metadata stack.
 * 'int_data_len'   – total byte-length of the INT data block.
 * 'flow'           – parsed flow of the original packet.
 */
static void
dpif_int_sink_send_report(struct dpif_int_sink *sink,
                          const void *pkt_hdr, size_t pkt_hdr_len,
                          const void *int_data, size_t int_data_len,
                          const struct flow *flow)
{
    if (sink->collector_fd < 0) {
        return;
    }

    /* --- Build the report in a stack buffer ---
     *
     * Layout:
     *   [IP_HEADER][UDP_HEADER][INT_REPORT_HDR][INT_INDIVIDUAL_HDR]
     *   [original packet headers][INT metadata stack]
     */
    size_t payload_len = (INT_REPORT_HDR_LEN + INT_INDIVIDUAL_HDR_LEN
                          + pkt_hdr_len + int_data_len);
    size_t total_len   = IP_HEADER_LEN + UDP_HEADER_LEN + payload_len;

    /* Allocate on the heap to avoid large stack frames. */
    uint8_t *buf = xmalloc(total_len);
    memset(buf, 0, total_len);

    struct ip_header      *ip  = (struct ip_header *)buf;
    struct udp_header     *udp = (struct udp_header *)(buf + IP_HEADER_LEN);
    struct int_report_hdr *rpt = (struct int_report_hdr *)
                                 (buf + IP_HEADER_LEN + UDP_HEADER_LEN);
    struct int_individual_hdr *ind = (struct int_individual_hdr *)
                                     (buf + IP_HEADER_LEN + UDP_HEADER_LEN
                                      + INT_REPORT_HDR_LEN);
    uint8_t *orig_hdrs  = buf + IP_HEADER_LEN + UDP_HEADER_LEN
                          + INT_REPORT_HDR_LEN + INT_INDIVIDUAL_HDR_LEN;
    uint8_t *int_stack  = orig_hdrs + pkt_hdr_len;

    /* Fill IPv4 header (the collector's IP is the destination; we use
     * 0.0.0.0 as source because the report is sent via a connected UDP
     * socket whose source IP is chosen by the kernel). */
    ip->ip_ihl_ver  = IP_IHL_VER(5, 4);
    ip->ip_tos      = 0;
    ip->ip_tot_len  = htons((uint16_t)total_len);
    ip->ip_id       = 0;
    ip->ip_frag_off = htons(IP_DF);
    ip->ip_ttl      = 64;
    ip->ip_proto    = IPPROTO_UDP;
    put_16aligned_be32(&ip->ip_src, htonl(0));  /* kernel fills actual src */
    put_16aligned_be32(&ip->ip_dst, flow->nw_dst);
    ip->ip_csum     = ipv4_csum(ip);

    /* Fill UDP header. */
    udp->udp_src  = htons(INT_REPORT_SRC_PORT);
    udp->udp_dst  = htons(sink->options->collector_port
                          ? sink->options->collector_port
                          : INT_REPORT_SRC_PORT);
    udp->udp_len  = htons((uint16_t)(UDP_HEADER_LEN + payload_len));
    udp->udp_csum = 0;  /* optional for IPv4; fill after data is in place */

    /* Fill INT Report Fixed Header. */
    rpt->ver       = 1;
    rpt->len       = (uint8_t)(INT_REPORT_HDR_LEN / 4);
    rpt->rsvd      = 0;
    rpt->domain_id = htonl(0);
    rpt->seq_num   = htonl(sink->seq_num++);
    rpt->hw_id     = htonl(sink->options->switch_id);

    /* Fill INT Report Individual Header. */
    ind->report_type    = 1;  /* flow report */
    ind->rsvd           = 0;
    ind->in_port        = htons((uint16_t)flow->in_port.ofp_port);
    ind->eg_port        = 0;  /* not available at sink */
    ind->queue_id       = 0;
    ind->queue_occupancy = 0;

    /* Copy original packet headers and INT metadata stack. */
    memcpy(orig_hdrs, pkt_hdr, pkt_hdr_len);
    memcpy(int_stack, int_data, int_data_len);

    /* Compute UDP checksum over the payload. */
    udp->udp_csum = udp_csum_compute(get_16aligned_be32(&ip->ip_src),
                                     get_16aligned_be32(&ip->ip_dst),
                                     udp,
                                     rpt, payload_len);

    /* Send via the pre-connected UDP socket; kernel fills source IP/MAC. */
    ssize_t sent = send(sink->collector_fd, buf, total_len, 0);
    if (sent < 0) {
        VLOG_WARN_RL(&rl, "INT sink: send to collector failed: %s",
                     ovs_strerror(errno));
        /* Close the socket so dpif_int_sink_run() will reconnect. */
        dpif_int_sink_close_fd(sink);
    }

    free(buf);
}

/* -----------------------------------------------------------------------
 * Core packet-processing entry point
 * ----------------------------------------------------------------------- */

void
dpif_int_sink_process_packet(struct dpif_int_sink *sink,
                             struct dp_packet *packet,
                             const struct flow *flow)
{
    if (!dpif_int_sink_is_enabled(sink) || !packet) {
        return;
    }

    /* Only process UDP packets destined to the INT port. */
    if (flow->nw_proto != IPPROTO_UDP) {
        return;
    }
    if (ntohs(flow->tp_dst) != INT_DST_PORT) {
        return;
    }

    /* Locate the UDP payload, which should start with the INT shim. */
    struct udp_header *udp = dp_packet_l4(packet);
    if (!udp) {
        return;
    }
    size_t udp_hdr_len  = UDP_HEADER_LEN;
    size_t udp_tot_len  = ntohs(udp->udp_len);  /* UDP hdr + payload */
    if (udp_tot_len < udp_hdr_len + INT_SHIM_LEN + INT_MD_HDR_LEN) {
        return;  /* packet too short to carry INT headers */
    }

    uint8_t *udp_payload = (uint8_t *)udp + udp_hdr_len;
    size_t   payload_len = udp_tot_len - udp_hdr_len;

    /* Parse INT shim. */
    struct int_shim_hdr *shim = (struct int_shim_hdr *)udp_payload;
    if (shim->type != INT_SHIM_TYPE) {
        return;  /* not INT-MD */
    }

    /* 'shim->length' is the total INT data size in 4-byte words, including
     * the shim itself. */
    size_t int_total_bytes = (size_t)shim->length * 4;
    if (int_total_bytes < INT_SHIM_LEN + INT_MD_HDR_LEN) {
        return;  /* malformed */
    }
    if (int_total_bytes > payload_len) {
        return;  /* truncated */
    }

    /* Parse INT MD header. */
    struct int_md_hdr *md = (struct int_md_hdr *)(udp_payload + INT_SHIM_LEN);

    /* Validate hop metadata length (must be at least 1 word). */
    if (md->hop_metadata_len == 0) {
        return;
    }

    /* ----------------------------------------------------------------
     * Send the telemetry report to the collector.
     * ---------------------------------------------------------------- */

    /* Determine how many bytes of the original packet headers to include.
     * We include up to INT_REPORT_HDR_COPY_LEN bytes starting from the
     * Ethernet header. */
    const uint8_t *pkt_start = dp_packet_data(packet);
    size_t pkt_total        = dp_packet_size(packet);
    size_t copy_len = MIN(pkt_total, INT_REPORT_HDR_COPY_LEN);

    dpif_int_sink_send_report(sink,
                              pkt_start, copy_len,
                              udp_payload, int_total_bytes,
                              flow);

    /* ----------------------------------------------------------------
     * Strip the INT shim + MD + metadata from the packet in-place.
     *
     * We do a memmove to close the gap, then shrink the packet:
     *
     *   Before:  [ETH][IP][UDP hdr][INT shim+md+metadata][orig payload]
     *   After:   [ETH][IP][UDP hdr][orig payload]
     * ---------------------------------------------------------------- */
    uint8_t *int_start  = udp_payload;          /* first INT byte */
    uint8_t *payload_after_int = int_start + int_total_bytes;
    size_t   remaining_payload = payload_len - int_total_bytes;

    if (remaining_payload > 0) {
        memmove(int_start, payload_after_int, remaining_payload);
    }

    /* Shrink the packet. */
    size_t shrink = int_total_bytes;
    dp_packet_set_size(packet, dp_packet_size(packet) - shrink);

    /* Fix UDP length field. */
    udp->udp_len = htons((uint16_t)(ntohs(udp->udp_len) - shrink));

    /* Fix IPv4 total length and re-compute the IP checksum. */
    struct ip_header *ip = dp_packet_l3(packet);
    if (ip) {
        ip->ip_tot_len = htons(ntohs(ip->ip_tot_len) - (uint16_t)shrink);
        ip->ip_csum = 0;
        ip->ip_csum = csum_finish(csum_continue(0, ip, IP_HEADER_LEN));

        /* Re-compute UDP checksum if it was non-zero. */
        if (udp->udp_csum) {
            size_t udp_payload_len = ntohs(udp->udp_len) - UDP_HEADER_LEN;
            udp->udp_csum = 0;
            udp->udp_csum = udp_csum_compute(get_16aligned_be32(&ip->ip_src),
                                             get_16aligned_be32(&ip->ip_dst),
                                             udp,
                                             (uint8_t *)udp + UDP_HEADER_LEN,
                                             udp_payload_len);
        }
    }
}
