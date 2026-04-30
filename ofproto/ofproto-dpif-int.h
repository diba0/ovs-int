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

#ifndef OFPROTO_DPIF_INT_H
#define OFPROTO_DPIF_INT_H 1

#include <stdint.h>
#include <stdbool.h>

struct dp_packet;
struct flow;

/* Configuration options for the INT sink.
 *
 * These are typically read from the bridge's other_config map, e.g.
 *   ovs-vsctl set bridge br0 \
 *       other_config:int-sink-collector-ip=192.168.1.100 \
 *       other_config:int-sink-collector-port=32766 \
 *       other_config:int-sink-switch-id=1
 */
struct dpif_int_sink_options {
    char    *collector_ip;    /* IP address of the telemetry collector. */
    uint16_t collector_port;  /* UDP port of the telemetry collector. */
    uint32_t switch_id;       /* Switch identifier included in reports. */
};

struct dpif_int_sink *dpif_int_sink_create(void);
struct dpif_int_sink *dpif_int_sink_ref(const struct dpif_int_sink *);
void dpif_int_sink_unref(struct dpif_int_sink *);

bool dpif_int_sink_is_enabled(const struct dpif_int_sink *);

/* Set or clear the INT-sink configuration.  Passing NULL disables the sink. */
void dpif_int_sink_set_options(struct dpif_int_sink *,
                               const struct dpif_int_sink_options *);

void dpif_int_sink_run(struct dpif_int_sink *);
void dpif_int_sink_wait(struct dpif_int_sink *);

/* Core processing entry point.
 *
 * Examines 'packet' (described by 'flow') for an INT shim header.  If one is
 * found, the function:
 *   1. Parses the INT metadata stack.
 *   2. Sends a telemetry report UDP datagram to the configured collector.
 *   3. Strips the INT shim and metadata from 'packet' in-place and fixes the
 *      IP/UDP length and checksum fields so that the cleaned packet can be
 *      forwarded normally.
 *
 * 'packet' must be a mutable copy (i.e. not the original upcall buffer).
 * If 'packet' is NULL, or the sink is not enabled, the function is a no-op.
 */
void dpif_int_sink_process_packet(struct dpif_int_sink *,
                                  struct dp_packet *packet,
                                  const struct flow *);

#endif /* ofproto/ofproto-dpif-int.h */
