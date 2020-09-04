/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef __included_live_h__
#define __included_live_h__

#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/srv6/sr.h>


#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>


typedef struct
{
   /* Packet's flow ID */
   u32 flow_ID;		        
   /* Packet's sequence number */
   u16 sequence_number;         

}  packet_identifier_t;

typedef struct {
    
    vlib_combined_counter_main_t repm_counters;

    u32 **clones;

    /* Pool of packets'classification-- SRv6 Live-Live Policy */
    packet_identifier_t *pkt_id;

    /* Hash table mapping new flow to existing FlowID-- SRv6 Live-Live Policy */
    mhash_t  flow_index_hash;
    
    /* API message ID base */
    u16 msg_id_base;

    ip6_sr_policy_t * live_policy;

    /* convenience */
    vnet_main_t * vnet_main;
} live_main_t;

extern live_main_t live_main;

extern vlib_node_registration_t sr_live_policy_rewrite_encaps_node;

#define LIVE_PLUGIN_BUILD_VER "1.0"

#endif /* __included_live_h__ */
