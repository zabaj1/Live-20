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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <live/live.h>

/**
 * @brief SR Live-Live policy rewrite trace
 */
typedef struct
{
  ip6_address_t src, dst;
  u32 flow;
  u16 seqnum;
  u8 type, length;
} sr_live_policy_rewrite_trace_t;

/* Graph arcs */
#define foreach_sr_live_policy_rewrite_next     \
_(IP6_LOOKUP, "ip6-lookup")         \
_(ERROR, "error-drop")

typedef enum
{
#define _(s,n) SR_LIVE_POLICY_REWRITE_NEXT_##s,
  foreach_sr_live_policy_rewrite_next
#undef _
    SR_LIVE_POLICY_REWRITE_N_NEXT,
} sr_live_policy_rewrite_next_t;

/* SR rewrite errors */
#define foreach_sr_live_policy_rewrite_error                     \
_(INTERNAL_ERROR, "Segment Routing undefined error")        \
_(BSID_ZERO, "BSID with SL = 0")                            \
_(COUNTER_TOTAL, "[Counter] SR live-live steered IPv6 packets")                 \
_(COUNTER_ENCAP, "SR: Encaps packets")                      \
_(COUNTER_INSERT, "SR: SRH inserted packets")               \
_(COUNTER_BSID, "SR: BindingSID steered packets")

typedef enum
{
#define _(sym,str) SR_LIVE_POLICY_REWRITE_ERROR_##sym,
  foreach_sr_live_policy_rewrite_error
#undef _
    SR_LIVE_POLICY_REWRITE_N_ERROR,
} sr_live_policy_rewrite_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *sr_live_policy_rewrite_error_strings[] = {
#define _(sym,string) string,
  foreach_sr_live_policy_rewrite_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

/*************************** SR rewrite graph node ****************************/
/**
 * @brief Trace for the SR live_policy Rewrite graph node
 */
static u8 *
format_sr_live_policy_rewrite_trace (u8 * s, va_list * args)
{
  //TODO
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sr_live_policy_rewrite_trace_t *t = va_arg (*args, sr_live_policy_rewrite_trace_t *);

  s = format
    (s, "SR live-live policy rewrite: src %U dst %U\n", format_ip6_address, &t->src, format_ip6_address, &t->dst);
  s = format
     (s, "  SRH Live-Live TLV: type %u, length %u, flow %u, sequence number %u", t->type, t->length, t->flow, t->seqnum);

  return s;
}

/**
 * @brief IPv6 encapsulation processing as per RFC2473
 */
static_always_inline void
encaps_processing_v6 (vlib_node_runtime_t * node,
          vlib_buffer_t * b0,
          ip6_header_t * ip0, ip6_header_t * ip0_encap)
{
  u32 new_l0;

  ip0_encap->hop_limit -= 1;
  new_l0 =
    ip0->payload_length + sizeof (ip6_header_t) +
    clib_net_to_host_u16 (ip0_encap->payload_length);
  ip0->payload_length = clib_host_to_net_u16 (new_l0);
  ip0->ip_version_traffic_class_and_flow_label =
    ip0_encap->ip_version_traffic_class_and_flow_label;
}

/**
 * @brief Graph node for applying a SR live_policy into an IPv6 packet. Encapsulation
 */
static uword
sr_live_policy_rewrite_encaps (vlib_main_t * vm, vlib_node_runtime_t * node,
        vlib_frame_t * from_frame)
{
  ip6_sr_main_t *sm = &sr_main;
  u32 n_left_from, next_index, *from, *to_next;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  int encap_pkts = 0, bsid_pkts = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
     
      /* Single loop */
      while (n_left_from > 0 && n_left_to_next > 0)
  {
    u32 bi0;
    vlib_buffer_t *b0;
    ip6_header_t *ip0 = 0, *ip0_encap = 0;
    ip6_sr_sl_t *sl0;
    u32 next0 = SR_LIVE_POLICY_REWRITE_NEXT_IP6_LOOKUP;

    live_tlv_t * live_tlv=0;
    ip6_sr_header_t *sr0=0;

    bi0 = from[0];
    to_next[0] = bi0;
    from += 1;
    to_next += 1;
    n_left_from -= 1;
    n_left_to_next -= 1;
    b0 = vlib_get_buffer (vm, bi0);

    sl0 =
      pool_elt_at_index (sm->sid_lists,
             vnet_buffer (b0)->ip.adj_index[VLIB_TX]);

    ASSERT (b0->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
      vec_len (sl0->rewrite));

    ip0_encap = vlib_buffer_get_current (b0);

    clib_memcpy (((u8 *) ip0_encap) - vec_len (sl0->rewrite),
           sl0->rewrite, vec_len (sl0->rewrite));
    vlib_buffer_advance (b0, -(word) vec_len (sl0->rewrite));

    ip0 = vlib_buffer_get_current (b0);

    sr0 = (ip6_sr_header_t *)(ip0+1);

    /* Pointer to the attached TLV */
    live_tlv = (live_tlv_t *)(&sr0->segments[sr0->segments_left] +1);
    /* Store the information from the vnet buffer to temporary variables */
    ip6_address_t sequence_num, flow_num;
    sequence_num.as_u32[3] = vnet_buffer(b0)->unused[2];
    flow_num.as_u32[3] = vnet_buffer(b0) -> unused[3];

    /* Copy information into the TLV */
    live_tlv->seqnum = clib_host_to_net_u16(sequence_num.as_u16[6]);
    live_tlv->flow = clib_host_to_net_u32(flow_num.as_u32[3]);

    encaps_processing_v6 (node, b0, ip0, ip0_encap);



    if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
        PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
      {
        sr_live_policy_rewrite_trace_t *tr =
    vlib_add_trace (vm, node, b0, sizeof (*tr));
        clib_memcpy (tr->src.as_u8, ip0->src_address.as_u8,
         sizeof (tr->src.as_u8));
        clib_memcpy (tr->dst.as_u8, ip0->dst_address.as_u8,
         sizeof (tr->dst.as_u8));
         tr->flow = clib_net_to_host_u32(live_tlv->flow);
         tr->seqnum = clib_net_to_host_u16(live_tlv->seqnum);
	       tr->type = live_tlv->type;
	       tr->length = live_tlv->length;
     }

    encap_pkts++;
    vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
             n_left_to_next, bi0, next0);
  }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Update counters */
  vlib_node_increment_counter (vm, sr_live_policy_rewrite_encaps_node.index,
             SR_LIVE_POLICY_REWRITE_ERROR_COUNTER_TOTAL,
             encap_pkts);
  vlib_node_increment_counter (vm, sr_live_policy_rewrite_encaps_node.index,
             SR_LIVE_POLICY_REWRITE_ERROR_COUNTER_BSID,
             bsid_pkts);

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (sr_live_policy_rewrite_encaps_node) = {
  .function = sr_live_policy_rewrite_encaps,
  .name = "sr-live-pl-rewrite-encaps",
  .vector_size = sizeof (u32),
  .format_trace = format_sr_live_policy_rewrite_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SR_LIVE_POLICY_REWRITE_N_ERROR,
  .error_strings = sr_live_policy_rewrite_error_strings,
  .n_next_nodes = SR_LIVE_POLICY_REWRITE_N_NEXT,
  .next_nodes = {
#define _(s,n) [SR_LIVE_POLICY_REWRITE_NEXT_##s] = n,
    foreach_sr_live_policy_rewrite_next
#undef _
  },
};
#endif /* CLIB_MARCH_VARIANT */
/* *INDENT-ON* */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
