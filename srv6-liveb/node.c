/*
 * node.c - skeleton vpp engine plug-in dual-loop node skeleton
 *
 * Copyright (c) <current-year> <your-organization>
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
#include <srv6-liveb/srv6-liveb.h>
#include <vnet/srv6/sr.h>

typedef struct {
  u32 localsid_index;
  u32 flow_id;
  u16 seq_num;
  u16 last;
} srv6_live_b_localsid_trace_t;

#ifndef CLIB_MARCH_VARIANT

/* packet trace format function */
static u8 * format_srv6_live_b_localsid_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srv6_live_b_localsid_trace_t * t = va_arg (*args, srv6_live_b_localsid_trace_t *);
  s = format (s, "SRv6 Live-Live b localsid: localsid_index %d\n  SRH TLV -> flow: %u, sequence number: %u\n  Live-Live b sliding window -> greatest delivered : %u",
              t->localsid_index, t->flow_id, t->seq_num, t->last);
  return s;
}

vlib_node_registration_t srv6_live_b_localsid_node;

#define foreach_srv6_live_b_localsid_counter \
_(PROCESSED, "srv6-live-live-b-localsid processed packets") \
_(NO_INNER_HEADER, "(SR-Error) No inner IP header")   \
_(NO_LS, "(Error) No Last SID (Segments Left >0)") \
_(DUPLICATE, "(Drop) Duplicate suppression") \
_(OUT_LEFT, "(Drop) Late packet out of the window from the left") \
_(NO_SRH, "(Error) No SRH.")

#endif /* CLIB_MARCH_VARIANT */

typedef enum {
#define _(sym,str) SRV6_LIVE_B_LOCALSID_COUNTER_##sym,
  foreach_srv6_live_b_localsid_counter
#undef _
  SRV6_LIVE_B_LOCALSID_N_COUNTERS,
} srv6_live_b_localsid_counters;

#ifndef CLIB_MARCH_VARIANT
static char * srv6_live_b_localsid_counter_strings[] = {
#define _(sym,string) string,
  foreach_srv6_live_b_localsid_counter
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum {
  SRV6_LIVE_B_LOCALSID_NEXT_ERROR,
  SRV6_LIVE_B_LOCALSID_NEXT_IP6_REWRITE,
  SRV6_LIVE_B_LOCALSID_N_NEXT,
} srv6_live_b_localsid_next_t;

/**
 * @brief Function doing End processing.
 */
static_always_inline void
end_decaps_srh_processing (vlib_main_t *vm, vlib_node_runtime_t * node,
         vlib_buffer_t * b0,
         ip6_header_t * ip0,
         ip6_sr_header_t * sr0,
         ip6_sr_localsid_t * ls0, u32 * next0, u32 * packet_flow_id, u16 * packet_sequence_number, u16 * last)
{
  /* Compute the size of the IPv6 header with all Ext. headers */
  u8 next_proto;
  ip6_ext_header_t *next_ext_header;
  u16 total_size = 0;

  next_proto = ip0->protocol;
  next_ext_header = (void *) (ip0 + 1);
  total_size = sizeof (ip6_header_t);
  while (ip6_ext_hdr (next_proto))
    {
      total_size += ip6_ext_header_len (next_ext_header);
      next_proto = next_ext_header->next_hdr;
      next_ext_header = ip6_ext_next_header (next_ext_header);
    }

  /* Ensure this is the last segment. Otherwise drop. */
  if (sr0 && sr0->segments_left != 0)
    {
      *next0 = SRV6_LIVE_B_LOCALSID_NEXT_ERROR;
      b0->error = node->errors[SRV6_LIVE_B_LOCALSID_COUNTER_NO_LS];
      return;
    }

  if (next_proto == IP_PROTOCOL_IPV6)
    {
      
      srv6_live_b_main_t *sm = &srv6_live_b_main;

      live_tlv_t * live_tlv=0;
      ip6_address_t * sids =0;
      uword *p=0;
      /* Live-Live B window */
      fixed_window_t *flow_window =0;
      
      /* Live-Live B variables*/
      int difference ;
      u64 variable_to_check=0;
      u16 window_length = 64;

      /* Pointer to the TLV */
      sids = sr0->segments + (sr0->first_segment);
      live_tlv = (live_tlv_t *) (sids + 1);
      /* Pointer to the flowID in the SID of arrived packet */      
      *packet_flow_id = clib_net_to_host_u32(live_tlv->flow);
      
      /* Checking wheter the Window flowID already exists in memory */
      p = mhash_get (&sm->flow_window_hash, packet_flow_id);

      if (p) /* Already managing the flow */
      {
        /* Pointer to the flow window */
        flow_window = pool_elt_at_index (sm-> packet_window, p[0]);
        /* Pointer to the sequence number */
        *packet_sequence_number = clib_net_to_host_u16(live_tlv->seqnum);
        /* If the sequence number (arrived packet) is smaller than the first sequence 
           number stored in the window */
        if (*packet_sequence_number < (flow_window->last_delivered - window_length))
          {
              /* Drop packet because it has arrived too late respect the time window*/
              *next0 = SRV6_LIVE_B_LOCALSID_NEXT_ERROR; /* drop packet: B solution */
              b0->error = node->errors[SRV6_LIVE_B_LOCALSID_COUNTER_OUT_LEFT]; /*add error livetpoliveB in control plane*/
              *last = flow_window->last_delivered;
	  }
        /* If the sequence number (arrived packet) is smaller than the last delivered -- the packet is inside the window */
        else if (*packet_sequence_number <= flow_window->last_delivered)
        {

            /* variable used to check the value of bits */
              variable_to_check = 0x00;
              /* Distance between the packet sequence number and the last delivered */
              difference = flow_window->last_delivered - *packet_sequence_number;
              /* Set the last bit of the variable to 1 */
              variable_to_check = variable_to_check | 0x01;
              /* Move to the left the last bit up to the relative position inside the window */
              variable_to_check = variable_to_check << difference;
              /* AND between the window and the variable: the variable is made of all 0s except 
                 the relative bit inside the window that represents the packet */     
              if (flow_window->delivered & variable_to_check)
              {
                /* Already delivered the packet of that sequence number: this is the replica */
                *next0 = SRV6_LIVE_B_LOCALSID_NEXT_ERROR; /* drop packet: B solution */
                  b0->error = node->errors[SRV6_LIVE_B_LOCALSID_COUNTER_DUPLICATE]; /*add error livetpoliveA in control plane*/
                }
            else
            {
              /* Haven't delivered the packet yet */
              /* OR between the window and the variable: it changes only the bit in the relative position
                 inside the window */
              flow_window->delivered = flow_window->delivered | variable_to_check;
              vlib_buffer_advance (b0, total_size);
              vnet_buffer (b0)->ip.adj_index[VLIB_TX] = ls0->nh_adj;
            }
            *last = flow_window->last_delivered;
	}
        else 
        {
          /* The packet sequence number is greater than the last delivered */
          /* Distance between the packet sequence number and the last delivered */
          difference = *packet_sequence_number - flow_window->last_delivered;
          /* Move the sliding window to the left: the last bit must be the last arrived packet */

          flow_window-> delivered = flow_window->delivered << difference;
          /* Fix the last bit to 1 because is the packet being processed */
          flow_window-> delivered = (flow_window->delivered) | 0x01;
          /* Update the last delivered */
          flow_window-> last_delivered = *packet_sequence_number;
          *last = *packet_sequence_number;
          vlib_buffer_advance (b0, total_size);
          vnet_buffer (b0)->ip.adj_index[VLIB_TX] = ls0->nh_adj;
        }
    

      return;

      }
      else
      {
        /* Creating new window structure */
        pool_get (sm->packet_window, flow_window);
        memset (flow_window, 0, sizeof(fixed_window_t));
        clib_memcpy(&flow_window->flow_id, packet_flow_id, sizeof(u32));

        *packet_sequence_number = clib_net_to_host_u16(live_tlv->seqnum);
        /* New time window */
        flow_window->delivered = 0x01;
        /* First and last packet delivered */
        flow_window->last_delivered=*packet_sequence_number;
	      *last = *packet_sequence_number; 
	      /* Set the hash */
        mhash_set (&sm->flow_window_hash, &flow_window->flow_id,
          flow_window - sm->packet_window, NULL);

        vlib_buffer_advance (b0, total_size);
        vnet_buffer (b0)->ip.adj_index[VLIB_TX] = ls0->nh_adj;


          return;
       }
  }
    
  *next0 = SRV6_LIVE_B_LOCALSID_NEXT_ERROR;
  b0->error = node->errors[SRV6_LIVE_B_LOCALSID_COUNTER_NO_INNER_HEADER];
  return;
}

/*
 * @brief SRv6 Live-Live B Localsid graph node
 * WARNING: YOU MUST DO THE DUAL LOOP
 */
static uword
srv6_live_b_localsid_fn (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  u32 next_index;
  u32 pkts_swapped = 0;
  
  ip6_sr_main_t * sm = &sr_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  u32 thread_index = vlib_get_thread_index ();

  while (n_left_from > 0)
  {
    u32 n_left_to_next;

    vlib_get_next_frame (vm, node, next_index,
       to_next, n_left_to_next);

    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 bi0;
      vlib_buffer_t * b0;
      ip6_header_t * ip0 = 0;
      ip6_sr_header_t * sr0;
      ip6_ext_header_t *prev0;
      u32 next0 = SRV6_LIVE_B_LOCALSID_NEXT_IP6_REWRITE;
      ip6_sr_localsid_t *ls0;
      
      u32 packet_flow_id;
      u16 packet_sequence_number;
      u16 last;

      bi0 = from[0];
      to_next[0] = bi0;
      from += 1;
      to_next += 1;
      n_left_from -= 1;
      n_left_to_next -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      ip0 = vlib_buffer_get_current (b0);
      sr0 = (ip6_sr_header_t *)(ip0+1);

      /* Lookup the SR End behavior based on IP DA (adj) */
      ls0 = pool_elt_at_index (sm->localsids, vnet_buffer(b0)->ip.adj_index[VLIB_TX]);
      

      /* SRH processing */
      ip6_ext_header_find_t (ip0, prev0, sr0, IP_PROTOCOL_IPV6_ROUTE);
      end_decaps_srh_processing (vm, node, b0, ip0, sr0, ls0, &next0, &packet_flow_id, &packet_sequence_number, &last);

      
      if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
      {
        srv6_live_b_localsid_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
        tr->localsid_index = ls0 - sm->localsids;
        tr->flow_id = packet_flow_id ;
        tr->seq_num = packet_sequence_number;
        tr->last = last;
      }

      /* This increments the SRv6 per LocalSID counters.*/
      vlib_increment_combined_counter
        (((next0 == SRV6_LIVE_B_LOCALSID_NEXT_ERROR) ? &(sm->sr_ls_invalid_counters) : &(sm->sr_ls_valid_counters)),
        thread_index,
        ls0 - sm->localsids,
        1, vlib_buffer_length_in_chain (vm, b0));

      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, 
        n_left_to_next, bi0, next0);

      pkts_swapped ++;
    }
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  }

  return frame->n_vectors;
}/*
 * @brief SRv6 Live-Live B Localsid graph node
 * WARNING: YOU MUST DO THE DUAL LOOP
 */
static uword
srv6_live_b_localsid_fn (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  u32 next_index;
  u32 pkts_swapped = 0;
  
  ip6_sr_main_t * sm = &sr_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  u32 thread_index = vlib_get_thread_index ();

  while (n_left_from > 0)
  {
    u32 n_left_to_next;

    vlib_get_next_frame (vm, node, next_index,
       to_next, n_left_to_next);

    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 bi0;
      vlib_buffer_t * b0;
      ip6_header_t * ip0 = 0;
      ip6_sr_header_t * sr0;
      ip6_ext_header_t *prev0;
      u32 next0 = SRV6_LIVE_B_LOCALSID_NEXT_IP6_REWRITE;
      ip6_sr_localsid_t *ls0;
      
      u32 packet_flow_id;
      u16 packet_sequence_number;
      u16 last;

      bi0 = from[0];
      to_next[0] = bi0;
      from += 1;
      to_next += 1;
      n_left_from -= 1;
      n_left_to_next -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      ip0 = vlib_buffer_get_current (b0);
      sr0 = (ip6_sr_header_t *)(ip0+1);

      /* Lookup the SR End behavior based on IP DA (adj) */
      ls0 = pool_elt_at_index (sm->localsids, vnet_buffer(b0)->ip.adj_index[VLIB_TX]);
      

      /* SRH processing */
      ip6_ext_header_find_t (ip0, prev0, sr0, IP_PROTOCOL_IPV6_ROUTE);
      end_decaps_srh_processing (vm, node, b0, ip0, sr0, ls0, &next0, &packet_flow_id, &packet_sequence_number, &last);

      
      if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
      {
        srv6_live_b_localsid_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
        tr->localsid_index = ls0 - sm->localsids;
        tr->flow_id = packet_flow_id ;
        tr->seq_num = packet_sequence_number;
        tr->last = last;
      }

      /* This increments the SRv6 per LocalSID counters.*/
      vlib_increment_combined_counter
        (((next0 == SRV6_LIVE_B_LOCALSID_NEXT_ERROR) ? &(sm->sr_ls_invalid_counters) : &(sm->sr_ls_valid_counters)),
        thread_index,
        ls0 - sm->localsids,
        1, vlib_buffer_length_in_chain (vm, b0));

      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, 
        n_left_to_next, bi0, next0);

      pkts_swapped ++;
    }
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (srv6_live_b_localsid_node) = {
  .function = srv6_live_b_localsid_fn,
  .name = "srv6-live-b-localsid",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_live_b_localsid_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SRV6_LIVE_B_LOCALSID_N_COUNTERS,
  .error_strings = srv6_live_b_localsid_counter_strings,
  .n_next_nodes = SRV6_LIVE_B_LOCALSID_N_NEXT,
  .next_nodes = {
        [SRV6_LIVE_B_LOCALSID_NEXT_IP6_REWRITE] = "ip6-rewrite",
        [SRV6_LIVE_B_LOCALSID_NEXT_ERROR] = "error-drop",
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
