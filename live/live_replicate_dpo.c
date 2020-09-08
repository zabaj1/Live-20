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
/**
 * @file
 * @brief live_replicate_dpo.c
 * 
 * Code related to the replicate_dpo.c 
 * @To see the difference search for ----> Live-Code
 * Need of flow classification before doing the replication
 * Need of using vlib opaque buffer to exchange information between VPP nodes
 */

#include <vnet/ip/lookup.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/receive_dpo.h>
#include <vnet/adj/adj.h>
#include <vnet/mpls/mpls_types.h>

#include <live/live.h>
#include <live/live_replicate_dpo.h>

#define foreach_live_replicate_dpo_error                       \
_(BUFFER_ALLOCATION_FAILURE, "Buffer Allocation Failure")

typedef enum {
#define _(sym,str) LIVE_REPLICATE_DPO_ERROR_##sym,
  foreach_live_replicate_dpo_error
#undef _
  LIVE_REPLICATE_DPO_N_ERROR,
} live_replicate_dpo_error_t;

static char * live_replicate_dpo_error_strings[] = {
#define _(sym,string) string,
  foreach_live_replicate_dpo_error
#undef _
};

/**
 * Pool of all DPOs. It's not static so the DP can have fast access
 */
live_replicate_t *live_replicate_pool;

dpo_type_t live_policy_dpo_type;

/**
 * The one instance of live_replicate main
 */
live_main_t live_main; //are we sure that this is the correct type?

static inline index_t
live_replicate_get_index (const live_replicate_t *rep)
{
    return (rep - live_replicate_pool);
}

static inline dpo_id_t*
live_replicate_get_buckets (live_replicate_t *rep)
{
    if (LIVE_REP_HAS_INLINE_BUCKETS(rep))
    {
        return (rep->rep_buckets_inline);
    }
    else
    {
        return (rep->rep_buckets);
    }
}

static live_replicate_t *
live_replicate_alloc_i (void)
{
    live_replicate_t *rep;

    pool_get_aligned(live_replicate_pool, rep, CLIB_CACHE_LINE_BYTES);
    clib_memset(rep, 0, sizeof(*rep));

    vlib_validate_combined_counter(&(live_main.repm_counters),
                                   live_replicate_get_index(rep));
    vlib_zero_combined_counter(&(live_main.repm_counters),
                               live_replicate_get_index(rep));

    return (rep);
}

static u8*
live_format_replicate_flags (u8 *s, va_list *args)
{
    int flags = va_arg (*args, int);

    if (flags == LIVE_REPLICATE_FLAGS_NONE)
    {
        s = format (s, "none");
    }
    else if (flags & LIVE_REPLICATE_FLAGS_HAS_LOCAL)
    {
        s = format (s, "has-local ");
    }

    return (s);
}

static u8*
live_replicate_format (index_t repi,
                  live_replicate_format_flags_t flags,
                  u32 indent,
                  u8 *s)
{
    vlib_counter_t to;
    live_replicate_t *rep;
    dpo_id_t *buckets;
    u32 i;

    repi &= ~MPLS_IS_REPLICATE;
    rep = live_replicate_get(repi);
    vlib_get_combined_counter(&(live_main.repm_counters), repi, &to);
    buckets = live_replicate_get_buckets(rep);

    s = format(s, "%U: ", format_dpo_type, live_policy_dpo_type);
    s = format(s, "[index:%d buckets:%d ", repi, rep->rep_n_buckets);
    s = format(s, "flags:[%U] ", live_format_replicate_flags, rep->rep_flags);
    s = format(s, "to:[%Ld:%Ld]]", to.packets, to.bytes);

    for (i = 0; i < rep->rep_n_buckets; i++)
    {
        s = format(s, "\n%U", format_white_space, indent+2);
        s = format(s, "[%d]", i);
        s = format(s, " %U", format_dpo_id, &buckets[i], indent+6);
    }
    return (s);
}

u8*
format_live_replicate (u8 * s, va_list * args)
{
    index_t repi = va_arg(*args, index_t);
    live_replicate_format_flags_t flags = va_arg(*args, live_replicate_format_flags_t);

    return (live_replicate_format(repi, flags, 0, s));
}
static u8*
format_live_replicate_dpo (u8 * s, va_list * args)
{
    index_t repi = va_arg(*args, index_t);
    u32 indent = va_arg(*args, u32);

    return (live_replicate_format(repi, LIVE_REPLICATE_FORMAT_DETAIL, indent, s));
}


static live_replicate_t *
live_replicate_create_i (u32 num_buckets,
                    dpo_proto_t rep_proto)
{
    live_replicate_t *rep;

    rep = live_replicate_alloc_i();
    rep->rep_n_buckets = num_buckets;
    rep->rep_proto = rep_proto;

    if (!LIVE_REP_HAS_INLINE_BUCKETS(rep))
    {
        vec_validate_aligned(rep->rep_buckets,
                             rep->rep_n_buckets - 1,
                             CLIB_CACHE_LINE_BYTES);
    }

    return (rep);
}

index_t
live_replicate_create (u32 n_buckets,
                  dpo_proto_t rep_proto)
{
    return (live_replicate_get_index(live_replicate_create_i(n_buckets, rep_proto)));
}

static inline void
live_replicate_set_bucket_i (live_replicate_t *rep,
                        u32 bucket,
                        dpo_id_t *buckets,
                        const dpo_id_t *next)
{
    if (dpo_is_receive(&buckets[bucket]))
    {
        rep->rep_flags &= ~LIVE_REPLICATE_FLAGS_HAS_LOCAL;
    }
    if (dpo_is_receive(next))
    {
        rep->rep_flags |= LIVE_REPLICATE_FLAGS_HAS_LOCAL;
    }
    dpo_stack(live_policy_dpo_type, rep->rep_proto, &buckets[bucket], next);
}

void
live_replicate_set_bucket (index_t repi,
                      u32 bucket,
                      const dpo_id_t *next)
{
    live_replicate_t *rep;
    dpo_id_t *buckets;

    repi &= ~MPLS_IS_REPLICATE;
    rep = live_replicate_get(repi);
    buckets = live_replicate_get_buckets(rep);

    ASSERT(bucket < rep->rep_n_buckets);

    live_replicate_set_bucket_i(rep, bucket, buckets, next);
}

int
live_replicate_is_drop (const dpo_id_t *dpo)
{
    live_replicate_t *rep;
    index_t repi;

    if (live_policy_dpo_type != dpo->dpoi_type)
        return (0);

    repi = dpo->dpoi_index & ~MPLS_IS_REPLICATE;
    rep = live_replicate_get(repi);

    if (1 == rep->rep_n_buckets)
    {
        return (dpo_is_drop(live_replicate_get_bucket_i(rep, 0)));
    }
    return (0);
}

const dpo_id_t *
live_replicate_get_bucket (index_t repi,
                      u32 bucket)
{
    live_replicate_t *rep;

    repi &= ~MPLS_IS_REPLICATE;
    rep = live_replicate_get(repi);

    return (live_replicate_get_bucket_i(rep, bucket));
}


static load_balance_path_t *
live_replicate_multipath_next_hop_fixup (load_balance_path_t *nhs,
                                    dpo_proto_t drop_proto)
{
    if (0 == vec_len(nhs))
    {
        load_balance_path_t *nh;

        /*
         * we need something for the live_replicate. so use the drop
         */
        vec_add2(nhs, nh, 1);

        nh->path_weight = 1;
        dpo_copy(&nh->path_dpo, drop_dpo_get(drop_proto));
    }

    return (nhs);
}

/*
 * Fill in adjacencies in block based on corresponding
 * next hop adjacencies.
 */
static void
live_replicate_fill_buckets (live_replicate_t *rep,
                        load_balance_path_t *nhs,
                        dpo_id_t *buckets,
                        u32 n_buckets)
{
    load_balance_path_t * nh;
    u16 bucket;

    bucket = 0;

    /*
     * the next-hops have normalised weights. that means their sum is the number
     * of buckets we need to fill.
     */
    vec_foreach (nh, nhs)
    {
        ASSERT(bucket < n_buckets);
        live_replicate_set_bucket_i(rep, bucket++, buckets, &nh->path_dpo);
    }
}

static inline void
live_replicate_set_n_buckets (live_replicate_t *rep,
                         u32 n_buckets)
{
    rep->rep_n_buckets = n_buckets;
}

void
live_replicate_multipath_update (const dpo_id_t *dpo,
                            load_balance_path_t * next_hops)
{
    load_balance_path_t * nh, * nhs;
    dpo_id_t *tmp_dpo;
    u32 ii, n_buckets;
    live_replicate_t *rep;
    index_t repi;

    ASSERT(live_policy_dpo_type == dpo->dpoi_type);
    repi = dpo->dpoi_index & ~MPLS_IS_REPLICATE;
    rep = live_replicate_get(repi);
    nhs = live_replicate_multipath_next_hop_fixup(next_hops,
                                             rep->rep_proto);
    n_buckets = vec_len(nhs);

    if (0 == rep->rep_n_buckets)
    {
        /*
         * first time initialisation. no packets inflight, so we can write
         * at leisure.
         */
        live_replicate_set_n_buckets(rep, n_buckets);

        if (!LIVE_REP_HAS_INLINE_BUCKETS(rep))
            vec_validate_aligned(rep->rep_buckets,
                                 rep->rep_n_buckets - 1,
                                 CLIB_CACHE_LINE_BYTES);

        live_replicate_fill_buckets(rep, nhs,
                               live_replicate_get_buckets(rep),
                               n_buckets);
    }
    else
    {
        /*
         * This is a modification of an existing live_replicate.
         * We need to ensure that packets in flight see a consistent state, that
         * is the number of reported buckets the REP has
         * is not more than it actually has. So if the
         * number of buckets is increasing, we must update the bucket array first,
         * then the reported number. vice-versa if the number of buckets goes down.
         */
        if (n_buckets == rep->rep_n_buckets)
        {
            /*
             * no change in the number of buckets. we can simply fill what
             * is new over what is old.
             */
            live_replicate_fill_buckets(rep, nhs,
                                   live_replicate_get_buckets(rep),
                                   n_buckets);
        }
        else if (n_buckets > rep->rep_n_buckets)
        {
            /*
             * we have more buckets. the old live_replicate map (if there is one)
             * will remain valid, i.e. mapping to indices within range, so we
             * update it last.
             */
            if (n_buckets > LIVE_REP_NUM_INLINE_BUCKETS &&
                rep->rep_n_buckets <= LIVE_REP_NUM_INLINE_BUCKETS)
            {
                /*
                 * the new increased number of buckets is crossing the threshold
                 * from the inline storage to out-line. Alloc the outline buckets
                 * first, then fixup the number. then reset the inlines.
                 */
                ASSERT(NULL == rep->rep_buckets);
                vec_validate_aligned(rep->rep_buckets,
                                     n_buckets - 1,
                                     CLIB_CACHE_LINE_BYTES);

                live_replicate_fill_buckets(rep, nhs,
                                       rep->rep_buckets,
                                       n_buckets);
                CLIB_MEMORY_BARRIER();
                live_replicate_set_n_buckets(rep, n_buckets);

                CLIB_MEMORY_BARRIER();

                for (ii = 0; ii < LIVE_REP_NUM_INLINE_BUCKETS; ii++)
                {
                    dpo_reset(&rep->rep_buckets_inline[ii]);
                }
            }
            else
            {
                if (n_buckets <= LIVE_REP_NUM_INLINE_BUCKETS)
                {
                    /*
                     * we are not crossing the threshold and it's still inline buckets.
                     * we can write the new on the old..
                     */
                    live_replicate_fill_buckets(rep, nhs,
                                           live_replicate_get_buckets(rep),
                                           n_buckets);
                    CLIB_MEMORY_BARRIER();
                    live_replicate_set_n_buckets(rep, n_buckets);
                }
                else
                {
                    /*
                     * we are not crossing the threshold. We need a new bucket array to
                     * hold the increased number of choices.
                     */
                    dpo_id_t *new_buckets, *old_buckets, *tmp_dpo;

                    new_buckets = NULL;
                    old_buckets = live_replicate_get_buckets(rep);

                    vec_validate_aligned(new_buckets,
                                         n_buckets - 1,
                                         CLIB_CACHE_LINE_BYTES);

                    live_replicate_fill_buckets(rep, nhs, new_buckets, n_buckets);
                    CLIB_MEMORY_BARRIER();
                    rep->rep_buckets = new_buckets;
                    CLIB_MEMORY_BARRIER();
                    live_replicate_set_n_buckets(rep, n_buckets);

                    vec_foreach(tmp_dpo, old_buckets)
                    {
                        dpo_reset(tmp_dpo);
                    }
                    vec_free(old_buckets);
                }
            }
        }
        else
        {
            /*
             * bucket size shrinkage.
             */
            if (n_buckets <= LIVE_REP_NUM_INLINE_BUCKETS &&
                rep->rep_n_buckets > LIVE_REP_NUM_INLINE_BUCKETS)
            {
                /*
                 * the new decreased number of buckets is crossing the threshold
                 * from out-line storage to inline:
                 *   1 - Fill the inline buckets,
                 *   2 - fixup the number (and this point the inline buckets are
                 *       used).
                 *   3 - free the outline buckets
                 */
                live_replicate_fill_buckets(rep, nhs,
                                       rep->rep_buckets_inline,
                                       n_buckets);
                CLIB_MEMORY_BARRIER();
                live_replicate_set_n_buckets(rep, n_buckets);
                CLIB_MEMORY_BARRIER();

                vec_foreach(tmp_dpo, rep->rep_buckets)
                {
                    dpo_reset(tmp_dpo);
                }
                vec_free(rep->rep_buckets);
            }
            else
            {
                /*
                 * not crossing the threshold.
                 *  1 - update the number to the smaller size
                 *  2 - write the new buckets
                 *  3 - reset those no longer used.
                 */
                dpo_id_t *buckets;
                u32 old_n_buckets;

                old_n_buckets = rep->rep_n_buckets;
                buckets = live_replicate_get_buckets(rep);

                live_replicate_set_n_buckets(rep, n_buckets);
                CLIB_MEMORY_BARRIER();

                live_replicate_fill_buckets(rep, nhs,
                                       buckets,
                                       n_buckets);

                for (ii = n_buckets; ii < old_n_buckets; ii++)
                {
                    dpo_reset(&buckets[ii]);
                }
            }
        }
    }

    vec_foreach (nh, nhs)
    {
        dpo_reset(&nh->path_dpo);
    }
    vec_free(nhs);
}

static void
live_replicate_lock (dpo_id_t *dpo)
{
    live_replicate_t *rep;

    rep = live_replicate_get(dpo->dpoi_index);

    rep->rep_locks++;
}

index_t
live_replicate_dup (live_replicate_flags_t flags,
               index_t repi)
{
    live_replicate_t *rep, *copy;

    rep = live_replicate_get(repi);

    if (rep->rep_flags == flags ||
        flags & LIVE_REPLICATE_FLAGS_HAS_LOCAL)
    {
        /*
         * we can include all the buckets from the original in the copy
         */
        return (repi);
    }
    else
    {
        /*
         * caller doesn't want the local paths that the original has
         */
        if (rep->rep_n_buckets == 1)
        {
            /*
             * original has only one bucket that is the local, so create
             * a new one with only the drop
             */
            copy = live_replicate_create_i (1, rep->rep_proto);

            live_replicate_set_bucket_i(copy, 0,
                                   live_replicate_get_buckets(copy),
                                   drop_dpo_get(rep->rep_proto));
        }
        else
        {
            dpo_id_t *old_buckets, *copy_buckets;
            u16 bucket, pos;

            copy = live_replicate_create_i(rep->rep_n_buckets - 1,
                                      rep->rep_proto);

            rep = live_replicate_get(repi);
            old_buckets = live_replicate_get_buckets(rep);
            copy_buckets = live_replicate_get_buckets(copy);
            pos = 0;

            for (bucket = 0; bucket < rep->rep_n_buckets; bucket++)
            {
                if (!dpo_is_receive(&old_buckets[bucket]))
                {
                    live_replicate_set_bucket_i(copy, pos, copy_buckets,
                                           (&old_buckets[bucket]));
                    pos++;
                }
            }
        }
    }

    return (live_replicate_get_index(copy));
}

static void
live_replicate_destroy (live_replicate_t *rep)
{
    dpo_id_t *buckets;
    int i;

    buckets = live_replicate_get_buckets(rep);

    for (i = 0; i < rep->rep_n_buckets; i++)
    {
        dpo_reset(&buckets[i]);
    }

    if (!LIVE_REP_HAS_INLINE_BUCKETS(rep))
    {
        vec_free(rep->rep_buckets);
    }

    pool_put(live_replicate_pool, rep);
}

static void
live_replicate_unlock (dpo_id_t *dpo)
{
    live_replicate_t *rep;

    rep = live_replicate_get(dpo->dpoi_index);

    rep->rep_locks--;

    if (0 == rep->rep_locks)
    {
        live_replicate_destroy(rep);
    }
}

static void
live_replicate_mem_show (void)
{
    fib_show_memory_usage("Live replicate",
			  pool_elts(live_replicate_pool),
			  pool_len(live_replicate_pool),
			  sizeof(live_replicate_t));
}

const static dpo_vft_t rep_vft = {
    .dv_lock = live_replicate_lock,
    .dv_unlock = live_replicate_unlock,
    .dv_format = format_live_replicate_dpo,
    .dv_mem_show = live_replicate_mem_show,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to a Live replicate
 *        object.
 *
 * this means that these graph nodes are ones from which a live_replicate is the
 * parent object in the DPO-graph.
 */
const static char* const live_replicate_ip6_nodes[] =
{
    "ip6-live-replicate",
    NULL,
};

const static char *const *const live_replicate_nodes[DPO_PROTO_NUM] =
{
	[DPO_PROTO_IP6] = live_replicate_ip6_nodes,
};

static clib_error_t *
live_replicate_module_init (vlib_main_t *vm)
{
    live_policy_dpo_type = dpo_register_new_type(&rep_vft, live_replicate_nodes);
    return (NULL);
}

VLIB_INIT_FUNCTION(live_replicate_module_init);

void
live_policy_dpo_set (dpo_id_t * dpo, dpo_proto_t proto, index_t index)
{
    live_replicate_t *rep;

    rep = live_replicate_alloc_i();

    rep->rep_proto = proto;

    dpo_set(dpo, live_policy_dpo_type, proto, index);
}

typedef struct live_replicate_trace_t_
{
    index_t rep_index;
    dpo_id_t dpo;
} live_replicate_trace_t;

always_inline u32
seq_to_u32 (u16 * seq)
{
  return (*((u32 *) seq) & 0xffff);
}


/* Live-Code: Function to set the Live-Live parameters */
static_always_inline void 
live_packet_processing (live_main_t * sm, vlib_buffer_t * b0)
{
      
  ip6_header_t *ip0;
  ASSERT (b0->current_data > 0);

  ip0 = vlib_buffer_get_current (b0);
    
  packet_identifier_t * current_packet =0;
  uword *g0 = 0;
  u32 flow_id0 =0;

  u16 *pointer_to_seq;
  u32 seq_n;
  
  /* Getting the packet's 5 tuple hash*/
  flow_id0 = ip6_compute_flow_hash(ip0, IP_FLOW_HASH_DEFAULT);

  /* Looking for existing flow index */
  g0 = mhash_get (&sm->flow_index_hash , &flow_id0);

  if (g0) 
  {
    /* pointer to the pkt_id pool at the index in g[0]*/
    current_packet = pool_elt_at_index(sm->pkt_id, g0[0]);
    /* Live-Code: Store the packet's FlowID and SeqNum 
                  in the vnet buffer (unusued bit of vnet_opaque_buffer)
    ------------  u32 unused[6] = Flow ID
    ------------  u32 unused[5] = 0000 and (u16) SeqNumber
    */
    vnet_buffer(b0) -> unused[3] = flow_id0;
    pointer_to_seq = &current_packet->sequence_number;
    seq_n = seq_to_u32(pointer_to_seq); 
    vnet_buffer(b0) -> unused[2] = seq_n;
    /* Increasing the sequence number */
    current_packet-> sequence_number+= 1; 
  }
  else
  {
    /* Allocation of memory  for the new packet_identifier_t */
    pool_get (sm-> pkt_id, current_packet);
    memset (current_packet, 0, sizeof(packet_identifier_t));
    /* Creating the new_packet_t */
    clib_memcpy (&current_packet->flow_ID, &flow_id0, sizeof(u32));
    /* Setting the sequence number to 1 */
    current_packet->sequence_number=1;
    /* Store the packet sequence number in the vnet buffer */
    /* unusued bit of vnet_opaque_buffer */
    vnet_buffer(b0) -> unused[3] = flow_id0;
    pointer_to_seq = &current_packet->sequence_number;
    seq_n = seq_to_u32(pointer_to_seq); 
    vnet_buffer(b0) -> unused[2] = seq_n;
    /* Increasing the sequence number */
    current_packet -> sequence_number+=1;
    /* Set the new hash */
    mhash_set (&sm->flow_index_hash, &current_packet->flow_ID, current_packet - sm->pkt_id ,
                  NULL);
  } 
}

static uword
live_replicate_inline (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
    vlib_combined_counter_main_t * cm = &live_main.repm_counters;
    live_main_t * rm = &live_main;
    u32 n_left_from, * from, * to_next, next_index;
    u32 thread_index = vlib_get_thread_index();

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;
  
    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame (vm, node, next_index,
                             to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
	{
            u32 next0, ci0, bi0, bucket, repi0;
            const live_replicate_t *rep0;
            vlib_buffer_t * b0, *c0;
            const dpo_id_t *dpo0;
	          u8 num_cloned;

            bi0 = from[0];
            from += 1;
            n_left_from -= 1;

            b0 = vlib_get_buffer (vm, bi0);
            /* Live-Code: before replication, Live-Live processing is needed */
            live_packet_processing(rm, b0);

            repi0 = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
            rep0 = live_replicate_get(repi0);

            vlib_increment_combined_counter(
                cm, thread_index, repi0, 1,
                vlib_buffer_length_in_chain(vm, b0));

	    vec_validate (rm->clones[thread_index], rep0->rep_n_buckets - 1);

	    num_cloned = vlib_buffer_clone (vm, bi0, rm->clones[thread_index],
                                            rep0->rep_n_buckets,
					    VLIB_BUFFER_CLONE_HEAD_SIZE);

	    if (num_cloned != rep0->rep_n_buckets)
	      {
		vlib_node_increment_counter
		  (vm, node->node_index,
		   LIVE_REPLICATE_DPO_ERROR_BUFFER_ALLOCATION_FAILURE, 1);
	      }

            for (bucket = 0; bucket < num_cloned; bucket++)
            {
                ci0 = rm->clones[thread_index][bucket];
                c0 = vlib_get_buffer(vm, ci0);

                to_next[0] = ci0;
                to_next += 1;
                n_left_to_next -= 1;

                dpo0 = live_replicate_get_bucket_i(rep0, bucket);
                next0 = dpo0->dpoi_next_node;
                vnet_buffer (c0)->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;

                if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
                {
                    live_replicate_trace_t *t;

                    if (c0 != b0)
		      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (c0);
                    t = vlib_add_trace (vm, node, c0, sizeof (*t));
                    t->rep_index = repi0;
                    t->dpo = *dpo0;
                }

                vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                                 to_next, n_left_to_next,
                                                 ci0, next0);
		if (PREDICT_FALSE (n_left_to_next == 0))
		  {
		    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
		    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
		  }
            }
	    vec_reset_length (rm->clones[thread_index]);
        }

        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    return frame->n_vectors;
}

static u8 *
format_live_replicate_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  live_replicate_trace_t *t = va_arg (*args, live_replicate_trace_t *);

  s = format (s, "Live replicate: %d via %U",
              t->rep_index,
              format_dpo_id, &t->dpo, 0);
  return s;
}

static uword
ip6_live_replicate (vlib_main_t * vm,
               vlib_node_runtime_t * node,
               vlib_frame_t * frame)
{
    return (live_replicate_inline (vm, node, frame));
}

/**
 * @brief IPv6 replication node
 */
VLIB_REGISTER_NODE (ip6_live_replicate_node) = {
  .function = ip6_live_replicate,
  .name = "ip6-live-replicate",
  .vector_size = sizeof (u32),

  .n_errors = ARRAY_LEN(live_replicate_dpo_error_strings),
  .error_strings = live_replicate_dpo_error_strings,

  .format_trace = format_live_replicate_trace,
  .n_next_nodes = 1,
  .next_nodes = {
      [0] = "ip6-drop",
  },
};