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
#ifndef __LIVE_REPLICATE_DPO_H__
#define __LIVE_REPLICATE_DPO_H__

#include <vlib/vlib.h>
#include <vnet/ip/lookup.h>
#include <vnet/dpo/dpo.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/fib_types.h>
#include <vnet/mpls/mpls_types.h>



/**
 * The number of buckets that a load-balance object can have and still
 * fit in one cache-line
 */
#define LIVE_REP_NUM_INLINE_BUCKETS 4

/**
 * The FIB DPO provieds;
 *  - load-balancing over the next DPOs in the chain/graph
 *  - per-route counters
 */
typedef struct live_replicate_t_ {
    /**
     * required for pool_get_aligned.
     *  memebers used in the switch path come first!
     */
    CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);

    /**
     * number of buckets in the live_replicate.
     */
    u16 rep_n_buckets;

   /**
     * The protocol of packets that traverse this REP.
     * need in combination with the flow hash config to determine how to hash.
     * u8.
     */
    dpo_proto_t rep_proto;

    /**
     * The number of locks, which is approximately the number of users,
     * of this load-balance.
     * Load-balance objects of via-entries are heavily shared by recursives,
     * so the lock count is a u32.
     */
    u32 rep_locks;

    /**
     * Vector of buckets containing the next DPOs, sized as repo_num
     */
    dpo_id_t *rep_buckets;

    /**
     * The rest of the cache line is used for buckets. In the common case
     * where there there are less than 4 buckets, then the buckets are
     * on the same cachlie and we save ourselves a pointer dereferance in 
     * the data-path.
     */
    dpo_id_t rep_buckets_inline[LIVE_REP_NUM_INLINE_BUCKETS];
} live_replicate_t;

STATIC_ASSERT(sizeof(live_replicate_t) <= CLIB_CACHE_LINE_BYTES,
	      "A live replicate object size exceeds one cachline");

/**
 * Flags controlling load-balance formatting/display
 */
typedef enum live_replicate_format_flags_t_ {
    LIVE_REPLICATE_FORMAT_NONE,
    LIVE_REPLICATE_FORMAT_DETAIL = (1 << 0),
} live_replicate_format_flags_t;

extern index_t live_replicate_create(u32 num_buckets,
                                dpo_proto_t rep_proto);
extern void live_replicate_multipath_update(
    const dpo_id_t *dpo,
    load_balance_path_t *next_hops);

extern void live_replicate_set_bucket(index_t repi,
                                 u32 bucket,
                                 const dpo_id_t *next);
extern void live_policy_dpo_set ( dpo_id_t * dpo,
				   dpo_proto_t	proto,
				   index_t index);

extern u8* format_live_replicate(u8 * s, va_list * args);

extern const dpo_id_t *live_replicate_get_bucket(index_t repi,
                                            u32 bucket);
extern int live_replicate_is_drop(const dpo_id_t *dpo);

extern u16 live_replicate_n_buckets(index_t repi);

/**
 * The encapsulation breakages are for fast DP access
 */
extern live_replicate_t *live_replicate_pool;
static inline live_replicate_t*
live_replicate_get (index_t repi)
{
    repi &= ~MPLS_IS_REPLICATE;
    return (pool_elt_at_index(live_replicate_pool, repi));
}

#define LIVE_REP_HAS_INLINE_BUCKETS(_rep)		\
    ((_rep)->rep_n_buckets <= LIVE_REP_NUM_INLINE_BUCKETS)

static inline const dpo_id_t *
live_replicate_get_bucket_i (const live_replicate_t *rep,
			   u32 bucket)
{
    ASSERT(bucket < rep->rep_n_buckets);

    if (PREDICT_TRUE(LIVE_REP_HAS_INLINE_BUCKETS(rep)))
    {
	return (&rep->rep_buckets_inline[bucket]);
    }
    else
    {
	return (&rep->rep_buckets[bucket]);
    }
}



#endif /* __included_live_h__ */
