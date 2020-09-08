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
 * @brief SRv6 Live-Live Plugin, plugin API / trace / CLI handling.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/fib/ip6_fib.h>
#include <live/live.h>
#include <live/live_replicate_dpo.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message structures */
#define vl_typedefs
#include <live/live.api.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <live/live.api.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <live/live.api.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n, v) static u32 api_version = (v);
#include <live/live.api.h>
#undef vl_api_version

#include <vpp/app/version.h>
#include <stdbool.h>

#include <live/live.api_enum.h>
#include <live/live.api_types.h>

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* List of message types that this plugin understands */

#define foreach_live_plugin_api_msg \
  _ (LIVE_ENABLE_DISABLE, live_enable_disable)

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = LIVE_PLUGIN_BUILD_VER,
    .description = "SRv6 Live-Live Policy Plugin",
};
/* *INDENT-ON* */

live_main_t live_main;

static dpo_type_t sr_live_pr_encaps_dpo_type;

/**
 * @brief live-live rewrite computation  
 *
 * Function to modify the rewrite parameters computed 
 * for the SRv6 Encapsulation Policy
 */

static inline u8 *
live_compute_rewrite_encaps (u8 * rs)
{
 
  ip6_header_t *iph;
  ip6_sr_header_t *srh;
  live_tlv_t *live_tlv;

  /* Resize precompute vector */ 
  vec_resize (rs, sizeof(live_tlv_t));
  
  /* Adding live-live tlv size to IPv6 payload length field */
  iph = (ip6_header_t *)rs;
  iph->payload_length += sizeof(live_tlv_t);

  /* Adding live-live tlv size in octets to SRH length field 
   * live-live tlv size: 1 byte */
  srh = (ip6_sr_header_t *)(iph + 1);
  srh->length += sizeof(live_tlv_t)/8;

  /* Attach the TLV to the end of SL */
  live_tlv = (live_tlv_t *)(&srh->segments[srh->segments_left] +1);

  /* Type and Length of TLV accordingly to SRH TLV data structure. 
   * Flow ID and Sequence Number initialized to 0 */
  live_tlv-> type =2;
  live_tlv-> length =7;
  live_tlv-> flow =0;
  live_tlv-> seqnum =0;
  return rs;
}

int live_enable_disable (live_main_t * sm, ip6_address_t * bsid,
                                   int enable_disable)
{
  ip6_sr_main_t * srm = &sr_main;
   int rv = 0;
  ip6_sr_policy_t *policy;
  uword *p=0;
  u32 *sl_index;
  ip6_sr_sl_t *segment_list;
  load_balance_path_t path;
  path.path_index = FIB_NODE_INDEX_INVALID;
  load_balance_path_t *ip6_path_vector =0;

  p = mhash_get (&srm->sr_policies_index_hash, bsid);

  if(p==0)
	{ 
		rv = 1;
 		return rv;
	}
  
  /* Spray policy implementation with Live-Live features :
   * 1. Policy DPO to the Live-Live replication node
   * 2. SLs DPOs to the SRv6 Live-Live encapsulation node
  */

  /* Pointer to the existing policy that need to be Live-Live confiured */
  policy = pool_elt_at_index(srm->sr_policies, p[0]);
  /* Setting the live-live DPO */
  dpo_reset(&policy->ip6_dpo);
  live_policy_dpo_set (&policy->ip6_dpo, DPO_PROTO_IP6, policy - srm->sr_policies);

      fib_prefix_t pfx = {
  .fp_proto = FIB_PROTOCOL_IP6,
  .fp_len = 128,
  .fp_addr = {
        .ip6 = policy->bsid,
        }
      };

  /* Remove existing spray policy DPO from the FIB */  
  fib_table_entry_special_remove (srm->fib_table_ip6, &pfx, FIB_SOURCE_SR);
  /* Update FIB entry's DPO pointing the Live-Live processing node */
  fib_table_entry_special_dpo_update (srm->fib_table_ip6,
            &pfx,
            FIB_SOURCE_SR,
            FIB_ENTRY_FLAG_EXCLUSIVE,
            &policy->ip6_dpo);


  path.path_weight =1;
  vec_foreach (sl_index, policy->segments_lists)
  {
    segment_list =  pool_elt_at_index(srm->sid_lists, *sl_index);
    /* Modify the precompute size to Encap */
    segment_list->rewrite = live_compute_rewrite_encaps(segment_list->rewrite); 
    /* Change the SLs' DPO to the Live-Live encapsulation DPO */
    dpo_reset(&segment_list->ip6_dpo);
    dpo_set (&segment_list->ip6_dpo, sr_live_pr_encaps_dpo_type, DPO_PROTO_IP6,
         segment_list - srm->sid_lists);
    path.path_dpo = segment_list->ip6_dpo;
    vec_add1(ip6_path_vector, path);
  }

  /* Update Live-Live replicate multipath */
  live_replicate_multipath_update(&policy->ip6_dpo, ip6_path_vector);

  /* Setting the Live-Live policy type*/
  policy->type = SR_POLICY_TYPE_LIVE;
  /* Keep modified policy in the plugin*/
  sm->live_policy = policy;

  return rv;
}

static clib_error_t *
live_enable_disable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
live_main_t * sm = &live_main;
  ip6_address_t bsid;
  int enable_disable = 1;
  int b =0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "disable"))
      enable_disable = 0;
    else if (unformat (input, "bsid %U", unformat_ip6_address, &bsid))
      b=1;
    else
      break;
  }

  if (b==0)
    return clib_error_return (0, "Please specify bsid of the policy");
    
  rv = live_enable_disable (sm, &bsid, enable_disable);

  switch(rv) {
  case 0:
    break;

  case 1:
    return clib_error_return (0, "No policies matched with the bsid");
    break;  
  default:
    return clib_error_return (0, "live_enable_disable returned %d",
                              rv);
  }
  return 0;
}

VLIB_CLI_COMMAND (sr_content_command, static) = {
    .path = "live sr policy",
    .short_help = 
    "live sr policy bsid <bsid> [disable]",
    .function = live_enable_disable_command_fn,
};

/**
 * @brief SRv6 Live-Live Plugin API message handler.
 */
static void vl_api_live_enable_disable_t_handler
(vl_api_live_enable_disable_t * mp)
{
  vl_api_live_enable_disable_reply_t * rmp;
  live_main_t * sm = &live_main;
  int rv;

  rv = live_enable_disable (sm, (ip6_address_t *) & mp->sw_if_index, 
                                      (int) (mp->enable_disable));
  
  REPLY_MACRO(VL_API_LIVE_ENABLE_DISABLE_REPLY);
}

/**
 * @brief Set up the API message handling tables.
 */
static clib_error_t *live_plugin_api_hookup (vlib_main_t *vm)
{
  live_main_t *sm = &live_main;
#define _(N, n)                                                         \
  vl_msg_api_set_handlers ((VL_API_##N + sm->msg_id_base), #n,          \
                           vl_api_##n##_t_handler, vl_noop_handler,     \
                           vl_api_##n##_t_endian, vl_api_##n##_t_print, \
                           sizeof (vl_api_##n##_t), 1);
  foreach_live_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <live/live.api.h>
#undef vl_msg_name_crc_list

static void setup_message_id_table (live_main_t *sm, api_main_t *am)
{
#define _(id, n, crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_live;
#undef _
}

/* Format for SLs DPO (same as defined in srv6 node) */
static u8 *
format_sr_live_segment_list_dpo (u8 * s, va_list * args)
{
  ip6_sr_main_t *sm = &sr_main;
  ip6_address_t *addr;
  ip6_sr_sl_t *sl;

  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);
  s = format (s, "SR: Segment List index:[%d]", index);
  s = format (s, "\n\tSegments:");

  sl = pool_elt_at_index (sm->sid_lists, index);

  s = format (s, "< ");
  vec_foreach (addr, sl->segments)
  {
    s = format (s, "%U, ", format_ip6_address, addr);
  }
  s = format (s, "\b\b > - ");
  s = format (s, "Weight: %u", sl->weight);

  return s;
}

void
sr_live_dpo_lock (dpo_id_t * dpo)
{
}

void
sr_live_dpo_unlock (dpo_id_t * dpo)
{
}

const static dpo_vft_t sr_live_policy_rewrite_vft = {
  .dv_lock = sr_live_dpo_lock,
  .dv_unlock = sr_live_dpo_unlock,
  .dv_format = format_sr_live_segment_list_dpo,
};

const static char *const sr_live_pr_encaps_ip6_nodes[] = {
  "sr-live-pl-rewrite-encaps",
  NULL,
};

const static char *const *const sr_live_pr_encaps_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = sr_live_pr_encaps_ip6_nodes,
};

/**
 * @brief Initialize the SRv6 Live-Live plugin.
 */
static clib_error_t * live_init (vlib_main_t * vm)
{
  live_main_t * sm = &live_main;
  clib_error_t * error = 0;
  u8 * name;

  vec_validate (sm->clones, vlib_num_workers());

  mhash_init(&sm->flow_index_hash, sizeof(uword), sizeof(u32));

  sr_live_pr_encaps_dpo_type =
    dpo_register_new_type (&sr_live_policy_rewrite_vft, sr_live_pr_encaps_nodes);

  sm->vnet_main =  vnet_get_main ();

  name = format (0, "live_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  sm->msg_id_base = vl_msg_api_get_msg_ids 
      ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = live_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  api_main_t *api_main = vlibapi_get_main();
  setup_message_id_table (sm, api_main);

  vec_free(name);

  return error;
}

VLIB_INIT_FUNCTION (live_init);

/**
 * @brief Hook the Live-Live plugin into the VPP graph hierarchy.
 */
VNET_FEATURE_INIT (live, static) = 
{
  .arc_name = "ip6-unicast",
  .node_name = "live",
  .runs_before =0,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
