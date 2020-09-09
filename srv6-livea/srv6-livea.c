/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <srv6-livea/srv6-livea.h>
#include <vnet/srv6/sr.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

unsigned char function_name[] = "SRv6 Live-Live A localsid plugin";
unsigned char keyword_str[] = "live.a.dx6";
unsigned char def_str[] = "Live Live A: Decapsulation and IPv6 Xconnection";
unsigned char params_str[] = "nh <next-hop> oif <iface-out> ";

srv6_live_a_main_t srv6_live_a_main;

/*****************************************/
/* SRv6 LocalSID instantiation and removal functions */
static int
srv6_live_a_localsid_creation_fn (ip6_sr_localsid_t * localsid)
{
  srv6_live_a_localsid_t *ls_mem = localsid->plugin_mem;
 
  adj_index_t nh_adj_index = ADJ_INDEX_INVALID;

  /* Step 1: Prepare xconnect adjacency for sending packets to the VNF */

  /* Retrieve the adjacency corresponding to the (OIF, next_hop) */
  nh_adj_index = adj_nbr_add_or_lock (FIB_PROTOCOL_IP6,
				      VNET_LINK_IP6, &ls_mem->nh_addr,
				      ls_mem->sw_if_index_out);
  if (nh_adj_index == ADJ_INDEX_INVALID)
    return -5;

  localsid->nh_adj = nh_adj_index;

  return 0;
}

static int
srv6_live_a_localsid_removal_fn (ip6_sr_localsid_t * localsid)
{

  /* Unlock (OIF, NHOP) adjacency (from sr_localsid.c:103) */
  adj_unlock (localsid->nh_adj);

  /* Clean up local SID memory */
  clib_mem_free (localsid->plugin_mem);

  return 0;
}

/**********************************/
/* SRv6 LocalSID format functions */
/*
 * Prints nicely the parameters of a localsid
 * Example: print "Table 5"
 */
u8 *
format_srv6_live_a_localsid (u8 * s, va_list * args)
{
  srv6_live_a_localsid_t *ls_mem = va_arg (*args, void *);

  vnet_main_t *vnm = vnet_get_main ();

  return (format (s,
		  "Next-hop:\t%U\n"
		  "\tOutgoing iface: %U\n",
		  format_ip6_address, &ls_mem->nh_addr.ip6,
		  format_vnet_sw_if_index_name, vnm, ls_mem->sw_if_index_out));
}

/*
 * Process the parameters of a localsid
 * Example: process from:
 * sr localsid address cafe::1 behavior new_srv6_localsid 5
 * everything from behavior on... so in this case 'new_srv6_localsid 5'
 * Notice that it MUST match the keyword_str and params_str defined above.
 */
uword
unformat_srv6_live_a_localsid (unformat_input_t * input, va_list * args)
{
  void **plugin_mem_p = va_arg (*args, void **);
  srv6_live_a_localsid_t *ls_mem;

  vnet_main_t *vnm = vnet_get_main ();

  ip46_address_t nh_addr;
  u32 sw_if_index_out;

  if (unformat (input, "live.a.dx6 nh %U oif %U",
		unformat_ip6_address, &nh_addr.ip6,
		unformat_vnet_sw_interface, vnm, &sw_if_index_out))
    {
      /* Allocate a portion of memory */
      ls_mem = clib_mem_alloc_aligned_at_offset (sizeof *ls_mem, 0, 0, 1);

      /* Set to zero the memory */
      memset (ls_mem, 0, sizeof *ls_mem);

      /* Our brand-new car is ready */
      clib_memcpy (&ls_mem->nh_addr.ip6, &nh_addr.ip6,
		   sizeof (ip6_address_t));
      ls_mem->sw_if_index_out = sw_if_index_out;

      /* Dont forget to add it to the localsid */
      *plugin_mem_p = ls_mem;
      return 1;
    }
  return 0;
}

/*************************/
/* SRv6 LocalSID FIB DPO */
static u8 *
format_srv6_live_a_dpo (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "SR: live_a_decaps_localsid_index:[%u]", index));
}

void
srv6_live_a_dpo_lock (dpo_id_t * dpo)
{
}

void
srv6_live_a_dpo_unlock (dpo_id_t * dpo)
{
}

const static dpo_vft_t srv6_live_a_vft = {
  .dv_lock = srv6_live_a_dpo_lock,
  .dv_unlock = srv6_live_a_dpo_unlock,
  .dv_format = format_srv6_live_a_dpo,
};

const static char *const srv6_live_a_ip6_nodes[] = {
  "srv6-live-a-localsid",
  NULL,
};

const static char *const *const srv6_live_a_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = srv6_live_a_ip6_nodes,
};

/**********************/
static clib_error_t *
srv6_live_a_init (vlib_main_t * vm)
{
  srv6_live_a_main_t *sm = &srv6_live_a_main;
  int rv = 0;

  mhash_init (&sm->flow_index_hash_end, sizeof(uword), sizeof(u32));
  
  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  /* Create DPO */
  sm->srv6_live_a_dpo_type = dpo_register_new_type (&srv6_live_a_vft, srv6_live_a_nodes);

  /* Register SRv6 LocalSID */
  rv = sr_localsid_register_function (vm,
				      function_name,
				      keyword_str,
				      def_str,
				      params_str,
		              128, //prefix length (required for SRV6 Mobile)
				      &sm->srv6_live_a_dpo_type,
				      format_srv6_live_a_localsid,
				      unformat_srv6_live_a_localsid,
				      srv6_live_a_localsid_creation_fn,
				      srv6_live_a_localsid_removal_fn);
  if (rv < 0)
    clib_error_return (0, "SRv6 LocalSID function could not be registered.");
  else
    sm->srv6_localsid_behavior_id = rv;

  return 0;
}

VLIB_INIT_FUNCTION (srv6_live_a_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "SRv6 Live-Live A Localsid",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
