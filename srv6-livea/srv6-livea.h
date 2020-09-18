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
#ifndef __included_srv6_livea_h__
#define __included_srv6_livea_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

typedef struct
{
   u32 flow_id_end;             /* Flow ID */

   u16 sequence_number_end;         /* number of packets */

   clib_spinlock_t lock;

}  packet_identifier_end_t;

typedef struct
{
  /*Pool of packets' classification--End.Live*/
    packet_identifier_end_t *pkt_id_end;

    /* Hash table mapping arrived new Flow-- End.Live*/
    mhash_t flow_index_hash_end;


  u16 msg_id_base;        /**< API message ID base */

  vlib_main_t *vlib_main;     /**< [convenience] vlib main */
  vnet_main_t *vnet_main;     /**< [convenience] vnet main */

  clib_spinlock_t flow_lock; /*Lock used to prevent double operation for a new incoming flow*/

  dpo_type_t srv6_live_a_dpo_type;    /**< DPO type */

  u32 srv6_localsid_behavior_id;  /**< SRv6 LocalSID behavior number */

} srv6_live_a_main_t;

/*
 * This is the memory that will be stored per each localsid
 * the user instantiates
 */
typedef struct
{
  ip46_address_t nh_addr;       /**< Proxied device address */
  u32 sw_if_index_out;                      /**< Outgoing iface to proxied device */
  int live;
} srv6_live_a_localsid_t;

extern srv6_live_a_main_t srv6_live_a_main;

format_function_t format_srv6_live_a_localsid;
unformat_function_t unformat_srv6_live_a_localsid;

void srv6_live_a_dpo_lock (dpo_id_t * dpo);
void srv6_live_a_dpo_unlock (dpo_id_t * dpo);

extern vlib_node_registration_t srv6_live_a_localsid_node;

#endif /* __included_srv6_livea_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

