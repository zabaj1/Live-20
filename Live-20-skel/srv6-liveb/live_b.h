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
#ifndef __included_srv6_live_b_h__
#define __included_srv6_live_b_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/srv6/sr.h>
#include <vnet/srv6/sr_packet.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>



/* Fixed window*/
typedef struct {

    u32 flow_id; /* Flow ID*/

    u64 delivered; /* 64 bits used as boolean window: 1/0 to store is packet in that position has been delivered */

    u16 last_delivered; /* Last packet delivered */

} fixed_window_t;



typedef struct
{
  /*Pool of packets' sliding window--End.LiveB*/

    fixed_window_t *packet_window;

    /* Hash table mapping Flow window-- End.LiveB*/
    mhash_t flow_window_hash;



  u16 msg_id_base;        /**< API message ID base */

  vlib_main_t *vlib_main;     /**< [convenience] vlib main */
  vnet_main_t *vnet_main;     /**< [convenience] vnet main */

  dpo_type_t srv6_live_b_dpo_type;    /**< DPO type */

  u32 srv6_localsid_behavior_id;  /**< SRv6 LocalSID behavior number */
} srv6_live_b_main_t;

/*
 * This is the memory that will be stored per each localsid
 * the user instantiates
 */
typedef struct
{
  ip46_address_t nh_addr;       /**< Proxied device address */
  u32 sw_if_index_out;                      /**< Outgoing iface to proxied device */
  int live;
  } srv6_live_b_localsid_t;

srv6_live_b_main_t srv6_live_b_main;

format_function_t format_srv6_live_b_localsid;
unformat_function_t unformat_srv6_live_b_localsid;

void srv6_live_b_dpo_lock (dpo_id_t * dpo);
void srv6_live_b_dpo_unlock (dpo_id_t * dpo);

extern vlib_node_registration_t srv6_live_b_localsid_node;

#endif /* __included_srv6_live_b_h__ */

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
