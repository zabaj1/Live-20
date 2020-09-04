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
/*
 *------------------------------------------------------------------
 * live_test.c - test live-live plugin
 *------------------------------------------------------------------
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vnet/srv6/sr.h>

#define __plugin_msg_base live_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

uword unformat_bsid (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <live/live_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <live/live_all_api_h.h> 
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun             /* define message structures */
#include <live/live_all_api_h.h> 
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <live/live_all_api_h.h> 
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <live/live_all_api_h.h>
#undef vl_api_version


typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    vat_main_t *vat_main;
} live_test_main_t;

live_test_main_t live_test_main;

#define foreach_standard_reply_retval_handler   \
_(live_enable_disable_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = live_test_main.vat_main;   \
        i32 retval = ntohl(mp->retval);                 \
        if (vam->async_mode) {                          \
            vam->async_errors += (retval < 0);          \
        } else {                                        \
            vam->retval = retval;                       \
            vam->result_ready = 1;                      \
        }                                               \
    }
foreach_standard_reply_retval_handler;
#undef _

/* 
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_vpe_api_reply_msg                                       \
_(LIVE_ENABLE_DISABLE_REPLY, live_enable_disable_reply)


static int api_live_enable_disable (vat_main_t * vam)
{
    unformat_input_t * i = vam->input;
    int enable_disable = 1;
    ip6_address_t bsid;
    vl_api_live_enable_disable_t * mp;
    int ret;

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
   /*     if (unformat (i, "%U", unformat_bsid, vam, &bsid))
            ;
	else*/ if (unformat (i, "bsid %d", &bsid))
	    ;
        else if (unformat (i, "disable"))
            enable_disable = 0;
        else
            break;
    }
    
    
    
    /* Construct the API message */
    M(LIVE_ENABLE_DISABLE, mp);
    clib_memcpy(mp->bsid_addr, &bsid, sizeof(ip6_address_t));
    mp->enable_disable = enable_disable;

    /* send it... */
    S(mp);

    /* Wait for a reply... */
    W (ret);
    return ret;
}

/* 
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg \
_(live_enable_disable, "<bsid> [disable]")

static void live_api_hookup (vat_main_t *vam)
{
    live_test_main_t * sm = &live_test_main;
    /* Hook up handlers for replies from the data plane plug-in */
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,                                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_vpe_api_reply_msg;
#undef _

    /* API messages we can send */
#define _(n,h) hash_set_mem (vam->function_by_name, #n, api_##n);
    foreach_vpe_api_msg;
#undef _    
    
    /* Help strings */
#define _(n,h) hash_set_mem (vam->help_by_name, #n, h);
    foreach_vpe_api_msg;
#undef _
}

clib_error_t * vat_plugin_register (vat_main_t *vam)
{
  live_test_main_t * sm = &live_test_main;
  u8 * name;

  sm->vat_main = vam;

  name = format (0, "live_%08x%c", api_version, 0);
  sm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  if (sm->msg_id_base != (u16) ~0)
    live_api_hookup (vam);
  
  vec_free(name);
  
  return 0;
}
