/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#ifndef service_dhcp_server
#define service_dhcp_server
#include <stdbool.h>
#include "dhcp_server_v4_apis.h"
#define INET6_ADDRSTRLEN    46
/*erouter topology mode*/
enum tp_mod {
    TPMOD_UNKNOWN,
    FAVOR_DEPTH,
    FAVOR_WIDTH,
};

struct serv_ipv6 {
    int         sefd;
    int         setok;

    bool        wan_ready;

    char        mso_prefix[INET6_ADDRSTRLEN];
    enum tp_mod tpmod;
};

#ifdef RDKB_EXTENDER_ENABLED
typedef enum {
    ROUTER =0,
    EXTENDER_MODE,
} Dev_Mode;

unsigned int Get_Device_Mode();
#endif


/*typedef enum
{
    DHCP_SERVER_START = 0,
    DHCP_SERVER_STOP,
    DHCP_SERVER_RESTART,
} DHCP_SERVER_TYPE;
*/
typedef enum
{
    DHCP_SERVER_STATE_PREPARING = 0,
    DHCP_SERVER_STATE_READY,
    DHCP_SERVER_STATE_STARTING,
    DHCP_SERVER_STATE_STARTED,
    DHCP_SERVER_STATE_RUNNING,
    DHCP_SERVER_STATE_STOPPING,
    DHCP_SERVER_STATE_STOPPED,
    DHCP_SERVER_STATE_DISABLED,
    DHCP_SERVER_STATE_BRIDGE_MODE,
    DHCP_SERVER_STATE_ERROR,
} DHCP_SERVER_STATE;

typedef struct _cmdLineArgs_
{
    char cCmdLineArgs [BUFF_LEN_64];
    struct _cmdLineArgs_ * next;
}CmdLineArgs;

void dhcp_server_stop();
int dhcp_server_start(char *);
//void dhcp_server_restart();
int service_dhcp_init();
void lan_status_change(char *);
int init_dhcp_server_service();
int dhcpv6s_start(struct serv_ipv6 *si6);
int dhcpv6s_stop(struct serv_ipv6 *si6);
int dhcpv6s_restart(struct serv_ipv6 *si6);
int serv_ipv6_init();
int serv_ipv6_term();
int return_dibbler_server_pid ();
void syslog_restart_request(void*);
void resync_to_nonvol(char *);
int updateCmdLineArgs(CommandLineArgs *pCmdLineArgs);
DHCP_SERVER_STATE DhcpServer_Starting (char *input,GlobalDhcpConfig *sGlbDhcpCfg);
DHCP_SERVER_STATE DhcpServer_Stopping(GlobalDhcpConfig *sGlbDhcpCfg);
#endif
