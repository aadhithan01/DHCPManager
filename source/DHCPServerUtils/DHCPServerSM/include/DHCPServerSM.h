/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 RDK Management
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

#ifndef DHCP_SERVER_SM_H
#define DHCP_SERVER_SM_H


#include "ccsp_psm_helper.h"
#include "service_dhcp_server.h"

#define CCSP_SUBSYS     "eRT."
#define PSM_VALUE_GET_STRING(name, str) PSM_Get_Record_Value2(g_vBus_handle, CCSP_SUBSYS, name, NULL, &(str))
#define PSM_VALUE_SET_STRING(name, str) PSM_Set_Record_Value2(g_vBus_handle, CCSP_SUBSYS, name, ccsp_string, str)
#define PSM_VALUE_GET_INS(name, pIns, ppInsArry) PsmGetNextLevelInstances(g_vBus_handle, CCSP_SUBSYS, name, pIns, ppInsArry)

#define PSM_NAME_NOTIFY_WIFI_CHANGES    "eRT.com.cisco.spvtg.ccsp.Device.WiFi.NotifyWiFiChanges"
#define DEFAULT_RESOLV_CONF     "/var/default/resolv.conf"
#define DEFAULT_CONF_DIR      	"/var/default"
#define RESOLV_CONF             "/etc/resolv.conf"
#define DHCP_LEASE_FILE         "/nvram/dnsmasq.leases"
#define DHCP_STATIC_HOSTS_FILE  "/etc/dhcp_static_hosts"
#define DHCP_OPTIONS_FILE       "/var/dhcp_options"

typedef enum
{
    DHCP_SERVER_START = 0,
    DHCP_SERVER_STOP,
    DHCP_SERVER_RESTART,
    DHCP_SERVER_UPDATE,
} DHCP_SERVER_TYPE;

typedef struct Dhcpv4ServerSM
{
    DHCP_SERVER_STATE currentState;
} Dhcpv4ServerSM;

void DHCPServerv4_SM_update(DHCP_SERVER_TYPE dhcpServerActionType);

#endif
