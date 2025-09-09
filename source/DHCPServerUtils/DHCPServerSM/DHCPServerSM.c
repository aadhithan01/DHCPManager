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

#include "DHCPServerSM.h"
#include <util.h>
#include "lan_manager_interface.h"
#include "dhcp_server_functions.h"

Dhcpv4ServerSM g_Dhcpv4ServerSM = {
    .currentState = DHCP_SERVER_STATE_STOPPED
};

void AllocateDhcpInterfaceConfig(DhcpInterfaceConfig ***ppDhcpCfgs, int LanConfig_count)
    {
        *ppDhcpCfgs = (DhcpInterfaceConfig **)malloc(LanConfig_count * sizeof(DhcpInterfaceConfig *));
        if (*ppDhcpCfgs == NULL)
        {
            DHCPMGR_LOG_ERROR("%s:%d Memory allocation for ppDhcpCfgs failed\n", __FUNCTION__, __LINE__);
            g_Dhcpv4ServerSM.currentState = DHCP_SERVER_STATE_ERROR;
            return;
        }
        for (int i = 0; i < LanConfig_count; i++)
        {
            (*ppDhcpCfgs)[i] = (DhcpInterfaceConfig *)malloc(sizeof(DhcpInterfaceConfig));
            if ((*ppDhcpCfgs)[i] == NULL)
            {
                DHCPMGR_LOG_ERROR("%s:%d Memory allocation for ppDhcpCfgs[%d] failed\n", __FUNCTION__, __LINE__, i);
                g_Dhcpv4ServerSM.currentState = DHCP_SERVER_STATE_ERROR;
                return;
            }
            memset((*ppDhcpCfgs)[i], 0, sizeof(DhcpInterfaceConfig));
        }
}

DHCP_SERVER_STATE DhcpServerv4_up(GlobalDhcpConfig *sGlbDhcpCfg, char *input)
{
    if (input != NULL)
    {
        DHCPMGR_LOG_INFO("%s:%d DHCP Server v4 is starting with input: %s\n", __FUNCTION__, __LINE__, input);
    }
    g_Dhcpv4ServerSM.currentState = DHCP_SERVER_STATE_STARTING;
    return DhcpServer_Starting(input, sGlbDhcpCfg);
}

DHCP_SERVER_STATE DhcpServerv4_Teardown(GlobalDhcpConfig *sGlbDhcpCfg)
{
    if(g_Dhcpv4ServerSM.currentState == DHCP_SERVER_STATE_STOPPING)
    {
        // Already in the process of stopping
        for (int i = 0; i < 9; i++)
        {
            sleep(1);
            if (g_Dhcpv4ServerSM.currentState != DHCP_SERVER_STATE_STOPPING)
            {
                break;
            }
        }
    }
    else if(g_Dhcpv4ServerSM.currentState == DHCP_SERVER_STATE_STOPPED)
    {
        DHCPMGR_LOG_INFO("%s:%d DHCP Server is already stopped.\n", __FUNCTION__, __LINE__);
        return g_Dhcpv4ServerSM.currentState;
    }
    else
    {
        g_Dhcpv4ServerSM.currentState = DHCP_SERVER_STATE_STOPPING;
        DhcpInterfaceConfig **pDhcpIf = NULL;
        LanConfig lanConfigs[MAX_IFACE_COUNT];
        int LanConfig_count = 0; 
        if(true == GetLanConfigFromProvider(&lanConfigs, &LanConfig_count))
        {
            if (lanConfigs == NULL || LanConfig_count == 0)
            {
                DHCPMGR_LOG_ERROR("%s:%d No LAN Configs found\n", __FUNCTION__, __LINE__);
                return DHCP_SERVER_STATE_ERROR;
            }
            DHCPMGR_LOG_INFO("%s:%d Lan Configs fetched successfully\n", __FUNCTION__, __LINE__);

            AllocateDhcpInterfaceConfig(&pDhcpIf, LanConfig_count);

            if (0 != Construct_dhcp_configuration(pDhcpIf, LanConfig_count, "dns_only", sGlbDhcpCfg, lanConfigs))
            {
                DHCPMGR_LOG_ERROR("%s:%d Failed to construct DHCP configuration\n", __FUNCTION__, __LINE__);
                g_Dhcpv4ServerSM.currentState = DHCP_SERVER_STATE_ERROR;
                return g_Dhcpv4ServerSM.currentState;
            }
            else
            {
                printDhcpConfig (pDhcpIf, LanConfig_count, sGlbDhcpCfg);
                dhcpServerInit(&sGlbDhcpCfg, pDhcpIf, LanConfig_count);
            }
        }
    }
    return g_Dhcpv4ServerSM.currentState;
}

DHCP_SERVER_STATE DhcpServerv6_up()
{
    return g_Dhcpv4ServerSM.currentState;
}

DHCP_SERVER_STATE DhcpServerv6_down()
{
    return g_Dhcpv4ServerSM.currentState;
}

DHCP_SERVER_STATE DhcpServerv4_preparing(GlobalDhcpConfig *sGlbDhcpCfg)
{
    DhcpInterfaceConfig **ppDhcpCfgs = NULL;
//    DhcpIfaces *pDhcpIfaces = NULL;
    LanConfig lanConfigs[MAX_IFACE_COUNT];
    int LanConfig_count = 0; 

    memset(sGlbDhcpCfg, 0, sizeof(GlobalDhcpConfig));

    if(true == GetLanConfigFromProvider(&lanConfigs, &LanConfig_count))
    {
       if (LanConfig_count == 0)
       {
                DHCPMGR_LOG_ERROR("No LAN Configs found");
                return DHCP_SERVER_STATE_ERROR;
       }
        DHCPMGR_LOG_INFO("%s : %d Lan Configs fetched successfully and count is %d\n", __FUNCTION__, __LINE__, LanConfig_count);
    }
    else
    {
        DHCPMGR_LOG_ERROR("%s : %d Failed to fetch Lan Configs", __FUNCTION__, __LINE__);
        return DHCP_SERVER_STATE_ERROR;
    }
    g_Dhcpv4ServerSM.currentState = DHCP_SERVER_STATE_PREPARING;

    AllocateDhcpInterfaceConfig(&ppDhcpCfgs, LanConfig_count);

    if (0 != Construct_dhcp_configuration(ppDhcpCfgs, LanConfig_count, NULL, sGlbDhcpCfg, lanConfigs))
    {
        DHCPMGR_LOG_ERROR("%s:%d Failed to construct DHCP configuration\n", __FUNCTION__, __LINE__);
        g_Dhcpv4ServerSM.currentState = DHCP_SERVER_STATE_ERROR;
        freeMemoryDHCP(&ppDhcpCfgs, LanConfig_count, &sGlbDhcpCfg);
        return g_Dhcpv4ServerSM.currentState;
    }
    else
    {
        DHCPMGR_LOG_INFO("%s: %d Global DHCP configuration populated successfully\n", __FUNCTION__, __LINE__);
        printDhcpConfig (ppDhcpCfgs, LanConfig_count, sGlbDhcpCfg);
        if(LanConfig_count <= 0 )
        {
            DHCPMGR_LOG_ERROR("%s:%d No LAN Configs found\n", __FUNCTION__, __LINE__);
            g_Dhcpv4ServerSM.currentState = DHCP_SERVER_STATE_ERROR;
            freeMemoryDHCP(&ppDhcpCfgs, LanConfig_count, &sGlbDhcpCfg);
            return -1;
        }
        dhcpServerInit(sGlbDhcpCfg, ppDhcpCfgs, LanConfig_count);
        updateCmdLineArgs (&sGlbDhcpCfg->sCmdArgs);
        freeMemoryDHCP(&ppDhcpCfgs, LanConfig_count, &sGlbDhcpCfg);
        g_Dhcpv4ServerSM.currentState = DHCP_SERVER_STATE_READY;
    }
    return g_Dhcpv4ServerSM.currentState;
}


void DHCPServerv4_SM_update(DHCP_SERVER_TYPE dhcpServerActionType)
{
    GlobalDhcpConfig sGlbDhcpCfg;
    switch (dhcpServerActionType)
    {
        case DHCP_SERVER_START:
            memset(&sGlbDhcpCfg, 0, sizeof(GlobalDhcpConfig));
            if (DhcpServerv4_preparing(&sGlbDhcpCfg) != DHCP_SERVER_STATE_READY)
            {
                DHCPMGR_LOG_ERROR(("Failed to prepare DHCP Server configuration\n"));
                g_Dhcpv4ServerSM.currentState = DHCP_SERVER_STATE_ERROR;
            }
            else
            {
               //To do list
                DHCPMGR_LOG_INFO("%s:%d DHCP Server configuration prepared successfully\n", __FUNCTION__, __LINE__);
                g_Dhcpv4ServerSM.currentState = DhcpServerv4_up(&sGlbDhcpCfg,NULL);
                if (g_Dhcpv4ServerSM.currentState == DHCP_SERVER_STATE_STARTED)
                {
                    DHCPMGR_LOG_INFO("%s:%d DHCP Server started successfully\n", __FUNCTION__, __LINE__);
                }
            }
            break;
        case DHCP_SERVER_STOP:
            memset(&sGlbDhcpCfg, 0, sizeof(GlobalDhcpConfig));

            if (DhcpServerv4_Teardown(&sGlbDhcpCfg) != DHCP_SERVER_STATE_STOPPING)
            {
                    DHCPMGR_LOG_ERROR("%s:%d Failed to stop DHCP Server\n", __FUNCTION__, __LINE__);
                    g_Dhcpv4ServerSM.currentState = DHCP_SERVER_STATE_ERROR;
            }
            else
            {
                    if(DhcpServer_Stopping(&sGlbDhcpCfg) == DHCP_SERVER_STATE_STOPPED)
                    {
                        g_Dhcpv4ServerSM.currentState = DHCP_SERVER_STATE_STOPPED;
                        DHCPMGR_LOG_INFO("%s:%d DHCP Server stopped successfully\n", __FUNCTION__, __LINE__);
                    }
                    else
                    {
                        g_Dhcpv4ServerSM.currentState = DHCP_SERVER_STATE_ERROR;
                        DHCPMGR_LOG_ERROR("%s:%d Failed to stop DHCP Server\n", __FUNCTION__, __LINE__);
                    }
            }
            break;
        case DHCP_SERVER_RESTART:
            // Logic to restart the DHCP server
            DHCPMGR_LOG_INFO("%s:%d DHCP Server is restarting...\n", __FUNCTION__, __LINE__);
            break;
        case DHCP_SERVER_UPDATE:
            // Logic to update the DHCP server configuration
            DHCPMGR_LOG_INFO("%s:%d DHCP Server is updating...\n", __FUNCTION__, __LINE__);
            break;
        default:
            DHCPMGR_LOG_ERROR("%s:%d Invalid DHCP Server type\n", __FUNCTION__, __LINE__);
            break;
    }
}
