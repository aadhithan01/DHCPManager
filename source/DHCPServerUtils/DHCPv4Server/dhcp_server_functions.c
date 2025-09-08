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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include "sysevent/sysevent.h"
#include "syscfg/syscfg.h"
#include "errno.h"
#include "util.h"
#include "dhcp_server_functions.h"
#include <telemetry_busmessage_sender.h>
#include <ccsp_psm_helper.h>
#include <ccsp_base_api.h>
#include <ccsp_memory.h>
#include <libnet.h>

#include "safec_lib_common.h"
#include "secure_wrapper.h"
#include "ifl.h"

#define HOSTS_FILE              "/etc/hosts"
#define HOSTNAME_FILE           "/etc/hostname"
#define DHCP_STATIC_HOSTS_FILE  "/etc/dhcp_static_hosts"
#define DHCP_OPTIONS_FILE       "/var/dhcp_options"
#define WAN_IF_NAME             "erouter0"
#define RESOLV_CONF             "/etc/resolv.conf"
#define TRUE                    1
#define FALSE                   0
#define STATIC_URLS_FILE        "/etc/static_urls"
#define STATIC_DNS_URLS_FILE    "/etc/static_dns_urls"
#define NETWORK_RES_FILE        "/var/tmp/networkresponse.txt"
#define DHCP_CONF               "/var/dnsmasq.conf"
#define DHCP_LEASE_FILE         "/nvram/dnsmasq.leases"
#define DEFAULT_RESOLV_CONF     "/var/default/resolv.conf"
#define DEFAULT_CONF_DIR        "/var/default"
#define DEFAULT_FILE            "/etc/utopia/system_defaults"

#ifdef RDKB_EXTENDER_ENABLED
#define TMP_RESOLVE_CONF        "/tmp/lte_resolv.conf"
#define MESH_WAN_IFNAME         "dmsb.Mesh.WAN.Interface.Name"
#define GRE_VLAN_IFACE_IP       "192.168.246.1"
#define GRE_VLAN_IFACE_DHCP_OPT "192.168.246.2,192.168.246.254,255.255.255.0,172800"
#endif

//#define LAN_IF_NAME     "brlan0"
#define XHS_IF_NAME     "brlan1"
#define ERROR             -1
#define SUCCESS            0
#define CCSP_SUBSYS  "eRT."
#define PSM_VALUE_GET_STRING(name, str)  PSM_Get_Record_Value2(g_vBus_handle, CCSP_SUBSYS, name, NULL, &(str))
#define PSM_NAME_NOTIFY_WIFI_CHANGES    "eRT.com.cisco.spvtg.ccsp.Device.WiFi.NotifyWiFiChanges"
#define PSM_NAME_WIFI_RES_MIG           "eRT.com.cisco.spvtg.ccsp.Device.WiFi.WiFiRestored_AfterMigration"
#define IS_MIG_CHECK_NEEDED(MIG_CHECK)  (!strncmp(MIG_CHECK, "true", 4)) ? (TRUE) : (FALSE)

#define isValidSubnetByte(byte) (((byte == 255) || (byte == 254) || (byte == 252) || \
                                  (byte == 248) || (byte == 240) || (byte == 224) || \
                                  (byte == 192) || (byte == 128)) ? 1 : 0)
extern void* g_vBus_handle;
//extern int g_iSyseventV4fd;
//extern token_t g_tSyseventV4_token;
extern char g_cDhcp_Lease_Time[8];
extern char g_cMfg_Name[8];
extern char g_cMig_Check[8];

extern void subnet(char *ipv4Addr, char *ipv4Subnet, char *subnet);
extern void copy_file(char *, char *);
extern void remove_file(char *);
extern unsigned int mask2cidr(char *subnetMask);

static unsigned int isValidSubnetMask(char *subnetMask);

typedef struct {
    char cDhcpOptions [BUFF_LEN_256];
}DhcpOptionsArray;

DhcpOptionsArray dhcpOptionsArray[] = {
        {"vendor:Plume,43,tag=123"},
        {"vendor:PP203X,43,tag=123"},
        {"vendor:HIXE12AWR,43,tag=123"},
        {"vendor:WNXE12AWR,43,tag=123"},
        {"vendor:SE401,43,tag=123"},
        {"vendor:WNXL11BWL,43,tag=123"},
    };

enum interface{
    ExistWithSameRange,
    ExistWithDifferentRange,
    NotExists
};

/*
 * A subnet mask should only have continuous 1s starting from MSB (Most Significant Bit).
 * Like 11111111.11111111.11100000.00000000.
 * Which means first 19 bits of an IP address belongs to network part and rest is host part.
 */
static unsigned int isValidSubnetMask(char *subnetMask)
{
    int l_iIpAddrOctets[4] = {-1, -1, -1, -1};
        char *ptr = subnetMask;
        char dotCount = 0;
        unsigned char idx = 0;

        if (!ptr)
            return 0;

        // check the subnet mask have 3 dots or not
        while(*ptr != '\0')
        {
                if (*ptr == '.')
                         dotCount++;

                ptr++;
        }

        if (3 != dotCount)
                return 0;

        sscanf(subnetMask, "%d.%d.%d.%d", &l_iIpAddrOctets[0], &l_iIpAddrOctets[1],
           &l_iIpAddrOctets[2], &l_iIpAddrOctets[3]);

        //first octets in subnet mask cannot be 0 and last octets in subnet mask cannot be 255
        if ((0 == l_iIpAddrOctets[0]) || (255 == l_iIpAddrOctets[3]))
                return 0;

        for (idx = 0; idx < 4; idx++)
        {
                if ((isValidSubnetByte(l_iIpAddrOctets[idx])) || (0 == l_iIpAddrOctets[idx]))
                {
                        if (255 != l_iIpAddrOctets[idx])
                        {
                                idx++; //host part. From this idx all octets should be 0
                                break;
                        }
                }
                else
                        return 0;
        }

        //host part. From this idx all octets should be 0
        for ( ; idx < 4; idx++)
        {
                if (0 != l_iIpAddrOctets[idx])
                      return 0;
        }

        return 1;
}

static int isValidLANIP(const char* ipStr)
{
        int octet1,octet2,octet3,octet4;
        struct sockaddr_in l_sSocAddr;
        if(!inet_pton(AF_INET, ipStr, &(l_sSocAddr.sin_addr)))
        {
                return 0;
        }

        sscanf(ipStr, "%d.%d.%d.%d", &octet1, &octet2, &octet3, &octet4);

        if( ((octet1 != 10) && (octet1 != 172) && (octet1 != 192)) ||
                ((octet1 == 172) && ((octet2<16) || (octet2>31)))  ||
                ((octet1== 192) && ((octet2 != 168) || (octet3== 147)) ) )
        {
                return 0;
        }
        return 1;
}

void * deleteNode(void *pHead, NodeType eNodeType)
{
    void * pVoid = NULL;
    if (NULL == pHead)
    {
        DHCPMGR_LOG_ERROR("%s:%d,NULL parameter passed\n",__FUNCTION__,__LINE__);
        return NULL;
    }
    switch(eNodeType)
    {
        case DHCP_OPTION:
        {
            DhcpOptionsList *pDhcpOptionsTemp = (DhcpOptionsList*)pHead;
            DhcpOptionsList *pDhcpOptionsHead = (DhcpOptionsList*)pHead;

            pDhcpOptionsHead = pDhcpOptionsHead->next;
            pDhcpOptionsTemp->next = NULL;
            if (NULL != pDhcpOptionsTemp)
                free (pDhcpOptionsTemp);
            pVoid = (DhcpOptionsList*)pDhcpOptionsHead;
            break;
        }
        case DHCP_VENDOR_CLASS:
        {
            DhcpVendorClassList *pDhcpVendorClassHead = (DhcpVendorClassList*)pHead;
            DhcpVendorClassList *pDhcpVendorClassTemp = (DhcpVendorClassList*)pHead;

            pDhcpVendorClassHead = pDhcpVendorClassHead->next;
            pDhcpVendorClassTemp->next = NULL;
            if (NULL != pDhcpVendorClassTemp)
                free (pDhcpVendorClassTemp);
            pVoid = (DhcpVendorClassList*)pDhcpVendorClassHead;
            break;
        }
        case DOMAIN_SPECIFIC_ADDRESS:
        {
            DomainAddress *pDomainSpecificAddrHead = (DomainAddress*)pHead;
            DomainAddress *pDomainSpecificAddrTemp = (DomainAddress*)pHead;

            pDomainSpecificAddrHead = pDomainSpecificAddrHead->next;
            pDomainSpecificAddrTemp->next = NULL;
            if (NULL != pDomainSpecificAddrTemp)
                free (pDomainSpecificAddrTemp);
            pVoid = (DomainAddress*)pDomainSpecificAddrHead;
            break;
        }
        case REDIRECTION_ADDRESS:
        {
            RedirectionAddress *pRedirectAddrHead = (RedirectionAddress*)pHead;
            RedirectionAddress *pRedirectAddrTemp = (RedirectionAddress*)pHead;

            pRedirectAddrHead = pRedirectAddrHead->next;
            pRedirectAddrTemp->next = NULL;
            if (NULL != pRedirectAddrTemp)
                free (pRedirectAddrTemp);
            pVoid = (RedirectionAddress*)pRedirectAddrHead;
            break;
        }
        default:
            break;
    }
    return pVoid;
}


void * initNode(char *pStr, NodeType eNodeType)
{
    void *pVoid = NULL;
    if (NULL == pStr)
    {
        DHCPMGR_LOG_ERROR("%s:%d, NULL parameter passed\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    switch (eNodeType)
    {
        case DHCP_OPTION:
        {
            DhcpOptionsList *pDhcpOptionsList = (DhcpOptionsList *)malloc(sizeof(DhcpOptionsList));
            if (NULL == pDhcpOptionsList)
            {
                DHCPMGR_LOG_ERROR("%s:%d, Failed to allocate the memory\n", __FUNCTION__, __LINE__);
                pVoid = NULL;
            }
            else
            {
                memset(pDhcpOptionsList, 0, sizeof(DhcpOptionsList));
                pDhcpOptionsList->next = NULL;
                snprintf(pDhcpOptionsList->cDhcpOptions, sizeof(pDhcpOptionsList->cDhcpOptions), "%s", pStr);
                DHCPMGR_LOG_INFO("DHCP_OPTION: %s\n", pDhcpOptionsList->cDhcpOptions);
                pVoid = (DhcpOptionsList *)pDhcpOptionsList;
            }
            break;
        }
        case DHCP_VENDOR_CLASS:
        {
            DhcpVendorClassList *pDhcpVendorClass = (DhcpVendorClassList *)malloc(sizeof(DhcpVendorClassList));
            if (NULL == pDhcpVendorClass)
            {
                DHCPMGR_LOG_ERROR("%s:%d, Failed to allocate the memory\n", __FUNCTION__, __LINE__);
                pVoid = NULL;
            }
            else
            {
                memset(pDhcpVendorClass, 0, sizeof(DhcpVendorClassList));
                pDhcpVendorClass->next = NULL;
                snprintf(pDhcpVendorClass->cVendorClass, sizeof(pDhcpVendorClass->cVendorClass), "%s", pStr);
                DHCPMGR_LOG_INFO("DHCP_VENDOR_CLASS: %s\n", pDhcpVendorClass->cVendorClass);
                pVoid = (DhcpVendorClassList *)pDhcpVendorClass;
            }
            break;
        }
        case DOMAIN_SPECIFIC_ADDRESS:
        {
            DomainAddress *pDomainSpecificAddr = (DomainAddress *)malloc(sizeof(DomainAddress));
            if (NULL == pDomainSpecificAddr)
            {
                DHCPMGR_LOG_ERROR("%s:%d, Failed to allocate the memory\n", __FUNCTION__, __LINE__);
                pVoid = NULL;
            }
            else
            {
                memset(pDomainSpecificAddr, 0, sizeof(DomainAddress));
                pDomainSpecificAddr->next = NULL;
                snprintf(pDomainSpecificAddr->cDomainSpecificAddr, sizeof(pDomainSpecificAddr->cDomainSpecificAddr), "%s", pStr);
                DHCPMGR_LOG_INFO("DOMAIN_SPECIFIC_ADDRESS: %s\n", pDomainSpecificAddr->cDomainSpecificAddr);
                pVoid = (DomainAddress *)pDomainSpecificAddr;
            }
            break;
        }
        case REDIRECTION_ADDRESS:
        {
            RedirectionAddress *pRedirectAddr = (RedirectionAddress *)malloc(sizeof(RedirectionAddress));
            if (NULL == pRedirectAddr)
            {
                DHCPMGR_LOG_ERROR("%s:%d, Failed to allocate the memory\n", __FUNCTION__, __LINE__);
                pVoid = NULL;
            }
            else
            {
                memset(pRedirectAddr, 0, sizeof(RedirectionAddress));
                pRedirectAddr->next = NULL;
                snprintf(pRedirectAddr->cRedirectionAddr, sizeof(pRedirectAddr->cRedirectionAddr), "%s", pStr);
                DHCPMGR_LOG_INFO("REDIRECTION_ADDRESS: %s\n", pRedirectAddr->cRedirectionAddr);
                pVoid = (RedirectionAddress *)pRedirectAddr;
            }
            break;
        }
        default:
        {
            DHCPMGR_LOG_ERROR("Invalid node type: %d\n", eNodeType);
            pVoid = NULL;
            break;
        }
    }
    if (NULL == pVoid)
        DHCPMGR_LOG_ERROR("%s:%d, Failed to allocate the memory\n", __FUNCTION__, __LINE__);
    return pVoid;
}

int insertNode(void **pHead, void *pNode, NodeType eNodeType)
{
    int iRet = 0;
    if (NULL == pNode)
    {
        DHCPMGR_LOG_ERROR("%s:%d, NULL parameter passed\n", __FUNCTION__, __LINE__);
        return -1;
    }
    switch (eNodeType)
    {
        case DHCP_OPTION:
        {
            DhcpOptionsList *pDhcpOptionsListHead = (DhcpOptionsList *)*pHead;
            if (NULL == pDhcpOptionsListHead)
            {
                pDhcpOptionsListHead = (DhcpOptionsList *)pNode;
                *pHead = (void *)pDhcpOptionsListHead;
                DHCPMGR_LOG_INFO("%s:%d, pDhcpOptionsListHead is NULL\n", __FUNCTION__, __LINE__);
            }
            else
            {
                DHCPMGR_LOG_INFO("%s:%d, Moving the pDhcpOptionsListHead pointer\n", __FUNCTION__, __LINE__);
                DhcpOptionsList *pDhcpOptionsListTemp = pDhcpOptionsListHead;
                while (NULL != pDhcpOptionsListTemp->next)
                    pDhcpOptionsListTemp = pDhcpOptionsListTemp->next;
                pDhcpOptionsListTemp->next = (DhcpOptionsList *)pNode;
            }
            break;
        }
        case DHCP_VENDOR_CLASS:
        {
            DhcpVendorClassList *pDhcpVendorClassHead = (DhcpVendorClassList *)*pHead;
            if (NULL == pDhcpVendorClassHead)
            {
                pDhcpVendorClassHead = (DhcpVendorClassList *)pNode;
                *pHead = (void *)pDhcpVendorClassHead;
                DHCPMGR_LOG_INFO("%s:%d, pDhcpVendorClassHead is NULL\n", __FUNCTION__, __LINE__);
            }
            else
            {
                DHCPMGR_LOG_INFO("%s:%d, Moving the pDhcpVendorClassHead pointer\n", __FUNCTION__, __LINE__);
                DhcpVendorClassList *pDhcpVendorClassTemp = pDhcpVendorClassHead;
                while (NULL != pDhcpVendorClassTemp->next)
                    pDhcpVendorClassTemp = pDhcpVendorClassTemp->next;
                pDhcpVendorClassTemp->next = (DhcpVendorClassList *)pNode;
            }
            break;
        }
        case DOMAIN_SPECIFIC_ADDRESS:
        {
            DomainAddress *pDomainSpecificHead = (DomainAddress *)*pHead;
            if (NULL == pDomainSpecificHead)
            {
                pDomainSpecificHead = (DomainAddress *)pNode;
                *pHead = (void *)pDomainSpecificHead;
                DHCPMGR_LOG_INFO("%s:%d, pDomainSpecificHead is NULL\n", __FUNCTION__, __LINE__);
            }
            else
            {
                DHCPMGR_LOG_INFO("%s:%d, Moving the pDomainSpecificHead pointer\n", __FUNCTION__, __LINE__);
                DomainAddress *pDomainSpecificTemp = pDomainSpecificHead;
                while (NULL != pDomainSpecificTemp->next)
                    pDomainSpecificTemp = pDomainSpecificTemp->next;
                pDomainSpecificTemp->next = (DomainAddress *)pNode;
            }
            break;
        }
        case REDIRECTION_ADDRESS:
        {
            RedirectionAddress *pRedirectAddrHead = (RedirectionAddress *)*pHead;
            if (NULL == pRedirectAddrHead)
            {
                pRedirectAddrHead = (RedirectionAddress *)pNode;
                *pHead = (void *)pRedirectAddrHead;
                DHCPMGR_LOG_INFO("%s:%d, pRedirectAddrHead is NULL\n", __FUNCTION__, __LINE__);
            }
            else
            {
                RedirectionAddress *pRedirectAddrTemp = pRedirectAddrHead;
                while (NULL != pRedirectAddrTemp->next)
                    pRedirectAddrTemp = pRedirectAddrTemp->next;
                pRedirectAddrTemp->next = (RedirectionAddress *)pNode;
                DHCPMGR_LOG_INFO("%s:%d, Moving the pRedirectAddrHead pointer\n", __FUNCTION__, __LINE__);
            }
            break;
        }
        case DHCP_INTERFACE_CONFIG:
        {
            DhcpIfaces *pDhcpIfacesHead = (DhcpIfaces *)*pHead;
            if (NULL == pDhcpIfacesHead)
            {
                pDhcpIfacesHead = (DhcpIfaces *)pNode;
                *pHead = (void *)pDhcpIfacesHead;
                DHCPMGR_LOG_INFO("%s:%d, pDhcpIfacesHead is NULL\n", __FUNCTION__, __LINE__);
            }
            else
            {
                DHCPMGR_LOG_INFO("%s:%d, Moving the pDhcpIfacesHead pointer\n", __FUNCTION__, __LINE__);
                DhcpIfaces *pDhcpIfacesTemp = pDhcpIfacesHead;
                while (NULL != pDhcpIfacesTemp->next)
                    pDhcpIfacesTemp = pDhcpIfacesTemp->next;
                pDhcpIfacesTemp->next = (DhcpIfaces *)pNode;
            }
            break;
        }
        default:
        {
            DHCPMGR_LOG_ERROR("%s:%d, Invalid node type: %d\n", __FUNCTION__, __LINE__, eNodeType);
            iRet = -1;
        }
    }
    return iRet;
}
void doExtraPools (DhcpOptionsList ** pDhcpOptionsList, int * pDhcpOptionCount, bool bIsDhcpNsEnabled, char *pWanDhcpDns)
{
    char cDhcpEnabled    [BUFF_LEN_8]  = {0};
    char cSyseventCmd    [BUFF_LEN_32] = {0};
    char cIpv4Inst       [BUFF_LEN_8]  = {0};
    char cIpv4InstStatus [BUFF_LEN_8]  = {0};
    char cPools          [BUFF_LEN_8]  = {0};
//    char cDhcpStartAddr  [BUFF_LEN_16] = {0};
//    char cDhcpEndAddr    [BUFF_LEN_16] = {0};
//    char cLanSubnet      [BUFF_LEN_16] = {0};
//    char cDhcpLeaseTime  [BUFF_LEN_8]  = {0};
    char cIfName         [BUFF_LEN_8]  = {0};

    char *pToken = NULL;
    int  iPool;
    int  iIpv4Inst;

    ifl_get_event("dhcp_server_current_pools", cPools, sizeof(cPools));
    pToken = strtok(cPools, "\n");
    while (pToken != NULL)
    {
        if (0 != pToken[0])
        {
            iPool = atoi(pToken);
            snprintf(cSyseventCmd, sizeof(cSyseventCmd), "dhcp_server_%d_enabled", iPool);
            ifl_get_event(cSyseventCmd, cDhcpEnabled, sizeof(cDhcpEnabled));

            if (!strncmp(cDhcpEnabled, "TRUE", 4))
            {
                snprintf(cSyseventCmd, sizeof(cSyseventCmd), "dhcp_server_%d_ipv4inst", iPool);
                ifl_get_event(cSyseventCmd, cIpv4Inst, sizeof(cIpv4Inst));
                iIpv4Inst = atoi(cIpv4Inst);

                snprintf(cSyseventCmd, sizeof(cSyseventCmd), "ipv4_%d-status", iIpv4Inst);
                ifl_get_event(cSyseventCmd, cIpv4InstStatus, sizeof(cIpv4InstStatus));

                if (!strncmp(cIpv4InstStatus, "up", 2))
                {
                    snprintf(cSyseventCmd, sizeof(cSyseventCmd), "ipv4_%d-ifname", iIpv4Inst);
                    ifl_get_event(cSyseventCmd, cIfName, sizeof(cIfName));

                        if ((true == bIsDhcpNsEnabled) && (NULL != pWanDhcpDns) && (0 < strlen(pWanDhcpDns)))
                        {
                            char cStrVar[BUFF_LEN_64] = {0};
                            snprintf(cStrVar, sizeof(cStrVar), "%s,6,%s", cIfName, pWanDhcpDns);
                            DhcpOptionsList* pXhsDhcpOptions = (DhcpOptionsList*)initNode(cStrVar, DHCP_OPTION);
                            if (NULL != pXhsDhcpOptions)
                            {
                                DHCPMGR_LOG_INFO("Xhs Dhcp-option: %s", cStrVar);
                                if (!insertNode((void*)pDhcpOptionsList, (void*)pXhsDhcpOptions, DHCP_OPTION))
                                {
                                    *pDhcpOptionCount += 1;
                                    DHCPMGR_LOG_INFO("%s:%d, DhcpOptionCount: %d", __FUNCTION__, __LINE__, *pDhcpOptionCount);
                                }
                            }
                            else
                            {
                                DHCPMGR_LOG_ERROR("%s:%d, Failed to init Node", __FUNCTION__, __LINE__);
                            }
                        }
                }
                else
                {
                    DHCPMGR_LOG_INFO("%s is not up, go to next pool", cIpv4InstStatus);
                }
            }
            else
            {
                DHCPMGR_LOG_INFO("%s is not TRUE, continue to next pool", cDhcpEnabled);
            }
        }
        else
        {
            DHCPMGR_LOG_INFO("Pool is empty, continue to next pool");
        }
        pToken = strtok(NULL, " ");
    }
}

void freeMemoryDHCP(DhcpInterfaceConfig **ppDhcpCfgs, int iDhcpIfCount, GlobalDhcpConfig *pGlbDhcpCfg)
{
    if (NULL != ppDhcpCfgs)
    {
        for (int iCount = 0; iCount < iDhcpIfCount; iCount++)
        {
            if (NULL != ppDhcpCfgs[iCount])
            {
                free(ppDhcpCfgs[iCount]);
                ppDhcpCfgs[iCount] = NULL;
            }
        }
        free(ppDhcpCfgs);
        ppDhcpCfgs = NULL;
    }
    if (NULL != pGlbDhcpCfg)
    {
        if (NULL != pGlbDhcpCfg->sDhcpOptions.ppVendorId)
        {
            for (int iCount = 0; iCount < pGlbDhcpCfg->sDhcpOptions.iVendorIdCount; iCount++)
            {
                if (NULL != pGlbDhcpCfg->sDhcpOptions.ppVendorId[iCount])
                {
                    free(pGlbDhcpCfg->sDhcpOptions.ppVendorId[iCount]);
                    pGlbDhcpCfg->sDhcpOptions.ppVendorId[iCount] = NULL;
                }
            }
            free(pGlbDhcpCfg->sDhcpOptions.ppVendorId);
            pGlbDhcpCfg->sDhcpOptions.ppVendorId = NULL;
        }
        if (NULL != pGlbDhcpCfg->sDhcpOptions.ppVendorClass)
        {
            for (int iCount = 0; iCount < pGlbDhcpCfg->sDhcpOptions.iVendorClassCount; iCount++)
            {
                if (NULL != pGlbDhcpCfg->sDhcpOptions.ppVendorClass[iCount])
                {
                    free(pGlbDhcpCfg->sDhcpOptions.ppVendorClass[iCount]);
                    pGlbDhcpCfg->sDhcpOptions.ppVendorClass[iCount] = NULL;
                }
            }
            free(pGlbDhcpCfg->sDhcpOptions.ppVendorClass);
            pGlbDhcpCfg->sDhcpOptions.ppVendorClass = NULL;
        }
        if (NULL != pGlbDhcpCfg->sRedirectInfo.ppRedirectionUrl)
        {
            for (int iCount = 0; iCount < pGlbDhcpCfg->sRedirectInfo.iRedirectionUrlCount; iCount++)
            {
                if (NULL != pGlbDhcpCfg->sRedirectInfo.ppRedirectionUrl[iCount])
                {
                    free(pGlbDhcpCfg->sRedirectInfo.ppRedirectionUrl[iCount]);
                    pGlbDhcpCfg->sRedirectInfo.ppRedirectionUrl[iCount] = NULL;
                }
            }
            free(pGlbDhcpCfg->sRedirectInfo.ppRedirectionUrl);
            pGlbDhcpCfg->sRedirectInfo.ppRedirectionUrl = NULL;
        }
        if (NULL != pGlbDhcpCfg->sDomainSpecific.ppDomainSpecificAddresses)
        {
            for (int iCount = 0; iCount < pGlbDhcpCfg->sDomainSpecific.iDomainSpecificAddressCount; iCount++)
            {
                if (NULL != pGlbDhcpCfg->sDomainSpecific.ppDomainSpecificAddresses[iCount])
                {
                    free(pGlbDhcpCfg->sDomainSpecific.ppDomainSpecificAddresses[iCount]);
                    pGlbDhcpCfg->sDomainSpecific.ppDomainSpecificAddresses[iCount] = NULL;
                }
            }
            free(pGlbDhcpCfg->sDomainSpecific.ppDomainSpecificAddresses);
            pGlbDhcpCfg->sDomainSpecific.ppDomainSpecificAddresses = NULL;
        }
        if (NULL != pGlbDhcpCfg->sCmdArgs.ppCmdLineArgs)
        {
            for (int iCount = 0; iCount < pGlbDhcpCfg->sCmdArgs.iNumOfArgs; iCount++)
            {
                if (NULL != pGlbDhcpCfg->sCmdArgs.ppCmdLineArgs[iCount])
                {
                    free(pGlbDhcpCfg->sCmdArgs.ppCmdLineArgs[iCount]);
                    pGlbDhcpCfg->sCmdArgs.ppCmdLineArgs[iCount] = NULL;
                }
            }
            free(pGlbDhcpCfg->sCmdArgs.ppCmdLineArgs);
            pGlbDhcpCfg->sCmdArgs.ppCmdLineArgs = NULL;
        }
    }
}

void Add_inf_to_dhcp_config(LanConfig *pLanConfig, int numOfLanConfigs, DhcpInterfaceConfig **ppHeadDhcpIf,int pDhcpIfacesCount)
{
    if (pLanConfig == NULL || ppHeadDhcpIf == NULL || numOfLanConfigs <= 0)
    {
        DHCPMGR_LOG_ERROR("%s:%d, Invalid parameters passed\n", __FUNCTION__, __LINE__);
        return;
    }

    for (int i = 0; i < pDhcpIfacesCount; i++)
    {
/*        DhcpIfaces *pIface = (DhcpIfaces *)malloc(sizeof(DhcpIfaces));
        if (pIface == NULL)
        {
            DHCPMGR_LOG_ERROR("%s:%d, Memory allocation failed\n", __FUNCTION__, __LINE__);
            continue;
        }

        memset(pIface, 0, sizeof(DhcpIfaces));
*/
        ppHeadDhcpIf[i]->bIsDhcpEnabled = pLanConfig[i].dhcpConfig.Dhcpv4_Enable;
        snprintf(ppHeadDhcpIf[i]->cGatewayName, sizeof(ppHeadDhcpIf[i]->cGatewayName), "%s", pLanConfig[i].bridgeInfo.bridgeName);

        if (pLanConfig[i].ipConfig.Ip_Enable && pLanConfig[i].dhcpConfig.Dhcpv4_Enable)
        {
            snprintf(ppHeadDhcpIf[i]->sAddressPool.cStartAddress, sizeof(ppHeadDhcpIf[i]->sAddressPool.cStartAddress), "%s", pLanConfig[i].dhcpConfig.Dhcpv4_Start_Addr);
            snprintf(ppHeadDhcpIf[i]->sAddressPool.cEndAddress, sizeof(ppHeadDhcpIf[i]->sAddressPool.cEndAddress), "%s", pLanConfig[i].dhcpConfig.Dhcpv4_End_Addr);
            snprintf(ppHeadDhcpIf[i]->cSubnetMask, sizeof(ppHeadDhcpIf[i]->cSubnetMask), "%s", pLanConfig[i].ipConfig.IpSubNet);
            snprintf(ppHeadDhcpIf[i]->cLeaseDuration, sizeof(ppHeadDhcpIf[i]->cLeaseDuration), "%d", pLanConfig[i].dhcpConfig.Dhcpv4_Lease_Time);
        }

/*       if (!insertNode((void *)ppHeadDhcpIf, pIface, DHCP_INTERFACE_CONFIG))
        {
            DHCPMGR_LOG_ERROR("%s:%d, Failed to insert node for interface %s\n", __FUNCTION__, __LINE__, pLanConfig[i].bridgeInfo.bridgeName);
            free(pIface);
        }
        else
        {
            (*pDhcpIfacesCount)++;
            DHCPMGR_LOG_INFO("%s:%d, Added interface %s to DHCP configuration, count: %d\n",
                    __FUNCTION__, __LINE__, pLanConfig[i].bridgeInfo.bridgeName, *pDhcpIfacesCount);
        }*/
    }
}

int Construct_dhcp_configuration(DhcpInterfaceConfig ** ppHeadDhcpIf, int pDhcpIfacesCount, char * Input, GlobalDhcpConfig *pGlbDhcpCfg, LanConfig *pLanConfig)
{
    DomainAddress       *pDomainAddress   = NULL;
    RedirectionAddress  *pRedirectAddress = NULL;
    DhcpOptionsList     *pDhcpOptionsList = NULL;
    DhcpVendorClassList *pDhcpVendorClass = NULL;

    DhcpOptionsList     * pHeadDhcpOptionsList = NULL;
    DhcpVendorClassList * pHeadDhcpVendorClass = NULL;
    DomainAddress       * pHeadDomainAddress   = NULL;
    RedirectionAddress  * pHeadRedirectionAddr = NULL;

    int  iDhcpOptionVendorCount = 0;
    int  iDhcpVendorClassCount  = 0;
    int  iDomainAddrCount       = 0;
    int  iRedirectionAddrCount  = 0;
//    int  iDhcpIfacesCount       = 0;
#ifdef RDKB_EXTENDER_ENABLED
    char cDevMode [BUFF_LEN_32]  = {0};
    char cBuf     [BUFF_LEN_512] = {0};
#endif /*RDKB_EXTENDER_ENABLED*/
    char cDnsOnlyPrefix     [BUFF_LEN_8]   = {0};
    char cSecWebUiEnabled   [BUFF_LEN_8]   = {0};
    char cWanCheck          [BUFF_LEN_16]  = {0};
    char cStatDnsEnabled    [BUFF_LEN_32]  = {0};
    char cDhcpNs1           [BUFF_LEN_128] = {0};
    char cDhcpNs2           [BUFF_LEN_128] = {0};
    char cLanIpAddress      [BUFF_LEN_16]  = {0};
    char cLanNetMask        [BUFF_LEN_16]  = {0};
    char cLanIfName         [BUFF_LEN_16]  = {0};
    char cCaptivePortalEn   [BUFF_LEN_8]   = {0};
    char cRedirectionFlag   [BUFF_LEN_8]   = {0};
    char cNetworkResult     [BUFF_LEN_8]   = {0};
    char cWifiNotConfigured [BUFF_LEN_8]   = {0};
    char cDhcpNsEnabled     [BUFF_LEN_32]  = {0};
    char cWanDhcpDns        [BUFF_LEN_256] = {0};
    char cPropagateWanDomain[BUFF_LEN_8]   = {0};
    char cLanDomain         [BUFF_LEN_32]  = {0};
    char cLanStatus         [BUFF_LEN_16]  = {0};
    char cIotEnabled        [BUFF_LEN_16]  = {0};
    char cIotIfName         [BUFF_LEN_16]  = {0};
//    char cIotStartAddr      [BUFF_LEN_16]  = {0};
//    char cIotEndAddr        [BUFF_LEN_16]  = {0};
//    char cIotNetMask        [BUFF_LEN_16]  = {0};
//    char cDhcpServerEnable  [BUFF_LEN_16]  = {0};
    char l_cLog_Level         [BUFF_LEN_8] = {0};

  //  bool bRfCaptive         = false;
    bool bCaptivePortalMode = false;
  //  bool bCaptiveCheck      = false;
    bool bIsDhcpNsEnabled   = false;
    bool bIsValidWanDhcpNs  = false;
    BOOL l_bCaptive_Check = FALSE;
    BOOL l_bRfCp = FALSE;
    BOOL l_bMig_Case = TRUE;
    BOOL l_bWifi_Res_Mig = FALSE;
//    BOOL l_bDhcpNs_Enabled = FALSE;
//    BOOL l_bIsValidWanDHCPNs = FALSE;

    char *pPsmGet          = NULL;
    int  iRetVal            = -1;
    int  iRetryCount        = 0;
    int  iMkDirRes          = -1;
    int l_iRet_Val;
    FILE *fpNetResult       = NULL;
    FILE *fpDefaultResolv   = NULL;
    FILE *l_fLocal_Dhcp_ConfFile = NULL;
#if defined (_XB6_PRODUCT_REQ_)
    char cRfCaptiveFeatureEnabled   [BUFF_LEN_8] = {0};
    char cRfCaptivePortEnabled      [BUFF_LEN_8] = {0};
#endif

    if ((NULL == Input) && ((NULL == ppHeadDhcpIf) || (NULL == pGlbDhcpCfg)))
    {
        DHCPMGR_LOG_INFO("%s:%d, NULL parameter passed", __FUNCTION__, __LINE__);
        return -1;
    }
    else if (NULL != Input)
    {
        if (0 > pDhcpIfacesCount)
        {
           DHCPMGR_LOG_INFO("%s:%d, No interface available ,exiting...!!", __FUNCTION__, __LINE__);
           return -1;
        }
       /* if (NULL == pGlbDhcpCfg)
        {
            return -1;
 //           pGlbDhcpCfg = &sGlbDhcpCfg; //this will give undefined behaviour
        } */
    }
    Add_inf_to_dhcp_config(pLanConfig, pDhcpIfacesCount, ppHeadDhcpIf, pDhcpIfacesCount);

// Lan interface and names were comes in LAN Config  // TODO LIST
 /*   DhcpIfaces *pPrivateLan = (DhcpIfaces*) malloc (sizeof(DhcpIfaces));
    if (NULL == pPrivateLan)
    {
        fprintf(g_fArmConsoleLog, "Failed to allocate the memory for DhcpIfaces structure\n");
        return -1;
    }

    memset(pPrivateLan, 0, sizeof(DhcpIfaces));
    pPrivateLan->sDhcpIfcfg.bIsDhcpEnabled = false;
    pPrivateLan->next = NULL;
    snprintf(pPrivateLan->sDhcpIfcfg.cLeaseDuration,sizeof(pPrivateLan->sDhcpIfcfg.cLeaseDuration),"%s",g_cDhcp_Lease_Time);

    // DHCP Server Enabled
    syscfg_get(NULL, "dhcp_server_enabled", cDhcpServerEnable, sizeof(cDhcpServerEnable));

    if (!strncmp(cDhcpServerEnable, "1", 1))
    {
        pPrivateLan->sDhcpIfcfg.bIsDhcpEnabled = true;
    }
 */

#ifdef RDKB_EXTENDER_ENABLED
    syscfg_get(NULL, "Device_Mode", cDevMode, sizeof(cDevMode));
    if (1 == atoi(cDevMode))
    {
        /*
         * Modem/Extender mode:
         * Start dnsmasq to assign IP address for to the tunnel interface
         */

        // set IP to interface to which dnsmasq should listen
        char *pPsmStrVal = NULL;
        char cMeshWanIfname[BUFF_LEN_16] = {0};

        //Mesh wan Iface details
        // Lan interface and names were comes in LAN Config  // TODO LIST
        /*
        DhcpIfaces *pMeshWanIf = malloc (sizeof(DhcpIfaces));
        if (NULL == pMeshWanIf)
        {
            fprintf(g_fArmConsoleLog, "%s:%d Failed to allocate memory\n",__FUNCTION__, __LINE__);
            return -1;
        }
       */
        memset(cMeshWanIfname, 0, sizeof(cMeshWanIfname));

        iRetVal = PSM_VALUE_GET_STRING(MESH_WAN_IFNAME, pPsmStrVal);

        if (CCSP_SUCCESS == iRetVal && pPsmStrVal != NULL)
        {
            strncpy(cMeshWanIfname, pPsmStrVal, sizeof(cMeshWanIfname));
            DHCPMGR_LOG_INFO("mesh_wan_ifname is %s", cMeshWanIfname);
            Ansc_FreeMemory_Callback(pPsmStrVal);
            pPsmStrVal = NULL;
        }
        v_secure_system("ip addr add "GRE_VLAN_IFACE_IP"/24 dev %s", cMeshWanIfname);

        snprintf(pGlbDhcpCfg->cResolvCfgFile, sizeof(pGlbDhcpCfg->cResolvCfgFile),"%s", TMP_RESOLVE_CONF);
        snprintf(pGlbDhcpCfg->cDhcpLeaseFile, sizeof(pGlbDhcpCfg->cDhcpLeaseFil),"%s", DHCP_LEASE_FILE);

        // Lan interface and names were comes in LAN Config  // TODO LIST
        /*
        pMeshWanIf->sDhcpIfcfg.bIsDhcpEnabled = true;
        snprintf(pMeshWanIf->sDhcpIfcfg.cGatewayName, sizeof(pMeshWanIf->sDhcpIfcfg.cGatewayName),"%s",cMeshWanIfname);
        snprintf(pMeshWanIf->sDhcpIfcfg.cSubnetMask, sizeof(pMeshWanIf->sDhcpIfcfg.cSubnetMask),"%s",GRE_VLAN_IFACE_NETMASK);
        snprintf(pMeshWanIf->sDhcpIfcfg.cLeaseDuration, sizeof(pMeshWanIf->sDhcpIfcfg.cLeaseDuration),"%s", GRE_VLAN_IFACE_DHCP_LEASE);

        snprintf(pMeshWanIf->sDhcpIfcfg.sAddressPool.cStartAddress, sizeof(pMeshWanIf->sDhcpIfcfg.sAddressPool.cStartAddress),"%s",GRE_VLAN_IFACE_DHCP_START);
        snprintf(pMeshWanIf->sDhcpIfcfg.sAddressPool.cEndAddress, sizeof(pMeshWanIf->sDhcpIfcfg.sAddressPool.cEndAddress),"%s",GRE_VLAN_IFACE_DHCP_END);
        pMeshWanIf->sDhcpIfcfg.sAddressPool.iDhcpTagNum = 0;
        pMeshWanIf->next = NULL;
        insertNode (ppHeadDhcpIf, pMeshWanIf, DHCP_INTERFACE_CONFIG);
        *pDhcpIfacesCount = *pDhcpIfacesCount +1;
        configListUpdate(ppHeadDhcpIf, pDhcpIfacesCount);
        */
        pDhcpOptionsList = malloc (sizeof(DhcpOptionsList));
        if (NULL == pDhcpOptionsList)
        {
            DHCPMGR_LOG_INFO("%s:%d, DHCP SERVER: Failed to allocate the memory", __FUNCTION__, __LINE__);
            return -1;
        }
        pDhcpOptionsList->next = NULL;

        // Add DHCP option 43: Vendor specific data
        memset (cBuf, 0, sizeof(cBuf));
        ifl_get_event("dhcpv4_option_43", cBuf, sizeof(cBuf));
        if (('\0' != cBuf[0]) && (strlen(cBuf) > 0))
        {
            snprintf(pDhcpOptionsList->cDhcpOptions, sizeof(pDhcpOptionsList->cDhcpOptions), "%s", cBuf);
            iDhcpOptionVendorCount++;
            pHeadDhcpOptionsList = pDhcpOptionsList;
        }
        return 0;
    }
#endif
    // prepare dhcp config file for GATEWAY mode

    if ((NULL != Input) && (!strncmp(Input, "dns_only", 8)))
    {
        DHCPMGR_LOG_INFO("dns_only case prefix is #");
        cDnsOnlyPrefix[0] = '#';
    }

    syscfg_get(NULL, "SecureWebUI_Enable", cSecWebUiEnabled, sizeof(cSecWebUiEnabled));
    ifl_get_event("phylink_wan_state", cWanCheck, sizeof(cWanCheck));
    if (!strncmp(cSecWebUiEnabled, "true", 4))
    {
        if(!strncmp(cWanCheck, "up", 2))
        {
            syscfg_set(NULL, "dhcpv6spool00::X_RDKCENTRAL_COM_DNSServersEnabled", "1");
            syscfg_set(NULL, "dhcp_nameserver_enabled", "1");
            syscfg_commit();
        }
        else
        {
            syscfg_get(NULL, "dhcp_nameserver_enabled", cStatDnsEnabled, sizeof(cStatDnsEnabled));
            syscfg_get(NULL, "dhcp_nameserver_1", cDhcpNs1, sizeof(cDhcpNs1));
            syscfg_get(NULL, "dhcp_nameserver_2", cDhcpNs2, sizeof(cDhcpNs2));
            if(('\0' != cStatDnsEnabled[0]) && ( 1 == atoi(cStatDnsEnabled)))
            {
                if(('\0' == cDhcpNs1[0]) || (0 == strcmp(cDhcpNs1, "0.0.0.0")))
                {
                    if(('\0' == cDhcpNs2[0]) || (0 == strcmp(cDhcpNs2, "0.0.0.0")))
                    {
                        syscfg_set_commit(NULL, "dhcp_nameserver_enabled", "0");
                    }
                }
            }
        }
    }
    else
    {
        syscfg_get(NULL, "dhcp_nameserver_enabled", cStatDnsEnabled, sizeof(cStatDnsEnabled));
        syscfg_get(NULL, "dhcp_nameserver_1", cDhcpNs1, sizeof(cDhcpNs1));
        syscfg_get(NULL, "dhcp_nameserver_2", cDhcpNs2, sizeof(cDhcpNs2));
        if(('\0' != cStatDnsEnabled[0]) && (1 == atoi(cStatDnsEnabled)))
        {
            if(('\0' == cDhcpNs1[0]) || (0 == strcmp(cDhcpNs1, "0.0.0.0")))
            {
                if(('\0' == cDhcpNs2[0]) || (0 == strcmp(cDhcpNs2, "0.0.0.0")))
                {
                    syscfg_set_commit(NULL, "dhcp_nameserver_enabled", "0");
                }
            }
        }
    }
    syscfg_get(NULL, "lan_ipaddr", cLanIpAddress, sizeof(cLanIpAddress));
    syscfg_get(NULL, "lan_netmask", cLanNetMask, sizeof(cLanNetMask));
    syscfg_get(NULL, "lan_ifname", cLanIfName, sizeof(cLanIfName));
    syscfg_get(NULL, "CaptivePortal_Enable", cCaptivePortalEn, sizeof(cCaptivePortalEn));
    syscfg_get(NULL, "redirection_flag", cRedirectionFlag, sizeof(cRedirectionFlag));
#if defined (_XB6_PRODUCT_REQ_)
    syscfg_get(NULL, "enableRFCaptivePortal", cRfCaptiveFeatureEnabled, sizeof(cRfCaptiveFeatureEnabled));
    syscfg_get(NULL, "rf_captive_portal", cRfCaptivePortEnabled, sizeof(cRfCaptivePortEnabled));
#endif

    if((0 == isValidLANIP(cLanIpAddress)) || (0 == isValidSubnetMask(cLanNetMask)))
    {
        FILE *fpCmd;
        char cCmd        [BUFF_LEN_512] = {0};
        char cResult     [BUFF_LEN_128] = {0};
        char cLanIP      [BUFF_LEN_16]  = {0};
        char cLanNetMask2[BUFF_LEN_16]  = {0};
        char cDhcpStart  [BUFF_LEN_16]  = {0};
        char cDhcpEnd    [BUFF_LEN_16]  = {0};

        DHCPMGR_LOG_INFO("LAN IP Address OR LAN net mask is not in valid format, setting to default lan_ipaddr:%s lan_netmask:%s",cLanIpAddress,cLanNetMask);
        snprintf(cCmd,sizeof(cCmd),"grep '$lan_ipaddr\\|$lan_netmask\\|$dhcp_start\\|$dhcp_end' %s"
                " | awk '/\\$lan_ipaddr/ {split($1,ip, \"=\");}"
                " /\\$lan_netmask/ {split($1,mask, \"=\");}"
                " /\\$dhcp_start/ {split($1,start, \"=\");}"
                " /\\$dhcp_end/ {split($1,end, \"=\");}"
                " END {print ip[2], mask[2], start[2], end[2]}'",DEFAULT_FILE);

        DHCPMGR_LOG_INFO("Command = %s",cCmd);

        if ((fpCmd = popen(cCmd, "r")) == NULL)
        {
            DHCPMGR_LOG_ERROR("popen ERROR");
        }
        else if (fgets(cResult, sizeof(cResult), fpCmd) == NULL)
        {
            pclose(fpCmd);
            DHCPMGR_LOG_ERROR("popen fgets ERROR");
        }
        else
        {
            sscanf(cResult, "%s %s %s %s",cLanIP, cLanNetMask2, cDhcpStart, cDhcpEnd);

            syscfg_set(NULL, "lan_ipaddr", cLanIP);
            syscfg_set(NULL, "lan_netmask", cLanNetMask2);
            syscfg_set(NULL, "dhcp_start", cDhcpStart);
            syscfg_set(NULL, "dhcp_end", cDhcpEnd);
            syscfg_commit();

            memset(cLanIpAddress, 0, sizeof(cLanIpAddress));
            strncpy(cLanIpAddress,cLanIP,sizeof(cLanIpAddress));

            memset(cLanNetMask, 0, sizeof(cLanNetMask));
            strncpy(cLanNetMask,cLanNetMask2,sizeof(cLanNetMask));

            pclose(fpCmd);
        }
    }


    // Static LAN DNS (brlan0)
    syscfg_get(NULL, "dhcp_nameserver_enabled", cDhcpNsEnabled, sizeof(cDhcpNsEnabled));
    if(('\0' != cDhcpNsEnabled[0]) && (1 == atoi(cDhcpNsEnabled)))
    {
        bIsDhcpNsEnabled = true;
    }

    // Get proper wan dns server list and check whether wan-dns is valid or not
    check_and_get_wan_dhcp_dns(cWanDhcpDns);
    if('\0' != cWanDhcpDns[0])
    {
        bIsValidWanDhcpNs = true;
    }

    fpNetResult = fopen(NETWORK_RES_FILE, "r");
    if (NULL == fpNetResult)
    {
        DHCPMGR_LOG_INFO("%s file is not present ", NETWORK_RES_FILE);
    }
    else
    {
        /* CID 60600: Unchecked return value from library */
        if ((fscanf(fpNetResult,"%s", cNetworkResult)) != 1)
        {
            DHCPMGR_LOG_INFO("read error of %s \n",NETWORK_RES_FILE);
        }

        fclose(fpNetResult);
    }

    iRetVal = PSM_VALUE_GET_STRING(PSM_NAME_NOTIFY_WIFI_CHANGES, pPsmGet);
    while ((CCSP_SUCCESS != iRetVal && pPsmGet == NULL) && (iRetryCount++ < 2))
    {
        iRetVal = PSM_VALUE_GET_STRING(PSM_NAME_NOTIFY_WIFI_CHANGES, pPsmGet);
    }
    if (CCSP_SUCCESS == iRetVal && pPsmGet != NULL)
    {
        strncpy(cWifiNotConfigured, pPsmGet, sizeof(cWifiNotConfigured));
        DHCPMGR_LOG_INFO("DHCP SERVER : NotifyWiFiChanges is %s\n", cWifiNotConfigured);
        Ansc_FreeMemory_Callback(pPsmGet);
        pPsmGet = NULL;
    }
    else
    {
        DHCPMGR_LOG_ERROR("DHCP SERVER : Error:%d while getting:%s or value is empty\n",
                iRetVal, PSM_NAME_NOTIFY_WIFI_CHANGES);
    }
    DHCPMGR_LOG_INFO("DHCP SERVER : CaptivePortal_Enabled is %s\n", cCaptivePortalEn);

    if (IS_MIG_CHECK_NEEDED(g_cMig_Check))
    {
        DHCPMGR_LOG_INFO("Wifi Migration checks are needed");

        char l_cMigCase[8] = {0};
        syscfg_get(NULL, "migration_cp_handler", l_cMigCase, sizeof(l_cMigCase));
        if(!strncmp(l_cMigCase, "true", 4))
        {
            DHCPMGR_LOG_INFO("DHCP SERVER : Initialize migration case variable to true");
            l_bMig_Case = TRUE;
        }
        else
        {
            DHCPMGR_LOG_INFO("DHCP SERVER : Initialize migration case variable to false");
            l_bMig_Case = FALSE;
        }
        char l_cWan_Service_Stat[16] = {0};
        ifl_get_event("wan_service-status", l_cWan_Service_Stat, sizeof(l_cWan_Service_Stat));

        int l_iRetry_Count = 0;
        l_iRet_Val = PSM_VALUE_GET_STRING(PSM_NAME_WIFI_RES_MIG, pPsmGet);
        while ((CCSP_SUCCESS != l_iRet_Val && pPsmGet == NULL) &&
               (l_iRetry_Count++ < 2))
        {
            l_iRet_Val = PSM_VALUE_GET_STRING(PSM_NAME_WIFI_RES_MIG, pPsmGet);
        }
        if (CCSP_SUCCESS == l_iRet_Val && pPsmGet != NULL)
        {
            /* BUFFER_SIZE_WARNING */
            if(!strncmp(pPsmGet, "true", 4))
            {
                l_bWifi_Res_Mig = TRUE;
            }
            else
            {
                l_bWifi_Res_Mig = FALSE;
            }
            DHCPMGR_LOG_INFO("DHCP SERVER : WiFiRestored_AfterMigration is %d", l_bWifi_Res_Mig);
            Ansc_FreeMemory_Callback(pPsmGet);
            pPsmGet = NULL;
        }
        else
        {
            DHCPMGR_LOG_ERROR("DHCP SERVER : Error:%d while getting:%s or value is empty",
                              l_iRet_Val, PSM_NAME_WIFI_RES_MIG);
        }

        if (l_bMig_Case && l_bWifi_Res_Mig)
        {
            DHCPMGR_LOG_INFO("DHCP SERVER : WiFi restored case setting MIGRATION_CASE variable to false");
            l_bMig_Case = FALSE;
        }
    }
    else
    {
        DHCPMGR_LOG_INFO("Migration checks are not needed");
    }

    if (IS_MIG_CHECK_NEEDED(g_cMig_Check))
    {
        l_bCaptive_Check = ((!strncmp(cCaptivePortalEn, "true", 4)) && (FALSE == l_bMig_Case)) ? (TRUE) : (FALSE);
    }
    else
    {
        l_bCaptive_Check = (!strncmp(cCaptivePortalEn, "true", 4)) ? (TRUE) : (FALSE);
    }

    if (l_bCaptive_Check)
    {
#if defined (_XB6_PRODUCT_REQ_)
        if ((!strncmp(cRfCaptiveFeatureEnabled,"true",4)) && (!strncmp(cRfCaptivePortEnabled,"true",4)))
        {
            l_bRfCp = TRUE;
        }
        if  ( (TRUE== l_bRfCp ) || ((!strncmp(cNetworkResult, "204", 3)) && (!strncmp(cRedirectionFlag, "true", 4)) &&
              (!strncmp(cWifiNotConfigured, "true", 4))))
        {
            bCaptivePortalMode = TRUE;
            if (TRUE== l_bRfCp )
            {
                DHCPMGR_LOG_INFO("DHCP SERVER : NO RF CAPTIVE_PORTAL_MODE");
            }
            else
            {
                DHCPMGR_LOG_INFO("DHCP SERVER : WiFi SSID and Passphrase are not modified,set CAPTIVE_PORTAL_MODE");
                t2_event_d("SYS_INFO_CaptivePortal", 1);
                if (access("/nvram/reverted", F_OK) == 0) //If file is present
                {
                    DHCPMGR_LOG_INFO("DHCP SERVER : Removing reverted flag");
                    remove_file("/nvram/reverted");
                }
            }
        }
        else
        {
            bCaptivePortalMode = FALSE;
            DHCPMGR_LOG_INFO("DHCP SERVER : WiFi SSID and Passphrase are already modified");
            DHCPMGR_LOG_INFO(" or no network response ,set CAPTIVE_PORTAL_MODE to false");
        }
#else
        if  ((!strncmp(cNetworkResult, "204", 3)) && (!strncmp(cRedirectionFlag, "true", 4)) &&
              (!strncmp(cWifiNotConfigured, "true", 4)))
        {
            bCaptivePortalMode = TRUE;
            DHCPMGR_LOG_INFO("DHCP SERVER : WiFi SSID and Passphrase are not modified,set CAPTIVE_PORTAL_MODE");
            t2_event_d("SYS_INFO_CaptivePortal", 1);
            if (access("/nvram/reverted", F_OK) == 0) //If file is present
            {
                DHCPMGR_LOG_INFO("DHCP SERVER : Removing reverted flag");
                remove_file("/nvram/reverted");
            }
        }
        else
        {
            bCaptivePortalMode = FALSE;
            DHCPMGR_LOG_INFO("DHCP SERVER : WiFi SSID and Passphrase are already modified");
            DHCPMGR_LOG_INFO(" or no network response ,set CAPTIVE_PORTAL_MODE to false");
        }
#endif
    }

    // Dont add resolv-file if in norf captive portal mode
    if(FALSE == l_bRfCp)
    {
        /*       fprintf(l_fLocal_Dhcp_ConfFile, "domain-needed\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "bogus-priv\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "address=/.c.f.ip6.arpa/\n"); */

        char cStrVar   [BUFF_LEN_64] = {0};
        pGlbDhcpCfg->bDomainNeeded = true;
        pGlbDhcpCfg->bBogusPriv    = true;

        snprintf(cStrVar, sizeof(cStrVar),"/.c.f.ip6.arpa/"),
        pDomainAddress =(DomainAddress*)initNode(cStrVar, DOMAIN_SPECIFIC_ADDRESS);
        if (NULL != pDomainAddress)
        {
            DHCPMGR_LOG_INFO("%s:%d: DomainAddress:%s\n", __FUNCTION__, __LINE__, pDomainAddress->cDomainSpecificAddr);
            if (!insertNode((void*)&pHeadDomainAddress, (void*)pDomainAddress, DOMAIN_SPECIFIC_ADDRESS))
            {
                iDomainAddrCount++;
                DHCPMGR_LOG_INFO("%s:%d, iDomainAddrCount:%d\n", __FUNCTION__, __LINE__, iDomainAddrCount);
            }
        }
        else
        {
            DHCPMGR_LOG_ERROR("DHCP SERVER : DomainAddress creation failed\n");
        }

        if (true == bCaptivePortalMode)
        {
            // Create a temporary resolv configuration file
            // Pass that as an option in DNSMASQ
            iMkDirRes = mkdir(DEFAULT_CONF_DIR, S_IRUSR | S_IWUSR);
            //mkdir successful or already exists
            if (0 == iMkDirRes || (0 != iMkDirRes && EEXIST == errno))
            {
                fpDefaultResolv = fopen(DEFAULT_RESOLV_CONF, "a+");
                if (NULL != fpDefaultResolv)
                {
                    fprintf(fpDefaultResolv, "nameserver 127.0.0.1\n");
                    snprintf(pGlbDhcpCfg->cResolvCfgFile, sizeof(pGlbDhcpCfg->cResolvCfgFile),"%s",DEFAULT_RESOLV_CONF);
                    fclose(fpDefaultResolv);
                }
                else
                {
                    DHCPMGR_LOG_ERROR("%s file creation failed\n", DEFAULT_RESOLV_CONF);
                }
            }
        }
        else
        {
            if ((access(DEFAULT_RESOLV_CONF, F_OK) == 0)) //DEFAULT_RESOLV_CONF file exists
            {
                remove_file(DEFAULT_RESOLV_CONF);
            }

            if(false == bIsDhcpNsEnabled )
            {
                snprintf(pGlbDhcpCfg->cResolvCfgFile, sizeof(pGlbDhcpCfg->cResolvCfgFile),"%s",RESOLV_CONF);
            }
        }

        //Propagate Domain
        syscfg_get(NULL, "dhcp_server_propagate_wan_domain", cPropagateWanDomain, sizeof(cPropagateWanDomain));

        // if we are provisioned to use the wan domain name, the we do so
        // otherwise we use the lan domain name
        if (!strncmp(cPropagateWanDomain, "1", 1))
        {
            ifl_get_event("dhcp_domain", cLanDomain, sizeof(cLanDomain));
        }
        if (0 == cLanDomain[0])
        {
            syscfg_get(NULL, "lan_domain", cLanDomain, sizeof(cLanDomain));
        }
        if (0 != cLanDomain[0])
        {
            snprintf(pGlbDhcpCfg->cDomain, sizeof(pGlbDhcpCfg->cDomain), "%s", cLanDomain);
        }
    }
    /*    else
    {
            fprintf(l_fLocal_Dhcp_ConfFile, "no-resolv\n");
    }
    */
    pGlbDhcpCfg->bExpandHosts = true;

    //Log Level is not used but still retaining the code
    syscfg_get(NULL, "log_level", l_cLog_Level, sizeof(l_cLog_Level));

    if ((NULL != Input) && (!strncmp(Input, "dns_only", 8)))
    {
#if 0 //TBD
        fprintf(l_fLocal_Dhcp_ConfFile, "no-dhcp-interface=%s\n", cLanIfName);
#endif
    }
    else
    {
        snprintf(pGlbDhcpCfg->cDhcpLeaseFile, sizeof(pGlbDhcpCfg->cDhcpLeaseFile), "%s", DHCP_LEASE_FILE);
        snprintf(pGlbDhcpCfg->cDhcpHostsFile, sizeof(pGlbDhcpCfg->cDhcpHostsFile), "%s", DHCP_STATIC_HOSTS_FILE);
        if ((false == bCaptivePortalMode) && (false == bIsDhcpNsEnabled))
        {
            snprintf(pGlbDhcpCfg->cDhcpOptsFile, sizeof(pGlbDhcpCfg->cDhcpOptsFile), "%s", DHCP_OPTIONS_FILE);
        }
    }

    int iDhcpOptonCount = sizeof(dhcpOptionsArray) / sizeof(dhcpOptionsArray[0]);
    for (int iCount = 0; iCount < iDhcpOptonCount; iCount++)
    {
        pDhcpOptionsList = (DhcpOptionsList*)initNode(dhcpOptionsArray[iCount].cDhcpOptions, DHCP_OPTION);
        if (NULL != pDhcpOptionsList)
        {
            DHCPMGR_LOG_INFO("%s:%d: dhcpOption:%s\n", __FUNCTION__, __LINE__, pDhcpOptionsList->cDhcpOptions);
            if (!insertNode((void*)&pHeadDhcpOptionsList, (void*)pDhcpOptionsList, DHCP_OPTION))
            {
                iDhcpOptionVendorCount++;
                DHCPMGR_LOG_INFO("%s:%d, iCount:%d, iDhcpOptionVendorCount:%d\n", __FUNCTION__, __LINE__, iCount, iDhcpOptionVendorCount);
            }
        }
        else
        {
            DHCPMGR_LOG_ERROR("%s:%d, Failed to init Node\n", __FUNCTION__, __LINE__);
        }
    }

    pDhcpVendorClass = (DhcpVendorClassList*)initNode("set:extender,WNXL11BWL", DHCP_VENDOR_CLASS);
    if (NULL != pDhcpVendorClass)
    {
        DHCPMGR_LOG_INFO("%s:%d: dhcpVendorClass:%s\n", __FUNCTION__, __LINE__, pDhcpVendorClass->cVendorClass);
        if (!insertNode((void*)&pHeadDhcpVendorClass, (void*)pDhcpVendorClass, DHCP_VENDOR_CLASS))
        {
            iDhcpVendorClassCount++;
            DHCPMGR_LOG_INFO("%s:%d, iDhcpVendorClassCount:%d\n", __FUNCTION__, __LINE__, iDhcpVendorClassCount);
        }
    }
    else
    {
        DHCPMGR_LOG_ERROR("%s:%d, Failed to init Node\n", __FUNCTION__, __LINE__);
    }
    char cTimeOffset[BUFF_LEN_32] = {0};
    FILE *fp = popen("dmcli eRT retv Device.Time.TimeOffset", "r");
    if (fp)
    {
        fgets(cTimeOffset, sizeof(cTimeOffset), fp);
        pclose(fp);

        if (strlen(cTimeOffset))
        {
            char cStrVar[BUFF_LEN_128] = {0};
            snprintf(cStrVar, sizeof(cStrVar), "tag:extender, option:time-offset,%s", cTimeOffset);
            pDhcpOptionsList = (DhcpOptionsList*)initNode(cStrVar, DHCP_OPTION);
            if (NULL != pDhcpOptionsList)
            {
                DHCPMGR_LOG_INFO("%s:%d: dhcpOption:%s\n", __FUNCTION__, __LINE__, pDhcpOptionsList->cDhcpOptions);
                if (!insertNode((void*)&pHeadDhcpOptionsList, (void*)pDhcpOptionsList, DHCP_OPTION))
                {
                    iDhcpOptionVendorCount++;
                    DHCPMGR_LOG_INFO("%s:%d, iDhcpOptionVendorCount:%d\n", __FUNCTION__, __LINE__, iDhcpOptionVendorCount);
                }
            }
            else
            {
                DHCPMGR_LOG_ERROR("%s:%d, Failed to init Node\n", __FUNCTION__, __LINE__);
            }
        }
        else
        {
            DHCPMGR_LOG_ERROR("%s:%d, Failed to get TimeOffset\n", __FUNCTION__, __LINE__);
        }
    }
    else
    {
        DHCPMGR_LOG_ERROR("%s:%d, Failed to get TimeOffset\n", __FUNCTION__, __LINE__);
    }
    /*        //Not taking into account prefix
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-leasefile=%s\n", DHCP_LEASE_FILE);
    #if 0
    //DHCP_NUM is the number of available dhcp address for the lan
    syscfg_get(NULL, "dhcp_num", l_cDhcp_Num, sizeof(l_cDhcp_Num));
    if (0 == l_cDhcp_Num[0])
    {
        DHCPMGR_LOG_INFO("DHCP NUM is empty, set the dhcp_num integer as zero");
        l_idhcp_num = 0;
    }
    else
    {
        l_idhcp_num = atoi(l_cDhcp_Num);
        DHCPMGR_LOG_INFO("DHCP NUM is not empty it is :%d", l_idhcp_num);
    }
    fprintf(l_fLocal_Dhcp_ConfFile, "%sdhcp-lease-max=%d\n", l_cDns_Only_Prefix, l_idhcp_num);
    #endif
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-hostsfile=%s\n", DHCP_STATIC_HOSTS_FILE);

    if ( ( FALSE == bCaptivePortalMode) &&\
            ( FALSE == bIsDhcpNsEnabled )
            )
    {
           fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-optsfile=%s\n", DHCP_OPTIONS_FILE);
    }

//Ethernet Backhaul changes for plume pods
#if defined (_XB6_PRODUCT_REQ_) || defined (_HUB4_PRODUCT_REQ_)
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=vendor:Plume,43,tag=123\n");
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=vendor:PP203X,43,tag=123\n");
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=vendor:HIXE12AWR,43,tag=123\n");
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=vendor:WNXE12AWR,43,tag=123\n");
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=vendor:SE401,43,tag=123\n");
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=vendor:WNXL11BWL,43,tag=123\n");
#endif
    */
        if ((NULL == Input) ||
               ((NULL != Input) && (strncmp(Input, "dns_only", 8)))) //not dns_only case
        {
            DHCPMGR_LOG_INFO("not dns_only case calling other prepare functions");
            prepare_dhcp_conf_static_hosts();
            prepare_dhcp_options_wan_dns();
        }

    #if defined (_XB6_PRODUCT_REQ_) || defined (_CBR_PRODUCT_REQ_)
        {
        struct in_addr ipv4Addr;
        int    ret = -1;
        int    resComp = -1;
        char   nmSrv[32]    = {0};
        char   dnsIP[64]    = {0};
        char   leftOut[128] = {0};
        char   ns_ip[256]   = {0};
        FILE*  fp1 = NULL;
        FILE*  fp2 = NULL;
     
        if ((fp1 = fopen(RESOLV_CONF, "r")))
        {
            while ( memset(nmSrv,   0, sizeof(nmSrv)),
                memset(dnsIP,   0, sizeof(dnsIP)),
                memset(leftOut, 0, sizeof(leftOut)),
                fscanf(fp1, "%s %s%[^\n]s\n", nmSrv, dnsIP, leftOut) != EOF)
            {
            ret = strcmp_s(nmSrv, sizeof(nmSrv), "nameserver", &resComp);
            ERR_CHK(ret);

            if (!ret && !resComp)
            {
                if (inet_pton(AF_INET, dnsIP, &ipv4Addr) > 0)
                {
                ret = strcat_s(ns_ip, sizeof(ns_ip), ",");
                ERR_CHK(ret);

                ret = strcat_s(ns_ip, sizeof(ns_ip), dnsIP);
                ERR_CHK(ret);
                }
            }
            }
            fclose(fp1);

            if (*ns_ip && (fp2 = fopen(DHCP_OPTIONS_FILE, "w")))
            {
            fprintf(fp2, "option:dns-server%s\n", ns_ip);
            fclose(fp2);
            }
            else
            {
            DHCPMGR_LOG_ERROR("DHCP_SERVER : Error in opening %s", DHCP_OPTIONS_FILE);
            }
        }
        else
        {
            DHCPMGR_LOG_ERROR("DHCP_SERVER : Error in opening %s", RESOLV_CONF);
        }
        }
    #endif

        ifl_get_event("lan-status", cLanStatus, sizeof(cLanStatus));
        DHCPMGR_LOG_INFO("%s:%d, DHCP_SERVER : LanStatus: %s", __FUNCTION__, __LINE__, cLanStatus);
        if ((!strncmp(cLanStatus, "started", 7)) && ('#' != cDnsOnlyPrefix[0]))
        {
            // calculate_dhcp_range has code to write dhcp-range
/*            snprintf(pPrivateLan->sDhcpIfcfg.cGatewayName, sizeof(pPrivateLan->sDhcpIfcfg.cGatewayName), "%s", cLanIfName);
            calculateDhcpRange(pPrivateLan, cDnsOnlyPrefix);

            if (!insertNode((void*)ppHeadDhcpIf, pPrivateLan, DHCP_INTERFACE_CONFIG))
            {
            pDhcpIfacesCount += 1;
            DHCPMGR_LOG_INFO("Brlan0:pDhcpIfacesCount: %d", pDhcpIfacesCount);
            }
            */
            DHCPMGR_LOG_INFO("%s:%d, DHCP_SERVER : bIsDhcpNsEnabled: %d", __FUNCTION__, __LINE__, bIsDhcpNsEnabled);
            if (true == bIsDhcpNsEnabled)
            {
            char cDhcpNsOptionStr[BUFF_LEN_1024] = {0};
            get_dhcp_option_for_brlan0(cDhcpNsOptionStr);
            DHCPMGR_LOG_INFO("%s:%d, DHCP_SERVER : [%s] %s", __FUNCTION__, __LINE__, cLanIfName, cDhcpNsOptionStr);
            if (('\0' != cDhcpNsOptionStr[0]) && (0 < strlen(cDhcpNsOptionStr)))
            {
                for (int i = 0; i < pDhcpIfacesCount; i++) 
                {
                    if (strcmp(ppHeadDhcpIf[i]->cGatewayName, cLanIfName) == 0) 
                    {
                        ppHeadDhcpIf[i]->sDhcpNameServer.bDhcpNameServerEnabled = true;
                        snprintf(ppHeadDhcpIf[i]->sDhcpNameServer.cDhcpNameServerIp, sizeof(ppHeadDhcpIf[i]->sDhcpNameServer.cDhcpNameServerIp), "%s", cDhcpNsOptionStr);
                        break;
                    }
                }
            }

            if (!strncmp(cSecWebUiEnabled, "true", 4))
            {
                char cLocFqdn[BUFF_LEN_16] = {0};
                char cCurLanIp[BUFF_LEN_16] = {0};
                char cStrVar[BUFF_LEN_64] = {0};

                ifl_get_event("current_lan_ipaddr", cCurLanIp, sizeof(cCurLanIp));
                syscfg_get(NULL, "SecureWebUI_LocalFqdn", cLocFqdn, sizeof(cLocFqdn));

                snprintf(cStrVar, sizeof(cStrVar), "/%s/%s", cLocFqdn, cCurLanIp);
                pDomainAddress = (DomainAddress*)initNode(cStrVar, DOMAIN_SPECIFIC_ADDRESS);
                if (NULL != pDomainAddress)
                {
                if (!insertNode((void*)&pHeadDomainAddress, (void*)pDomainAddress, DOMAIN_SPECIFIC_ADDRESS))
                {
                    iDomainAddrCount++;
                    DHCPMGR_LOG_INFO("%s:%d, iDomainAddrCount:%d", __FUNCTION__, __LINE__, iDomainAddrCount);
                }
                }
                else
                {
                DHCPMGR_LOG_ERROR("%s:%d, Failed to init Node", __FUNCTION__, __LINE__);
                }

                pRedirectAddress = (RedirectionAddress*)initNode(cStrVar, REDIRECTION_ADDRESS);
                if (NULL != pRedirectAddress)
                {
                if (!insertNode((void*)&pHeadRedirectionAddr, (void*)pRedirectAddress, REDIRECTION_ADDRESS))
                {
                    iRedirectionAddrCount++;
                    DHCPMGR_LOG_INFO("%s:%d, iRedirectionAddrCount:%d", __FUNCTION__, __LINE__, iRedirectionAddrCount);
                }
                }
                else
                {
                DHCPMGR_LOG_ERROR("%s:%d, Failed to init Node", __FUNCTION__, __LINE__);
                }
            }
            DHCPMGR_LOG_INFO("DHCP_SERVER : [%s] %s", cLanIfName, cDhcpNsOptionStr);
            }
        }
        /*        if (!strncmp(cLanStatus, "started", 7))
            {
                // calculate_dhcp_range has code to write dhcp-range
                fprintf(l_fLocal_Dhcp_ConfFile, "interface=%s\n",cLanIfName);
                calculate_dhcp_range(l_fLocal_Dhcp_ConfFile, cDnsOnlyPrefix);


                // Add brlan0 custom dns server configuration
                if( bIsDhcpNsEnabled )
                {
                    char cDhcpNs_OptionString[ 1024 ] = { 0 };
                    get_dhcp_option_for_brlan0( cDhcpNs_OptionString );
                    fprintf(l_fLocal_Dhcp_ConfFile, "%s\n", cDhcpNs_OptionString);
                    if (!strncmp(cSecWebUiEnabled, "true", 4))
                    {
                        char  l_clocFqdn[16] = {0},l_cCurLanIP[16] = {0};
                        ifl_get_event( "current_lan_ipaddr", l_cCurLanIP, sizeof(l_cCurLanIP));
                        syscfg_get(NULL, "SecureWebUI_LocalFqdn", l_clocFqdn, sizeof(l_clocFqdn));
                        fprintf(l_fLocal_Dhcp_ConfFile, "address=/%s/%s\n",l_clocFqdn,l_cCurLanIP );
                        fprintf(l_fLocal_Dhcp_ConfFile, "server=/%s/%s\n",l_clocFqdn,l_cCurLanIP );
                    }
                    DHCPMGR_LOG_INFO("DHCP_SERVER : [%s] %s", cLanIfName, cDhcpNs_OptionString );
                 }
             }
        */
            // For boot time optimization, run do_extra_pools only when brlan1 interface is available
            // Ideally interface presence is done by passing SIOCGIFCONF and going thru the complete
            // Interface list but using SIOCGIFADDR	as it is only call to get IP Address of the interface
            // If the interface is not present then fecthing IPv4 address will fail with error ENODEV
            if (is_iface_present(XHS_IF_NAME))
            {
                DHCPMGR_LOG_INFO("%s interface is present creating dnsmasq", XHS_IF_NAME);
                doExtraPools(&pHeadDhcpOptionsList, &iDhcpOptionVendorCount, bIsDhcpNsEnabled, cWanDhcpDns);
            }
            else
            {
                DHCPMGR_LOG_INFO("%s interface is not present, not adding dnsmasq entries", XHS_IF_NAME);
            }

            //Lost And Found Enable
            syscfg_get(NULL, "lost_and_found_enable", cIotEnabled, sizeof(cIotEnabled));
        /*        if (!strncmp(cIotEnabled, "true", 4))
            {
            DHCPMGR_LOG_INFO("IOT_LOG : DHCP server configuring for IOT");

                syscfg_get(NULL, "iot_ifname", cIotIfName, sizeof(cIotIfName));

                if( strstr( cIotIfName, "l2sd0.106")) {
                  memset(cIotIfName, 0, sizeof(cIotIfName));
                  syscfg_get( NULL, "iot_brname", cIotIfName, sizeof(cIotIfName));
                }
                syscfg_get(NULL, "iot_dhcp_start", cIotStartAddr, sizeof(cIotStartAddr));
                syscfg_get(NULL, "iot_dhcp_end", cIotEndAddr, sizeof(cIotEndAddr));
                syscfg_get(NULL, "iot_netmask", cIotNetMask, sizeof(cIotNetMask));

            fprintf(l_fLocal_Dhcp_ConfFile, "interface=%s\n", cIotIfName);
                if (!strncmp(g_cDhcp_Lease_Time, "-1", 2))
                {
                    //TODO add dns_only prefix
                    fprintf(l_fLocal_Dhcp_ConfFile, "%sdhcp-range=%s,%s,%s,infinite\n",
                           cDnsOnlyPrefix, cIotStartAddr, cIotEndAddr, cIotNetMask);
                }
                else
                {
                    //TODO add dns_only prefix
                    fprintf(l_fLocal_Dhcp_ConfFile, "%sdhcp-range=%s,%s,%s,86400\n",
                           cDnsOnlyPrefix, cIotStartAddr, cIotEndAddr, cIotNetMask);
                }

                // Add iot custom dns server configuration
                if( bIsDhcpNsEnabled && bIsValidWanDhcpNs )
                {
                    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=%s,6,%s\n", cIotIfName, cWanDhcpDns);
                    DHCPMGR_LOG_INFO("DHCP_SERVER : [%s] dhcp-option=%s,6,%s",cIotIfName, cIotIfName, cWanDhcpDns);
                }
            }
        */
            if ((!strncmp(cIotEnabled, "true", 4)) && (true == bIsDhcpNsEnabled) && (true == bIsValidWanDhcpNs))
            {
            // Add iot custom dns server configuration
            char  cStrVar   [BUFF_LEN_512] = {0};
            snprintf(cStrVar, sizeof(cStrVar),"%s,6,%s",cIotIfName,cWanDhcpDns);
            DhcpOptionsList* pIotDhcpOptions = (DhcpOptionsList*)initNode(cStrVar,DHCP_OPTION);
            if (NULL != pIotDhcpOptions)
            {
                if (!insertNode ((void*)&pHeadDhcpOptionsList, (void*)pIotDhcpOptions , DHCP_OPTION))
                {
                iDhcpOptionVendorCount++;
                DHCPMGR_LOG_INFO("Iot:iDhcpOptionVendorCount: %d", iDhcpOptionVendorCount);
                }
            }
            else
            {
                DHCPMGR_LOG_ERROR("%s:%d, Failed to init Node", __FUNCTION__, __LINE__);
            }
            DHCPMGR_LOG_INFO("DHCP_SERVER : [%s] dhcp-option=%s,6,%s", cIotIfName, cIotIfName, cWanDhcpDns);
            }
            DHCPMGR_LOG_INFO("DHCP server configuring for Mesh network");

        #if defined (_COSA_INTEL_XB3_ARM_)
        #if 0
            fprintf(l_fLocal_Dhcp_ConfFile, "interface=l2sd0.112\n");
            fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.0.5,169.254.0.253,255.255.255.0,infinite\n");

            // Add l2sd0.112 custom dns server configuration
            if( bIsDhcpNsEnabled && bIsValidWanDhcpNs )
            {
            fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=l2sd0.112,6,%s\n", cWanDhcpDns);
            DHCPMGR_LOG_INFO("DHCP_SERVER : [l2sd0.112] dhcp-option=l2sd0.112,6,%s", cWanDhcpDns);
            }

            fprintf(l_fLocal_Dhcp_ConfFile, "interface=l2sd0.113\n");
            fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.1.5,169.254.1.253,255.255.255.0,infinite\n");

            // Add l2sd0.113 custom dns server configuration
            if( bIsDhcpNsEnabled && bIsValidWanDhcpNs )
            {
            fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=l2sd0.113,6,%s\n", cWanDhcpDns);
            DHCPMGR_LOG_INFO("DHCP_SERVER : [l2sd0.113] dhcp-option=l2sd0.113,6,%s", cWanDhcpDns);
            }

            // Mesh Bhaul vlan address pool

            fprintf(l_fLocal_Dhcp_ConfFile, "interface=br403\n");
            fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=192.168.245.2,192.168.245.253,255.255.255.0,infinite\n");

            // Add l2sd0.1060 custom dns server configuration
            if( bIsDhcpNsEnabled && bIsValidWanDhcpNs )
            {
            fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=br403,6,%s\n", cWanDhcpDns);
            DHCPMGR_LOG_INFO("DHCP_SERVER : [br403] dhcp-option=br403,6,%s", cWanDhcpDns);
            }

            fprintf(l_fLocal_Dhcp_ConfFile, "interface=l2sd0.4090\n");
            fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=192.168.251.2,192.168.251.253,255.255.255.0,infinite\n");

            // Add l2sd0.4090 custom dns server configuration
            if( bIsDhcpNsEnabled && bIsValidWanDhcpNs )
            {
            fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=l2sd0.4090,6,%s\n", cWanDhcpDns);
            DHCPMGR_LOG_INFO("DHCP_SERVER : [l2sd0.4090] dhcp-option=l2sd0.4090,6,%s", cWanDhcpDns);
            }

            fprintf(l_fLocal_Dhcp_ConfFile, "interface=brebhaul\n");
            fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.85.5,169.254.85.253,255.255.255.0,infinite\n");

            // Add brebhaul custom dns server configuration
            if( bIsDhcpNsEnabled && bIsValidWanDhcpNs )
            {
            fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=brebhaul,6,%s\n", cWanDhcpDns);
            DHCPMGR_LOG_INFO("DHCP_SERVER : [brebhaul] dhcp-option=brebhaul,6,%s", cWanDhcpDns);
            }
        #endif
        #elif defined (INTEL_PUMA7) || (defined (_COSA_BCM_ARM_) && !defined(_CBR_PRODUCT_REQ_)) || defined(_COSA_QCA_ARM_) // ARRIS XB6 ATOM, TCXB6
        //    fprintf(l_fLocal_Dhcp_ConfFile, "interface=ath12\n");
        //    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.0.5,169.254.0.253,255.255.255.0,infinite\n");

            // Add ath12 custom dns server configuration
            if( bIsDhcpNsEnabled && bIsValidWanDhcpNs )
            {
        //            fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=ath12,6,%s\n", cWanDhcpDns);
                char  cStrVar   [BUFF_LEN_512] = {0};
                snprintf(cStrVar, sizeof(cStrVar),"%s,6,%s","ath12",cWanDhcpDns);
                DhcpOptionsList* pDhcpOptions = (DhcpOptionsList*)initNode(cStrVar,DHCP_OPTION);
                if (NULL != pDhcpOptions)
                {
                if (!insertNode ((void*)&pHeadDhcpOptionsList, (void*)pDhcpOptions , DHCP_OPTION))
                {
                    iDhcpOptionVendorCount++;
                    DHCPMGR_LOG_INFO("%s:%d iDhcpOptionVendorCount:%d", __FUNCTION__, __LINE__, iDhcpOptionVendorCount);
                }
                }
                else
                {
                DHCPMGR_LOG_ERROR("%s:%d, Failed to init Node", __FUNCTION__, __LINE__);
                }   
                DHCPMGR_LOG_INFO("DHCP_SERVER : [ath12] dhcp-option=ath12,6,%s", cWanDhcpDns);
            }

        //    fprintf(l_fLocal_Dhcp_ConfFile, "interface=ath13\n");
        //    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.1.5,169.254.1.253,255.255.255.0,infinite\n");

            // Add ath12 custom dns server configuration
            if( bIsDhcpNsEnabled && bIsValidWanDhcpNs )
            {
         //           fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=ath13,6,%s\n", cWanDhcpDns);
                char  cStrVar   [BUFF_LEN_512] = {0};
                snprintf(cStrVar, sizeof(cStrVar),"%s,6,%s","ath13",cWanDhcpDns);
                DhcpOptionsList* pDhcpOptions = (DhcpOptionsList*)initNode(cStrVar,DHCP_OPTION);
                if (NULL != pDhcpOptions)
                {
                if (!insertNode ((void*)&pHeadDhcpOptionsList, (void*)pDhcpOptions , DHCP_OPTION))
                {
                    iDhcpOptionVendorCount++;
                    DHCPMGR_LOG_INFO("%s:%d, iDhcpOptionVendorCount:%d", __FUNCTION__, __LINE__, iDhcpOptionVendorCount);
                }
                }
                else
                {
                DHCPMGR_LOG_ERROR("%s:%d, Failed to init Node", __FUNCTION__, __LINE__);
                }
                DHCPMGR_LOG_INFO("DHCP_SERVER : [ath13] dhcp-option=ath13,6,%s", cWanDhcpDns);
            }

         //   fprintf(l_fLocal_Dhcp_ConfFile, "interface=br403\n");
         //   fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=192.168.245.2,192.168.245.253,255.255.255.0,infinite\n");

            // Add br403 custom dns server configuration
            if( bIsDhcpNsEnabled && bIsValidWanDhcpNs )
            {
        //        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=br403,6,%s\n", cWanDhcpDns);
            char cStrVar   [BUFF_LEN_512] = {0};
            snprintf(cStrVar, sizeof(cStrVar),"%s,6,%s","br403",cWanDhcpDns);
            DhcpOptionsList* pDhcpOptions = (DhcpOptionsList*)initNode(cStrVar,DHCP_OPTION);
            if (NULL != pDhcpOptions)
            {
                if (!insertNode ((void*)&pHeadDhcpOptionsList, (void*)pDhcpOptions , DHCP_OPTION))
                {
                iDhcpOptionVendorCount++;
                DHCPMGR_LOG_INFO("%s:%d iDhcpOptionVendorCount:%d", __FUNCTION__, __LINE__, iDhcpOptionVendorCount);
                }
            }
            else
            {
                DHCPMGR_LOG_ERROR("%s:%d, Failed to init Node", __FUNCTION__, __LINE__);
            }
            DHCPMGR_LOG_INFO("DHCP_SERVER : [br403] dhcp-option=br403,6,%s", cWanDhcpDns);
            }

        //    fprintf(l_fLocal_Dhcp_ConfFile, "interface=brebhaul\n");
        //    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.85.5,169.254.85.253,255.255.255.0,infinite\n");

            // Add brebhaul custom dns server configuration
            if( bIsDhcpNsEnabled && bIsValidWanDhcpNs )
            {
        //        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=brebhaul,6,%s\n", cWanDhcpDns);
            char cStrVar   [BUFF_LEN_512] = {0};
            snprintf(cStrVar, sizeof(cStrVar),"%s,6,%s","brebhaul",cWanDhcpDns);
            DhcpOptionsList* pDhcpOptions = (DhcpOptionsList*)initNode(cStrVar,DHCP_OPTION);
            if (NULL != pDhcpOptions)
            {
                if (!insertNode ((void*)&pHeadDhcpOptionsList, (void*)pDhcpOptions , DHCP_OPTION))
                {
                iDhcpOptionVendorCount++;
                DHCPMGR_LOG_INFO("%s:%d  iDhcpOptionVendorCount:%d", __FUNCTION__, __LINE__, iDhcpOptionVendorCount);
                }
            }
            else
            {
                DHCPMGR_LOG_ERROR("%s:%d, Failed to init Node", __FUNCTION__, __LINE__);
            }
            DHCPMGR_LOG_INFO("DHCP_SERVER : [brebhaul] dhcp-option=brebhaul,6,%s", cWanDhcpDns);
            }
        #endif

        #if defined (_HUB4_PRODUCT_REQ_)
        //    fprintf(l_fLocal_Dhcp_ConfFile, "interface=brlan6\n");
        //    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.0.5,169.254.0.253,255.255.255.0,infinite\n");


            // Add brlan112 custom dns server configuration
            if( bIsDhcpNsEnabled && bIsValidWanDhcpNs )
            {
        //            fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=brlan6,6,%s\n", cWanDhcpDns);
                char cStrVar   [BUFF_LEN_512] = {0};
                snprintf(cStrVar, sizeof(cStrVar),"%s,6,%s","brlan6",cWanDhcpDns);
                DhcpOptionsList* pDhcpOptions = (DhcpOptionsList*)initNode(cStrVar,DHCP_OPTION);
                if (NULL != pDhcpOptions)
                {
                if (!insertNode ((void*)&pHeadDhcpOptionsList, (void*)pDhcpOptions , DHCP_OPTION))
                {
                    iDhcpOptionVendorCount++;
                    DHCPMGR_LOG_INFO("%s:%d iDhcpOptionVendorCount:%d", __FUNCTION__, __LINE__, iDhcpOptionVendorCount);
                }
                }
                else
                {
                DHCPMGR_LOG_ERROR("%s:%d, Failed to init Node", __FUNCTION__, __LINE__);
                }
                DHCPMGR_LOG_INFO("DHCP_SERVER : [brlan6] dhcp-option=brlan6,6,%s", cWanDhcpDns);
            }

//    fprintf(l_fLocal_Dhcp_ConfFile, "interface=brlan7\n");
//    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.1.5,169.254.1.253,255.255.255.0,infinite\n");

        // Add brlan113 custom dns server configuration
        if( bIsDhcpNsEnabled && bIsValidWanDhcpNs )
        {
//            fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=brlan7,6,%s\n", cWanDhcpDns);
            char cStrVar   [BUFF_LEN_512] = {0};
            snprintf(cStrVar, sizeof(cStrVar),"%s,6,%s","brlan7",cWanDhcpDns);
            DhcpOptionsList* pDhcpOptions = (DhcpOptionsList*)initNode(cStrVar,DHCP_OPTION);
            if (NULL != pDhcpOptions)
            {
                if (!insertNode ((void*)&pHeadDhcpOptionsList, (void*)pDhcpOptions , DHCP_OPTION))
                {
                    iDhcpOptionVendorCount++;
                    DHCPMGR_LOG_INFO("%s:%d iDhcpOptionVendorCount:%d\n",__FUNCTION__,__LINE__,iDhcpOptionVendorCount);
                }
            }
            else
            {
                DHCPMGR_LOG_ERROR("%s:%d, Failed to init Node\n",__FUNCTION__,__LINE__);
            }
            DHCPMGR_LOG_INFO("DHCP_SERVER : [brlan7] dhcp-option=brlan7,6,%s", cWanDhcpDns);
        }

//       fprintf(l_fLocal_Dhcp_ConfFile, "interface=br403\n");
//    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=192.168.245.2,192.168.245.253,255.255.255.0,infinite\n");

    // Add br403 custom dns server configuration
    if( bIsDhcpNsEnabled && bIsValidWanDhcpNs )
    {
//        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=br403,6,%s\n", cWanDhcpDns);
        char cStrVar   [BUFF_LEN_512] = {0};
        snprintf(cStrVar, sizeof(cStrVar),"%s,6,%s","br403",cWanDhcpDns);
        DhcpOptionsList* pDhcpOptions = (DhcpOptionsList*)initNode(cStrVar,DHCP_OPTION);
        if (NULL != pDhcpOptions)
        {
            if (!insertNode ((void*)&pHeadDhcpOptionsList, (void*)pDhcpOptions , DHCP_OPTION))
            {
                iDhcpOptionVendorCount++;
                DHCPMGR_LOG_INFO("%s:%d. iDhcpOptionVendorCount:%d\n",__FUNCTION__,__LINE__,iDhcpOptionVendorCount);
            }
        }
        else
        {
            DHCPMGR_LOG_ERROR("%s:%d, Failed to init Node\n",__FUNCTION__,__LINE__);
        }
        DHCPMGR_LOG_INFO("DHCP_SERVER : [br403] dhcp-option=br403,6,%s", cWanDhcpDns);
    }
#endif

#if defined (_XB7_PRODUCT_REQ_)
//    fprintf(l_fLocal_Dhcp_ConfFile, "interface=brlan112\n");
//    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.0.5,169.254.0.253,255.255.255.0,infinite\n");


        // Add brlan112 custom dns server configuration
        if( bIsDhcpNsEnabled && bIsValidWanDhcpNs )
        {
//            fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=brlan112,6,%s\n", cWanDhcpDns);
            char cStrVar   [BUFF_LEN_512] = {0};
            snprintf(cStrVar, sizeof(cStrVar),"%s,6,%s","brlan112",cWanDhcpDns);
            DhcpOptionsList* pDhcpOptions = (DhcpOptionsList*)initNode(cStrVar,DHCP_OPTION);
            if (NULL != pDhcpOptions)
            {
                if (!insertNode ((void*)&pHeadDhcpOptionsList, (void*)pDhcpOptions , DHCP_OPTION))
                {
                    iDhcpOptionVendorCount++;
                    DHCPMGR_LOG_INFO("%s:%d iDhcpOptionVendorCount:%d\n",__FUNCTION__,__LINE__,iDhcpOptionVendorCount);
                }
            }
            else
            {
                DHCPMGR_LOG_ERROR("%s:%d, Failed to init Node\n",__FUNCTION__,__LINE__);
            }
            DHCPMGR_LOG_INFO("DHCP_SERVER : [brlan112] dhcp-option=brlan112,6,%s", cWanDhcpDns);
        }

//    fprintf(l_fLocal_Dhcp_ConfFile, "interface=brlan113\n");
//    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.1.5,169.254.1.253,255.255.255.0,infinite\n");

        // Add brlan113 custom dns server configuration
        if( bIsDhcpNsEnabled && bIsValidWanDhcpNs )
        {
//            fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=brlan113,6,%s\n", cWanDhcpDns);
            char cStrVar   [BUFF_LEN_512] = {0};
            snprintf(cStrVar, sizeof(cStrVar),"%s,6,%s","brlan113",cWanDhcpDns);
            DhcpOptionsList* pDhcpOptions = (DhcpOptionsList*)initNode(cStrVar,DHCP_OPTION);
            if (NULL != pDhcpOptions)
            {
                if (!insertNode ((void*)&pHeadDhcpOptionsList, (void*)pDhcpOptions , DHCP_OPTION))
                {
                    iDhcpOptionVendorCount++;
                    DHCPMGR_LOG_INFO("%s:%d  iDhcpOptionVendorCount:%d\n",__FUNCTION__,__LINE__,iDhcpOptionVendorCount);
                }
            }
            else
            {
                DHCPMGR_LOG_ERROR("%s:%d, Failed to init Node\n",__FUNCTION__,__LINE__);
            }
            DHCPMGR_LOG_INFO("DHCP_SERVER : [brlan113] dhcp-option=brlan113,6,%s", cWanDhcpDns);
        }

#endif
#if defined (_PLATFORM_TURRIS_) 
    //Wifi Backhaul link local connections // NEED TO ADD NEW DHCPMANAGER IMPELENTATION FOR _PLATFORM_TURRIS_
    fprintf(l_fLocal_Dhcp_ConfFile, "interface=wifi2\n");
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.0.5,169.254.0.126,255.255.255.128,infinite\n");
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=wifi2,3\n");
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=wifi2,6\n");

    fprintf(l_fLocal_Dhcp_ConfFile, "interface=wifi3\n");
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.1.5,169.254.1.126,255.255.255.128,infinite\n");
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=wifi3,3\n");
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=wifi3,6\n");

    fprintf(l_fLocal_Dhcp_ConfFile, "interface=wifi6\n");
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.0.130,169.254.0.252,255.255.255.128,infinite\n");
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=wifi6,3\n");
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=wifi6,6\n");

    fprintf(l_fLocal_Dhcp_ConfFile, "interface=wifi7\n");
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.1.130,169.254.1.252,255.255.255.128,infinite\n");
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=wifi7,3\n");
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=wifi7,6\n");
    fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-script=/etc/dhcp_script.sh\n");
#endif

#if defined (WIFI_MANAGE_SUPPORTED)
       //interface deatils will be provided by LAN Manager
#endif /*WIFI_MANAGE_SUPPORTED*/

        if (TRUE == bCaptivePortalMode)
        {
                //In factory default condition, prepare whitelisting and redirection IP
            char cStrVar   [BUFF_LEN_512] = {0};
                 snprintf(cStrVar, sizeof(cStrVar),"/#/%s", cLanIpAddress);
        pDomainAddress =(DomainAddress*)initNode(cStrVar, DOMAIN_SPECIFIC_ADDRESS);
        if (NULL != pDomainAddress)
        {
            DHCPMGR_LOG_INFO("%s:%d, DomainAddress : %s\n",__FUNCTION__,__LINE__, pDomainAddress->cDomainSpecificAddr);
            if (!insertNode ((void*)&pHeadDomainAddress, (void*)pDomainAddress, DOMAIN_SPECIFIC_ADDRESS))
            {
                iDomainAddrCount++;
                DHCPMGR_LOG_INFO("%s:%d, iDomainAddrCount : %d\n",__FUNCTION__,__LINE__, iDomainAddrCount);
            }
        }
        if(FALSE == l_bRfCp)
        {
//            fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=252,\"\\n\"\n");
            char cStrVar   [BUFF_LEN_512] = {0};
            snprintf(cStrVar, sizeof(cStrVar),"252,\"\\n\"");
            //fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=252,\"\\n\"\n");
            DhcpOptionsList* pRfCapDhcpOptions = (DhcpOptionsList*)initNode(cStrVar,DHCP_OPTION);
            if (NULL != pRfCapDhcpOptions)
            {
                DHCPMGR_LOG_INFO("%s:%d, RfCapDhcp-option : %s\n",__FUNCTION__,__LINE__,pRfCapDhcpOptions->cDhcpOptions);
                if (!insertNode ((void*)&pHeadDhcpOptionsList, (void*)pRfCapDhcpOptions, DHCP_OPTION))
                {
                    iDhcpOptionVendorCount++;
                    DHCPMGR_LOG_INFO("%s:%d, iDhcpOptionVendorCount : %d\n",__FUNCTION__,__LINE__,iDhcpOptionVendorCount);
                }
            }
            prepare_whitelist_urls(l_fLocal_Dhcp_ConfFile);
        }
#if 0 //TBD
        ifl_set_event( "captiveportaldhcp", "completed");
#endif
        }

        //Prepare static dns urls
        if( bIsDhcpNsEnabled )
        {
               prepare_static_dns_urls( l_fLocal_Dhcp_ConfFile );
        }

//        remove_file(DHCP_CONF);
        fclose(l_fLocal_Dhcp_ConfFile);
        copy_file(l_fLocal_Dhcp_ConfFile, DHCP_CONF);
        remove_file(l_fLocal_Dhcp_ConfFile);
        DHCPMGR_LOG_INFO("DHCP SERVER : Completed preparing DHCP configuration");
#if defined (WAN_FAILOVER_SUPPORTED)
    #if !defined (RDKB_EXTENDER_ENABLED)
        char lan_ipaddr[20]={'\0'};
        char l_cLine[255] = {0};
        FILE *l_fResolv_Conf = NULL;
        int Flag=0;
        l_fResolv_Conf = fopen(RESOLV_CONF, "r");
        if (NULL != l_fResolv_Conf)
        {
            while(fgets(l_cLine, 80, l_fResolv_Conf) != NULL )
            {
                char *property = NULL;
                if (NULL != (property = strstr(l_cLine, "127.0.0.1")))
                {
                    Flag=1;
                    break;
                }
            }
            fclose(l_fResolv_Conf);
            if(Flag==1)
            {
                l_fResolv_Conf = fopen(RESOLV_CONF, "w");
                if (NULL != l_fResolv_Conf)
                {
                    syscfg_get(NULL, "lan_ipaddr", lan_ipaddr, sizeof(lan_ipaddr));
                    //fprintf(g_fArmConsoleLog, "strlen of lan_ipaddr:%d\n",strlen(lan_ipaddr));
                    if(strlen(lan_ipaddr)>0)
                    {
                        fprintf(l_fResolv_Conf,"nameserver %s\n",lan_ipaddr);
                    }
                    fclose(l_fResolv_Conf);
                }
            }
        }
        else
        {
            DHCPMGR_LOG_INFO("opening of %s file failed with error:%d\n", RESOLV_CONF, errno);
        }
    #endif//RDKB_EXTENDER_ENABLED
#endif //WAN_FAILOVER_SUPPORTED
        DHCPMGR_LOG_INFO("%s:%d, iDhcpOptionVendorCount:%d\n",__FUNCTION__,__LINE__,iDhcpOptionVendorCount);
    if (0 < iDhcpOptionVendorCount)
    {
        pGlbDhcpCfg->sDhcpOptions.iVendorIdCount = iDhcpOptionVendorCount;
        pGlbDhcpCfg->sDhcpOptions.ppVendorId = malloc (sizeof(char*)*iDhcpOptionVendorCount);
        if (NULL != pGlbDhcpCfg->sDhcpOptions.ppVendorId)
        {
            DhcpOptionsList * pDhcpOptionList = pHeadDhcpOptionsList;
            for (int iCount=0; iCount < iDhcpOptionVendorCount; iCount++)
            {
                pGlbDhcpCfg->sDhcpOptions.ppVendorId[iCount] = malloc (BUFF_LEN_64);
                if (NULL != pGlbDhcpCfg->sDhcpOptions.ppVendorId[iCount])
                {
                    memset (pGlbDhcpCfg->sDhcpOptions.ppVendorId[iCount], 0, BUFF_LEN_64);
                    if (NULL != pDhcpOptionList)
                    {
                        snprintf (pGlbDhcpCfg->sDhcpOptions.ppVendorId[iCount], BUFF_LEN_64, "%s",pDhcpOptionList->cDhcpOptions);
                        pDhcpOptionList = (DhcpOptionsList*) deleteNode(pDhcpOptionList, DHCP_OPTION);
                    }
                    else
                    {
                        DHCPMGR_LOG_ERROR("%s:%d, pDhcpOptionList is NULL\n",__FUNCTION__,__LINE__);
                    }
                }
            }
        }
    }
    if (0 < iDhcpVendorClassCount)
    {
        pGlbDhcpCfg->sDhcpOptions.iVendorClassCount = iDhcpVendorClassCount;
        pGlbDhcpCfg->sDhcpOptions.ppVendorClass = malloc (sizeof(char*)*iDhcpVendorClassCount);
        if (NULL != pGlbDhcpCfg->sDhcpOptions.ppVendorClass)
        {
            DhcpVendorClassList * pDhcpVendorClass = pHeadDhcpVendorClass;
            for (int iCount=0; iCount < iDhcpVendorClassCount; iCount++)
            {
                pGlbDhcpCfg->sDhcpOptions.ppVendorClass[iCount] = malloc (BUFF_LEN_64);
                if (NULL != pGlbDhcpCfg->sDhcpOptions.ppVendorClass[iCount])
                {
                    memset (pGlbDhcpCfg->sDhcpOptions.ppVendorClass[iCount], 0, BUFF_LEN_64);
                    if (NULL != pDhcpVendorClass)
                    {
                        snprintf (pGlbDhcpCfg->sDhcpOptions.ppVendorClass[iCount], BUFF_LEN_64, "%s",pDhcpVendorClass->cVendorClass);
                        pDhcpVendorClass = (DhcpVendorClassList*) deleteNode(pDhcpVendorClass, DHCP_VENDOR_CLASS);
                    }
                    else
                    {
                        DHCPMGR_LOG_ERROR("%s:%d, pDhcpVendorClass is NULL\n",__FUNCTION__,__LINE__);
                    }
                }
            }
        }
    }
    DHCPMGR_LOG_INFO("%s:%d, iDomainAddrCount:%d\n",__FUNCTION__,__LINE__,iDomainAddrCount);
    if (0 < iDomainAddrCount)
    {
        pGlbDhcpCfg->sDomainSpecific.iDomainSpecificAddressCount = iDomainAddrCount;
        pGlbDhcpCfg->sDomainSpecific.bIsDomainSpecificEnabled = true;
        pGlbDhcpCfg->sDomainSpecific.ppDomainSpecificAddresses = malloc(sizeof(char*)*iDomainAddrCount);
        if (NULL != pGlbDhcpCfg->sDomainSpecific.ppDomainSpecificAddresses)
        {
            DomainAddress *pDomainAddr = pHeadDomainAddress;
            for (int iCount=0; iCount < iDomainAddrCount; iCount++)
            {
                pGlbDhcpCfg->sDomainSpecific.ppDomainSpecificAddresses[iCount] = malloc (BUFF_LEN_64);
                if (NULL != pGlbDhcpCfg->sDomainSpecific.ppDomainSpecificAddresses[iCount])
                {
                    memset(pGlbDhcpCfg->sDomainSpecific.ppDomainSpecificAddresses[iCount], 0, BUFF_LEN_64);
                    if (NULL != pDomainAddr)
                    {
                        snprintf(pGlbDhcpCfg->sDomainSpecific.ppDomainSpecificAddresses[iCount], BUFF_LEN_64,"%s",pDomainAddr->cDomainSpecificAddr);
                        pDomainAddr = (DomainAddress*)deleteNode(pDomainAddr, DOMAIN_SPECIFIC_ADDRESS);
                    }
                    else
                    {
                        DHCPMGR_LOG_INFO("%s:%d, pDomainAddr is NULL\n",__FUNCTION__,__LINE__);
                    }
                }
            }
        }
    }
    if (0 < iRedirectionAddrCount)
    {
        DHCPMGR_LOG_INFO("%s:%d, iRedirectionAddrCount:%d\n",__FUNCTION__,__LINE__,iRedirectionAddrCount);
        pGlbDhcpCfg->sRedirectInfo.iRedirectionUrlCount = iRedirectionAddrCount;
        pGlbDhcpCfg->sRedirectInfo.bIsRedirectionEnabled = true;
        pGlbDhcpCfg->sRedirectInfo.ppRedirectionUrl = malloc(sizeof(char*)*iRedirectionAddrCount);
        if (NULL != pGlbDhcpCfg->sRedirectInfo.ppRedirectionUrl)
        {
            RedirectionAddress *pRedirectionAddr = pHeadRedirectionAddr;
            for (int iCount=0; iCount < iRedirectionAddrCount; iCount++)
            {
                pGlbDhcpCfg->sRedirectInfo.ppRedirectionUrl[iCount] = malloc (BUFF_LEN_128);
                if (NULL != pGlbDhcpCfg->sRedirectInfo.ppRedirectionUrl[iCount])
                {
                    memset(pGlbDhcpCfg->sRedirectInfo.ppRedirectionUrl[iCount], 0, BUFF_LEN_128);
                    if (NULL != pRedirectionAddr)
                    {
                        snprintf(pGlbDhcpCfg->sRedirectInfo.ppRedirectionUrl[iCount], BUFF_LEN_128,"%s",pRedirectionAddr->cRedirectionAddr);
                        pRedirectionAddr = (RedirectionAddress*)deleteNode(pRedirectionAddr, REDIRECTION_ADDRESS);
                    }
                    else
                    {
                        DHCPMGR_LOG_INFO("%s:%d, pRedirectionAddr is NULL\n",__FUNCTION__,__LINE__);
                    }
                }
            }
        }
    }
    return 0;
}

int prepare_hostname()
{
    char l_cHostName[16] = {0}, l_cCurLanIP[16] = {0}, l_clocFqdn[16] = {0}, l_cSecWebUI_Enabled[8] = {0};
        FILE *l_fHosts_File = NULL;
        FILE *l_fHosts_Name_File = NULL;
        int l_iRes = 0;

        syscfg_get(NULL, "hostname", l_cHostName, sizeof(l_cHostName));
        ifl_get_event( "current_lan_ipaddr", l_cCurLanIP, sizeof(l_cCurLanIP));
        syscfg_get(NULL, "SecureWebUI_LocalFqdn", l_clocFqdn, sizeof(l_clocFqdn));
        syscfg_get(NULL, "SecureWebUI_Enable", l_cSecWebUI_Enabled, sizeof(l_cSecWebUI_Enabled));

    // Open in Write mode each time for avoiding duplicate entries
       l_fHosts_File = fopen(HOSTS_FILE, "w+");
    l_fHosts_Name_File = fopen(HOSTNAME_FILE, "w+");

    if (0 != l_cHostName[0])
    {
                l_iRes = sethostname(l_cHostName, sizeof(l_cHostName));
                if (ERROR == l_iRes)
                {
                     DHCPMGR_LOG_ERROR("Un-Successful in setting hostname error is:%d", errno);
                }
                if (NULL == l_fHosts_Name_File)
                {
                DHCPMGR_LOG_ERROR("Hosts Name file: %s creation failed ", HOSTNAME_FILE);
        }
                else
                {
                        fprintf(l_fHosts_Name_File, "%s\n", l_cHostName);
                        fclose(l_fHosts_Name_File);
                        l_fHosts_Name_File = NULL;
                        if (NULL != l_fHosts_File)
                {
                                if (strncmp(l_cSecWebUI_Enabled, "true", 4))
                                {
                                    fprintf(l_fHosts_File, "%s     %s\n", l_cCurLanIP, l_cHostName);
                                }
                        }
                        else
            {
                                DHCPMGR_LOG_ERROR("Hosts file: %s creation failed ", HOSTS_FILE);
                                return 0;
                        }
               }
    }
    else
        {
                  DHCPMGR_LOG_INFO("Hostname is empty not writing to %s file", HOSTNAME_FILE);
        }

        if (NULL != l_fHosts_File)
        {
                fprintf(l_fHosts_File, "127.0.0.1       localhost\n");
                fprintf(l_fHosts_File, "::1             localhost\n");
                if (strlen(l_clocFqdn)!=0)
                {
                        if (!strncmp(l_cSecWebUI_Enabled, "true", 4))
                        {
                            fprintf(l_fHosts_File, "%s              %s\n", l_cCurLanIP, l_clocFqdn);
                        }
                }

                //The following lines are desirable for IPv6 capable hosts
                fprintf(l_fHosts_File, "::1             ip6-localhost ip6-loopback\n");
                fprintf(l_fHosts_File, "fe00::0         ip6-localnet\n");
                fprintf(l_fHosts_File, "ff00::0         ip6-mcastprefix\n");
                fprintf(l_fHosts_File, "ff02::1         ip6-allnodes\n");
                fprintf(l_fHosts_File, "ff02::2         ip6-allrouters\n");
                fprintf(l_fHosts_File, "ff02::3         ip6-allhosts\n");
                fclose(l_fHosts_File);
        }
        else
        {
               DHCPMGR_LOG_ERROR("Hosts file: %s creation failed ", HOSTS_FILE);
        }
        if (NULL != l_fHosts_Name_File) {
               fclose(l_fHosts_Name_File);
        }
        return 0;
}

void calculate_dhcp_range (FILE *local_dhcpconf_file, char *prefix)
{
    char l_cLanIPAddress[16]  = {0}, l_cLanNetMask[16] = {0}, l_cDhcp_Start[16] = {0};
        char l_cDhcp_End[16] = {0}, l_cDhcp_Num[16]  = {0};
        char l_cLanSubnet[16] = {0}, l_cIpSubnet[16] = {0};

        int  l_iStartAddr_Last_Oct = 0, l_iEndAddr_Last_Oct;
        int l_iStartIpValid = 0, l_iEndIpValid = 0;
        int l_iFirstOct, l_iSecOct, l_iThirdOct, l_iLastOct;
        int l_iCIDR;

        struct sockaddr_in l_sSocAddr;
        errno_t safec_rc = -1;

    syscfg_get(NULL, "lan_ipaddr", l_cLanIPAddress, sizeof(l_cLanIPAddress));
    syscfg_get(NULL, "lan_netmask", l_cLanNetMask, sizeof(l_cLanNetMask));
        if (0 == isValidSubnetMask(l_cLanNetMask))
        {
              DHCPMGR_LOG_INFO("[DHCPCORRUPT_TRACE] DHCP Net Mask:%s is corrupted. Setting to default Net Mask",
                         l_cLanNetMask);
                //copy the default netmask
                safec_rc = strcpy_s(l_cLanNetMask, sizeof(l_cLanNetMask),"255.255.255.0");
                ERR_CHK(safec_rc);
                syscfg_set_commit(NULL, "lan_netmask", l_cLanNetMask);
        }

        subnet(l_cLanIPAddress, l_cLanNetMask, l_cLanSubnet);

        sscanf(l_cLanNetMask, "%d.%d.%d.%d", &l_iFirstOct, &l_iSecOct, &l_iThirdOct, &l_iLastOct);

        syscfg_get(NULL, "dhcp_start", l_cDhcp_Start, sizeof(l_cDhcp_Start));
        DHCPMGR_LOG_INFO("dhcp_start:%s", l_cDhcp_Start);

        // inet_pton validates whether IP has 4 octets and all octets are in between 0 and 255
        l_iStartIpValid = inet_pton(AF_INET, l_cDhcp_Start, &(l_sSocAddr.sin_addr));
        if (1 == l_iStartIpValid)
        {
                sscanf(l_cDhcp_Start, "%d.%d.%d.%d", &l_iFirstOct, &l_iSecOct, &l_iThirdOct, &l_iLastOct);
                l_iStartAddr_Last_Oct = l_iLastOct;

                subnet(l_cDhcp_Start, l_cLanNetMask, l_cIpSubnet);
                if ((l_iStartAddr_Last_Oct < 2 || l_iStartAddr_Last_Oct > 254) &&
            (strncmp(l_cIpSubnet, l_cLanSubnet, sizeof(l_cIpSubnet))))
                {
                        DHCPMGR_LOG_INFO("Last Octet of DHCP Start Address:%d is not in range", l_iStartAddr_Last_Oct);
                        l_iStartIpValid = 0;
                }
                else if (strncmp(l_cIpSubnet, l_cLanSubnet, sizeof(l_cIpSubnet)))
                {
                        DHCPMGR_LOG_INFO("DHCP Start Address:%s is not in the same subnet as LAN IP:%s",
                                         l_cDhcp_Start, l_cLanIPAddress);

            l_iStartIpValid = 0;
                }
                else
                {
                      DHCPMGR_LOG_INFO("DHCP_SERVER: Start address from syscfg_db :%s", l_cDhcp_Start);
                }
        }
        else
        {
                DHCPMGR_LOG_INFO("Start Address is not in valid format need a re-calculation");
                l_iStartIpValid = 0;
        }

        // Start Address is not valid lets calculate it
        if (0 == l_iStartIpValid)
        {
        DHCPMGR_LOG_INFO("DHCP Start Address:%s is not valid re-calculating it", l_cDhcp_Start);
        sscanf(l_cLanSubnet, "%d.%d.%d.%d", &l_iFirstOct, &l_iSecOct, &l_iThirdOct, &l_iLastOct);
        l_iLastOct = 2;
        safec_rc = sprintf_s(l_cDhcp_Start, sizeof(l_cDhcp_Start),"%d.%d.%d.%d", l_iFirstOct, l_iSecOct, l_iThirdOct, l_iLastOct);
        ERR_CHK(safec_rc);
        syscfg_set(NULL, "dhcp_start", l_cDhcp_Start);
        }

    syscfg_get(NULL, "dhcp_end", l_cDhcp_End, sizeof(l_cDhcp_End));
    DHCPMGR_LOG_INFO("dhcp_end:%s", l_cDhcp_End);

        l_iEndIpValid = inet_pton(AF_INET, l_cDhcp_End, &(l_sSocAddr.sin_addr));
        if (1 == l_iEndIpValid)
    {
        sscanf(l_cDhcp_End, "%d.%d.%d.%d", &l_iFirstOct, &l_iSecOct, &l_iThirdOct, &l_iLastOct);
        l_iEndAddr_Last_Oct = l_iLastOct;

             subnet(l_cDhcp_End, l_cLanNetMask, l_cIpSubnet);
        if (l_iEndAddr_Last_Oct < 2 && l_iEndAddr_Last_Oct > 254)
        {
            DHCPMGR_LOG_INFO("Last Octet of DHCP End Address:%d is not in range", l_iEndAddr_Last_Oct);
            l_iEndIpValid = 0;

        }
                  else if (strncmp(l_cIpSubnet, l_cLanSubnet, sizeof(l_cIpSubnet)))
        {
            DHCPMGR_LOG_INFO("DHCP End Address:%s is not in the same subnet as LAN IP:%s",
                    l_cDhcp_End, l_cLanIPAddress);

            l_iEndIpValid = 0;
        }
        else
        {
                    DHCPMGR_LOG_INFO("DHCP_SERVER: End address from syscfg_db :%s", l_cDhcp_End);
        }
    }
        else
        {
                DHCPMGR_LOG_INFO("End Address is not in valid format need a re-calculation");
                l_iEndIpValid = 0;
        }

        // End Address is not valid lets calculate it
        if (0 == l_iEndIpValid)
        {
                //DHCP_NUM is the number of available dhcp address for the lan
                syscfg_get(NULL, "dhcp_num", l_cDhcp_Num, sizeof(l_cDhcp_Num));
                DHCPMGR_LOG_INFO("dhcp_num is:%s", l_cDhcp_Num);

                DHCPMGR_LOG_INFO("DHCP END Address:%s is not valid re-calculating it", l_cDhcp_End);
        l_iCIDR = mask2cidr(l_cLanNetMask); //FIXME
        //Extract 1st 3 octets of the lan subnet and
        //set the last octet to 253 for the start address
        if (24 == l_iCIDR)
        {
            sscanf(l_cLanSubnet, "%d.%d.%d.%d", &l_iFirstOct, &l_iSecOct, &l_iThirdOct, &l_iLastOct);
            l_iLastOct = 253;
            safec_rc = sprintf_s(l_cDhcp_End, sizeof(l_cDhcp_End),"%d.%d.%d.%d", l_iFirstOct, l_iSecOct, l_iThirdOct, l_iLastOct);
            ERR_CHK(safec_rc);
        }
        //Extract 1st 2 octets of the lan subnet and
        //set the last remaining to 255.253 for the start address
        else if (16 == l_iCIDR)
        {
            sscanf(l_cLanSubnet, "%d.%d.%d.%d", &l_iFirstOct, &l_iSecOct, &l_iThirdOct, &l_iLastOct);
            l_iThirdOct = 255;
            l_iLastOct = 253;

            safec_rc = sprintf_s(l_cDhcp_End, sizeof(l_cDhcp_End),"%d.%d.%d.%d", l_iFirstOct, l_iSecOct, l_iThirdOct, l_iLastOct);
            ERR_CHK(safec_rc);
        }
        //Extract 1st octet of the lan subnet and
        //set the last remaining octets to 255.255.253 for the start address
        else if (8 == l_iCIDR)
        {
            sscanf(l_cLanSubnet, "%d.%d.%d.%d", &l_iFirstOct, &l_iSecOct, &l_iThirdOct, &l_iLastOct);
            l_iSecOct = 255;
            l_iThirdOct = 255;
            l_iLastOct = 253;

            safec_rc = sprintf_s(l_cDhcp_End, sizeof(l_cDhcp_End),"%d.%d.%d.%d", l_iFirstOct, l_iSecOct, l_iThirdOct, l_iLastOct);
            ERR_CHK(safec_rc);
        }
        else
        {
            DHCPMGR_LOG_INFO("Invalid Subnet mask");
        }
        syscfg_set(NULL, "dhcp_end", l_cDhcp_End);
        }

        if (!strncmp(g_cDhcp_Lease_Time, "-1", 2))
    {
        fprintf(local_dhcpconf_file, "%sdhcp-range=%s,%s,%s,infinite\n", prefix,
                                l_cDhcp_Start, l_cDhcp_End, l_cLanNetMask);
    }
    else
    {
        fprintf(local_dhcpconf_file, "%sdhcp-range=%s,%s,%s,%s\n", prefix,
                                l_cDhcp_Start, l_cDhcp_End, l_cLanNetMask, g_cDhcp_Lease_Time);
    }
}

//We are not using static hosts in XB3 still we will convert this to C code
/*--------------------------------------------------------------
 Prepare the dhcp server static hosts/ip file
--------------------------------------------------------------*/
void prepare_dhcp_conf_static_hosts()
{
        char l_cLocalStatHosts[32] = {0}, l_cDhcpStatHosts[8]  = {0};
    char l_cHostLine[255] = {0}, l_cSyscfgCmd[32] = {0};
        int l_iStatHostsNum, l_iIter;
    FILE *l_fLocalStatHosts = NULL;
    errno_t safec_rc = -1;

    safec_rc = sprintf_s(l_cLocalStatHosts, sizeof(l_cLocalStatHosts),"/tmp/dhcp_static_hosts%d", getpid());
    if(safec_rc < EOK){
       ERR_CHK(safec_rc);
       return;
    }
    l_fLocalStatHosts = fopen(l_cLocalStatHosts, "w+"); //It will create a file and open, re-write fresh RDK-B 12160
    if(NULL == l_fLocalStatHosts)
    {
        DHCPMGR_LOG_ERROR("File: %s creation failed with error:%d", l_cLocalStatHosts, errno);
        return;
    }
    syscfg_get(NULL, "dhcp_num_static_hosts", l_cDhcpStatHosts, sizeof(l_cDhcpStatHosts));
        l_iStatHostsNum = atoi(l_cDhcpStatHosts);

        for (l_iIter = 1; l_iIter <= l_iStatHostsNum; l_iIter++)
        {
                safec_rc = sprintf_s(l_cSyscfgCmd, sizeof(l_cSyscfgCmd),"dhcp_static_host_%d", l_iIter);
                ERR_CHK(safec_rc);

                syscfg_get(NULL, l_cSyscfgCmd, l_cHostLine, sizeof(l_cHostLine));

                fprintf(l_fLocalStatHosts, "%s,%s\n", l_cHostLine, g_cDhcp_Lease_Time);
        }
        fclose(l_fLocalStatHosts);
        copy_file(l_cLocalStatHosts, DHCP_STATIC_HOSTS_FILE);
        remove_file(l_cLocalStatHosts);
}

void prepare_dhcp_options_wan_dns()
{
        // Since we are not using prepare_dhcp_options fn DHCP_OPTION_STR is always empty
        char l_cLocalDhcpOpt[32] = {0}, l_cPropagate_Ns[8] = {0}, l_cWan_Dhcp_Dns[255] = {0};
        char *l_cToken = NULL, l_cNs[255] = {""};
        FILE *l_fLocalDhcpOpt = NULL;
        char pL_cNs[256];
        errno_t safec_rc = -1;

    safec_rc = sprintf_s(l_cLocalDhcpOpt, sizeof(l_cLocalDhcpOpt),"/tmp/dhcp_options%d", getpid());
    if(safec_rc < EOK){
       ERR_CHK(safec_rc);
       return;
    }
    l_fLocalDhcpOpt = fopen(l_cLocalDhcpOpt, "a+"); //It will create a file and open
    if(NULL == l_fLocalDhcpOpt)
    {
        DHCPMGR_LOG_ERROR("File: %s creation failed with error:%d", l_cLocalDhcpOpt, errno);
        return;
    }
        syscfg_get(NULL, "dhcp_server_propagate_wan_nameserver", l_cPropagate_Ns, sizeof(l_cPropagate_Ns));

        if (strncmp(l_cPropagate_Ns, "1", 1))
        {
        syscfg_get(NULL, "block_nat_redirection", l_cPropagate_Ns, sizeof(l_cPropagate_Ns));
            DHCPMGR_LOG_INFO("Propagate NS is set from block_nat_redirection value is:%s", l_cPropagate_Ns);
        }

        if (!strncmp(l_cPropagate_Ns, "1", 1))
        {
                ifl_get_event( "wan_dhcp_dns", l_cWan_Dhcp_Dns, sizeof(l_cWan_Dhcp_Dns));
                if (0 != l_cWan_Dhcp_Dns[0])
                {
                        l_cToken = strtok(l_cWan_Dhcp_Dns, " ");
                        while (l_cToken != NULL)
                        {
                                if (0 != l_cNs[0])
                                {
                                        safec_rc = sprintf_s(pL_cNs, sizeof(pL_cNs),"%s,%s", l_cNs, l_cToken);
                                        ERR_CHK(safec_rc);

                                        strncpy(l_cNs, pL_cNs, strlen(pL_cNs));
                                }
                                else
                                {
                                        safec_rc = sprintf_s(l_cNs, sizeof(l_cNs),"%s", l_cToken);
                                        ERR_CHK(safec_rc);
                                }
                                l_cToken = strtok(NULL, " ");
                        }
                        l_cNs[strlen(l_cNs)] = '\0';
                        DHCPMGR_LOG_INFO("l_cNs is:%s", l_cNs);
                        fprintf(l_fLocalDhcpOpt, "option:dns-server, %s\n", l_cNs);
                }
                else
                {
                        DHCPMGR_LOG_INFO("wan_dhcp_dns is empty, so file:%s will be empty ", DHCP_OPTIONS_FILE);
                }
        }
        fclose(l_fLocalDhcpOpt);
        copy_file(l_cLocalDhcpOpt, DHCP_OPTIONS_FILE);
        remove_file(l_cLocalDhcpOpt);
}

void get_ipv4_dns(char *cNsServer4)
{
    char l_cLine[255] = {0};
    FILE *l_fResolv_Conf = NULL;

    cNsServer4[0] = '\0';

    l_fResolv_Conf = fopen(RESOLV_CONF, "r");
    if (NULL != l_fResolv_Conf)
    {
        while(fgets(l_cLine, 80, l_fResolv_Conf) != NULL )
        {
            char *property = NULL;
            if (NULL != (property = strstr(l_cLine, "nameserver ")))
            {
                property = property + strlen("nameserver ");
                if (strstr(property, "."))
                {
                    //strlen - 1 to strip \n
                    strncpy(cNsServer4, property, (strlen(property) - 1));
                    break;
                }
            }
        }
        fclose(l_fResolv_Conf);
    }
    else
    {
        DHCPMGR_LOG_ERROR("opening of %s file failed with error:%d", RESOLV_CONF, errno);
    }
    DHCPMGR_LOG_INFO("Nameserver IPv4 address is:%s", cNsServer4);
}

void prepare_whitelist_urls(FILE *fp_local_dhcp_conf)
{
        char l_cRedirect_Url[64] = {0}, l_cCloud_Personal_Url[64] = {0}, l_cUrl[64] = {0};
        char l_cErouter0_Ipv4Addr[16] = {0}, l_cNsServer4[16] = {0}, l_cLine[255] = {0};
        FILE *l_fStatic_Urls = NULL;
    char *l_cRemoveHttp = NULL;

    // Redirection URL can be get from DML
    syscfg_get(NULL, "redirection_url", l_cRedirect_Url, sizeof(l_cRedirect_Url));
        if (0 != l_cRedirect_Url[0])
        {
            if (NULL != (l_cRemoveHttp = strstr(l_cRedirect_Url, "http://")))
        {
                l_cRemoveHttp = l_cRemoveHttp + strlen("http://");
                /* BUFFER_SIZE_WARNING */
               memmove(l_cRedirect_Url, l_cRemoveHttp, strlen(l_cRemoveHttp)+1);
        }
        else if (NULL != (l_cRemoveHttp = strstr(l_cRedirect_Url, "https://")))
        {
                      l_cRemoveHttp = l_cRemoveHttp + strlen("https://");
            strncpy(l_cRedirect_Url, l_cRemoveHttp, sizeof(l_cRedirect_Url));
        }
                else
                {
                      DHCPMGR_LOG_INFO("redirection_url doesnt contain http / https tag");
                }
        }
    DHCPMGR_LOG_INFO("redirection URL after stripping http / https is:%s", l_cRedirect_Url);

    // CloudPersonalization URL can be get from DML
        syscfg_get(NULL, "CloudPersonalizationURL", l_cCloud_Personal_Url, sizeof(l_cCloud_Personal_Url));
    DHCPMGR_LOG_INFO("CloudPersonalizationURL is:%s", l_cCloud_Personal_Url);

        if (0 != l_cCloud_Personal_Url[0])
        {
             l_cRemoveHttp = NULL;
            if (NULL != (l_cRemoveHttp = strstr(l_cCloud_Personal_Url, "http://")))
            {
            l_cRemoveHttp = l_cRemoveHttp + strlen("http://");
                strncpy(l_cCloud_Personal_Url, l_cRemoveHttp, sizeof(l_cCloud_Personal_Url));
       }
                else if (NULL != (l_cRemoveHttp = strstr(l_cCloud_Personal_Url, "https://")))
                {
                          l_cRemoveHttp = l_cRemoveHttp + strlen("https://");
            strncpy(l_cCloud_Personal_Url, l_cRemoveHttp, sizeof(l_cCloud_Personal_Url));
                }
                else
                {
                DHCPMGR_LOG_INFO("CloudPersonalizationURL doesnt contain http / https tag");
                }
        }
        iface_get_ipv4addr(WAN_IF_NAME, l_cErouter0_Ipv4Addr, sizeof(l_cErouter0_Ipv4Addr));
    if (0 != l_cErouter0_Ipv4Addr[0])
        {
            get_ipv4_dns(l_cNsServer4);
    }
    // erouter0 doesnt have IPv4 Address not doing anything
    // TODO: ipv6 DNS whitelisting in case of ipv6 only clients
    else
    {
          DHCPMGR_LOG_INFO("erouter0 interface doesnt have IPv4 address");
    }

        if (0 != l_cNsServer4[0])
        {
                fprintf(fp_local_dhcp_conf, "server=/%s/%s\n", l_cRedirect_Url, l_cNsServer4);
                fprintf(fp_local_dhcp_conf, "server=/%s/%s\n", l_cCloud_Personal_Url, l_cNsServer4);

                l_fStatic_Urls = fopen(STATIC_URLS_FILE, "r");
                if (NULL != l_fStatic_Urls)
                {
                        while(fgets(l_cLine, 80, l_fStatic_Urls) != NULL)
                        {
                                strncpy(l_cUrl, l_cLine, (strlen(l_cLine) - 1));
                                fprintf(fp_local_dhcp_conf, "server=/%s/%s\n", l_cUrl, l_cNsServer4);
                        }
                        fclose(l_fStatic_Urls);
                }
                else
                {
                        DHCPMGR_LOG_ERROR("opening of %s file failed with error:%d", STATIC_URLS_FILE, errno);
                }
        }
        else
        {
                DHCPMGR_LOG_INFO("IPv4 DNS server is not present in %s file not whitelisting URLs ", RESOLV_CONF);
        }
}

void do_extra_pools (FILE *local_dhcpconf_file, char *prefix, unsigned char bDhcpNs_Enabled, char *pWan_Dhcp_Dns)
{
        char l_cDhcpEnabled[8] = {0}, l_cSysevent_Cmd[32] = {0};
        char l_cIpv4Inst[8] = {0}, l_cIpv4InstStatus[8] = {0};
        char l_cDhcp_Start_Addr[16] = {0}, l_cDhcp_End_Addr[16] = {0};
        char l_cLan_Subnet[16] = {0}, l_cDhcp_Lease_Time[8] = {0}, l_cIfName[8] = {0};
        char l_cPools[8] = {0};
        char *l_cToken = NULL;
        int l_iPool, l_iIpv4Inst;
        errno_t safec_rc = -1;


        ifl_get_event(
                       "dhcp_server_current_pools", l_cPools, sizeof(l_cPools));

        l_cToken = strtok(l_cPools, "\n");
        while(l_cToken != NULL)
        {
                if (0 != l_cToken[0])
                {
                        l_iPool = atoi(l_cToken);
                        safec_rc = sprintf_s(l_cSysevent_Cmd, sizeof(l_cSysevent_Cmd),"dhcp_server_%d_enabled", l_iPool);
                        if(safec_rc < EOK)
                        {
                                ERR_CHK(safec_rc);
                        }
                ifl_get_event(
                              l_cSysevent_Cmd, l_cDhcpEnabled, sizeof(l_cDhcpEnabled));

                        if (!strncmp(l_cDhcpEnabled, "TRUE", 4))
                        {
                                safec_rc = sprintf_s(l_cSysevent_Cmd, sizeof(l_cSysevent_Cmd),"dhcp_server_%d_ipv4inst", l_iPool);
                                if(safec_rc < EOK)
                                {
                                        ERR_CHK(safec_rc);
                                }
                        ifl_get_event(
                                                 l_cSysevent_Cmd, l_cIpv4Inst, sizeof(l_cIpv4Inst));
                        l_iIpv4Inst = atoi(l_cIpv4Inst);
                                safec_rc = sprintf_s(l_cSysevent_Cmd, sizeof(l_cSysevent_Cmd),"ipv4_%d-status", l_iIpv4Inst);
                                if(safec_rc < EOK)
                                {
                                        ERR_CHK(safec_rc);
                                }
                        ifl_get_event(
                                             l_cSysevent_Cmd, l_cIpv4InstStatus, sizeof(l_cIpv4InstStatus));

                                if (!strncmp(l_cIpv4InstStatus, "up", 2))
                                {
                                        safec_rc = sprintf_s(l_cSysevent_Cmd, sizeof(l_cSysevent_Cmd),"dhcp_server_%d_startaddr", l_iPool);
                                        if(safec_rc < EOK)
                                        {
                                                ERR_CHK(safec_rc);
                                        }
                                ifl_get_event(
                                            l_cSysevent_Cmd, l_cDhcp_Start_Addr, sizeof(l_cDhcp_Start_Addr));

                                        safec_rc = sprintf_s(l_cSysevent_Cmd, sizeof(l_cSysevent_Cmd),"dhcp_server_%d_endaddr", l_iPool);
                                        if(safec_rc < EOK)
                                        {
                                                ERR_CHK(safec_rc);
                                        }
                                ifl_get_event(
                                             l_cSysevent_Cmd, l_cDhcp_End_Addr, sizeof(l_cDhcp_End_Addr));

                                        safec_rc = sprintf_s(l_cSysevent_Cmd, sizeof(l_cSysevent_Cmd),"dhcp_server_%d_subnet", l_iPool);
                                        if(safec_rc < EOK)
                                        {
                                                ERR_CHK(safec_rc);
                                        }
                                ifl_get_event(
                                             l_cSysevent_Cmd, l_cLan_Subnet, sizeof(l_cLan_Subnet));

                                        safec_rc = sprintf_s(l_cSysevent_Cmd, sizeof(l_cSysevent_Cmd),"dhcp_server_%d_leasetime", l_iPool);
                                        if(safec_rc < EOK)
                                        {
                                                ERR_CHK(safec_rc);
                                        }
                                ifl_get_event(
                                             l_cSysevent_Cmd, l_cDhcp_Lease_Time, sizeof(l_cDhcp_Lease_Time));

                                        safec_rc = sprintf_s(l_cSysevent_Cmd, sizeof(l_cSysevent_Cmd),"ipv4_%d-ifname", l_iIpv4Inst);
                                        if(safec_rc < EOK)
                                        {
                                                ERR_CHK(safec_rc);
                                        }
                                 ifl_get_event(
                                             l_cSysevent_Cmd, l_cIfName, sizeof(l_cIfName));

                                             //TODO prefix is not considered for first drop
                                        if ((0 != l_cDhcp_Start_Addr[0]) && (0 != l_cDhcp_End_Addr[0]))
                                        {
                                                fprintf(local_dhcpconf_file, "%sinterface=%s\n", prefix, l_cIfName);
                                                fprintf(local_dhcpconf_file, "%sdhcp-range=set:%d,%s,%s,%s,%s\n", prefix, l_iPool,
                                              l_cDhcp_Start_Addr, l_cDhcp_End_Addr, l_cLan_Subnet, l_cDhcp_Lease_Time);

                                                DHCPMGR_LOG_INFO("DHCP_SERVER : [BRLAN1] %sdhcp-range=set:%d,%s,%s,%s,%s",
                                                                                prefix, l_iPool, l_cDhcp_Start_Addr, l_cDhcp_End_Addr,
                                                                                l_cLan_Subnet, l_cDhcp_Lease_Time);

                                                // Needs to configure dhcp option for corresponding interface wan dns servers
                                                if( ( bDhcpNs_Enabled ) && \
                                                ( NULL != pWan_Dhcp_Dns ) && \
                                                        ( '\0' != pWan_Dhcp_Dns[ 0 ] ) \
                                                  )
                                                {
                                                        fprintf(local_dhcpconf_file, "%sdhcp-option=%s,6,%s\n", prefix, l_cIfName, pWan_Dhcp_Dns);
                                                        DHCPMGR_LOG_INFO("DHCP_SERVER : [%s] %sdhcp-option=%s,6,%s", l_cIfName, prefix, l_cIfName, pWan_Dhcp_Dns);
                                                }
                                         }
                                }
                                else
                                {
                                        DHCPMGR_LOG_INFO("%s is not up go to next pool", l_cIpv4InstStatus);
                                }
                        }
                        else
                        {
                                DHCPMGR_LOG_INFO("%s is not TRUE continue to next pool", l_cDhcpEnabled);
                        }
                }
                else
                {
                        DHCPMGR_LOG_INFO("pool is empty continue to next pool");
                }
                l_cToken = strtok(NULL, " ");
       }
}

void UpdateConfigListintoConfFile(FILE *l_fLocal_Dhcp_ConfFile)
{
    char count[12];
    int dhcp_dyn_cnfig_counter=0;
    char dhcp_dyn_conf_change[1024] = {0};
    ifl_get_event( "dhcp_conf_change_counter", count,sizeof(count));
    dhcp_dyn_cnfig_counter = atoi(count);
    for(int i=1; i<= dhcp_dyn_cnfig_counter; i++)
    {
        char dynConfChange[256]  = {0};
        snprintf(dhcp_dyn_conf_change,sizeof(dynConfChange), "dhcp_dyn_conf_change_%d",i);
        ifl_get_event( dhcp_dyn_conf_change, dynConfChange, sizeof(dynConfChange));
        if(dynConfChange[0] != '\0' )
        {
            char confInterface[32] = {0};
            char confDhcprange[128] = {0};
            char * token = strtok(dynConfChange, "|");
            if(token != NULL){
                strncpy(confInterface,token,(sizeof(confInterface)-1));
            }
            while( token != NULL )
            {
                strncpy(confDhcprange,token,(sizeof(confDhcprange)-1));
                token = strtok(NULL, " ");
            }
            fprintf(l_fLocal_Dhcp_ConfFile, "%s\n", confInterface);
            fprintf(l_fLocal_Dhcp_ConfFile, "%s\n", confDhcprange);
        }
        else
        {
                DHCPMGR_LOG_INFO("Not able to set the value as sysevent set is null");
        }

    }

}

void AddConfList(char *confToken)
{
    char count[12];
    int dhcp_dyn_cnfig_counter=0;
    char dhcp_dyn_conf_change[1024];
    char conf[256]={'\0'};
    strncpy(conf, confToken, sizeof(conf)-1);
    ifl_get_event( "dhcp_conf_change_counter", count,sizeof(count));
    dhcp_dyn_cnfig_counter = atoi(count);
    snprintf(dhcp_dyn_conf_change, sizeof(conf), "dhcp_dyn_conf_change_%d",dhcp_dyn_cnfig_counter+1);
    ifl_set_event( dhcp_dyn_conf_change , conf);
    dhcp_dyn_cnfig_counter++;
    sprintf(count, "%d", dhcp_dyn_cnfig_counter);
    ifl_set_event( "dhcp_conf_change_counter", count);
}

void UpdateConfList(char *confTok, int ct)
{

    char conf[256]={'\0'};
    char dhcp_dyn_conf_change[1024] = {0};
    strncpy(conf, confTok, sizeof(conf)-1);
    snprintf(dhcp_dyn_conf_change, sizeof(conf), "dhcp_dyn_conf_change_%d",ct);
    DHCPMGR_LOG_INFO("sysevent set dhcp_dyn_conf_change_%d: %s\n",ct,conf);
    ifl_set_event( dhcp_dyn_conf_change , conf);
}

enum interface IsInterfaceExists(char *confTok, char * confInf, int* inst)
{
    char count[12];
    int dhcp_dyn_cnfig_counter=0;
    char dhcp_dyn_conf_change[1024] = {0};
    char conf[256]={'\0'};
    char infc[32]={'\0'};
    strncpy(conf, confTok, sizeof(conf)-1);
    strncpy(infc, confInf, sizeof(infc)-1);

    ifl_get_event( "dhcp_conf_change_counter", count,sizeof(count));
    dhcp_dyn_cnfig_counter = atoi(count);
    if(dhcp_dyn_cnfig_counter ==0)
    {
        return NotExists;
    }
    else
    {
        for(int i=1; i<= dhcp_dyn_cnfig_counter; i++)
        {
            char dynConfChange[256]  = {0};
            char dynConfChag[256]  = {0};
            snprintf(dhcp_dyn_conf_change,sizeof(dynConfChange), "dhcp_dyn_conf_change_%d",i);
            ifl_get_event( dhcp_dyn_conf_change, dynConfChange, sizeof(dynConfChange));
            strncpy(dynConfChag, dynConfChange, sizeof(dynConfChag)-1);
            char dynInf[32] = {0};
            if(dynConfChag[0] != '\0' )
            {
                char * tokenInf = strtok(dynConfChag, "|");
                strncpy(dynInf,tokenInf,(sizeof(dynInf)-1));
            }
            if (strcmp(infc,dynInf)==0)
            {
                if (strcmp(conf,dynConfChange)==0)
                {
                    return ExistWithSameRange;
                }
                else
                {
                    *inst =i;
                    return ExistWithDifferentRange;
                }
            }
            else
            {
                DHCPMGR_LOG_INFO("event not present in the list hence update it\n");
            }
        }
    }
    return NotExists;

}

void UpdateDhcpConfChangeBasedOnEvent()
{
    char confToken[256]  = {0};
    char confTok[256] = {0};
    enum interface inf;
    char confInface[32] = {0};
    int instance;
    ifl_get_event( "dhcp_conf_change", confToken, sizeof(confToken));
    strncpy(confTok, confToken, sizeof(confTok)-1);
    if(confTok[0] != '\0' )
    {
        char * token = strtok(confTok, "|");
        strncpy(confInface,token,(sizeof(confInface)-1));
    }
    inf= IsInterfaceExists(confToken,confInface,&instance);
    switch(inf)
    {
        case ExistWithSameRange:
            DHCPMGR_LOG_INFO("No change\n");
            break;
        case ExistWithDifferentRange:
            DHCPMGR_LOG_INFO("upadte the list\n");
            UpdateConfList(confToken,instance);
            break;
        case NotExists:
            DHCPMGR_LOG_INFO("add to list\n");
            AddConfList(confToken);
            break;
    }
}

//Input to this function
//1st Input Lan IP Address and 2nd Input LAN Subnet Mask
int prepare_dhcp_conf (char *input)
{
    DHCPMGR_LOG_INFO("DHCP SERVER : Prepare DHCP configuration");
    char l_cNetwork_Res[8] = {0}, l_cLocalDhcpConf[32] = {0};
    char l_cLanIPAddress[16] = {0}, l_cLanNetMask[16] = {0}, l_cLan_if_name[16] = {0};
    char l_cCaptivePortalEn[8] = {0}, l_cRedirect_Flag[8] = {0}, l_cMigCase[8] = {0};
#if defined (_XB6_PRODUCT_REQ_)
    char l_cRfCPFeatureEnabled[8] = {0}, l_cRfCPEnabled[8] = {0};
#endif
    char l_cWifi_Not_Configured[8] = {0};
    char l_cIotEnabled[16] = {0}, l_cIotIfName[16] = {0}, l_cIotStartAddr[16] = {0};
        char l_cIotEndAddr[16] = {0}, l_cIotNetMask[16] = {0};
        char l_cPropagate_Dom[8] = {0}, l_cLan_Domain[32] = {0}, l_cLog_Level[8] = {0};
        char l_cLan_Status[16] = {0};
    char l_cWan_Service_Stat[16] = {0}, l_cDns_Only_Prefix[8] = {0};
        char *l_cpPsm_Get = NULL;
        char l_cDhcpNs_Enabled[ 32 ]           = { 0 },
           l_cWan_Dhcp_Dns [ 256 ]             = { 0 };
        char l_cSecWebUI_Enabled[8] = {0};
        char l_cWan_Check[16] = {0};
        char l_statDns_Enabled[ 32 ] = { 0 };
        char l_cDhcpNs_1[ 128 ] = { 0 }, l_cDhcpNs_2[ 128 ] = { 0 };

#ifdef RDKB_EXTENDER_ENABLED

        char dev_Mode[20] = {0};
        char buff[512] = {0};
#endif


        int l_iMkdir_Res, l_iRet_Val;
        int l_iRetry_Count = 0;

        FILE *l_fLocal_Dhcp_ConfFile = NULL;
    FILE *l_fNetRes = NULL, *l_fDef_Resolv = NULL;

    BOOL l_bRfCp = FALSE;
    BOOL l_bCaptivePortal_Mode = FALSE;
        BOOL l_bCaptive_Check = FALSE;
        BOOL l_bMig_Case = TRUE,
             l_bWifi_Res_Mig = FALSE,
                 l_bDhcpNs_Enabled = FALSE,
                 l_bIsValidWanDHCPNs = FALSE;
                 errno_t safec_rc = -1;

        safec_rc = sprintf_s(l_cLocalDhcpConf, sizeof(l_cLocalDhcpConf),"/tmp/dnsmasq.conf%d", getpid());
        if(safec_rc < EOK)
        {
                ERR_CHK(safec_rc);
        }

        l_fLocal_Dhcp_ConfFile = fopen(l_cLocalDhcpConf, "a+"); //It will create a file and open
    if(NULL == l_fLocal_Dhcp_ConfFile)
    {
        DHCPMGR_LOG_ERROR("File: %s creation failed with error:%d", l_cLocalDhcpConf, errno);
               return 0;
    }

#ifdef RDKB_EXTENDER_ENABLED

    syscfg_get(NULL, "Device_Mode", dev_Mode, sizeof(dev_Mode));
    if (atoi(dev_Mode) == 1)
    {
        /*
         * Modem/Extender mode:
         * Start dnsmasq to assign IP address for to the tunnel interface
         */

        // set IP to interface to which dnsmasq should listen
        int ret_val;
        char *psmStrValue = NULL;
        char mesh_wan_ifname[16] = {0};
        memset(mesh_wan_ifname, 0, sizeof(mesh_wan_ifname));

        ret_val = PSM_VALUE_GET_STRING(MESH_WAN_IFNAME, psmStrValue);

        if (CCSP_SUCCESS == ret_val && psmStrValue != NULL)
        {
                strncpy(mesh_wan_ifname, psmStrValue, sizeof(mesh_wan_ifname));
                DHCPMGR_LOG_INFO("mesh_wan_ifname is %s", mesh_wan_ifname);
                Ansc_FreeMemory_Callback(psmStrValue);
                psmStrValue = NULL;
        }
        addr_add_va_arg("dev %s %s/24", mesh_wan_ifname, GRE_VLAN_IFACE_IP);

        // edit the config file

        fprintf(l_fLocal_Dhcp_ConfFile, "#We want dnsmasq to read /var/tmp/lte_resolv.conf \n");
        memset (buff, 0, sizeof(buff));
        snprintf(buff, sizeof(buff), "resolv-file=%s\n\n", TMP_RESOLVE_CONF);
        fprintf(l_fLocal_Dhcp_ConfFile, buff);
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-leasefile=%s\n", DHCP_LEASE_FILE); 
        fprintf(l_fLocal_Dhcp_ConfFile, "#We want dnsmasq to listen for DHCP and DNS requests only on specified interfaces\n");
        memset (buff, 0, sizeof(buff));
        snprintf(buff, sizeof(buff), "interface=%s\n\n", mesh_wan_ifname);
        fprintf(l_fLocal_Dhcp_ConfFile, buff);

        fprintf(l_fLocal_Dhcp_ConfFile, "#We need to supply the range of addresses available for lease and optionally a lease time\n");
        memset (buff, 0, sizeof(buff));
        snprintf(buff, sizeof(buff), "dhcp-range=%s\n\n", GRE_VLAN_IFACE_DHCP_OPT);
        fprintf(l_fLocal_Dhcp_ConfFile, buff);

	UpdateConfigListintoConfFile(l_fLocal_Dhcp_ConfFile); 
#if 0

        bool dns_flag = 0;
        char dns_ip1[16] = {0};
        char dns_ip2[16] = {0};
        char dns1_ipv6[128] = {0};
        char dns2_ipv6[128] = {0};
        struct sockaddr_in sa;
        memset (buff, 0, sizeof(buff));

        ifl_get_event( "ipv4_dns_0", dns_ip1, sizeof(dns_ip1));
        if (inet_pton(AF_INET, dns_ip1, &(sa.sin_addr)))
        {
            dns_flag = 1;
        }
        else
        {
            // nameserver IP not a valid v4 IP, so memset buffer
            memset(dns_ip1, 0, sizeof(dns_ip1));
            memset(dns2_ipv6, 0, sizeof(dns2_ipv6));

        }

        ifl_get_event( "ipv4_dns_1", dns_ip2, sizeof(dns_ip2));
        if (inet_pton(AF_INET, dns_ip2, &(sa.sin_addr)))
        {
            dns_flag = 1;
        }
        else
        {
            // nameserver IP not a valid v4 IP, so memset buffer
            memset(dns_ip2, 0, sizeof(dns_ip2));
        }
        struct in6_addr ipv6_addr;
        memset(&ipv6_addr, 0, sizeof(struct in6_addr));

        memset(dns1_ipv6, 0, sizeof(dns1_ipv6));

        ifl_get_event( "cellular_wan_v6_dns1", dns1_ipv6, sizeof(dns1_ipv6));
        if (inet_pton(AF_INET6, dns1_ipv6, &ipv6_addr))
        {
            dns_flag = 1;
        }

        ifl_get_event( "cellular_wan_v6_dns2", dns2_ipv6, sizeof(dns2_ipv6));
        if (inet_pton(AF_INET6, dns2_ipv6, &ipv6_addr))
        {
            dns_flag = 1;
        }

        if (dns_flag)
        {
            strcpy(buff, "dhcp-option=6");
            if (strlen(dns_ip1) > 0)
            {
                strcat(buff,",");
                strncat(buff,dns_ip1,strlen(dns_ip1));
            }
            if (strlen(dns_ip2) > 0)
            {
                strcat(buff,",");
                strncat(buff,dns_ip2,strlen(dns_ip2));
            }

            fprintf(l_fLocal_Dhcp_ConfFile,"%s\n", buff);

            if (strlen(dns1_ipv6) > 0)
            {
                strcat(buff,",");
                strncat(buff,dns1_ipv6,strlen(dns1_ipv6));
            }

            if (strlen(dns2_ipv6) > 0)
            {
                strcat(buff,",");
                strncat(buff,dns2_ipv6,strlen(dns2_ipv6));
            }
            
	    FILE *fp = NULL;
            snprintf(dns,sizeof(dns),"%s",buff);
            tok = strtok(dns, ","); // ignore dhcp-option=6
            tok = strtok(NULL, ","); // first dns ip
            if (tok)
            {
                fp = fopen(TMP_RESOLVE_CONF,"w");
                if (NULL == fp)
                {
                    DHCPMGR_LOG_ERROR("Error in opening resolv.conf file in write mode");
                    fclose(l_fLocal_Dhcp_ConfFile);
                    return -1;
                }

                while (NULL != tok)
                {
                    DHCPMGR_LOG_INFO ("\n tok :%s \n",tok);
                    fprintf(fp,"nameserver %s\n",tok);
                    tok = strtok(NULL, ",");
                }
                fclose(fp);
            }
        }
#endif
        // Add DHCP option 43: Vendor specific data
        memset (buff, 0, sizeof(buff));
        ifl_get_event( "dhcpv4_option_43", buff, sizeof(buff));
        if ((buff != NULL) && strlen(buff) > 0)
        {
            fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=43,%s\n", buff);
        }

        remove_file(DHCP_CONF);
        fclose(l_fLocal_Dhcp_ConfFile);
        copy_file(l_cLocalDhcpConf, DHCP_CONF);
        remove_file(l_cLocalDhcpConf);
        return 0;
    }

#endif

    // prepare dhcp config file for GATEWAY mode

        if ((NULL != input) && (!strncmp(input, "dns_only", 8)))
        {
                DHCPMGR_LOG_INFO("dns_only case prefix is #");
                l_cDns_Only_Prefix[0] = '#';
        }

    syscfg_get(NULL, "SecureWebUI_Enable", l_cSecWebUI_Enabled, sizeof(l_cSecWebUI_Enabled));
    ifl_get_event( "phylink_wan_state", l_cWan_Check, sizeof(l_cWan_Check));
    if (!strncmp(l_cSecWebUI_Enabled, "true", 4))
    {
        if(!strncmp(l_cWan_Check, "up", 2))
        {
            syscfg_set(NULL, "dhcpv6spool00::X_RDKCENTRAL_COM_DNSServersEnabled", "1");
            syscfg_set(NULL, "dhcp_nameserver_enabled", "1");
            syscfg_commit();
        }
        else
        {
            syscfg_get(NULL, "dhcp_nameserver_enabled", l_statDns_Enabled, sizeof(l_statDns_Enabled));
            syscfg_get(NULL, "dhcp_nameserver_1", l_cDhcpNs_1, sizeof(l_cDhcpNs_1));
            syscfg_get(NULL, "dhcp_nameserver_2", l_cDhcpNs_2, sizeof(l_cDhcpNs_2));
            if( ( '\0' != l_statDns_Enabled[ 0 ] ) && ( 1 == atoi( l_statDns_Enabled ) ) )
            {
                if( ( '\0' == l_cDhcpNs_1[ 0 ] ) || ( 0 == strcmp( l_cDhcpNs_1, "0.0.0.0" ) ) )
                {
                    if( ( '\0' == l_cDhcpNs_2[ 0 ] ) || ( 0 == strcmp( l_cDhcpNs_2, "0.0.0.0" ) ) )
                    {
                        syscfg_set_commit(NULL, "dhcp_nameserver_enabled", "0");
                    }
                }
            }
        }
    }
    else
    {
        syscfg_get(NULL, "dhcp_nameserver_enabled", l_statDns_Enabled, sizeof(l_statDns_Enabled));
        syscfg_get(NULL, "dhcp_nameserver_1", l_cDhcpNs_1, sizeof(l_cDhcpNs_1));
        syscfg_get(NULL, "dhcp_nameserver_2", l_cDhcpNs_2, sizeof(l_cDhcpNs_2));
        if( ( '\0' != l_statDns_Enabled[ 0 ] ) && ( 1 == atoi( l_statDns_Enabled ) ) )
        {
            if( ( '\0' == l_cDhcpNs_1[ 0 ] ) || ( 0 == strcmp( l_cDhcpNs_1, "0.0.0.0" ) ) )
            {
                if( ( '\0' == l_cDhcpNs_2[ 0 ] ) || ( 0 == strcmp( l_cDhcpNs_2, "0.0.0.0" ) ) )
                {
                       syscfg_set_commit(NULL, "dhcp_nameserver_enabled", "0");
                }
             }
         }
    }
    syscfg_get(NULL, "lan_ipaddr", l_cLanIPAddress, sizeof(l_cLanIPAddress));
    syscfg_get(NULL, "lan_netmask", l_cLanNetMask, sizeof(l_cLanNetMask));
    syscfg_get(NULL, "lan_ifname", l_cLan_if_name, sizeof(l_cLan_if_name));
    syscfg_get(NULL, "CaptivePortal_Enable", l_cCaptivePortalEn, sizeof(l_cCaptivePortalEn));
    syscfg_get(NULL, "redirection_flag", l_cRedirect_Flag, sizeof(l_cRedirect_Flag));
#if defined (_XB6_PRODUCT_REQ_)
    syscfg_get(NULL, "enableRFCaptivePortal", l_cRfCPFeatureEnabled, sizeof(l_cRfCPFeatureEnabled));
    syscfg_get(NULL, "rf_captive_portal", l_cRfCPEnabled, sizeof(l_cRfCPEnabled));
#endif

    if((0 == isValidLANIP(l_cLanIPAddress)) || (0 == isValidSubnetMask(l_cLanNetMask)))
    {
        FILE *fp;
        char cmd[512];
        char result[128];
        char lanIP[16]={0}, lanNetMask[16]={0}, dhcpStart[16]={0}, dhcpEnd[16]={0};

        DHCPMGR_LOG_INFO("LAN IP Address OR LAN net mask is not in valid format, setting to default lan_ipaddr:%s lan_netmask:%s",l_cLanIPAddress,l_cLanNetMask);
        snprintf(cmd,sizeof(cmd),"grep '$lan_ipaddr\\|$lan_netmask\\|$dhcp_start\\|$dhcp_end' %s"
          " | awk '/\\$lan_ipaddr/ {split($1,ip, \"=\");}"
          " /\\$lan_netmask/ {split($1,mask, \"=\");}"
          " /\\$dhcp_start/ {split($1,start, \"=\");}"
          " /\\$dhcp_end/ {split($1,end, \"=\");}"
          " END {print ip[2], mask[2], start[2], end[2]}'",DEFAULT_FILE);

        DHCPMGR_LOG_INFO("Command = %s",cmd);

        if ((fp = popen(cmd, "r")) == NULL)
        {
                DHCPMGR_LOG_ERROR("popen ERROR");
        }
        else if (fgets(result, sizeof(result), fp) == NULL)
        {
                pclose(fp);
                DHCPMGR_LOG_ERROR("popen fgets ERROR");
        }
        else
        {       sscanf(result, "%15s %15s %15s %15s",lanIP, lanNetMask, dhcpStart, dhcpEnd);

                syscfg_set(NULL, "lan_ipaddr", lanIP);
                syscfg_set(NULL, "lan_netmask", lanNetMask);
                syscfg_set(NULL, "dhcp_start", dhcpStart);
                syscfg_set(NULL, "dhcp_end", dhcpEnd);
                syscfg_commit();

                memset(l_cLanIPAddress, 0, sizeof(l_cLanIPAddress));
                strncpy(l_cLanIPAddress,lanIP,sizeof(l_cLanIPAddress));

                memset(l_cLanNetMask, 0, sizeof(l_cLanNetMask));
                strncpy(l_cLanNetMask,lanNetMask,sizeof(l_cLanNetMask));

                pclose(fp);
        }
    }


    // Static LAN DNS (brlan0)
        syscfg_get(NULL, "dhcp_nameserver_enabled", l_cDhcpNs_Enabled, sizeof(l_cDhcpNs_Enabled));
        if( ( '\0' != l_cDhcpNs_Enabled[ 0 ] ) && \
                ( 1 == atoi( l_cDhcpNs_Enabled ) )
          )
        {
                l_bDhcpNs_Enabled = TRUE;
        }

        // Get proper wan dns server list and check whether wan-dns is valid or not
        check_and_get_wan_dhcp_dns( l_cWan_Dhcp_Dns );
        if( '\0' != l_cWan_Dhcp_Dns[ 0 ] )
        {
               l_bIsValidWanDHCPNs = TRUE;
        }

    l_fNetRes = fopen(NETWORK_RES_FILE, "r");
    if (NULL == l_fNetRes)
    {
               DHCPMGR_LOG_INFO("%s file is not present ", NETWORK_RES_FILE);
    }
    else
        {
                errno_t ret_chk = -1;
                ret_chk = fscanf(l_fNetRes,"%7s", l_cNetwork_Res);
                if (ret_chk == -1)
                    ERR_CHK(ret_chk);
                fclose(l_fNetRes);
        }


        l_iRet_Val = PSM_VALUE_GET_STRING(PSM_NAME_NOTIFY_WIFI_CHANGES, l_cpPsm_Get);
        while ((CCSP_SUCCESS != l_iRet_Val && l_cpPsm_Get == NULL) &&
                (l_iRetry_Count++ < 2))
        {
                l_iRet_Val = PSM_VALUE_GET_STRING(PSM_NAME_NOTIFY_WIFI_CHANGES, l_cpPsm_Get);
        }
    if (CCSP_SUCCESS == l_iRet_Val && l_cpPsm_Get != NULL)
        {
            strncpy(l_cWifi_Not_Configured, l_cpPsm_Get, sizeof(l_cWifi_Not_Configured));
                           DHCPMGR_LOG_INFO("DHCP SERVER : NotifyWiFiChanges is %s", l_cWifi_Not_Configured);
                Ansc_FreeMemory_Callback(l_cpPsm_Get);
                l_cpPsm_Get = NULL;
        }
        else
        {
                DHCPMGR_LOG_ERROR("DHCP SERVER : Error:%d while getting:%s or value is empty",
                             l_iRet_Val, PSM_NAME_NOTIFY_WIFI_CHANGES);
        }
        DHCPMGR_LOG_INFO("DHCP SERVER : CaptivePortal_Enabled is %s", l_cCaptivePortalEn);

        if (IS_MIG_CHECK_NEEDED(g_cMig_Check))
        {
                DHCPMGR_LOG_INFO("Wifi Migration checks are needed");

                syscfg_get(NULL, "migration_cp_handler", l_cMigCase, sizeof(l_cMigCase));
                if(!strncmp(l_cMigCase, "true", 4))
                {
                    DHCPMGR_LOG_INFO("DHCP SERVER : Initialize migration case variable to true");
                    l_bMig_Case = TRUE;
                }
                else
                {
                   DHCPMGR_LOG_INFO("DHCP SERVER : Initialize migration case variable to false");
                   l_bMig_Case = FALSE;
                }
                ifl_get_event( "wan_service-status", l_cWan_Service_Stat, sizeof(l_cWan_Service_Stat));

                l_iRetry_Count = 0;
                l_iRet_Val = PSM_VALUE_GET_STRING(PSM_NAME_WIFI_RES_MIG, l_cpPsm_Get);
                while ((CCSP_SUCCESS != l_iRet_Val && l_cpPsm_Get == NULL) &&
                       (l_iRetry_Count++ < 2))
                {
                        l_iRet_Val = PSM_VALUE_GET_STRING(PSM_NAME_WIFI_RES_MIG, l_cpPsm_Get);
                }
        if (CCSP_SUCCESS == l_iRet_Val && l_cpPsm_Get != NULL)
                {
                        /* BUFFER_SIZE_WARNING */
                        if(!strncmp(l_cpPsm_Get, "true", 4))
                        {
                           l_bWifi_Res_Mig = TRUE;
                        }
                        else
                        {
                           l_bWifi_Res_Mig = FALSE;
                        }
                        DHCPMGR_LOG_INFO("DHCP SERVER : WiFiRestored_AfterMigration is %d", l_bWifi_Res_Mig);
             Ansc_FreeMemory_Callback(l_cpPsm_Get);
             l_cpPsm_Get = NULL;
             }
                else
                {
                        DHCPMGR_LOG_ERROR("DHCP SERVER : Error:%d while getting:%s or value is empty",
                                         l_iRet_Val, PSM_NAME_WIFI_RES_MIG);
                }

                if (l_bMig_Case && l_bWifi_Res_Mig)
                {
                    DHCPMGR_LOG_INFO("DHCP SERVER : WiFi restored case setting MIGRATION_CASE variable to false");
                    l_bMig_Case = FALSE;
                }
        }
        else
        {
                    DHCPMGR_LOG_INFO("Migration checks are not needed");
        }

        if (IS_MIG_CHECK_NEEDED(g_cMig_Check))
        {
              l_bCaptive_Check = ((!strncmp(l_cCaptivePortalEn, "true", 4)) && (FALSE == l_bMig_Case)) ? (TRUE) : (FALSE);
        }
        else
        {
              l_bCaptive_Check = (!strncmp(l_cCaptivePortalEn, "true", 4)) ? (TRUE) : (FALSE);
        }

        if (l_bCaptive_Check)
        {
#if defined (_XB6_PRODUCT_REQ_)
           if ((!strncmp(l_cRfCPFeatureEnabled,"true",4)) && (!strncmp(l_cRfCPEnabled,"true",4)))
           {
                l_bRfCp = TRUE;

           }
           if  ( (TRUE== l_bRfCp ) || ((!strncmp(l_cNetwork_Res, "204", 3)) && (!strncmp(l_cRedirect_Flag, "true", 4)) &&
                     (!strncmp(l_cWifi_Not_Configured, "true", 4))))
           {
              l_bCaptivePortal_Mode = TRUE;
              if (TRUE== l_bRfCp )
              {
                 DHCPMGR_LOG_INFO("DHCP SERVER : NO RF CAPTIVE_PORTAL_MODE");
              }
              else
              {
                     DHCPMGR_LOG_INFO("DHCP SERVER : WiFi SSID and Passphrase are not modified,set CAPTIVE_PORTAL_MODE");
                     t2_event_d("SYS_INFO_CaptivePortal", 1);
                     if (access("/nvram/reverted", F_OK) == 0) //If file is present
                     {
                       DHCPMGR_LOG_INFO("DHCP SERVER : Removing reverted flag");
                       remove_file("/nvram/reverted");
                     }
              }
           }
           else
           {
              l_bCaptivePortal_Mode = FALSE;
              DHCPMGR_LOG_INFO("DHCP SERVER : WiFi SSID and Passphrase are already modified");
              DHCPMGR_LOG_INFO(" or no network response ,set CAPTIVE_PORTAL_MODE to false");
           }
#else
       if  ((!strncmp(l_cNetwork_Res, "204", 3)) && (!strncmp(l_cRedirect_Flag, "true", 4)) &&
                   (!strncmp(l_cWifi_Not_Configured, "true", 4)))
           {
              l_bCaptivePortal_Mode = TRUE;
              DHCPMGR_LOG_INFO("DHCP SERVER : WiFi SSID and Passphrase are not modified,set CAPTIVE_PORTAL_MODE");
              t2_event_d("SYS_INFO_CaptivePortal", 1);
              if (access("/nvram/reverted", F_OK) == 0) //If file is present
              {
                 DHCPMGR_LOG_INFO("DHCP SERVER : Removing reverted flag");
                 remove_file("/nvram/reverted");
              }
           }
           else
           {
              l_bCaptivePortal_Mode = FALSE;
              DHCPMGR_LOG_INFO("DHCP SERVER : WiFi SSID and Passphrase are already modified");
              DHCPMGR_LOG_INFO(" or no network response ,set CAPTIVE_PORTAL_MODE to false");
           }
#endif
       }


    // Dont add resolv-file if in norf captive portal mode
    if(FALSE == l_bRfCp)
    {
        fprintf(l_fLocal_Dhcp_ConfFile, "domain-needed\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "bogus-priv\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "address=/.c.f.ip6.arpa/\n");

        if (TRUE == l_bCaptivePortal_Mode)
        {
            // Create a temporary resolv configuration file
            // Pass that as an option in DNSMASQ
            l_iMkdir_Res = mkdir(DEFAULT_CONF_DIR, S_IRUSR | S_IWUSR);
            //mkdir successful or already exists
            if (0 == l_iMkdir_Res || (0 != l_iMkdir_Res && EEXIST == errno))
            {
                l_fDef_Resolv = fopen(DEFAULT_RESOLV_CONF, "a+");
                if (NULL != l_fDef_Resolv)
                {
                    fprintf(l_fDef_Resolv, "nameserver 127.0.0.1\n");
                    fprintf(l_fLocal_Dhcp_ConfFile, "resolv-file=%s\n",DEFAULT_RESOLV_CONF);
                    fclose(l_fDef_Resolv);
                }
                else
                {
                    DHCPMGR_LOG_ERROR("%s file creation failed", DEFAULT_RESOLV_CONF);
                }
            }
        }
        else
        {
            if ((access(DEFAULT_RESOLV_CONF, F_OK) == 0)) //DEFAULT_RESOLV_CONF file exists
            {
                remove_file(DEFAULT_RESOLV_CONF);
            }

            if( FALSE == l_bDhcpNs_Enabled )
            {
                fprintf(l_fLocal_Dhcp_ConfFile, "resolv-file=%s\n", RESOLV_CONF);
            }
        }

        //Propagate Domain
        syscfg_get(NULL, "dhcp_server_propagate_wan_domain", l_cPropagate_Dom, sizeof(l_cPropagate_Dom));

        // if we are provisioned to use the wan domain name, the we do so
        // otherwise we use the lan domain name
        if (!strncmp(l_cPropagate_Dom, "1", 1))
        {
            ifl_get_event( "dhcp_domain", l_cLan_Domain, sizeof(l_cLan_Domain));
        }
        if (0 == l_cLan_Domain[0])
        {
            syscfg_get(NULL, "lan_domain", l_cLan_Domain, sizeof(l_cLan_Domain));
        }
        if (0 != l_cLan_Domain[0])
        {
            fprintf(l_fLocal_Dhcp_ConfFile, "domain=%s\n",l_cLan_Domain);
        }
    }
    else
    {
            fprintf(l_fLocal_Dhcp_ConfFile, "no-resolv\n");
    }

        fprintf(l_fLocal_Dhcp_ConfFile, "expand-hosts\n");

        //Log Level is not used but still retaining the code
        syscfg_get(NULL, "log_level", l_cLog_Level, sizeof(l_cLog_Level));

        if ((NULL != input) && (!strncmp(input, "dns_only", 8)))
        {
             fprintf(l_fLocal_Dhcp_ConfFile, "no-dhcp-interface=%s\n", l_cLan_if_name);
        }

        //Not taking into account prefix
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-leasefile=%s\n", DHCP_LEASE_FILE);
        #if 0
        //DHCP_NUM is the number of available dhcp address for the lan
        syscfg_get(NULL, "dhcp_num", l_cDhcp_Num, sizeof(l_cDhcp_Num));
        if (0 == l_cDhcp_Num[0])
        {
            DHCPMGR_LOG_INFO("DHCP NUM is empty, set the dhcp_num integer as zero");
            l_idhcp_num = 0;
        }
        else
        {
            l_idhcp_num = atoi(l_cDhcp_Num);
            DHCPMGR_LOG_INFO("DHCP NUM is not empty it is :%d", l_idhcp_num);
        }
        fprintf(l_fLocal_Dhcp_ConfFile, "%sdhcp-lease-max=%d\n", l_cDns_Only_Prefix, l_idhcp_num);
        #endif
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-hostsfile=%s\n", DHCP_STATIC_HOSTS_FILE);

        if ( ( FALSE == l_bCaptivePortal_Mode) &&\
                ( FALSE == l_bDhcpNs_Enabled )
                )
        {
               fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-optsfile=%s\n", DHCP_OPTIONS_FILE);
        }
//Ethernet Backhaul changes for plume pods
#if defined (_XB6_PRODUCT_REQ_) || defined (_HUB4_PRODUCT_REQ_)
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=vendor:Plume,43,tag=123\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=vendor:PP203X,43,tag=123\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=vendor:HIXE12AWR,43,tag=123\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=vendor:WNXE12AWR,43,tag=123\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=vendor:SE401,43,tag=123\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=vendor:WNXL11BWL,43,tag=123\n");
#endif
        if ((NULL == input) ||
               ((NULL != input) && (strncmp(input, "dns_only", 8)))) //not dns_only case
        {
                DHCPMGR_LOG_INFO("not dns_only case calling other prepare functions");
                prepare_dhcp_conf_static_hosts();
                prepare_dhcp_options_wan_dns();
        }

#if defined (_XB6_PRODUCT_REQ_) || defined (_CBR_PRODUCT_REQ_)
    {
        struct in_addr ipv4Addr;
        int    ret = -1;
        int    resComp = -1;
        char   nmSrv[32]    = {0};
        char   dnsIP[64]    = {0};
        char   leftOut[128] = {0};
        char   ns_ip[256]   = {0};
        FILE*  fp1 = NULL;
        FILE*  fp2 = NULL;
 
        if ((fp1 = fopen(RESOLV_CONF, "r")))
        {
            while ( memset(nmSrv,   0, sizeof(nmSrv)),
                    memset(dnsIP,   0, sizeof(dnsIP)),
                    memset(leftOut, 0, sizeof(leftOut)),
                    fscanf(fp1, "%s %s%[^\n]s\n", nmSrv, dnsIP, leftOut) != EOF)
            {
                ret = strcmp_s(nmSrv, sizeof(nmSrv), "nameserver", &resComp);
                ERR_CHK(ret);

                if (!ret && !resComp)
                {
                    if (inet_pton(AF_INET, dnsIP, &ipv4Addr) > 0)
                    {
                        ret = strcat_s(ns_ip, sizeof(ns_ip), ",");
                        ERR_CHK(ret);

                        ret = strcat_s(ns_ip, sizeof(ns_ip), dnsIP);
                        ERR_CHK(ret);
                    }
                }
            }
	                fclose(fp1);

            if (*ns_ip && (fp2 = fopen(DHCP_OPTIONS_FILE, "w")))
            {
                fprintf(fp2, "option:dns-server%s\n", ns_ip);
                fclose(fp2);
            }
            else
            {
                DHCPMGR_LOG_ERROR("DHCP_SERVER : Error in opening %s",DHCP_OPTIONS_FILE );
            }
        }
        else
        {
            DHCPMGR_LOG_ERROR("DHCP_SERVER : Error in opening %s",RESOLV_CONF );
        }
    }
#endif

        ifl_get_event( "lan-status", l_cLan_Status, sizeof(l_cLan_Status));
        if (!strncmp(l_cLan_Status, "started", 7))
        {
                // calculate_dhcp_range has code to write dhcp-range
                fprintf(l_fLocal_Dhcp_ConfFile, "interface=%s\n",l_cLan_if_name);
                calculate_dhcp_range(l_fLocal_Dhcp_ConfFile, l_cDns_Only_Prefix);


                // Add brlan0 custom dns server configuration
                if( l_bDhcpNs_Enabled )
                {
                        char cDhcpNs_OptionString[ 1024 ] = { 0 };
                        get_dhcp_option_for_brlan0( cDhcpNs_OptionString );
                        fprintf(l_fLocal_Dhcp_ConfFile, "%s\n", cDhcpNs_OptionString);
                        if (!strncmp(l_cSecWebUI_Enabled, "true", 4))
                        {
                            char  l_clocFqdn[16] = {0},l_cCurLanIP[16] = {0};
                            ifl_get_event( "current_lan_ipaddr", l_cCurLanIP, sizeof(l_cCurLanIP));
                            syscfg_get(NULL, "SecureWebUI_LocalFqdn", l_clocFqdn, sizeof(l_clocFqdn));
                            fprintf(l_fLocal_Dhcp_ConfFile, "address=/%s/%s\n",l_clocFqdn,l_cCurLanIP );
                            fprintf(l_fLocal_Dhcp_ConfFile, "server=/%s/%s\n",l_clocFqdn,l_cCurLanIP );
                        }
                        DHCPMGR_LOG_INFO("DHCP_SERVER : [%s] %s", l_cLan_if_name, cDhcpNs_OptionString );
                 }
         }

    // For boot time optimization, run do_extra_pools only when brlan1 interface is available
        // Ideally interface presence is done by passing SIOCGIFCONF and going thru the complete
        // Interface list but using SIOCGIFADDR	as it is only call to get IP Address of the interface
        // If the interface is not present then fecthing IPv4 address will fail with error ENODEV
        if (is_iface_present(XHS_IF_NAME))
        {
               DHCPMGR_LOG_INFO("%s interface is present creating dnsmasq", XHS_IF_NAME);
        do_extra_pools(l_fLocal_Dhcp_ConfFile, l_cDns_Only_Prefix, l_bDhcpNs_Enabled, l_cWan_Dhcp_Dns);
        }
        else
        {
                DHCPMGR_LOG_INFO("%s interface is not present, not adding dnsmasq entries", XHS_IF_NAME);
        }

                //Lost And Found Enable
    syscfg_get(NULL, "lost_and_found_enable", l_cIotEnabled, sizeof(l_cIotEnabled));
        if (!strncmp(l_cIotEnabled, "true", 4))
        {
        DHCPMGR_LOG_INFO("IOT_LOG : DHCP server configuring for IOT");

            syscfg_get(NULL, "iot_ifname", l_cIotIfName, sizeof(l_cIotIfName));
            if( strstr( l_cIotIfName, "l2sd0.106")) {
                  memset(l_cIotIfName, 0, sizeof(l_cIotIfName));
                  syscfg_get( NULL, "iot_brname", l_cIotIfName, sizeof(l_cIotIfName));
            }
            syscfg_get(NULL, "iot_dhcp_start", l_cIotStartAddr, sizeof(l_cIotStartAddr));
            syscfg_get(NULL, "iot_dhcp_end", l_cIotEndAddr, sizeof(l_cIotEndAddr));
            syscfg_get(NULL, "iot_netmask", l_cIotNetMask, sizeof(l_cIotNetMask));

        fprintf(l_fLocal_Dhcp_ConfFile, "interface=%s\n", l_cIotIfName);
                if (!strncmp(g_cDhcp_Lease_Time, "-1", 2))
                {
                        //TODO add dns_only prefix
                        fprintf(l_fLocal_Dhcp_ConfFile, "%sdhcp-range=%s,%s,%s,infinite\n",
                               l_cDns_Only_Prefix, l_cIotStartAddr, l_cIotEndAddr, l_cIotNetMask);
                }
                else
                {
                        //TODO add dns_only prefix
                        fprintf(l_fLocal_Dhcp_ConfFile, "%sdhcp-range=%s,%s,%s,86400\n",
                               l_cDns_Only_Prefix, l_cIotStartAddr, l_cIotEndAddr, l_cIotNetMask);
                }

                // Add iot custom dns server configuration
                if( l_bDhcpNs_Enabled && l_bIsValidWanDHCPNs )
                {
                        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=%s,6,%s\n", l_cIotIfName, l_cWan_Dhcp_Dns);
                        DHCPMGR_LOG_INFO("DHCP_SERVER : [%s] dhcp-option=%s,6,%s",l_cIotIfName, l_cIotIfName, l_cWan_Dhcp_Dns);
                }
        }

        DHCPMGR_LOG_INFO("DHCP server configuring for Mesh network");
#if defined (_COSA_INTEL_XB3_ARM_)
        fprintf(l_fLocal_Dhcp_ConfFile, "interface=l2sd0.112\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.0.5,169.254.0.253,255.255.255.0,infinite\n");

        // Add l2sd0.112 custom dns server configuration
        if( l_bDhcpNs_Enabled && l_bIsValidWanDHCPNs )
        {
                fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=l2sd0.112,6,%s\n", l_cWan_Dhcp_Dns);
                DHCPMGR_LOG_INFO("DHCP_SERVER : [l2sd0.112] dhcp-option=l2sd0.112,6,%s", l_cWan_Dhcp_Dns);
        }

        fprintf(l_fLocal_Dhcp_ConfFile, "interface=l2sd0.113\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.1.5,169.254.1.253,255.255.255.0,infinite\n");

        // Add l2sd0.113 custom dns server configuration
        if( l_bDhcpNs_Enabled && l_bIsValidWanDHCPNs )
        {
                fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=l2sd0.113,6,%s\n", l_cWan_Dhcp_Dns);
                DHCPMGR_LOG_INFO("DHCP_SERVER : [l2sd0.113] dhcp-option=l2sd0.113,6,%s", l_cWan_Dhcp_Dns);
        }

        // Mesh Bhaul vlan address pool

        fprintf(l_fLocal_Dhcp_ConfFile, "interface=br403\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=192.168.245.2,192.168.245.253,255.255.255.0,infinite\n");

        // Add l2sd0.1060 custom dns server configuration
        if( l_bDhcpNs_Enabled && l_bIsValidWanDHCPNs )
        {
                fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=br403,6,%s\n", l_cWan_Dhcp_Dns);
                DHCPMGR_LOG_INFO("DHCP_SERVER : [br403] dhcp-option=br403,6,%s", l_cWan_Dhcp_Dns);
        }

        fprintf(l_fLocal_Dhcp_ConfFile, "interface=l2sd0.4090\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=192.168.251.2,192.168.251.253,255.255.255.0,infinite\n");

        // Add l2sd0.4090 custom dns server configuration
        if( l_bDhcpNs_Enabled && l_bIsValidWanDHCPNs )
        {
                fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=l2sd0.4090,6,%s\n", l_cWan_Dhcp_Dns);
                DHCPMGR_LOG_INFO("DHCP_SERVER : [l2sd0.4090] dhcp-option=l2sd0.4090,6,%s", l_cWan_Dhcp_Dns);
        }

        fprintf(l_fLocal_Dhcp_ConfFile, "interface=brebhaul\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.85.5,169.254.85.253,255.255.255.0,infinite\n");

        if( l_bDhcpNs_Enabled && l_bIsValidWanDHCPNs )
        {
                fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=brebhaul,6,%s\n", l_cWan_Dhcp_Dns);
                DHCPMGR_LOG_INFO("DHCP_SERVER : [brebhaul] dhcp-option=brebhaul,6,%s", l_cWan_Dhcp_Dns);
        }

#elif defined (INTEL_PUMA7) || (defined (_COSA_BCM_ARM_) && !defined(_CBR_PRODUCT_REQ_)) || defined(_COSA_QCA_ARM_) // ARRIS XB6 ATOM, TCXB6
        fprintf(l_fLocal_Dhcp_ConfFile, "interface=ath12\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.0.5,169.254.0.253,255.255.255.0,infinite\n");

                // Add ath12 custom dns server configuration
                if( l_bDhcpNs_Enabled && l_bIsValidWanDHCPNs )
                {
                        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=ath12,6,%s\n", l_cWan_Dhcp_Dns);
                        DHCPMGR_LOG_INFO("DHCP_SERVER : [ath12] dhcp-option=ath12,6,%s", l_cWan_Dhcp_Dns);
                }

        fprintf(l_fLocal_Dhcp_ConfFile, "interface=ath13\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.1.5,169.254.1.253,255.255.255.0,infinite\n");

                // Add ath12 custom dns server configuration
                if( l_bDhcpNs_Enabled && l_bIsValidWanDHCPNs )
                {
                        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=ath13,6,%s\n", l_cWan_Dhcp_Dns);
                        DHCPMGR_LOG_INFO("DHCP_SERVER : [ath13] dhcp-option=ath13,6,%s", l_cWan_Dhcp_Dns);
                }

       fprintf(l_fLocal_Dhcp_ConfFile, "interface=br403\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=192.168.245.2,192.168.245.253,255.255.255.0,infinite\n");

        // Add br403 custom dns server configuration
        if( l_bDhcpNs_Enabled && l_bIsValidWanDHCPNs )
        {
                fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=br403,6,%s\n", l_cWan_Dhcp_Dns);
                DHCPMGR_LOG_INFO("DHCP_SERVER : [br403] dhcp-option=br403,6,%s", l_cWan_Dhcp_Dns);
        }

        fprintf(l_fLocal_Dhcp_ConfFile, "interface=brebhaul\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.85.5,169.254.85.253,255.255.255.0,infinite\n");

        // Add brehaul custom dns server configuration
        if( l_bDhcpNs_Enabled && l_bIsValidWanDHCPNs )
        {
                fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=brebhaul,6,%s\n", l_cWan_Dhcp_Dns);
                DHCPMGR_LOG_INFO("DHCP_SERVER : [brebhaul] dhcp-option=brebhaul,6,%s", l_cWan_Dhcp_Dns);
        }
#endif

#if defined (_HUB4_PRODUCT_REQ_)
        fprintf(l_fLocal_Dhcp_ConfFile, "interface=brlan6\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.0.5,169.254.0.253,255.255.255.0,infinite\n");


                // Add brlan112 custom dns server configuration
                if( l_bDhcpNs_Enabled && l_bIsValidWanDHCPNs )
                {
                        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=brlan6,6,%s\n", l_cWan_Dhcp_Dns);
                        DHCPMGR_LOG_INFO("DHCP_SERVER : [brlan6] dhcp-option=brlan6,6,%s", l_cWan_Dhcp_Dns);
                }

        fprintf(l_fLocal_Dhcp_ConfFile, "interface=brlan7\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.1.5,169.254.1.253,255.255.255.0,infinite\n");

                // Add brlan113 custom dns server configuration
                if( l_bDhcpNs_Enabled && l_bIsValidWanDHCPNs )
                {
                        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=brlan7,6,%s\n", l_cWan_Dhcp_Dns);
                        DHCPMGR_LOG_INFO("DHCP_SERVER : [brlan7] dhcp-option=brlan7,6,%s", l_cWan_Dhcp_Dns);
                }

       fprintf(l_fLocal_Dhcp_ConfFile, "interface=br403\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=192.168.245.2,192.168.245.253,255.255.255.0,infinite\n");

        // Add br403 custom dns server configuration
        if( l_bDhcpNs_Enabled && l_bIsValidWanDHCPNs )
        {
                fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=br403,6,%s\n", l_cWan_Dhcp_Dns);
                DHCPMGR_LOG_INFO("DHCP_SERVER : [br403] dhcp-option=br403,6,%s", l_cWan_Dhcp_Dns);
        }
#endif

#if defined (_XB7_PRODUCT_REQ_)
        fprintf(l_fLocal_Dhcp_ConfFile, "interface=brlan112\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.0.5,169.254.0.253,255.255.255.0,infinite\n");


                // Add brlan112 custom dns server configuration
                if( l_bDhcpNs_Enabled && l_bIsValidWanDHCPNs )
                {
                        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=brlan112,6,%s\n", l_cWan_Dhcp_Dns);
                        DHCPMGR_LOG_INFO("DHCP_SERVER : [brlan112] dhcp-option=brlan112,6,%s", l_cWan_Dhcp_Dns);
                }

        fprintf(l_fLocal_Dhcp_ConfFile, "interface=brlan113\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.1.5,169.254.1.253,255.255.255.0,infinite\n");

                // Add brlan113 custom dns server configuration
                if( l_bDhcpNs_Enabled && l_bIsValidWanDHCPNs )
                {
                        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=brlan113,6,%s\n", l_cWan_Dhcp_Dns);
                        DHCPMGR_LOG_INFO("DHCP_SERVER : [brlan113] dhcp-option=brlan113,6,%s", l_cWan_Dhcp_Dns);
                }

#endif
#if defined (_PLATFORM_TURRIS_)
        //Wifi Backhaul link local connections
        fprintf(l_fLocal_Dhcp_ConfFile, "interface=wifi2\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.0.5,169.254.0.126,255.255.255.128,infinite\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=wifi2,3\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=wifi2,6\n");

        fprintf(l_fLocal_Dhcp_ConfFile, "interface=wifi3\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.1.5,169.254.1.126,255.255.255.128,infinite\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=wifi3,3\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=wifi3,6\n");

        fprintf(l_fLocal_Dhcp_ConfFile, "interface=wifi6\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.0.130,169.254.0.252,255.255.255.128,infinite\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=wifi6,3\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=wifi6,6\n");

        fprintf(l_fLocal_Dhcp_ConfFile, "interface=wifi7\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-range=169.254.1.130,169.254.1.252,255.255.255.128,infinite\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=wifi7,3\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=wifi7,6\n");
        fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-script=/etc/dhcp_script.sh\n");
#endif
        if (TRUE == l_bCaptivePortal_Mode)
        {
                //In factory default condition, prepare whitelisting and redirection IP
                fprintf(l_fLocal_Dhcp_ConfFile, "address=/#/%s\n", l_cLanIPAddress);
        if(FALSE == l_bRfCp)
        {
            fprintf(l_fLocal_Dhcp_ConfFile, "dhcp-option=252,\"\\n\"\n");
            prepare_whitelist_urls(l_fLocal_Dhcp_ConfFile);
        }

        ifl_set_event( "captiveportaldhcp", "completed");
        }

        //Prepare static dns urls
        if( l_bDhcpNs_Enabled )
        {
               prepare_static_dns_urls( l_fLocal_Dhcp_ConfFile );
        }

//        remove_file(DHCP_CONF);
        fclose(l_fLocal_Dhcp_ConfFile);
        copy_file(l_cLocalDhcpConf, DHCP_CONF);
        remove_file(l_cLocalDhcpConf);
        DHCPMGR_LOG_INFO("DHCP SERVER : Completed preparing DHCP configuration");
#if defined (WAN_FAILOVER_SUPPORTED)
    #if !defined (RDKB_EXTENDER_ENABLED)
        char lan_ipaddr[20]={'\0'};
        char l_cLine[255] = {0};
        FILE *l_fResolv_Conf = NULL;
        int Flag=0;
        l_fResolv_Conf = fopen(RESOLV_CONF, "r");
        if (NULL != l_fResolv_Conf)
        {
            while(fgets(l_cLine, 80, l_fResolv_Conf) != NULL )
            {
                char *property = NULL;
                if (NULL != (property = strstr(l_cLine, "127.0.0.1")))
                {
                    Flag=1;
                    break;
                }
            }
            fclose(l_fResolv_Conf);
            if(Flag==1)
            {
                l_fResolv_Conf = fopen(RESOLV_CONF, "w");
                if (NULL != l_fResolv_Conf)
                {
                    syscfg_get(NULL, "lan_ipaddr", lan_ipaddr, sizeof(lan_ipaddr));
                    //fprintf(g_fArmConsoleLog, "strlen of lan_ipaddr:%d\n",strlen(lan_ipaddr));
                    if(strlen(lan_ipaddr)>0)
                    {
                        fprintf(l_fResolv_Conf,"nameserver %s\n",lan_ipaddr);
                    }
                    fclose(l_fResolv_Conf);
                }
            }
        }
        else
        {
            DHCPMGR_LOG_INFO("opening of %s file failed with error:%d\n", RESOLV_CONF, errno);
        }
    #endif//RDKB_EXTENDER_ENABLED
#endif //WAN_FAILOVER_SUPPORTED
        return 0;
}

void get_dhcp_option_for_brlan0( char *pDhcpNs_OptionString )
{
	char l_cDhcpNs_1[ 128 ] 	 			 = { 0 },
		 l_cDhcpNs_2[ 128 ] 	 			 = { 0 },
		 l_cDhcpNs_3[ 128 ] 				 = { 0 },
                 l_cLocalNs[ 128 ]                               = { 0 },
                 l_cWan_Dhcp_Dns[ 256 ]                          = { 0 },
		 l_cDhcpNs_OptionString[ 1024 ] 	         = { 0 },
		 l_cDhcpNs_OptionString_new[ 1424 ]              = { 0 }; //CID 177296 : Uninitialized scalar variable
         errno_t safec_rc                                = -1;

    // Static LAN DNS
	syscfg_get(NULL, "dhcp_nameserver_1", l_cDhcpNs_1, sizeof(l_cDhcpNs_1));
	syscfg_get(NULL, "dhcp_nameserver_2", l_cDhcpNs_2, sizeof(l_cDhcpNs_2));	
	syscfg_get(NULL, "dhcp_nameserver_3", l_cDhcpNs_3, sizeof(l_cDhcpNs_3));
        ifl_get_event("current_lan_ipaddr", l_cLocalNs, sizeof(l_cLocalNs));

	safec_rc = strcpy_s( l_cDhcpNs_OptionString, sizeof(l_cDhcpNs_OptionString),"dhcp-option=brlan0,6");
	ERR_CHK(safec_rc);

	if( ( '\0' != l_cDhcpNs_1[ 0 ] ) && \
		( 0 != strcmp( l_cDhcpNs_1, "0.0.0.0" ) ) 
	  )
	{
		safec_rc = sprintf_s( l_cDhcpNs_OptionString_new, sizeof(l_cDhcpNs_OptionString_new),"%s,%s", l_cDhcpNs_OptionString, l_cDhcpNs_1 );
		if(safec_rc < EOK){
			ERR_CHK(safec_rc);
		}
	}

	if( ( '\0' != l_cDhcpNs_2[ 0 ] ) && \
		( 0 != strcmp( l_cDhcpNs_2, "0.0.0.0" ) ) 
	  )
	{
		memset(l_cDhcpNs_OptionString_new, 0 ,sizeof(l_cDhcpNs_OptionString_new));
		safec_rc = sprintf_s( l_cDhcpNs_OptionString_new, sizeof(l_cDhcpNs_OptionString_new),"%s,%s", l_cDhcpNs_OptionString, l_cDhcpNs_2 );
		if(safec_rc < EOK){
			ERR_CHK(safec_rc);
		}
	}

	
	if( ( '\0' != l_cDhcpNs_3[ 0 ] ) && \
		( 0 != strcmp( l_cDhcpNs_3, "0.0.0.0" ) ) 
	  )
	{
		memset(l_cDhcpNs_OptionString_new, 0 ,sizeof(l_cDhcpNs_OptionString_new));
		safec_rc = sprintf_s( l_cDhcpNs_OptionString_new, sizeof(l_cDhcpNs_OptionString_new),"%s,%s", l_cDhcpNs_OptionString, l_cDhcpNs_3 );
        if(safec_rc < EOK){
           ERR_CHK(safec_rc);
        }
	}

        char l_cSecWebUI_Enabled[8] = {0};
	FILE *l_fResolv_Conf = NULL;
	char l_cLine[255] = {0};
        syscfg_get(NULL, "SecureWebUI_Enable", l_cSecWebUI_Enabled, sizeof(l_cSecWebUI_Enabled));
        if (!strncmp(l_cSecWebUI_Enabled, "true", 4))
        {
                check_and_get_wan_dhcp_dns( l_cWan_Dhcp_Dns );
		//Read the nameserver addresses from reslov.conf
		if ( !(l_cWan_Dhcp_Dns[0]) ) {
			l_fResolv_Conf = fopen(RESOLV_CONF, "r");
			if (NULL != l_fResolv_Conf)
			{
				while(fgets(l_cLine, 80, l_fResolv_Conf) != NULL )
				{
					char *property = NULL;
					if (NULL != (property = strstr(l_cLine, "nameserver ")))
					{
						property = property + strlen("nameserver ");
						if (strstr(property, "."))
						{
							strncat(l_cWan_Dhcp_Dns, property, (strlen(property) - 1));
							//Add , to separate dns addresses
							l_cWan_Dhcp_Dns[strlen(l_cWan_Dhcp_Dns)]=',';
						}
					}
				}
				// Adding NULL at the end of dhcp options addresses
				if(strlen(l_cWan_Dhcp_Dns) != 0)
					l_cWan_Dhcp_Dns[strlen(l_cWan_Dhcp_Dns)-1]='\0';
				fclose(l_fResolv_Conf);
			}
			else
			{
				DHCPMGR_LOG_ERROR("%s:%d DHCP SERVER : get_dhcp_option_for_brlan0 :opening file %s failed\n",__FUNCTION__,__LINE__, RESOLV_CONF );
			}
		}
		DHCPMGR_LOG_INFO("%s:%d DHCP SERVER : get_dhcp_option_for_brlan0:%s\n",__FUNCTION__,__LINE__, l_cWan_Dhcp_Dns );
		memset(l_cDhcpNs_OptionString_new, 0 ,sizeof(l_cDhcpNs_OptionString_new));
		if ( '\0' != l_cWan_Dhcp_Dns[ 0 ] ){
                    safec_rc = sprintf_s( l_cDhcpNs_OptionString_new, sizeof(l_cDhcpNs_OptionString_new),"%s,%s,%s", l_cDhcpNs_OptionString, l_cWan_Dhcp_Dns, l_cLocalNs );
                    if(safec_rc < EOK){
                      ERR_CHK(safec_rc);
                    }
                }    
                else{
                    safec_rc = sprintf_s( l_cDhcpNs_OptionString_new, sizeof(l_cDhcpNs_OptionString_new),"%s,%s", l_cDhcpNs_OptionString, l_cLocalNs );
                    if(safec_rc < EOK){
                       ERR_CHK(safec_rc);
                    }
                }
        }
        // Copy custom dns servers
       safec_rc = strcpy_s( pDhcpNs_OptionString, 1024, l_cDhcpNs_OptionString_new ); /* Here pDhcpNs_OptionString is pointer, it's pointing to the array size is 1024 bytes */
       ERR_CHK(safec_rc);
}

void get_dhcp_option_for_brlan0_dummy( char *pDhcpNs_OptionString )
{
        char l_cDhcpNs_1[ 128 ]                                  = { 0 },
                 l_cDhcpNs_2[ 128 ]                              = { 0 },
                 l_cDhcpNs_3[ 128 ]                              = { 0 },
                 l_cLocalNs[ 128 ]                               = { 0 },
                 l_cWan_Dhcp_Dns[ 256 ]                          = { 0 },
                 l_cDhcpNs_OptionString[ 1024 ]                  = { 0 },
                 l_cDhcpNs_OptionString_new[ 1424 ]              = { 0 }; // Uninitialized scalar variable
         errno_t safec_rc                                = -1;

    // Static LAN DNS
        syscfg_get(NULL, "dhcp_nameserver_1", l_cDhcpNs_1, sizeof(l_cDhcpNs_1));
        syscfg_get(NULL, "dhcp_nameserver_2", l_cDhcpNs_2, sizeof(l_cDhcpNs_2));
        syscfg_get(NULL, "dhcp_nameserver_3", l_cDhcpNs_3, sizeof(l_cDhcpNs_3));
        ifl_get_event( "current_lan_ipaddr", l_cLocalNs, sizeof(l_cLocalNs));

        safec_rc = strcpy_s( l_cDhcpNs_OptionString, sizeof(l_cDhcpNs_OptionString),"dhcp-option=brlan0,6");
        ERR_CHK(safec_rc);

        if( ( '\0' != l_cDhcpNs_1[ 0 ] ) && \
                ( 0 != strcmp( l_cDhcpNs_1, "0.0.0.0" ) )
          )
        {
                safec_rc = sprintf_s( l_cDhcpNs_OptionString_new, sizeof(l_cDhcpNs_OptionString_new),"%s,%s", l_cDhcpNs_OptionString, l_cDhcpNs_1 );
                ERR_CHK(safec_rc);
        }

        if( ( '\0' != l_cDhcpNs_2[ 0 ] ) && \
               ( 0 != strcmp( l_cDhcpNs_2, "0.0.0.0" ) )
        )
        {
                memset(l_cDhcpNs_OptionString_new, 0 ,sizeof(l_cDhcpNs_OptionString_new));
                safec_rc = sprintf_s( l_cDhcpNs_OptionString_new, sizeof(l_cDhcpNs_OptionString_new),"%s,%s", l_cDhcpNs_OptionString, l_cDhcpNs_2 );
                ERR_CHK(safec_rc);
        }


        if( ( '\0' != l_cDhcpNs_3[ 0 ] ) && \
               ( 0 != strcmp( l_cDhcpNs_3, "0.0.0.0" ) )
          )
        {
                memset(l_cDhcpNs_OptionString_new, 0 ,sizeof(l_cDhcpNs_OptionString_new));
                safec_rc = sprintf_s( l_cDhcpNs_OptionString_new, sizeof(l_cDhcpNs_OptionString_new),"%s,%s", l_cDhcpNs_OptionString, l_cDhcpNs_3 );
                if(safec_rc < EOK){
                ERR_CHK(safec_rc);
        }
        }

        char l_cSecWebUI_Enabled[8] = {0};
        FILE *l_fResolv_Conf = NULL;
        char l_cLine[255] = {0};
        syscfg_get(NULL, "SecureWebUI_Enable", l_cSecWebUI_Enabled, sizeof(l_cSecWebUI_Enabled));
        if (!strncmp(l_cSecWebUI_Enabled, "true", 4))
        {
                check_and_get_wan_dhcp_dns( l_cWan_Dhcp_Dns );
                //Read the nameserver addresses from reslov.conf
                if ( !(l_cWan_Dhcp_Dns[0]) )
                {
                    l_fResolv_Conf = fopen(RESOLV_CONF, "r");
                    if (NULL != l_fResolv_Conf)
                    {
                        while(fgets(l_cLine, 80, l_fResolv_Conf) != NULL )
                        {
                            char *property = NULL;
                            if (NULL != (property = strstr(l_cLine, "nameserver ")))
                            {
                                property = property + strlen("nameserver ");
                                if (strstr(property, "."))
                                {
                                    strncat(l_cWan_Dhcp_Dns, property, (strlen(property) - 1));
                                    //Add , to separate dns addresses
                                    l_cWan_Dhcp_Dns[strlen(l_cWan_Dhcp_Dns)]=',';
                                }
                            }
                        }
                        // Adding NULL at the end of dhcp options addresses
                        if(strlen(l_cWan_Dhcp_Dns) != 0)
                        {
                            l_cWan_Dhcp_Dns[strlen(l_cWan_Dhcp_Dns)-1]='\0';
                        }
                        fclose(l_fResolv_Conf);
                    }
                    else
                    {
                        DHCPMGR_LOG_INFO("DHCP SERVER : get_dhcp_option_for_brlan0 :opening file %s failed\n", RESOLV_CONF );
                    }
                }
                DHCPMGR_LOG_INFO("DHCP SERVER : get_dhcp_option_for_brlan0:%s\n", l_cWan_Dhcp_Dns);
                memset(l_cDhcpNs_OptionString_new, 0 ,sizeof(l_cDhcpNs_OptionString_new));
                if ( '\0' != l_cWan_Dhcp_Dns[ 0 ] )
                {
                  safec_rc = sprintf_s( l_cDhcpNs_OptionString_new, sizeof(l_cDhcpNs_OptionString_new),"%s,%s,%s", l_cDhcpNs_OptionString, l_cLocalNs, l_cWan_Dhcp_Dns );
                  ERR_CHK(safec_rc);
                }
                else{
                    safec_rc = sprintf_s( l_cDhcpNs_OptionString_new, sizeof(l_cDhcpNs_OptionString_new),"%s,%s", l_cDhcpNs_OptionString, l_cLocalNs );
                    ERR_CHK(safec_rc);

                }

        }
        // Copy custom dns servers
       safec_rc = strcpy_s( pDhcpNs_OptionString, 1024, l_cDhcpNs_OptionString_new ); /* Here pDhcpNs_OptionString is pointer, it's pointing to the array size is 1024 bytes */
       ERR_CHK(safec_rc);
}

void check_and_get_wan_dhcp_dns( char *pl_cWan_Dhcp_Dns )
{
        char l_cWan_Dhcp_Dns[ 256 ] = { 0 };
        int  charCounter                     = 0;
        errno_t safec_rc = -1;

        ifl_get_event( "wan_dhcp_dns", l_cWan_Dhcp_Dns, sizeof(l_cWan_Dhcp_Dns));

        DHCPMGR_LOG_INFO("DHCP SERVER : wan_dhcp_dns:%s", l_cWan_Dhcp_Dns );

        // Replace " "(space) charecter as ","(comma)
        while( l_cWan_Dhcp_Dns[ charCounter ] != '\0' )
        {
                if( l_cWan_Dhcp_Dns[ charCounter ] == ' ' )
                {
                    l_cWan_Dhcp_Dns[ charCounter ] = ',';
                }
                charCounter++;
        }

        /* Here pl_cWan_Dhcp_Dns is pointer, it's pointing to the array size is 256 bytes */
        safec_rc = strcpy_s( pl_cWan_Dhcp_Dns, 256, l_cWan_Dhcp_Dns );
        ERR_CHK(safec_rc);

        DHCPMGR_LOG_INFO("DHCP SERVER : After conversion wan_dhcp_dns:%s ", l_cWan_Dhcp_Dns );
}

void prepare_static_dns_urls(FILE *fp_local_dhcp_conf)
{
        char  l_cLine[ 128 ]            = { 0 };
        FILE *l_fStaticDns_Urls         = NULL;

        l_fStaticDns_Urls = fopen( STATIC_DNS_URLS_FILE, "r" );
        if (NULL != l_fStaticDns_Urls)
        {
                while( fgets( l_cLine, 128, l_fStaticDns_Urls ) != NULL )
                {
                        char *pos = NULL;

                        // Remove line \n charecter from string
                        if ( ( pos = strchr( l_cLine, '\n' ) ) != NULL )
                        *pos = '\0';

                        DHCPMGR_LOG_INFO("url=/%s/", l_cLine );
                        fprintf( fp_local_dhcp_conf, "server=/%s/\n", l_cLine );
                        DHCPMGR_LOG_INFO("server=/%s/", l_cLine );
                        memset( l_cLine, 0, sizeof( l_cLine ) );
                }

                fclose( l_fStaticDns_Urls );
        }
        else
        {
                DHCPMGR_LOG_ERROR("opening of %s file failed with error:%d", STATIC_DNS_URLS_FILE, errno);
        }
}
