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

#ifndef  _DHCP_SERVER_FUNCTIONS_H
#define  _DHCP_SERVER_FUNCTIONS_H

#include <dhcp_server_v4_apis.h>
#include "lan_manager_interface.h"

typedef enum _NodeType_
{
    DHCP_OPTION,
    DHCP_VENDOR_CLASS,
    DOMAIN_SPECIFIC_ADDRESS,
    REDIRECTION_ADDRESS,
    DHCP_INTERFACE_CONFIG
}NodeType;

//error codes this API can generate.
/*typedef enum _dhcpmgrrError
{
    //Generic error codes
    DHCPMGR_STATUS_FAILURE                            = 1,
    DHCPMGR_STATUS_SUCCESS                            = RBUS_ERROR_SUCCESS,                       
    DHCPMGR_STATUS_BUS_ERROR                          = RBUS_ERROR_BUS_ERROR,                    
    DHCPMGR_STATUS_INVALID_INPUT                       = RBUS_ERROR_INVALID_INPUT               
} dhcpmgrError_t; */

typedef struct _dhcpIfaces_
{
    DhcpInterfaceConfig sDhcpIfcfg;
    struct _dhcpIfaces_ * next;
}DhcpIfaces;

typedef struct _dhcpOptions_
{
    char cDhcpOptions      [BUFF_LEN_64];
    struct _dhcpOptions_ * next;
}DhcpOptionsList;

typedef struct _dhcpVendorClass_
{
    char cVendorClass      [BUFF_LEN_64];
    struct _dhcpVendorClass_ * next;
}DhcpVendorClassList;

typedef struct _domainAddr_
{
    char cDomainSpecificAddr  [BUFF_LEN_64];
    struct _domainAddr_ *     next;
}DomainAddress;

typedef struct _redirectionAddress_
{
    char cRedirectionAddr          [BUFF_LEN_128];
    struct _redirectionAddress_  * next;
}RedirectionAddress;

int Construct_dhcp_configuration(DhcpInterfaceConfig ** ppHeadDhcpIf, int  pDhcpIfacesCount, char * pInput, GlobalDhcpConfig *pGlbDhcpCfg, LanConfig *pLanConfigs);
void printDhcpConfig (DhcpInterfaceConfig **ppDhcpCfgs, int iDhcpIfCount, GlobalDhcpConfig * pGlbDhcpCfg);
int  fillInterfaceDetails(DhcpIfaces *pDhcpIfaces, int iDhcpIfacesCount, DhcpInterfaceConfig ***ppDhcpCfgs);
void freeMemoryDHCP(DhcpInterfaceConfig **ppDhcpCfgs, int iDhcpIfCount, GlobalDhcpConfig * pGlbDhcpCfg);
int prepare_hostname();
void calculate_dhcp_range (FILE *local_dhcpconf_file, char *prefix);
void prepare_dhcp_conf_static_hosts();
void prepare_dhcp_options_wan_dns();
void prepare_whitelist_urls(FILE *);
void do_extra_pools (FILE *local_dhcpconf_file, char *prefix, unsigned char bDhcpNs_Enabled, char *pWan_Dhcp_Dns);
int prepare_dhcp_conf();
void check_and_get_wan_dhcp_dns( char *pl_cWan_Dhcp_Dns );
void get_dhcp_option_for_brlan0( char *pDhcpNs_OptionString );
void prepare_static_dns_urls(FILE *fp_local_dhcp_conf);
void UpdateDhcpConfChangeBasedOnEvent();
#endif /* _DHCP_SERVER_FUNCTIONS_H */
