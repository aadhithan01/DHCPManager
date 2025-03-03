#ifndef DHCPV4_INTERFACE_H
#define DHCPV4_INTERFACE_H

#include <sys/types.h>

#include "dhcp_client_utils.h"
#include "util.h"

typedef struct _DHCPv4_PLUGIN_MSG
{
    BOOL addressAssigned;              /** Have we been assigned an IP address ? */
    BOOL isExpired;                    /** Is the lease time expired ? */
    char address[BUFLEN_32];           /** New IP address,   */
    char netmask[BUFLEN_32];           /** New netmask */
    char gateway[BUFLEN_32];           /** New gateway,   */
    char dnsServer[BUFLEN_64];         /** New dns Server,   */
    char dnsServer1[BUFLEN_64];        /** New dns Server,   */
    char ifname[BUFLEN_32];            /** Dhcp interface name */
    uint32_t leaseTime;                /** Lease time, ,   */
    uint32_t rebindingTime;            /** Rebinding time,   */
    uint32_t renewalTime;              /** Renewal Time,   */
    int32_t timeOffset;                /** New time offset,   */
    BOOL isTimeOffsetAssigned;         /** Is the time offset assigned ? */
    char timeZone[BUFLEN_64];          /** New time zone,   */
    uint32_t upstreamCurrRate;         /** Upstream rate */
    uint32_t downstreamCurrRate;       /** Downstream rate */
    char dhcpServerId[BUFLEN_64];      /** Dhcp server id */
    char dhcpState[BUFLEN_64];         /** Dhcp state. */
    BOOL mtuAssigned;                  /** Have we been assigned MTU size ? */
    uint32_t mtuSize;                  /** MTU Size, if mtuAssigned==TRUE */
    char sipSrv[BUFLEN_64];            /** Dhcp sipsrv. */
    char staticRoutes[BUFLEN_64];      /** Dhcp classless static route */
} DHCPv4_PLUGIN_MSG;


/**
 * @brief Interface API for starting the DHCPv4 client.
 *
 * This function creates the configuration file using the provided request and send option lists,
 * starts the DHCPv4 client, and collects the process ID (PID).
 *
 * @param[in] interfaceName The name of the network interface.
 * @param[in] req_opt_list Pointer to the list of requested DHCP options.
 * @param[in] send_opt_list Pointer to the list of options to be sent.
 * @return The process ID (PID) of the started DHCPv4 client.
 */
pid_t start_dhcpv4_client(char *interfaceName, dhcp_opt_list *req_opt_list, dhcp_opt_list *send_opt_list);

/**
 * @brief Interface API for triggering a renew from the DHCPv4 client.
 *
 * This function sends the respective signal to the DHCPv4 client application to trigger a renew.
 *
 * @param[in] processID The process ID (PID) of the DHCPv4 client.
 * @return 0 on success, -1 on failure.
 */
int send_dhcpv4_renew(pid_t processID);

/**
 * @brief Interface API for triggering a release from the DHCPv4 client.
 *
 * This function sends the respective signal to the DHCPv4 client application to trigger a release and terminate.
 *
 * @param[in] processID The process ID (PID) of the DHCPv4 client.
 * @return 0 on success, -1 on failure.
 */
int send_dhcpv4_release(pid_t processID);

/**
 * @brief Interface API for stopping the DHCPv4 client.
 *
 * This function sends the respective signal to the DHCPv4 client application to stop the client.
 *
 * @param[in] processID The process ID (PID) of the DHCPv4 client.
 * @return 0 on success, -1 on failure.
 */
int stop_dhcpv4_client(pid_t processID);

#endif // DHCPV4_INTERFACE_H
