##########################################################################
# Copyright 2020 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
##########################################################################

SUBDIRS = dhcpmgr_udhcpc_plugin

AM_CFLAGS = -fno-exceptions -Wall -Wextra
AM_LDFLAGS = -lhal_platform -lz -lpthread -lccsp_common $(DBUS_LIBS)

ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libCcspDhcpMgr_Dhcpv4Client.la

libCcspDhcpMgr_Dhcpv4Client_la_CPPFLAGS = -I$(top_srcdir)/source/DHCPClientUtils/DHCPv4Client/include \
                                          -I$(top_srcdir)/source/DHCPClientUtils/ \
                                          -I$(top_srcdir)/source/DHCPServerUtils/utils \
                                          -I$(top_srcdir)/source/DHCPServerUtils/utils/include \
                                          -I$(top_srcdir)/source/DHCPMgrInterface \
                                          -I$(top_srcdir)/source/DHCPMgrInterface/include 

libCcspDhcpMgr_Dhcpv4Client_la_SOURCES = dhcp_client_common.c dhcpv4_interface.c dhcpv4_interface_udhcpc.c

libCcspDhcpMgr_Dhcpv4Client_la_LIBADD = -lccsp_common -ltelemetry_msgsender -lulog -lsyscfg -lsysevent -ltime_conversion -lprint_uptime -lhal_platform 
