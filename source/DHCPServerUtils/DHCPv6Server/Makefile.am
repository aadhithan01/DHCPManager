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

AM_CFLAGS = -fno-exceptions -Wall -Wextra
AM_LDFLAGS = -lz -lpthread -lccsp_common $(DBUS_LIBS)

noinst_LTLIBRARIES = libCcspDhcpMgr_Dhcpv6Server.la

libCcspDhcpMgr_Dhcpv6Server_la_CPPFLAGS = -I$(top_srcdir)/source/DHCPServerUtils/DHCPv6Server/include \
                                          -I$(top_srcdir)/source/DHCPServerUtils/utils \
                                          -I$(top_srcdir)/source/DHCPServerUtils/utils/include \
                                          -I$(top_srcdir)/source/TR-181/include \
                                          -I$(top_srcdir)/source/TR-181/middle_layer_src \
                                          -I$(top_srcdir)/source/DHCPMgrUtils/include \
                                          -I$(top_srcdir)/source/TR-181/board_sbapi \
                                          -I$(top_srcdir)/source//DHCPClientUtils/DHCPv6Client/include \
                                          -I$(top_srcdir)/source/DHCPMgrInterface \
					  -I$(top_srcdir)/source/DHCPMgrInterface/include

libCcspDhcpMgr_Dhcpv6Server_la_SOURCES = dhcpv6server_function.c
if BCI_SUPPORT
libCcspDhcpMgr_Dhcpv6Server_la_SOURCES += service_ipv6.c
endif

libCcspDhcpMgr_Dhcpv6Server_la_LIBADD = -lccsp_common -ltelemetry_msgsender -lulog -lsyscfg -lsysevent -ltime_conversion -lprint_uptime -lnet
