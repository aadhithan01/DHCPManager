##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2020 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

AM_CFLAGS =

ACLOCAL_AMFLAGS = -I m4

noinst_LTLIBRARIES = libCcspDhcpMgr_middle_layer_src.la

libCcspDhcpMgr_middle_layer_src_la_CPPFLAGS = -I$(top_srcdir)/source/TR-181/include \
                                              -I$(top_srcdir)/source/TR-181/middle_layer_src \
                                              -I$(top_srcdir)/source/DHCPMgrUtils/include \
                                              -I$(top_srcdir)/source/DHCPMgrUtils \
                                              -I$(top_srcdir)/source/DHCPMgrInterface/include \
                                              -I$(top_srcdir)/source/DHCPClientUtils/DHCPv4Client/include \
                                              -I$(top_srcdir)/source/DHCPClientUtils/DHCPv4Client \
                                              -I$(top_srcdir)/source/DHCPServerUtils/utils/include \
                                              -I$(top_srcdir)/source/DHCPServerUtils/DHCPv4Server/include \
                                              -I$(top_srcdir)/source/DHCPClientUtils/DHCPv6Client/include \
                                              -I$(top_srcdir)/source/DHCPClientUtils/DHCPv6Client \
                                              -I$(top_srcdir)/source/DHCPClientUtils/DHCPv6Server/include \
                                              -I$(top_srcdir)/source/DHCPServerUtils/DHCPServerSM/include

libCcspDhcpMgr_middle_layer_src_la_SOURCES = cosa_dhcpv4_internal.c cosa_dhcpv6_internal.c plugin_main.c cosa_apis_util.c cosa_dhcpv4_dml.c cosa_dhcpv6_dml.c cosa_webconfig_api.c cosa_x_cisco_com_devicecontrol_internal.c dhcpmgr_rbus_apis.c
libCcspDhcpMgr_middle_layer_src_la_LDFLAGS = -lccsp_common -lsyscfg -lsysevent -lsecure_wrapper  
#$(top_srcdir)/source/DHCPServerUtils/libCcspDhcpMgr_DhcpServerSM.la