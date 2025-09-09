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

ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = CcspDHCPMgr

CcspDHCPMgr_CPPFLAGS = -I$(top_srcdir)/source/TR-181/include \
                       -I$(top_srcdir)/source/TR-181/middle_layer_src \
                       -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus \
                       -I$(top_srcdir)/source/DHCPMgrInterface \
                       -I$(top_srcdir)/source/DHCPMgrInterface/include \
                       -I$(top_srcdir)/source/DHCPClientUtils \
                       -I$(top_srcdir)/source/DHCPServerUtils/include \
                       -I$(top_srcdir)/source/DHCPServerUtils/DHCPv4Server/include \
                       -I$(top_srcdir)/source/DHCPServerUtils/DHCPv6Server/include \
                       -I$(top_srcdir)/source/DHCPServerUtils/DHCPServerSM/include \
                       -I$(top_srcdir)/source/DHCPServerUtils/utils/include \
                       -I$(top_srcdir)/source/DHCPClientUtils/DHCPv4Client/include \
                       -I$(top_srcdir)/source/DHCPClientUtils/DHCPv6Client/include \
                       -I$(top_srcdir)/source/DHCPClientUtils/DHCPv6Client/ \
                       -I$(top_srcdir)/source/DHCPClientUtils/DHCPv4Client/ \
                       -I$(top_srcdir)/source/DHCPMgrUtils/include \
                       -I$(top_srcdir)/source/DHCPMgrUtils
                       

CcspDHCPMgr_DEPENDENCIES = \
        $(EXTRA_DEPENDENCIES) \
        ${top_builddir}/source/DHCPMgrInterface/libifl.la \
        ${top_builddir}/source/TR-181/middle_layer_src/libCcspDhcpMgr_middle_layer_src.la \
        ${top_builddir}/source/TR-181/board_sbapi/libCcspDhcpMgr_board_sbapi.la \
        ${top_builddir}/source/DHCPServerUtils/utils/libCcspDhcpMgr_utils.la \
        ${top_builddir}/source/DHCPClientUtils/DHCPv4Client/libCcspDhcpMgr_Dhcpv4Client.la \
        ${top_builddir}/source/DHCPClientUtils/DHCPv6Client/libCcspDhcpMgr_Dhcpv6Client.la \
        ${top_builddir}/source/DHCPMgrUtils/libCcspDhcpMgrUtils.la

if DHCP_SERVER_SUPPORT
CcspDHCPMgr_DEPENDENCIES += \
        ${top_builddir}/source/DHCPServerUtils/DHCPv4Server/libCcspDhcpMgr_Dhcpv4Server.la \
        ${top_builddir}/source/DHCPServerUtils/DHCPv6Server/libCcspDhcpMgr_Dhcpv6Server.la  \
        ${top_builddir}/source/DHCPServerUtils/DHCPServerSM/libCcspDhcpMgr_DhcpServerSM.la
endif

CcspDHCPMgr_CFLAGS = $(SYSTEMD_CFLAGS) $(NONROOT_CFLAGS)
CcspDHCPMgr_SOURCES = ssp_messagebus_interface.c ssp_main.c ssp_action.c dm_pack_datamodel.c
CcspDHCPMgr_LDFLAGS = -rdynamic $(SYSTEMD_LDFLAGS) -pthread
CcspDHCPMgr_LDADD = $(CcspDHCPMgr_DEPENDENCIES) -lccsp_common -lsyscfg -ldl -lrbus
