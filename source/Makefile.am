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

SUBDIRS = DHCPMgrInterface  IPv6rtmon TR-181


if DHCP_SERVER_SUPPORT
SUBDIRS += DHCPServerUtils
endif

SUBDIRS += DHCPServerUtils/utils


if DHCP_CLIENT_SUPPORT
SUBDIRS += DHCPClientUtils
endif

if RA_MONITOR_SUPPORT
SUBDIRS += IPv6rtmon
endif

SUBDIRS += DHCPMgrUtils DHCPMgrSsp
