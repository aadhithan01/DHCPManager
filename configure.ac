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

#                                              -*- Autoconf -*-
# Process this file with autoconf to produce configure script.
#


AC_PREREQ([2.65])
AC_INIT([tr181], [1.0], [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE([foreign])
LT_INIT
GTEST_ENABLE_FLAG = ""

#AC_ARG_ENABLE([gtestapp],
#             AS_HELP_STRING([--enable-gtestapp],[enable Gtest support (default is no)]),
#             [
#               case "${enableval}" in
#                yes) GTEST_SUPPORT_ENABLED=true
#                     GTEST_ENABLE_FLAG="-DGTEST_ENABLE"
#                     m4_if(m4_sysval,[0],[AC_CONFIG_FILES([source/test/Makefile])]);;
#                no) GTEST_SUPPORT_ENABLED=false AC_MSG_ERROR([Gtest support is disabled]);;
#                 *) AC_MSG_ERROR([bad value ${enableval} for --enable-gtestapp ]);;
#               esac
#             ],
#             [echo "Gtestapp is disabled"])
#AM_CONDITIONAL([WITH_GTEST_SUPPORT], [test x$GTEST_SUPPORT_ENABLED = xtrue])

AC_PREFIX_DEFAULT(`pwd`)
AC_ENABLE_SHARED
AC_DISABLE_STATIC

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AM_PROG_CC_C_O
AM_PROG_LIBTOOL(libtool)

# Specify ccsp cpu arch

AC_ARG_WITH([ccsp-arch],
[AC_HELP_STRING([--with-ccsp-arch={arm,atom,pc,mips}],
                [specify the ccsp board CPU platform])],
[case x"$withval" in
   xarm)
     CCSP_ARCH=arm
     ;;
   xatom)
     CCSP_ARCH=atom
     ;;
   xpc)
     CCSP_ARCH=pc
     ;;
   xmips)
     CCSP_ARCH=mips
     ;;
   *)
     AC_MSG_ERROR([$withval is an invalid option to --with-ccsp-arch])
     ;;
 esac],
[CCSP_ARCH=''])
if test x"${CCSP_ARCH}" != x; then
  AC_DEFINE_UNQUOTED(CCSP_ARCH, "$CCSP_ARCH",
                     [The board CPU architecture])
fi

AM_CONDITIONAL(CCSP_ARCH_ARM, test "x$CCSP_ARCH" = xarm)
AM_CONDITIONAL(CCSP_ARCH_ATOM, test "x$CCSP_ARCH" = xatom)
AM_CONDITIONAL(CCSP_ARCH_PC, test "x$CCSP_ARCH" = xpc)
AM_CONDITIONAL(CCSP_ARCH_MIPS, test "x$CCSP_ARCH" = xmips)

# Specify ccsp platform (device)

AC_ARG_WITH([ccsp-platform],
[AC_HELP_STRING([--with-ccsp-platform={intel_usg,pc,bcm}],
                [specify the ccsp platform])],
[case x"$withval" in
   xintel_usg)
     CCSP_PLATFORM=intel_usg
     ;;
   xpc)
     CCSP_PLATFORM=pc
     ;;
   xbcm)
     CCSP_PLATFORM=bcm
     ;;
   *)
     AC_MSG_ERROR([$withval is an invalid option to --with-ccsp-platform])
     ;;
 esac],
[CCSP_PLATFORM=''])
if test x"${CCSP_PLATFORM}" != x; then
  AC_DEFINE_UNQUOTED(CCSP_PLATFORM, "$CCSP_PLATFORM",
                     [The CCSP platform device])
fi

AC_ARG_ENABLE([maptsupport],
             AS_HELP_STRING([--enable-maptsupport],[enable mapt support (default is no)]),
             [
              case "${enableval}" in
               yes) MAPT_SUPPORT_ENABLED=true;;
               no)  MAPT_SUPPORT_ENABLED=false;;
               *) AC_MSG_ERROR([bad value ${enableval} for --enable-maptsupport ]);;
              esac
             ],
             [echo "mapt is disabled"])
AM_CONDITIONAL(FEATURE_SUPPORT_MAPT_NAT46, test "x$MAPT_SUPPORT_ENABLED" = xtrue)

SYSTEMD_CFLAGS=" "
SYSTEMD_LDFLAGS=" "
AC_ARG_ENABLE([notify],
        AS_HELP_STRING([--enable-notify],[enable systemd notify]),
        [
          case "${enableval}" in
          yes) SYSTEMD_CFLAGS="-DENABLE_SD_NOTIFY"
                SYSTEMD_LDFLAGS="-lsystemd" ;;
           no) AC_MSG_ERROR([systemd notify is disabled]) ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-notify ]) ;;
           esac
           ],
        [echo "headless build is enable"])

NONROOT_CFLAGS=" "
AC_ARG_ENABLE([dropearly],
        AS_HELP_STRING([--enable-dropearly],[enable dropearly]),
        [
          case "${enableval}" in
           yes) NONROOT_CFLAGS="-DDROP_ROOT_EARLY" ;;
            no) AC_MSG_NOTICE([dropearly is disabled]) ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-dropearly ]) ;;
           esac
           ],
         [echo "dropearly is enable"])

# Checks for DHCPServer support
AC_ARG_ENABLE([dhcp_server_support],
[  --enable-dhcp_server_support=val Turn on dhcp_server, val=true or false],
[case "${enableval}" in
  yes) dhcp_server_support=true ;;
  no)  dhcp_server_support=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-dhcp_server_support]) ;;
esac],[dhcp_server_support=true])
AM_CONDITIONAL(DHCP_SERVER_SUPPORT, test x"$dhcp_server_support" = x"true")

# Checks for DHCPClient support
AC_ARG_ENABLE([dhcp_client_support],
[  --enable-dhcp_client_support=val Turn on dhcp_client, val=true or false],
[case "${enableval}" in
  yes) dhcp_client_support=true ;;
  no)  dhcp_client_support=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-dhcp_client_support]) ;;
esac],[dhcp_client_support=true])
AM_CONDITIONAL(DHCP_CLIENT_SUPPORT, test x"$dhcp_client_support" = x"true")


# Checks for DHCPv4Server support
AC_ARG_ENABLE([dhcpv4_server_support],
[  --enable-dhcpv4_server_support=val Turn on dhcpv4_server, val=true or false],
[case "${enableval}" in
  yes) dhcpv4_server_support=true ;;
  no)  dhcpv4_server_support=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-dhcpv4_server_support]) ;;
esac],[dhcpv4_server_support=true])
AM_CONDITIONAL(DHCPV4_SERVER_SUPPORT, test x"$dhcpv4_server_support" = x"true")


# Checks for DHCPv6Server support
AC_ARG_ENABLE([dhcpv6_server_support],
[  --enable-dhcpv6_server_support=val Turn on dhcpv6_server, val=true or false],
[case "${enableval}" in
  yes) dhcpv6_server_support=true ;;
  no)  dhcpv6_server_support=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-dhcpv6_server_support]) ;;
esac],[dhcpv6_server_support=true])
AM_CONDITIONAL(DHCPV6_SERVER_SUPPORT, test x"$dhcpv6_server_support" = x"true")



# Checks for DHCPv4Client support
AC_ARG_ENABLE([dhcpv4_client_support],
[  --enable-dhcpv4_client_support=val Turn on dhcpv4_client, val=true or false],
[case "${enableval}" in
  yes) dhcpv4_client_support=true ;;
  no)  dhcpv4_client_support=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-dhcpv4_client_support]) ;;
esac],[dhcpv4_client_support=true])
AM_CONDITIONAL(DHCPV4_CLIENT_SUPPORT, test x"$dhcpv4_client_support" = x"true")



# Checks for DHCPv6Client support
AC_ARG_ENABLE([dhcpv6_client_support],
[  --enable-dhcpv6_client_support=val Turn on dhcpv6_client, val=true or false],
[case "${enableval}" in
  yes) dhcpv6_client_support=true ;;
  no)  dhcpv6_client_support=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-dhcpv6_client_support]) ;;
esac],[dhcpv6_client_support=true])
AM_CONDITIONAL(DHCPV6_CLIENT_SUPPORT, test x"$dhcpv6_client_support" = x"true")

# Checks for BCI support
AC_ARG_ENABLE([bci_support],
[  --enable-bci_support=val Turn on bci, val=true or false],
[case "${enableval}" in
  yes) bci_support=true ;;
  no)  bci_support=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-bci_support]) ;;
esac],[bci_support=false])
AM_CONDITIONAL(BCI_SUPPORT, test x"$bci_support" = x"true")

# Check ra_monitor_support
AM_CONDITIONAL([RA_MONITOR_SUPPORT], [test "$RA_MONITOR_SUPPORT" = "yes"])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE

# Checks for library functions.
AC_FUNC_MALLOC

AC_SUBST(CCSP_ARCH)
AC_SUBST(SYSTEMD_CFLAGS)
AC_SUBST(SYSTEMD_LDFLAGS)
AC_SUBST(NONROOT_CFLAGS)

AC_CONFIG_FILES(
        source/DHCPMgrInterface/Makefile
        source/DHCPServerUtils/Makefile
        source/DHCPServerUtils/DHCPv4Server/Makefile
        source/DHCPServerUtils/DHCPv6Server/Makefile
        source/DHCPServerUtils/DHCPServerSM/Makefile
        source/DHCPServerUtils/utils/Makefile
        source/DHCPClientUtils/Makefile
        source/DHCPClientUtils/DHCPv4Client/Makefile
        source/DHCPClientUtils/DHCPv4Client/dhcpmgr_udhcpc_plugin/Makefile
        source/DHCPClientUtils/DHCPv6Client/Makefile
        source/DHCPClientUtils/DHCPv6Client/dhcpmgr_dibbler_plugin/Makefile
	      source/DHCPMgrUtils/Makefile
        source/DHCPMgrUtils/CustomOptions/Makefile
        source/IPv6rtmon/Makefile
        source/TR-181/board_sbapi/Makefile
        source/TR-181/middle_layer_src/Makefile
        source/TR-181/Makefile
        source/Makefile
        source/DHCPMgrSsp/Makefile
        Makefile
)

AC_SUBST(GTEST_ENABLE_FLAG)

AC_OUTPUT
