# $Id$

# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.64)

AC_INIT([dnstap-evldns],
        [0.1.0],
        [https://github.com/dnstap/dnstap-evldns/issues],
        [dnstap-evldns],
        [https://github.com/dnstap/dnstap-evldns])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign 1.11 silent-rules])
AM_SILENT_RULES([yes])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

CHECK_COMPILER_FLAG([Wall], [CFLAGS="-Wall $CFLAGS"])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_PROG_LN_S

# Checks for libraries.
PKG_CHECK_MODULES([libevent], [libevent >= 2])
PKG_CHECK_MODULES([libldns], [libldns >= 1.6.5])
PKG_CHECK_MODULES([libprotobuf_c], [libprotobuf-c >= 1.0.1])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])
AC_CHECK_HEADERS([sys/socket.h netdb.h])
AC_CHECK_HEADERS([ldns/ldns.h event.h])
AC_HEADER_STDBOOL

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_SEARCH_LIBS([dlopen], [dl])
AC_CHECK_FUNCS([socket memset strdup])
AC_CHECK_FUNCS([getaddrinfo getnameinfo])
AC_SUBST(AM_CPPFLAGS)
AC_SUBST(AM_CFLAGS)
AC_SUBST(AM_LDFLAGS)
AC_OUTPUT
