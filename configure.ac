# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])

AC_INIT([ob-uspagent],[1.0.0])
AM_INIT_AUTOMAKE([foreign silent-rules subdir-objects -Wall -Werror -Wno-portability])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS

LT_PREREQ([2.2])
LT_INIT([shared disable-static])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

AC_ARG_ENABLE(stomp, [AS_HELP_STRING([--enable-stomp], [enable STOMP Message support])],,enable_stomp=yes)
AC_ARG_ENABLE(mqtt, [AS_HELP_STRING([--enable-mqtt], [enable MQTT Message support])],,enable_mqtt=yes)
AC_ARG_ENABLE(coap, [AS_HELP_STRING([--enable-coap], [enable COAP Message support])],,enable_coap=yes)

# Checks for libraries.
# This also defines autotools magic variables for use in the .am files
PKG_CHECK_MODULES([openssl], [openssl])
PKG_CHECK_MODULES([sqlite3], [sqlite3])
PKG_CHECK_MODULES([libcurl], [libcurl])
PKG_CHECK_MODULES([zlib], [zlib])

AS_IF([test "x$enable_stomp" = xno], [
	AC_DEFINE(DISABLE_STOMP)
])

AS_IF([test "x$enable_coap" = xyes], [
	AC_DEFINE(ENABLE_COAP)
])

AS_IF([test "x$enable_mqtt" = xyes], [
	PKG_CHECK_MODULES([libmosquitto], [libmosquitto])
	AC_DEFINE(ENABLE_MQTT)
])

# Check which flavour of strerror_r is available on the target
AC_FUNC_STRERROR_R

AC_CHECK_HEADERS([malloc.h])
AC_CHECK_HEADERS([execinfo.h])
AC_CHECK_FUNCS([mallinfo])
AC_CHECK_FUNCS([mallinfo2])

# Generate Makefiles
AC_CONFIG_FILES([Makefile])

# Finally, generate top-level config.status.
AC_OUTPUT
