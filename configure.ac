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
AC_ARG_ENABLE(websockets, [AS_HELP_STRING([--enable-websockets], [enable WebSockets Message support])],,enable_websockets=yes)
AC_ARG_ENABLE(uds, [AS_HELP_STRING([--enable-uds], [enable UDS MTP Message support])],,enable_uds=yes)
AC_ARG_ENABLE(bulkdata, [AS_HELP_STRING([--enable-bulkdata], [enable Bulk Data Collection support])],,enable_bulkdata=yes)
AC_ARG_ENABLE(hardening, [AS_HELP_STRING([--enable-hardening], [enable compiler hardening flags])],,enable_hardening=no)

# Checks for libraries.
# This also defines autotools magic variables for use in the .am files
PKG_CHECK_MODULES([sqlite3], [sqlite3])
PKG_CHECK_MODULES([zlib], [zlib])

AS_IF([test "x$enable_stomp" = "xno"], [
	AC_DEFINE(DISABLE_STOMP)
],
# ELSE
[
    PKG_CHECK_MODULES([openssl], [openssl])
])


AS_IF([test "x$enable_coap" = "xyes"], [
	AC_DEFINE(ENABLE_COAP)
    PKG_CHECK_MODULES([openssl], [openssl])
])

AS_IF([test "x$enable_mqtt" = "xyes"], [
	PKG_CHECK_MODULES([libmosquitto], [libmosquitto])
	AC_DEFINE(ENABLE_MQTT)
    PKG_CHECK_MODULES([openssl], [openssl])
])

AS_IF([test "x$enable_websockets" = "xyes"], [
    PKG_CHECK_MODULES([libwebsockets], [libwebsockets >= 4.2.0])
	AC_DEFINE(ENABLE_WEBSOCKETS)
    PKG_CHECK_MODULES([openssl], [openssl])
])

AS_IF([test "x$enable_uds" = "xyes"], [
	AC_DEFINE(ENABLE_UDS)
])

AS_IF([test "x$enable_bulkdata" = "xyes"], [
    PKG_CHECK_MODULES([libcurl], [libcurl])
    PKG_CHECK_MODULES([openssl], [openssl])
],
# ELSE
[
	AC_DEFINE(REMOVE_DEVICE_BULKDATA)
])

AS_IF([test "x$enable_hardening" = "xyes"], [
    # Print better error message if these macros are not defined
    m4_pattern_forbid([AX_CHECK_COMPILE_FLAG])dnl
    m4_pattern_forbid([AX_CHECK_LINK_FLAG])dnl

    # Enable compiler hardening flags - do not touch CFLAGS or LDFLAGS directly
    AX_CHECK_COMPILE_FLAG([-fstack-protector-strong], [CFLAGS_HARDENING="$CFLAGS_HARDENING -fstack-protector-strong"])
    AX_CHECK_COMPILE_FLAG([-fPIE], [CFLAGS_HARDENING="$CFLAGS_HARDENING -fPIE"])
    AX_CHECK_LINK_FLAG([-pie], [LDFLAGS_HARDENING="$LDFLAGS_HARDENING -pie"])
    AX_CHECK_LINK_FLAG([-Wl,-z,relro], [LDFLAGS_HARDENING="$LDFLAGS_HARDENING -Wl,-z,relro"])
    AX_CHECK_LINK_FLAG([-Wl,-z,now], [LDFLAGS_HARDENING="$LDFLAGS_HARDENING -Wl,-z,now"])
    AX_CHECK_LINK_FLAG([-Wl,-z,noexecstack], [LDFLAGS_HARDENING="$LDFLAGS_HARDENING -Wl,-z,noexecstack"])

    # Fortify requires optimization
    CFLAGS_HARDENING="$CFLAGS_HARDENING -O2 -D_FORTIFY_SOURCE=2"
    AC_SUBST([CFLAGS_HARDENING])
    AC_SUBST([LDFLAGS_HARDENING])
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
