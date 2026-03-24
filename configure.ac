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
AC_ARG_ENABLE(asan, [AS_HELP_STRING([--enable-asan], [enable address sanitizer])],,enable_asan=no)
AC_ARG_ENABLE(tsan, [AS_HELP_STRING([--enable-tsan], [enable thread sanitizer])],,enable_tsan=no)

# Checks for libraries.
# This also defines autotools magic variables for use in the .am files
PKG_CHECK_MODULES([sqlite3], [sqlite3])
PKG_CHECK_MODULES([zlib], [zlib])

AS_IF([test "x$prefix" = "xNONE"], [prefix="$ac_default_prefix"])
LOCAL_STATE_DIR_DEFINE_STR="$prefix/var/obuspa"
DISABLE_STOMP_DEFINE=""
ENABLE_COAP_DEFINE=""
ENABLE_MQTT_DEFINE=""
ENABLE_WEBSOCKETS_DEFINE=""
ENABLE_UDS_DEFINE=""
REMOVE_DEVICE_BULKDATA_DEFINE=""

AS_IF([test "x$enable_stomp" = "xno"], [
	DISABLE_STOMP_DEFINE="#define DISABLE_STOMP 1"
],
# ELSE
[
    PKG_CHECK_MODULES([openssl], [openssl])
])


AS_IF([test "x$enable_coap" = "xyes"], [
	ENABLE_COAP_DEFINE="#define ENABLE_COAP 1"
    PKG_CHECK_MODULES([openssl], [openssl])
])

AS_IF([test "x$enable_mqtt" = "xyes"], [
	PKG_CHECK_MODULES([libmosquitto], [libmosquitto])
	ENABLE_MQTT_DEFINE="#define ENABLE_MQTT 1"
    PKG_CHECK_MODULES([openssl], [openssl])
])

AS_IF([test "x$enable_websockets" = "xyes"], [
    PKG_CHECK_MODULES([libwebsockets], [libwebsockets >= 4.2.0])
	ENABLE_WEBSOCKETS_DEFINE="#define ENABLE_WEBSOCKETS 1"
    PKG_CHECK_MODULES([openssl], [openssl])
])

AS_IF([test "x$enable_uds" = "xyes"], [
	ENABLE_UDS_DEFINE="#define ENABLE_UDS 1"
])

AS_IF([test "x$enable_bulkdata" = "xyes"], [
    PKG_CHECK_MODULES([libcurl], [libcurl])
    PKG_CHECK_MODULES([openssl], [openssl])
],
# ELSE
[
	REMOVE_DEVICE_BULKDATA_DEFINE="#define REMOVE_DEVICE_BULKDATA 1"
])

AC_SUBST([LOCAL_STATE_DIR_DEFINE_STR])
AC_SUBST([DISABLE_STOMP_DEFINE])
AC_SUBST([ENABLE_COAP_DEFINE])
AC_SUBST([ENABLE_MQTT_DEFINE])
AC_SUBST([ENABLE_WEBSOCKETS_DEFINE])
AC_SUBST([ENABLE_UDS_DEFINE])
AC_SUBST([REMOVE_DEVICE_BULKDATA_DEFINE])

AS_IF([test "x$enable_hardening" = "xyes"], [
    # Enable compiler hardening flags - do not touch CFLAGS or LDFLAGS directly
    CFLAGS_HARDENING="$CFLAGS_HARDENING -fstack-protector-strong"
    CFLAGS_HARDENING="$CFLAGS_HARDENING -fPIE"
    LDFLAGS_HARDENING="$LDFLAGS_HARDENING -pie"
    LDFLAGS_HARDENING="$LDFLAGS_HARDENING -Wl,-z,relro"
    LDFLAGS_HARDENING="$LDFLAGS_HARDENING -Wl,-z,now"
    LDFLAGS_HARDENING="$LDFLAGS_HARDENING -Wl,-z,noexecstack"

    # Fortify requires optimization
    CFLAGS_HARDENING="$CFLAGS_HARDENING -O2 -D_FORTIFY_SOURCE=2"
    AC_SUBST([CFLAGS_HARDENING])
    AC_SUBST([LDFLAGS_HARDENING])
])

# Enable compiler sanitizer flags - do not touch CPPFLAGS, CFLAGS, or LDFLAGS directly
# Sanitizer builds can sometimes trigger erroneous string truncation warnings, so silence them in CPPFLAGS
if test "x$enable_asan" = "xyes" && test "x$enable_tsan" = "xyes"; then
    AC_MSG_ERROR([--enable-asan and --enable-tsan are mutually exclusive. Please enable only one.])
fi

AS_IF([test "x$enable_asan" = "xyes"], [
    CPPFLAGS_SANITIZER="-Wno-stringop-truncation"
    CFLAGS_SANITIZER="-g -O1 -fsanitize=address -fno-omit-frame-pointer -fno-common"
    LDFLAGS_SANITIZER="-fsanitize=address"
    AC_SUBST([CPPFLAGS_SANITIZER])
    AC_SUBST([CFLAGS_SANITIZER])
    AC_SUBST([LDFLAGS_SANITIZER])
])

AS_IF([test "x$enable_tsan" = "xyes"], [
    CPPFLAGS_SANITIZER="-Wno-stringop-truncation"
    CFLAGS_SANITIZER="-g -O2 -fsanitize=thread -fno-omit-frame-pointer -fno-common"
    LDFLAGS_SANITIZER="-fsanitize=thread"
    AC_SUBST([CPPFLAGS_SANITIZER])
    AC_SUBST([CFLAGS_SANITIZER])
    AC_SUBST([LDFLAGS_SANITIZER])
])

# Check which flavour of strerror_r is available on the target
AC_FUNC_STRERROR_R

AC_CHECK_HEADERS([malloc.h])
AC_CHECK_HEADERS([execinfo.h])
AC_CHECK_FUNCS([mallinfo])
AC_CHECK_FUNCS([mallinfo2])

# Generate Makefiles
AC_CONFIG_FILES([Makefile])

# Generate vendor_options.h
AC_CONFIG_FILES([include/obuspa/vendor_options.h:include/obuspa/vendor_options.h.in])

# Finally, generate top-level config.status.
AC_OUTPUT
