# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([ob-uspagent],[1.0.0])
AM_INIT_AUTOMAKE([foreign silent-rules subdir-objects -Wall -Werror -Wno-portability])
AC_CONFIG_MACRO_DIR([m4])
LT_PREREQ([2.2])
LT_INIT([shared disable-static])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# Checks for libraries.
# This also defines autotools magic variables for use in the .am files
PKG_CHECK_MODULES([openssl], [openssl])
PKG_CHECK_MODULES([sqlite3], [sqlite3])
PKG_CHECK_MODULES([libcurl], [libcurl])
PKG_CHECK_MODULES([libcares], [libcares])
PKG_CHECK_MODULES([zlib], [zlib])
PKG_CHECK_MODULES([libcoap], [libcoap-1])

# Generate Makefiles
AC_CONFIG_FILES([Makefile])

# Finally, generate top-level config.status.
AC_OUTPUT
