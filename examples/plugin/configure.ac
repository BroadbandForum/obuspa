# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([plugin],[0.0.1])
AM_INIT_AUTOMAKE([foreign silent-rules subdir-objects -Wall -Werror -Wno-portability])
AC_CONFIG_MACRO_DIR([./m4])
LT_PREREQ([2.2])

# Define _GNU_SOURCE if using GNU versions of strerror_r and dladdr()
AC_USE_SYSTEM_EXTENSIONS

# Configure use of libtool
LT_INIT([shared disable-static])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# Find out if GNU or XSI versions of strerror_r are being used
AC_FUNC_STRERROR_R

# Check for glibc specific functionality, setting HAVE_MALLINFO and HAVE_EXECINFO_H defines in the generated makefiles
AC_CHECK_HEADERS([malloc.h])
AC_CHECK_HEADERS([execinfo.h])
AC_CHECK_FUNCS([mallinfo])
AC_CHECK_FUNCS([mallinfo2])

# Needed to work with default vendor_defs.h (USP Broker and USP Service functionalities need UDS MTP)
AC_DEFINE(ENABLE_UDS)

# Needed to get include path for OpenSSL headers
PKG_CHECK_MODULES([openssl], [openssl])

# Generate Makefiles
AC_CONFIG_FILES([Makefile])

# Finally, generate top-level config.status.
AC_OUTPUT
