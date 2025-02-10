AM_CPPFLAGS = -I$(top_srcdir)/../../src/include \
              -I$(top_srcdir)/../../src/core \
              -I$(top_srcdir)/../../src/vendor
AM_CFLAGS = -Wall -Wfatal-errors

pkglib_LTLIBRARIES = plugin.la
plugin_la_SOURCES = vendor_plugin.c
plugin_la_CPPFLAGS = $(openssl_CFLAGS)
plugin_la_CPPFLAGS += $(AM_CPPFLAGS) \
                      -Werror \
                      -Werror=unused-value \
                      -Werror=format \
                      -Winit-self \
                      -Wparentheses -Werror=parentheses \
                      -Wuninitialized -Werror=uninitialized -Werror=maybe-uninitialized -Wpointer-arith
plugin_la_LDFLAGS = -avoid-version -module -shared -export-dynamic
