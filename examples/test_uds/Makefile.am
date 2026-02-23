pkglib_LTLIBRARIES += test_uds.la
test_uds_la_SOURCES = examples/test_uds/test_uds.c
test_uds_la_CPPFLAGS = $(openssl_CFLAGS)
test_uds_la_CPPFLAGS += $(AM_CPPFLAGS) \
                        -Werror \
                        -Werror=unused-value \
                        -Werror=format \
                        -Winit-self \
                        -Wparentheses -Werror=parentheses \
                        -Wuninitialized -Werror=uninitialized -Werror=maybe-uninitialized -Wpointer-arith
test_uds_la_LDFLAGS = -avoid-version -module -shared -export-dynamic
