AM_CPPFLAGS = -I$(top_srcdir)/include \
              -I$(top_srcdir)/include/obuspa \
              -I$(top_srcdir)/include/obuspa/core \
              -I$(top_srcdir)/include/obuspa/protobuf-c \
              -I$(top_srcdir)/src/libjson/ccan/json

# Enable warnings, treat warnings as errors, and stop compilation at
# first error.
# Sub-makes are free to supplement AM_CFLAGS, e.g.
#         AM_CFLAGS += -Wno-error
# as necessary.
AM_CFLAGS = -Wall -Wfatal-errors
AM_LDFLAGS =

# Hardening
AM_CFLAGS += $(CFLAGS_HARDENING)
AM_LDFLAGS += $(LDFLAGS_HARDENING)

# Sanitizers
AM_CPPFLAGS += $(CPPFLAGS_SANITIZER)
AM_CFLAGS += $(CFLAGS_SANITIZER)
AM_LDFLAGS += $(LDFLAGS_SANITIZER)

bin_PROGRAMS = obuspa

SOURCES = src/core/main.c \
                    src/core/mtp_exec.c \
                    src/core/dm_exec.c \
                    src/core/bdc_exec.c \
                    src/core/stomp.c \
                    src/core/socket_set.c \
                    src/core/msg_handler.c \
                    src/core/msg_utils.c \
                    src/core/handle_get.c \
                    src/core/handle_set.c \
                    src/core/handle_add.c \
                    src/core/handle_delete.c \
                    src/core/handle_notify.c \
                    src/core/handle_operate.c \
                    src/core/handle_get_supported_protocol.c \
                    src/core/handle_get_instances.c \
                    src/core/handle_get_supported_dm.c \
                    src/core/group_get_vector.c \
                    src/core/group_set_vector.c \
                    src/core/group_add_vector.c \
                    src/core/group_del_vector.c \
                    src/core/inst_sel_vector.c \
                    src/core/proto_trace.c \
                    src/core/data_model.c \
                    src/core/error_resp.c \
                    src/core/usp_register.c \
                    src/core/usp_api.c \
                    src/core/dm_access.c \
                    src/core/device_local_agent.c \
                    src/core/device_controller.c \
                    src/core/device_mtp.c \
                    src/core/device_stomp.c \
                    src/core/device_subscription.c \
                    src/core/device_security.c \
                    src/core/device_ctrust.c \
                    src/core/device_bulkdata.c \
                    src/core/device_selftest_example.c \
                    src/core/device_iplcap.c \
                    src/core/device_time.c \
                    src/core/uptime.c \
                    src/core/rfc1123.c \
                    src/core/database.c \
                    src/core/usp_err.c \
                    src/core/usp_log.c \
                    src/core/usp_mem.c \
                    src/core/nu_ipaddr.c \
                    src/core/nu_macaddr.c \
                    src/core/retry_wait.c \
                    src/core/path_resolver.c \
                    src/core/str_vector.c \
                    src/core/int_vector.c \
                    src/core/kv_vector.c \
                    src/core/dm_inst_vector.c \
                    src/core/expr_vector.c \
                    src/core/dm_trans.c \
                    src/core/subs_vector.c \
                    src/core/subs_retry.c \
                    src/core/sync_timer.c \
                    src/core/cli_server.c \
                    src/core/cli_client.c \
                    src/core/iso8601.c \
                    src/core/text_utils.c \
                    src/core/os_utils.c \
                    src/core/device_request.c \
                    src/core/dllist.c \
                    src/core/se_cache.c \
                    src/libjson/ccan/json/json.c \
                    src/protobuf-c/usp-msg.pb-c.c \
                    src/protobuf-c/usp-record.pb-c.c \
                    src/protobuf-c/protobuf-c.c \
                    src/core/coap_common.c \
                    src/core/coap_client.c \
                    src/core/coap_server.c \
                    src/core/uri.c \
                    src/core/mqtt.c \
                    src/core/device_mqtt.c \
                    src/core/wsclient.c \
                    src/core/wsserver.c \
                    src/core/usp_record.c \
                    src/core/sar_vector.c \
                    src/core/e2e_context.c \
                    src/core/plugin.c \
                    src/core/device_uds.c \
                    src/core/fd_vector.c \
                    src/core/uds.c \
                    src/core/usp_service.c \
                    src/core/usp_broker.c


obuspa_SOURCES = $(SOURCES)
obuspa_CPPFLAGS = $(openssl_CFLAGS) $(sqlite3_CFLAGS) $(libcurl_CFLAGS) $(zlib_CFLAGS) $(libmosquitto_CFLAGS) $(libwebsockets_CFLAGS)
obuspa_CPPFLAGS +=  $(AM_CPPFLAGS) \
                      -Werror \
                      -Werror=unused-value \
                      -Werror=format \
                      -Winit-self \
                      -Wparentheses -Werror=parentheses \
                      -Wuninitialized -Werror=uninitialized -Wpointer-arith
# NOTE: In order for GCC to check for uninitialised variables, you need to turn optimisation on i.e. "-O2"

# Turn on rdynamic linker flags so that backtrace_symbols() call works
obuspa_LDFLAGS = $(AM_LDFLAGS) -rdynamic

obuspa_LDADD = -lm -ldl -lpthread -lrt
obuspa_LDADD += $(openssl_LIBS) $(sqlite3_LIBS) $(libcurl_LIBS) $(zlib_LIBS) $(libmosquitto_LIBS) $(libwebsockets_LIBS)

# Import vendor makefile
include src/vendor/vendor.am

# Import plugin makefiles
pkglib_LTLIBRARIES = 
include examples/test_uds/Makefile.am

# Include files
public_includedir = $(includedir)/obuspa
public_include_HEADERS = \
    include/obuspa/compiler.h \
    include/obuspa/usp_api.h \
    include/obuspa/usp_err_codes.h \
    include/obuspa/vendor_api.h \
    include/obuspa/vendor_defs.h \
    include/obuspa/vendor_options.h

private_core_includedir = $(includedir)/obuspa/core
private_core_include_HEADERS = \
    include/obuspa/core/bdc_exec.h \
    include/obuspa/core/cli.h \
    include/obuspa/core/common_defs.h \
    include/obuspa/core/data_model.h \
    include/obuspa/core/database.h \
    include/obuspa/core/device.h \
    include/obuspa/core/dllist.h \
    include/obuspa/core/dm_access.h \
    include/obuspa/core/dm_exec.h \
    include/obuspa/core/dm_inst_vector.h \
    include/obuspa/core/dm_trans.h \
    include/obuspa/core/e2e_context.h \
    include/obuspa/core/e2e_defs.h \
    include/obuspa/core/expr_vector.h \
    include/obuspa/core/group_add_vector.h \
    include/obuspa/core/group_del_vector.h \
    include/obuspa/core/group_get_vector.h \
    include/obuspa/core/group_set_vector.h \
    include/obuspa/core/inst_sel_vector.h \
    include/obuspa/core/int_vector.h \
    include/obuspa/core/iso8601.h \
    include/obuspa/core/kv_vector.h \
    include/obuspa/core/mqtt.h \
    include/obuspa/core/msg_handler.h \
    include/obuspa/core/msg_utils.h \
    include/obuspa/core/mtp_exec.h \
    include/obuspa/core/nu_ipaddr.h \
    include/obuspa/core/nu_macaddr.h \
    include/obuspa/core/os_utils.h \
    include/obuspa/core/path_resolver.h \
    include/obuspa/core/plugin.h \
    include/obuspa/core/proto_trace.h \
    include/obuspa/core/retry_wait.h \
    include/obuspa/core/rfc1123.h \
    include/obuspa/core/sar_vector.h \
    include/obuspa/core/se_cache.h \
    include/obuspa/core/socket_set.h \
    include/obuspa/core/stomp.h \
    include/obuspa/core/str_vector.h \
    include/obuspa/core/subs_retry.h \
    include/obuspa/core/subs_vector.h \
    include/obuspa/core/sync_timer.h \
    include/obuspa/core/text_utils.h \
    include/obuspa/core/uds.h \
    include/obuspa/core/uptime.h \
    include/obuspa/core/uri.h \
    include/obuspa/core/usp_broker.h \
    include/obuspa/core/usp_coap.h \
    include/obuspa/core/usp_err.h \
    include/obuspa/core/usp_log.h \
    include/obuspa/core/usp_mem.h \
    include/obuspa/core/usp_record.h \
    include/obuspa/core/usp_service.h \
    include/obuspa/core/version.h \
    include/obuspa/core/wsclient.h \
    include/obuspa/core/wsserver.h

private_libjson_includedir = $(includedir)/obuspa/libjson
private_libjson_include_HEADERS = src/libjson/ccan/json/json.h

private_protobuf_includedir = $(includedir)/obuspa/protobuf-c
private_protobuf_include_HEADERS = \
    include/obuspa/protobuf-c/protobuf-c.h \
    include/obuspa/protobuf-c/usp-msg.pb-c.h \
    include/obuspa/protobuf-c/usp-record.pb-c.h
