# OB-USP-AGENT Changelog

## 2026-05-07 v11.0.3
### Added
- Device.LocalAgent.ControllerTrust.UntrustedRole. The role is specified at compile time using ROLE_UNTRUSTED in vendor_defs.h.

### Fixed
- cmake based build system does not install headers for plugin development
- compiler.h moved out of plugin API header directory



## 2026-04-20 v11.0.2
### Fixed
- Race hazard that could cause two Boot! events to be sent on STOMP MTP
- Failure to open factory reset database sqlite file (FACTORY_RESET_FILE) should be caught when opening, rather than when writing



## 2026-03-23 v11.0.1
### Added
- IPLayerCapacity() Speed Test command (which uses OB-UDP-ST). To enable, comment out REMOVE_IP_CAPACITY_DIAG in vendor_defs.h

### Fixed
- Multiple EndpointID or Password TLVs in UDS handshake frame should be handled as protocol error
- USP Service is prevented from re-registering DM if it disconnects while the USP Broker is waiting for a response from it
- Build failure in database.c on some platforms due to compiler type size issues



## 2026-02-20 v11.0.0
### Added
- Authenticated UDS connections: USP Services must provide a passsword in the UDS Handshake frame if 
  UnixDomainSocket.{i}.AuthRequired is set to true. Passwords are configured in UnixDomainSockets.Authentication.{i}
- Data model registration permissions: USP Services are only permitted to register the DM elements specified
  in USPServices.Trust.{i}, if UnixDomainSocket.{i}.RegistrationRestricted is set to true.
- File descriptor passing via Unix domain socket ancilliary data for USP Services. Currently this feature is
  being discussed for inclusion in the USP v1.6 specification. Disabled by default, this feature
  may be enabled by defining FD_PASSING_EXPERIMENTAL in vendor_defs.h
- Lines in the factory reset text file that begin with `+` automatically add the parameter to OBUSPA's database. 
  If it is already present, its existing value is left unchanged.
- TP-469 Conformance Test Plan Results for each release are checked in at 
  [conformance_test_results.txt](https://github.com/BroadbandForum/obuspa/blob/master/conformance_test_results.txt).
  The CI directory contains the files used by the test procedure.

### Modified
- factory_reset_example.txt renamed as stomp_factory_reset_example.txt
- OBUSPA's database may configure DeviceInfo.ProductClass, Manufacturer and ModelName, overriding compile time defaults.

### Fixed
- Crash that occurred if invalid UDS MTP parameters were present in OBUSPA's database at startup.
- OBUSPA was not automatically creating intermediate directories in the MUTABLE_CERT_DIR path.
- Alias uniqueness validation failures returned error code 7004 instead of 7025.



## 2026-02-09 v10.0.14
### Fixed
- Changes introduced in v10.0.13 could cause FactoryReset() to hit an assert. The cause has been fixed.
- Websocket server thread prevents graceful shutdown after disabling it, or after duplicate messages in its send queue

### Modified
- Removed automatic creation of the default database directory during make install (GitHub Issue #148)


## 2026-01-12 v10.0.13
### Added
- If USP database file is corrupt, a new database is created using the factory reset configuration

### Fixed
- R-GET.0 not working for invalid object names in path
- Memory leak with WebSockets MTP, if from_id does not match EID in Sec-WebSocket-Extensions header



## 2025-12-05 v10.0.12
### Added
- 'obuspa -c add' CLI command now supports setting child parameters. Example:
 `obuspa -c add 'Device.LocalAgent.Subscription.(NotifType=Event,ReferenceList="Device.",Enable=true)'`
- SIGTERM signal handler to cleanly shutdown
- USP_SIGNAL_Reboot API function to initiate shutting down, then rebooting the device
- USP_LOG_GetLogLevel and USP_LOG_SetLogLevel API functions to atomically access the log level at runtime

### Fixed
- Compilation failure when #include'ing only usp_api.h (enable_callstack_debug should be declared in usp_api.h)
- Race hazard preventing graceful shutdown. Occurs if re-initiating shutdown whilst in the process of shutting down
- Race hazard causing USP Broker to reject all messages from a USP Service. Occurs when USP Service disconnects, then immediately reconnects over UDS MTP, whilst USP Broker is waiting for a synchronous USP response


## 2025-11-05 v10.0.11
### Updated
- Code has been updated to use the latest v1.5.2 release of protobuf-c

### Fixed
- A certificate file in the MUTABLE_CERT_DIR that did not contain Alias could be left open. Note: This cannot occur if the certificate was added using Device.LocalAgent.AddCertificate().


## 2025-10-10 v10.0.10
### Added
- Device.LocalAgent.AddCertificate() support. See QUICK_START_GUIDE.md for how to use this feature.
- can_mtp_connect vendor hook should also control Bulk Data Collection report generation

### Fixed
- Compilation failure with recent USP_PROCESS_DoWorkSync changes when REMOVE_USP_BROKER is defined
- Removed Clang static analyzer false positives


## 2025-09-30 v10.0.9
### Added
- Device.Security.Certificate may be removed from OBUSPA's data model using the define REMOVE_DEVICE_SECURITY_CERTIFICATE in vendor_defs.h.
This does not affect  Device.LocalAgent.Certificate, which still reports the trust store certificates.
- Configure options to enable address sanitizer (--enable-asan) and thread sanitizer builds (--enable-tsan) have been added. These options are disabled by default.
- To support compilation of OBUSPA data model plug-ins, the build process now installs header files to $(includedir)/obuspa

### Fixed
- USP Command and Event arguments should not be allowed to be registered more than once

### Modified
- 'obuspa -c' output has been made cleaner, containing only logs from the data model thread
- The m4-extra directory and AX_CHECK_XXX autotools macros (added in v10.0.8) have been removed, as they filter rather than stop the build if unsupported compiler options are used.

## 2025-09-15 v10.0.8
### Added
- Functions to access the data model from vendor threads (USP_PROCESS_DoWorkSync, USP_PROCESS_DM_GetParameterValue, USP_PROCESS_DM_SetParameterValue)
- Configure option (--enable-hardening) to enable compiler hardening flags (disabled by default)

### Fixed
- Concurrent CLI invocations can get stuck

### Modified
- Maximum allowed MTP frame size received has been increased to 5MB (from 64K)

## 2025-08-18 v10.0.7
### Fixed
- Suppress annoying warnings when using OBUSPA CLI commands
- MQTT client should not disconnect if no Response Topic
- R-GET.0 not applied for partial paths
- USP Services should not reuse group_ids registered by internal data model providers
- Crash if object creation notification contains too many keys


## 2025-08-04 v10.0.6
### Fixed
- Wildcarded delete response with allow_partial=true incorrect if one instance not permitted to be deleted
- MQTT connection not retried if TLS handshake fails and libmoquitto version<2.0.13
- MQTT Send message queue gets stuck if packet too large


## 2025-07-22 v10.0.5
### Added
- Support for permission Targets containing search expressions (configured by ALLOWED_PARAMS_FOR_SE_BASED_PERMS in vendor_defs.h)

### Fixed
- MQTT client should not assert if no Response Topic
- Changing LocalAgent.MTP.Enable should not assert when Protocol is UDS
- LocalAgent.MTP.{i}.Status is not working for UDS MTP
- Async Operation max concurrency limit regression (broken in v10.0.0)


## 2025-06-24 v10.0.4
### Fixed
- ControllerTrust Permission Order uniqueness should be enforced when Add request with allow_partial=false adds multiple permissions with the same Order
- GSDM response should not contain unique keys for child objects when first_level_only=true

## 2025-06-06 v10.0.3
### Fixed
- First object creation notification after bootup may be missed
- CLI initiated event arguments do not support JSON formatted data
- Provide better documentation for OBUSPA CLI -c commands
- Removed .gitattributes file, as this causes problems when building OBUSPA for OpenWRT

## 2025-05-27 v10.0.2
### Fixed
- Code should compile with --disable-bulkdata (regression introduced in v10.0.1)
- Wrong error code returned in conformance test 1.100
- Crash occurs if USP Service registers a DM element, but does not provide it in the GSDM response

## 2025-05-02 v10.0.1
### Added
- Support for Device.BulkData.Profile.{i}.Controller parameter


## 2025-04-07: v10.0.0
### Added
- Instance based permissions
- Reason and Cause arguments have been added to Device.Reboot(), Device.FactoryReset() and Device.Boot!
- Get response only contains the names of objects that also have Obj read permissions (in addition to Param read permissions) (USPv1.4)

### Fixed
- Potential memory leak in DEVICE_SECURITY_SetALPN


## 2025-03-25 v9.0.9
### Added
- USP 1.4: GSDM should contain unique keys
- USP 1.4: GSDM should support request of non-objects

### Fixed
- Periodic! notifications should be sent after the Boot! event
- Empty string should not be interpreted as 0 by parameter value conversion functions


## 2025-03-07 v9.0.8
### Added
- USP Broker: Optimize Get requests spanning multiple USP Services
- USP Broker: Search Expressions optimizations (pass through of requests and subscriptions containing search expressions to USP Services)

### Fixed
- Compilation failures when INCLUDE_PROGRAMMATIC_FACTORY_RESET is defined (GitHub PR#122)

## 2025-02-24 v9.0.7
### Added
- HardwareVersion can also be specified by an environment variable (USP_BOARD_HW_VERSION)

### Fixed
- Crash that could occur once at startup if the controller trust permissions table contained invalid data


## 2025-02-10 v9.0.6
### Added
- Example vendor layer plug-in and documentation (in quick start guide)

## 2025-01-13 v9.0.5
### Fixed
- Compilation failure when building for pure USP Service
- Subscription ID should be immutable
- OpenSSL should be initialized only once

## 2024-12-09 v9.0.4
### Added
- USP Broker support for registration of parameters, events and USP commands (USP 1.4)
- Bulk Data Collection over MQTT

### Fixed
- Event and OperationComplete subscriptions to 'Device.' on a USP Broker now set subscriptions on each USP Service containing only the DM elements that were registered
- USP Conformance test 11.11 failure: MQTT PUBLISH frames should not be sent until SUBACK frame indicates successfully subscribed

## 2024-11-11 v9.0.3
### Added
- New CLI command for interacting directly with USP Services, when obuspa runs as a USP Broker:
 `obuspa -c service [endpoint] [command] [path-expr] [optional: value or notify type]`

## 2024-10-29 v9.0.2
### Fixed
- OpenSSL deprecated functions should not be used

## 2024-09-27 v9.0.1
### Fixed
- UDS MTP should be accessible by USP Services running as non root
- 'obuspa -c' should not crash with long command arguments


## 2024--09-17 v9.0.0
  * MQTT
    * Application Layer Protocol Negotiation (ALPN) support for MQTT over TLS
    * Device.MQTT.Client.{i}.ForceReconnect() support added
    * MQTTv5 Assigned Client Identifier is not being saved in Device.MQTT.Client.{i}.ClientID
    * MQTT keep alive can now be completely disabled (if required) when linking with libmosquitto v2.0.x
    * OBUSPA should subscribe to all topics indicated by the subscribe-topic user properties in the CONNACK [R-MQTT.15]
    * OBUSPA should delete pending USP notifications (on MQTT MTP) if notification has expired whilst waiting to be sent
    * MQTT connection blocks for too long if server is unresponsive. To workaround the underlying issue in libmosquitto, OBUSPA tests for server responsiveness by transiently connecting, before proceeding with the libmosquitto connect (if responsive).
    * OBUSPA should disconnect if unable to subscribe to anything [R-MQTT.17]
    * Device.MQTT.Client.{i}.Name should be auto-assigned by the agent, if not given at creation time, and immutable thereafter
    * Device.MQTT.Client.{i}.RequestResponseInfo should control whether response information is requested in the CONNECT frame. Previously it was always requested, regardless of the value of the parameter
    * Removed unimplemented parameter: Device.MQTT.Client.{i}.RequestProblemInfo
    * Modifying MQTT KeepAliveTime should not force a reconnect
    * MQTT ConnectRetryTime parameter modifications should apply at the next retry [GH #109]
    * MQTT CleanSession and CleanStart parameter modifications should apply at the next retry
    * USP Connect record not always sent immediately after connection on MQTT
    * Improved MQTT MTP debug
    * Code maintenance improvements to MQTT MTP
    * Removed unmaintained MQTT tests

  * Websockets
    * WebSocket client does not send Boot! event (regression introduced in v8.0)
    * WebSocket client not started after MTP dynamically added to controller table (regression introduced in v8.0)

  * STOMP
    * STOMP connects shouldn't block the data model thread
    * STOMP ServerRetryMaxInterval parameter modifications should apply at the next retry

  * USP Broker
    * CLI initiated gets have been optimized to pass through the path to the USP Service, when possible
    * Support a USP Service registering Device.DNS.SD before Device.DNS (in separate register messages)
    * Workaround for USP Services which have limitations on the number of parameters requested in a get
    * Support additional DM elements registered directly under Device.
    * USP Broker should not assume hierarchically ordered fields in GSDM and get instances responses
    * USP Service acting as pure Controller does not accept responses unless Broker is in the USP Service's Controller table

  * Data model
    * VALUE_CHANGE_WILL_IGNORE flag support
    * Get requests with max_depth >= 0x80000000 should return full sub-tree
    * Get instances failures during path resolution should be gracefully ignored
    * Device.LocalAgent.X_VANTIVA-COM_PreConnectTimeout controls how long to wait for the can_mtp_connect vendor hook to allow connection, before connecting anyway
    * USP_REGISTER_Object_UniqueKey() validates that the unique key parameters have not already been registered

  * Miscellaneous
    * Dockerfile rewritten to use debian:stable and build libwebsockets [GH #95, #108]
    * Compiling without UDS fails [GH#110]
    * An unused variable warning seen during cmake based builds has been addressed
    * Prevent accidental CLI socket stealing


## 2024-08-30 v8.0.9
### Added
- Application Layer Protocol Negotiation (ALPN) support for MQTT over TLS
- Code maintenance improvements to MQTT MTP

## 2024-08-19 v8.0.8
### Fixed
- Dockerfile rewritten to use debian:stable and build libwebsockets [GH #95, #108]

## 2024-08-05 v8.0.7
### Added
- Improved MQTT MTP debug

### Fixed
- USP Service acting as pure Controller does not accept responses unless Broker is in the USP Service's Controller table

## 2024-07-29 v8.0.6
### Fixed
- Get requests with max_depth >= 0x80000000 should return full sub-tree
- USP Connect record not always sent immediately after connection on MQTT

### Removed
- Unmaintained MQTT tests

## 2024-07-08 v8.0.5
### Fixed
- MQTT keep alive can now be completely disabled (if required) when linking with libmosquitto v2.0.x
- OBUSPA should subscribe to all topics indicated by the subscribe-topic user properties in the CONNACK [R-MQTT.15]
- OBUSPA should delete pending USP notifications (on MQTT MTP) if notification has expired whilst waiting to be sent
- MQTT connection blocks for too long if server is unresponsive. To workaround the underlying issue in libmosquitto, OBUSPA tests for server responsiveness by transiently connecting, before proceeding with the libmosquitto connect (if responsive).
- OBUSPA should disconnect if unable to subscribe to anything [R-MQTT.17]
- Device.MQTT.Client.{i}.Name should be auto-assigned by the agent, if not given at creation time, and immutable thereafter
- Device.MQTT.Client.{i}.RequestResponseInfo should control whether response information is requested in the CONNECT frame. Previously it was always requested, regardless of the value of the parameter
- Removed unimplemented parameter: Device.MQTT.Client.{i}.RequestProblemInfo
- Modifying MQTT KeepAliveTime should not force a reconnect
- MQTTv5 Assigned Client Identifier is not being saved in Device.MQTT.Client.{i}.ClientID
- MQTT ConnectRetryTime parameter modifications should apply at the next retry [GH #109]
- MQTT CleanSession and CleanStart parameter modifications should apply at the next retry
- STOMP ServerRetryMaxInterval parameter modifications should apply at the next retry

### Added
- Device.LocalAgent.X_VANTIVA-COM_PreConnectTimeout controls how long to wait for the can_mtp_connect vendor hook to allow connection, before connecting anyway
- USP_REGISTER_Object_UniqueKey() validates that the unique key parameters have not already been registered

## 2024-06-10 v8.0.4
### Fixed
- Compiling without UDS fails [GH#110]
- WebSocket client does not send Boot! event (regression introduced in v8.0)
- WebSocket client not started after MTP dynamically added to controller table (regression introduced in v8.0)

## 2024-05-13 v8.0.3
### Added
- USP Broker: CLI initiated gets have been optimized to pass through the path to the USP Service, when possible
- USP Broker: Support a USP Service registering Device.DNS.SD before Device.DNS (in separate register messages)
- USP Broker: Workaround for USP Services which have limitations on the number of parameters requested in a get
- USP Broker: Support additional DM elements registered directly under Device.

### Fixed
- Get instances failures during path resolution should be gracefully ignored
- An unused variable warning seen during cmake based builds has been addressed


## 2024-04-29 v8.0.2
### Added
- VALUE_CHANGE_WILL_IGNORE flag support

### Fixed
- Prevent accidental CLI socket stealing

## 2024-04-15 v8.0.1
### Fixed
- USP Broker should not assume hierarchically ordered fields in GSDM and get instances responses
- STOMP connects shouldn't block the data model thread


## 2024-04-03 v8.0.0
  * USP Services Support
    * USP Broker functionality
    * USP Service functionality
    * Unix Domain Socket MTP
    * Register and Deregister messages
  * Dynamic roles and permissions
  * CMake build support
  * Get requests
    * Requests for concrete data model paths that are not instantiated now return an error, instead of an empty response [R-GET.0]
    * Under certain circumstances it was possible for an object's parameters to be spread across more than one resolved_path_result in the Get Response
  * WebSockets MTP
    * EndpointID is now indicated in the query component of the WebSocket request URI [R-WS.10b]
    * When using WebSockets MTP, the ping failure count was not being reset after reconnect. Under certain circumstances this led to unnecessary reconnects.
  * Integrator enhancements
    * New vendor hooks
      * can_mtp_connect_cb - allows the vendor layer to delay connection to a Controller ACS until critical device functionality is running (for example NTP time synchronized)
      * modify_firmware_updated_cb - allows the vendor layer to modify the FirmwareUpdated argument being passed in the Boot! event. This can be used to override the default calculation for this argument, if it does not catch all cases of the firmware being updated.
    * New USP API functions
      * USP_PROCESS_DoWork - allows the vendor layer to perform work in the context of the data model thread (for example calling USP_DM_SetParameterValue)
      * USP_REGISTER_AsyncOperation_MaxConcurrency - used to prevent concurrent processing of duplicate asynchronous USP commands


  * Bug Fixes
    * The default value for Device.LocalAgent.MTP.{i}.Protocol has been made dependent on which MTPs are configured in the build options
    * In protocol buffer traces, 64 bit numeric values were being printed incorrectly on 32 bit CPU architectures
    * A minor error in mqtt_factory_reset_example.txt has been addressed (GH#78)
    * After a reboot which interrupted the action of multiple asynchronous USP commands, it was possible for some commands to not be restarted, when it was intended that they were
    * Under certain circumstances, object creation notifications could have been sent at start up before the Boot! notification
    * A cause of error due to changes in the instantiated data model during the processing of USP requests has been prevented
    * Non UTF-8 characters in JSON formatted text containing parameter values are now converted to the Unicode replacement character (U+FFFD)
    * A subscription's ReferenceList is now immutable after being set



## 2024-01-08 v7.0.6
### Fixed
- The default value for Device.LocalAgent.MTP.{i}.Protocol now takes into account which MTPs are present


## 2023-11-15 v7.0.5
### Fixed
- WebSockets ping failure count is not reset after reconnect (GH#97)


## 2023-09-08 v7.0.4
### Added
- A new core vendor hook has been added (modify_firmware_updated_cb_t), which allows the FirmwareUpdated argument of the Boot! event to be modified from the default determined by OBUSPA.
- New function: USP_PROCESS_DoWork() performs work (via a callback) in the context of the data model thread (GH#93). Example usage: Initiating the setting of parameters from a non-data model thread.

### Fixed
- E2E session context SessionId fields are printed incorrectly in logs on 32-bit devices



## 2023-05-09 v7.0.3
### Fixed
- Prevent a parent object's parameters being spread across more than one resolved_path_result in the GetResponse, if it has many child object instances
- Example mqtt factory reset database should not contain wildcard in ResponseTopicConfigured (GH#78)

## 2023-03-13 v7.0.2
### Fixed
- USP Agent should attempt to restart all async operations, even if one restart fails
- Object creation notifications should not be sent at start up, if the object has a refresh instances vendor hook
- Instance cache should not expire during the phases of processing a USP request
- libjson modified to replace non-UTF8 characters with the Unicode replacement character (U+FFFD) instead of asserting

### Added
- New function: USP_REGISTER_AsyncOperation_MaxConcurrency() to register whether a USP command allows another invocation whilst running

## 2023-02-02 v7.0.1
### Added
- CMake support (GH#69)
- Development environment within Docker container

### Modified
- Memory allocation wrapper functions refactored to avoid erroneous warnings when compiling with -Wuse-after-free



## 2023-01-05 v7.0.0
  * Bug Fixes
    * MQTT MTP
      * GH#30: MQTT publish QoS cannot be configured (stuck at 0)
      * For MQTTv3.x MTP, Agent should subscribe to wildcarded agent topic and publish to topic containing '/reply-to='
      * When changing a subscription's topic, The agent was unsubscribing from the new topic (not the old topic)
      * For MQTTv5 MTP, Agent should subscribe to topic from CONNACK, if available
      * MQTT exponential backoff reconnect time was 1 second too long
      * libmosquitto subscribe/unsubscribe functions were being called unnecessarily (and failing)
      * MQTT_DeleteSubscription() was being called unnecessarily (and failing)
      * Memory leak when unescaping a received MQTT response topic
      * MQTT subscription topic must be unique
      * MQTT subscription topic must be non empty string
      * When disabling the agent's MQTT client, the MQTT DISCONNECT frame is not sent and socket stays open
      * Missing mutex protection in some MQTT functions

    * WebSocket MTP
      * Agent's websocket server is not restarted after IP address change or initial failure
      * Requirement for libwebsockets version >= 4.1.0 made explicit in configure.ac

    * USP Spec and Test Plan modifications
      * MQTT Content Type property changed to usp.msg (changed R-MQTT.27)
      * A USP Set referencing zero instances returns an empty success (changed TP-469 conformance test 1.23)
      * Errors in received USP packets should be handled according to requirements in R-MTP.5
      * USP Record should be ignored if the protobuf cannot be unpacked

    * Miscellaneous
      * GH#55: Updated Dockerfile to use Ubuntu Kinetic which includes the required versions of libmosquitto and libwebsockets
      * GH#64: Crash if PeriodicNotifInterval is set to 0
      * GetResponse optimized for large numbers of object instances
      * If 'obuspa -c get' truncates the printing of a parameter value, this is now indicated
      * OnBoardRequest notification should be retried, if corresponding NotifyResponse not received
      * Adding a Controller MTP object fails, if Protocol is not specified and CoAP is disabled ('configure --disable-coap')
      * Default value for RebootCause would be better as "FactoryReset"
      * Alias should be registered as a unique key for LocalAgent.Certificate
      * GetSupportedDM response should indicate that parameters registered with USP_REGISTER_DBParam_SecureWithType() are readable
      * Added note that the start_transaction vendor hook must never return a failure, as it is not possible for OBUSPA to handle the failure in all cases



## 2022-10-28 v6.0.5
### Fixed
- OnBoardRequest notification should be retried, if corresponding NotifyResponse not received
- Adding a Controller MTP object fails, if Protocol is not specified and CoAP is disabled ('configure --disable-coap')

## 2022-10-03 v6.0.4
### Fixed
- GH#30: MQTT publish QoS cannot be configured (stuck at 0)
- GH#64: Crash if PeriodicNotifInterval is set to 0
- GH#55: Ubuntu 22 (latest) contains earlier version of libwebsockets than Ubuntu 20
- Requirement for libwebsockets version >= 4.1.0 made explicit in configure.ac
- GetResponse optimized for large numbers of object instances
- USP Record should be ignored if the protobuf cannot be unpacked
- Default value for RebootCause would be better as "FactoryReset"
- MQTT exponential backoff reconnect time was 1 second too long
- Alias should be registered as a unique key for LocalAgent.Certificate

### Modified
- MQTT Content Type property changed to usp.msg (changed R-MQTT.27)
- A USP Set referencing zero instances returns an empty success (changed TP-469 conformance test 1.23)


## 2022-09-02 v6.0.3

### Fixed
- For MQTTv3.x MTP, Agent should subscribe to wildcarded agent topic and publish to topic containing '/reply-to='
- libmosquitto subscribe/unsubscribe functions were being called unnecessarily (and failing)
- MQTT_DeleteSubscription() was being called unnecessarily (and failing)
- Memory leak when unescaping a received MQTT response topic
- MQTT subscription topic must be unique
- MQTT subscription topic must be non empty string
- When changing a subscription’s topic, The agent was unsubscribing from the new topic (not the old topic)
- For MQTTv5 MTP, Agent should subscribe to topic from CONNACK, if available
- Missing mutex protection in some MQTT functions


## 2022-07-25 v6.0.2

### Fixed
- When disabling the agent's MQTT client, the MQTT DISCONNECT frame is not sent and socket stays open
- Errors in received USP packets should be handled according to requirements in R-MTP.5


## 2022-07-11 v6.0.1

### Fixed
- Agent's websocket server is not restarted after IP address change or initial failure
- GetSupportedDM response should indicate that parameters registered with USP_REGISTER_DBParam_SecureWithType() are readable


## 2022-07-28 v6.0.0
  * New Features
    * USP 1.2 Spec Enhancements
      * Get request and response (max_depth field)
      * GetSupportedDM response (value_type, value_change and command_type fields)
      * USP Connect and Disconnect records
    * Basic End-to-End session context support (mainly segmentation and reassembly aspects). Disabled by default. To enable, uncomment E2ESESSION_EXPERIMENTAL_USP_V_1_2 in vendor_defs.h
    * The severity level of log messages now propagates to syslog() invocations. To override the default severity level passed to syslog, modify SYSLOG_SEVERITY_OVERRIDE in vendor_defs.h.
    * Added extra parameter types: DM_BASE_64, DM_DECIMAL, DM_LONG and DM_HEX_BINARY
    * MTP credentials username core vendor hook

  * Data Model Enhancements
    * Device.DeviceInfo.UpTime
    * Device.LocalAgent.MTP.{i}.MQTT.ResponseTopicDiscovered

  * Bug Fixes
    * Data model thread locks up on high message throughput
    * Agent crashes when nested objects are created in an ADD message with allow_partial=false
    * Password in STOMP header should be escaped
    * GetSupportedDM Response reports incorrect Add and Delete permissions for objects registered using USP_REGISTER_GroupedObject()
    * Bulk Data Collection Protocol parameter is validating against old value, not new value
    * Reference following should allow references to contain key based addressing
    * 64 bit signed and unsigned integer parameter values are now represented with full precision in JSON encoded data (for Bulk Data Collection reports and Boot! event). To enable the old behavior (which represented them as floating point doubles) comment out the REPRESENT_JSON_NUMBERS_WITH_FULL_PRECISION define in vendor_defs.h
    * Empty Subscription ID should not be allowed
    * Subscription ID should be auto-assigned
    * Compile error if MQTT and STOMP are disabled
    * getopt_long options structure was wrong for authcert option
    * Set Request obj_path is not required to contain an instance number
    * STOMP DISCONNECT frame should be sent before disconnecting if no agent destination configured (USP Compliance Test 6.7)
    * Compilation fails when WebSockets enabled and CoAP disabled
    * MQTT does not wait until all responses are sent when disabling MTP (GH Issue 33)
    * MQTT v5.0 response topic memory leak
    * Optional input arguments to USP Commands should be ignored
    * EndpointId should be in quotes in Sec-WebSocket-Extension header
    * MQTT KeepAlive 0 not working as expected

  * Other
    * Tidy up MQTT code: Added function header comments and re-ordered some MQTT functions
    * Removed GET_RESPONSE_SIMPLE_FORMAT from vendor_defs.h. In USP 1.2 it was clarified that only the simple format must be used.
    * WebSockets example factory reset file
    * Updated quick start guide with instructions for cloning from github (GH Issue 39)


## 2022-06-13

### Added
- USP 1.2 Connect and Disconnect record support
- WebSockets example factory reset file

### Fixed
- 64 bit signed and unsigned integer parameter values are now represented with full precision in JSON encoded data (for Bulk Data Collection reports and Boot! event). To enable the old behavior (which represented them as floating point doubles) comment out the REPRESENT_JSON_NUMBERS_WITH_FULL_PRECISION define in vendor_defs.h
- Bulk Data Collection Protocol parameter is validating against old value, not new value
- Empty Subscription ID should not be allowed

### Modified
- MQTT function header comments

## 2022-05-20
### Added
- Get request and response upgraded to USP 1.2 spec (max_depth field)
- GetSupportedDM response upgraded to USP 1.2 spec (value_type, value_change and command_type fields)
- Added extra parameter types: DM_BASE_64, DM_DECIMAL, DM_LONG and DM_HEX_BINARY

## 2022-04-29

### Added
- Basic End-to-End session context support (mainly segmentation and reassembly aspects). Disabled by default. To enable, uncomment E2ESESSION_EXPERIMENTAL_USP_V_1_2 in vendor_defs.h
- Device.DeviceInfo.UpTime parameter

### Fixed
- Compile error if MQTT and STOMP are disabled
- getopt_long options structure was wrong for authcert option
- Password in STOMP header should be escaped
- Set Message obj_path is not required to contain an instance number

### Modified
- Removed GET_RESPONSE_SIMPLE_FORMAT from vendor_defs.h. In USP 1.2 it was clarified that only the simple format must be used.


## 2022-03-23

### Fixed
- STOMP DISCONNECT frame should be sent before disconnecting if no agent destination configured (USP Compliance Test 6.7)

### Modified
- The GET_RESPONSE_SIMPLE_FORMAT define has been enabled (as default) to make the GetResponse contain a resolved_path_result for every object (and sub object).



## 2022-02-21

### Added
- MTP credentials username core vendor hook
- Functions for creation of Connect and Disconnect USP Records

### Fixed
- 'killall obuspa' doesn't work anymore
- Compilation fails when WebSockets enabled and CoAP disabled
- MQTT does not wait until all responses are sent when disabling MTP (GH Issue 33)

### Modified
- Updated quick start guide with instructions for cloning from github (GH Issue 39)



## 2022-02-07

### Added
- MQTT v5.0 ResponseTopicDiscovered parameter implemented
- Reference following should allow references to contain key based addressing

### Fixed
- MQTT v5.0 response topic memory leak
- Subscription ID should be auto-assigned
- Optional input arguments to USP Commands should be ignored
- EndpointId should be in quotes in Sec-WebSocket-Extension header

### Modified
- Updates to support upcoming USP v1.2 protocol buffer changes



## 2022-01-24

### Fixed
- Agent crashes when nested objects are created in an ADD message with allow_partial=false
- MQTT KeepAlive 0 Not working as expected

### Modified
- Refactored internal USP payload information structures



## 2021-12-05 v5.0.0
  * New Features
    * WebSockets MTP Support in both client and server modes
    * 'obuspa -c event' signals a USP event (for testing purposes)
    * TLS Server Name Indication for STOMP
    * Added ABOUT files (for open source attribution and inventory purposes)
    * 'obuspa -c version' includes versions of shared library dependencies

  * Bug Fixes
    * MQTT connect can block, holding up the data model thread (GH Issue #31)
    * MQTT Connect callback should not add trust store certs everytime (GH Issue #29)
    * MQTT Subscriptions don't work at startup (GH Issue #23)
    * MQTT subscribe-topic in CONNACK is not retrieved correctly
    * CoAP RST message format error (GH#25)
    * Support for mallinfo2, mallinfo deprecated on glibc >= 2.33 (GH#26)
    * RequestChallenge/ChallengeResponse : Retries and Lockout period applied per ChallengeRef
    * ControllerTrust parameter set permission was incorrectly additionally considering the set permission of the parent object
    * Compilation error in protobuf C library with GCC 10.3
    * Compilation errors on GCC 11.2 cross compiler for ARM

  * Other
    * Added 'const' declaration to 'char *' usage in logger functions for calling from C++
    * Removed unnecessary log message for object deletion subscription containing wildcard and partial path
    * Get Supported Protocol version updated
    * Factory reset database improvements


## 2021-11-16

### Fixed
- Added 'const' declaration to 'char *' usage in logger functions for calling from C++


## 2021-11-04

### Added
- WebSockets client Support
- TLS Server Name Indication for STOMP
- 'obuspa -c event' signals a USP event (for testing purposes)

### Fixed
- Compilation errors on GCC 11.2 cross compiler for ARM
- ControllerTrust parameter set permission was incorrectly additionally considering the set permission of the parent object


## 2021-10-04

### Added
- Support for mallinfo2, mallinfo deprecated on glibc >= 2.33 (GH#26)

## 2021-09-20

### Fixed
- CoAP RST message format error (GH#25)
- Get Supported Protocol version needs updating
- Factory reset database improvements


## 2021-08-20

### Fixed
- MQTT Subscriptions don't work at startup (GH Issue #23)
- MQTT subscribe-topic in CONNACK is not retrieved correctly
- Removed unnecessary log message for object deletion subscription containing wildcard and partial path







