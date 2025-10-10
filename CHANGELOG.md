# OB-USP-AGENT Changelog since Release 10.0.0

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
