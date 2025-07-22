# OB-USP-AGENT Changelog since Release 10.0.0

## 2025-07-22 v10.0.5
### Added
- Support for permission Targets containing search expressions (configured by ALLOWED_PARAMS_FOR_SE_BASED_PERMS in vendor_defs.h)

### Fixed
- MQTT client should disconnect if no Response Topic
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
