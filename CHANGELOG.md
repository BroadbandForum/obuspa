# OB-USP-AGENT Changelog since Release 10.0.0

## 2025-05-27 v10.0.2
### Fixed
- Code should compile with --disable-bulkdata (regression introduced in v10.0.1)
- Wrong error code returned in conformance test 1.100
- Crash occurs if USP Service registers a DM element, but does not provide it in the GSDM response

## 2025-05-02 v10.0.1
### Added
- Support for Device.BulkData.Profile.{i}.Controller parameter
