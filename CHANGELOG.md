# OB-USP-AGENT Changelog since Release 9.0.0

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

