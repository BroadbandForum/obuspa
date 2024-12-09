# OB-USP-AGENT Changelog since Release 9.0.0

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

