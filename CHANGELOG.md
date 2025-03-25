# OB-USP-AGENT Changelog since Release 9.0.0

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

