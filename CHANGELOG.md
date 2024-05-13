# OB-USP-AGENT Changelog since Release 8.0.0

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
