# OB-USP-AGENT Changelog since Release 5.0.0

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





