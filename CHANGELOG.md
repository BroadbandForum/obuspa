# OB-USP-AGENT Changelog since Release 5.0.0

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





