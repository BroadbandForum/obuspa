# OB-USP-AGENT Changelog since Release 4.1

## 2021-11-16: Added 'const' declaration to 'char *' usage in logger functions

### Fixed
- Added 'const' declaration to 'char *' usage in logger functions for calling from C++


## 2021-11-04: Added WebSockets client Support

### Added
- WebSockets client Support
- TLS Server Name Indication for STOMP
- 'obuspa -c event' signals a USP event (for testing purposes)

### Fixed
- Compilation errors on GCC 11.2 cross compiler for ARM
- ControllerTrust parameter set permission was incorrectly additionally considering the set permission of the parent object


## 2021-10-04: Add support for mallinfo2, mallinfo deprecated on glibc >= 2.33 (GH#26)

### Added
- Support for mallinfo2, mallinfo deprecated on glibc >= 2.33 (GH#26)

## 2021-09-20: Fixed CoAP RST message format error (GH#25) and other issues

### Fixed
- CoAP RST message format error (GH#25)
- Get Supported Protocol version needs updating
- Factory reset database improvements


## 2021-08-20: MQTT Bug Fixes for subscriptions and subscribe-topic

### Fixed
- MQTT Subscriptions don't work at startup (GH Issue #23)
- MQTT subscribe-topic in CONNACK is not retrieved correctly
- Removed unnecessary log message for object deletion subscription containing wildcard and partial path

