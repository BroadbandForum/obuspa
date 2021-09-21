# OB-USP-AGENT Changelog since Release 4.1

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

