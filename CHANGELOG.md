# OB-USP-AGENT Changelog since Release 8.0.0

## 2024-07-29 v8.0.6
### Fixed
- Get requests with max_depth >= 0x80000000 should return full sub-tree
- USP Connect record not always sent immediately after connection on MQTT

### Removed
- Unmaintained MQTT tests

## 2024-07-08 v8.0.5
### Fixed
- MQTT keep alive can now be completely disabled (if required) when linking with libmosquitto v2.0.x
- OBUSPA should subscribe to all topics indicated by the subscribe-topic user properties in the CONNACK [R-MQTT.15]
- OBUSPA should delete pending USP notifications (on MQTT MTP) if notification has expired whilst waiting to be sent
- MQTT connection blocks for too long if server is unresponsive. To workaround the underlying issue in libmosquitto, OBUSPA tests for server responsiveness by transiently connecting, before proceeding with the libmosquitto connect (if responsive).
- OBUSPA should disconnect if unable to subscribe to anything [R-MQTT.17]
- Device.MQTT.Client.{i}.Name should be auto-assigned by the agent, if not given at creation time, and immutable thereafter
- Device.MQTT.Client.{i}.RequestResponseInfo should control whether response information is requested in the CONNECT frame. Previously it was always requested, regardless of the value of the parameter
- Removed unimplemented parameter: Device.MQTT.Client.{i}.RequestProblemInfo
- Modifying MQTT KeepAliveTime should not force a reconnect
- MQTTv5 Assigned Client Identifier is not being saved in Device.MQTT.Client.{i}.ClientID
- MQTT ConnectRetryTime parameter modifications should apply at the next retry [GH #109]
- MQTT CleanSession and CleanStart parameter modifications should apply at the next retry
- STOMP ServerRetryMaxInterval parameter modifications should apply at the next retry

### Added
- Device.LocalAgent.X_VANTIVA-COM_PreConnectTimeout controls how long to wait for the can_mtp_connect vendor hook to allow connection, before connecting anyway
- USP_REGISTER_Object_UniqueKey() validates that the unique key parameters have not already been registered

## 2024-06-10 v8.0.4
### Fixed
- Compiling without UDS fails [GH#110]
- WebSocket client does not send Boot! event (regression introduced in v8.0)
- WebSocket client not started after MTP dynamically added to controller table (regression introduced in v8.0)

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
