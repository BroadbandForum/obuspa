# OB-USP-AGENT Changelog since Release 6.0.0

## 2022-09-02 v6.0.3

### Fixed
- For MQTTv3.x MTP, Agent should subscribe to wildcarded agent topic and publish to topic containing '/reply-to='
- libmosquitto subscribe/unsubscribe functions were being called unnecessarily (and failing)
- MQTT_DeleteSubscription() was being called unnecessarily (and failing)
- Memory leak when unescaping a received MQTT response topic
- MQTT subscription topic must be unique
- MQTT subscription topic must be non empty string
- When changing a subscription’s topic, The agent was unsubscribing from the new topic (not the old topic)
- For MQTTv5 MTP, Agent should subscribe to topic from CONNACK, if available
- Missing mutex protection in some MQTT functions


## 2022-07-25 v6.0.2

### Fixed
- When disabling the agent's MQTT client, the MQTT DISCONNECT frame is not sent and socket stays open
- Errors in received USP packets should be handled according to requirements in R-MTP.5


## 2022-07-11 v6.0.1

### Fixed
- Agent's websocket server is not restarted after IP address change or initial failure
- GetSupportedDM response should indicate that parameters registered with USP_REGISTER_DBParam_SecureWithType() are readable

