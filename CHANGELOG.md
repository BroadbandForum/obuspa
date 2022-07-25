# OB-USP-AGENT Changelog since Release 6.0.0

## 2022-07-25 v6.0.2

### Fixed
- When disabling the agent's MQTT client, the MQTT DISCONNECT frame is not sent and socket stays open
- Errors in received USP packets should be handled according to requirements in R-MTP.5


## 2022-07-11 v6.0.1

### Fixed
- Agent's websocket server is not restarted after IP address change or initial failure
- GetSupportedDM response should indicate that parameters registered with USP_REGISTER_DBParam_SecureWithType() are readable

