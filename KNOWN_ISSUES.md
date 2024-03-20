# OB-USP-Agent Known Issues

* **(SECURITY)** OBUSPA should not make use of functions which OpenSSL is deprecating.
* **(ACCESS CONTROL)** A Get request for a specific parameter which the Controller does not have permission to read, should result in a Get response containing an error rather than an empty response.
* **(MQTT)** When using MQTTv5, OBUSPA is not saving the Client Id assigned to it by the MQTT Broker in Device.MQTT.Client.\{i\}.ClientID.
* **(MQTT)** OBUSPA should disconnect from the MQTT Broker if it failed to subscribe to at least one topic [\[R-MQTT.17\]](https://usp.technology/specification/index.htm#r-mqtt.17)
* **(MQTT)** A connect over MQTT blocks for too long if the MQTT broker is unresponsive. This can cause OBUSPA to drop other MQTT connections. The underlying libmosquitto library needs a connect-with-timeout function. [\[GH#100\]](https://github.com/BroadbandForum/obuspa/issues/100)
* **(MQTT)** MQTT PublishRetainResponse and PublishRetainNotify parameters should be implemented
* **(MQTT)** OBUSPA should expire queued USP notifications if the MQTT Broker is offline
* **(MQTT)** OBUSPA should allow other MQTT messaging applications (e.g. IoT applications) on the device to share its MQTT connections.


