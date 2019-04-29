# Release History
## Release 1.0.0
This release contains the following features:
* MTPs
   * CoAP (alpha quality).
      *  No DTLS Support
   * STOMP
      * TLS Support
      * Authentication: username/password or client cert
      * IPv4 and IPv6 Supported
      * USP Record
      * NoSessionContext Record Type Supported
      * PLAINTEXT Payload Security Supported
      * No Support for: SessionContext Record Type, TLS12 Payload Security, Payload SAR, or MAC Signature
* USP Message
   * Support for: Get, Set, Add, Delete, Operate, GetSupportedDM, GetInstances, GetSupportedProtocol, and Notify
* Data Model Addressing
   * By Unique Key
   * By Instance Number
* Data Model Searching
   * By Wildcard
   * By Expression
* Data Model Reference Path Following
   * Fully supported except when: embedded in a Search Expression, as part of a list of references
* HTTP Bulk Data Collection
   * Only JSON is supported with the NameValuePair Report Format
* Controller Trust
   * Roles and Permissions are supported (but fixed at compile time)
   * Credentials are supported (but limited to trust store certificates that are fixed at initialization time)
* USP Data Model implemented
   * Device.Reboot()
   * Device.Boot!
   * Device.FactoryReset()
   * Device.SelfTestDiagnostics()
   * Device.DeviceInfo.
   * Device.LocalAgent.
   * Device.LocalAgent.MTP.{i}.
   * Device.LocalAgent.MTP.{i}.CoAP.
   * Device.LocalAgent.MTP.{i}.STOMP.
   * Device.LocalAgent.Controller.{i}.MTP.{i}.
   * Device.LocalAgent.Controller.{i}.MTP.{i}.CoAP.
   * Device.LocalAgent.Controller.{i}.MTP.{i}.STOMP.
   * Device.LocalAgent.Controller.{i}.BootParameter.{i}.
   * Device.LocalAgent.Subscription.{i}.
   * Device.LocalAgent.Request.{i}.
   * Device.LocalAgent.ControllerTrust.
   * Device.LocalAgent.ControllerTrust.Role.{i}.
   * Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.
   * Device.LocalAgent.ControllerTrust.Credential.{i}.
   * Device.Time.
   * Device.Security.
   * Device.Security.Certificate.{i}.
   * Device.BulkData.
   * Device.BulkData.Profile.{i}.
   * Device.BulkData.Profile.{i}.Parameter.{i}.
   * Device.BulkData.Profile.{i}.JSONEncoding.
   * Device.BulkData.Profile.{i}.HTTP.
   * Device.BulkData.Profile.{i}.HTTP.RequestURIParameter.{i}.
   * Device.STOMP.
   * Device.STOMP.Connection.{i}.



