# Release History
## Release 4.0.0
  * ControllerTrust support
    * Challenge/Response mechanism
    * OnBoardRequest mechanism
    * Device.LocalAgent.Certificate (certs trusted by OBUSPA)
    * Device.Security.Certificate (all other certs)
  * Bulk Data Collection via USP notifications
  * Configure options for supported MTPs
  * ScheduleTimer USP command support
  * Reference following in search expressions
  * Example Dockerfile
  * Bug Fixes
    * Reporting of memory leaks when -m option used
    * Exponential backoff for MQTT
    * Reporting of synchronous USP command failures
    * Database persistence of multi-instance objects consisting purely of ReadOnly parameters
    * USP SetResponse when using wildcards
    * ObjectCreation/Deletion notifications if ReferenceList contains a partial path and object uses refresh instances vendor hook
    * KV_VECTOR_FindKey() when start_index is non zero
    * Reporting of object access in GetSupportedDM response for read only objects that use the grouped vendor interface
    * Default Endpoint ID containing characters which should be percent encoded
    * Legacy OpenSSL 1.0.2g support
    * MQTT Response Topic
    * MQTT Secure Password Parameter
  * Other Changes
    * MQTT broker certificate hostname validation
    * Timeout for SSL handshake if STOMP broker doesn't respond
    * subscription_id field ignored in NotifyResp
    * MQTT protocol tracing improved
    * X_ARRIS-COM_EnableEncryption parameter name changed to EnableEncryption, for STOMP MTP
  * Known Issues
    * ControllerTrust ChallengeResponse handling of retries

## Release 3.0.0
  * MQTT MTP support
     * MQTT v5.0 and MQTT v3.1.1 support
     * TLS support
     * MQTT topic subscriptions
  * Architectural enhancements
     * More efficient USP Get and Set for groups of parameters provided by separate components
     * On-demand querying of table instance numbers
  * Build support for MUSL libc
  * Bug fixes
     * Conformance test failures
     * Defaulted unique key parameters are validated for uniqueness when adding an instance to a table
     * Deleting a controller deletes its subscriptions
     * References to objects without trailing instance numbers do not cause assert
     * USPRetry set of parameters, should actually be named USPNotifRetry
  * Other changes
     * Ignore sender certificate in USP records
     * Annotations on function prototypes for better Clang static analyzer results
     * CoAP.Interfaces parameter removed
     * More robust handling of badly formed percent encoded CoAP resource in URI query option

## Release 2.1.0
  * Simultaneous sessions with multiple CoAP based controllers are now supported
  * USP Record error handling has been upgraded to be compliant with the USP 1.1 Specification
  * The InstantiatedPath field in the USP AddResponse message is now formed correctly
  * Percent encoded CoAP resource names are now handled correctly
  * Queued USP notifications are not sent out if their NotifExpiration period has elapsed

## Release 2.0.0
  * CoAP
     * New USP optimized implementation
     * DTLS support
     * Robustness improvements
     * Specification of CoAP server network interface
     * reply-to URI query option support
  * New command line arguments
     * Trust store certificates file (-t)
     * Factory reset parameters text file (-r)
     * Network interface for USP communications (-i)
  * Data Model improvements
     * Device.Time.LocalTimezone added
     * Bulk Data Collection client certificate support
  * Bug fixes
     * Session Retry wait interval calculation should not overflow
     * Agent should not generate an error if trying to delete an instance which is already deleted
     * An empty subscription ReferenceList should not cause a crash
     * UINT32 parameter limit validation should not fail for 32 bit architectures
     * Error message for path containing back-to-back instance searches should not be confusing

## Release 1.0.1
  * configure now checks for libcoap availability
  * Out of tree builds are now supported
  * Added contibuting guidelines

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

