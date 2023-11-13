# OBUSPA Internal USP services
This document describes how to use OBUSPA to provide USP internal services
## Overview 
USP Internal Services are described in detail on the Broadband Forum website here:-
https://usp.technology/specification/index.html#sec:software-modularization-theory-of-operations
[![USPservices](https://usp.technology/specification/extensions/device-modularization/use-cases.png)

## Features

USP Services provide broadly two features:-

- Allow applications running on a device to register part of their data model with the USP Agent. This exposes that part of the data model to any cloud services or other USP Services (with permission) to access and control that Service.  Note that when the USP Agent is running in conjunction with USP Services, it is typically referred to as the USP Broker.  A USP Broker acts as both an Agent in the conventional sense,  but also as a Controller with respect to any USP services registering with it.

- Allow applications running on a device to control (subject to permission) the Broker and other USP Services.

## Building support for USP services

USP Broker support is enabled by default. It can be explicitly disabled by defining "REMOVE_USP_BROKER" in /src/vendor/vendor_defs.h 

## Running OBUSPA as a Broker

The Broker is enabled by default.  However, some configuration is necessary in order to configure the Unix domain sockets used by internal services.  In addition, if we are running several instances of OBUSPA, it is necessary to change some command line options to ensure a different database and CLI socket path are used for each instance.

OBUSPA stores its configuration in a database file, the path of which can be provided as a command line option.  https://github.com/BroadbandForum/obuspa/blob/master/QUICK_START_GUIDE.md contains a detailed description of this database in the section entitled "Running OB-USP-AGENT for the first time".

We need to copy and modify the factory_reset_example.txt to broker_reset.txt and add additional data model entries that OBUSPA uses to instantiate the domain sockets used by the UDS backend.  Though different configurations are possible, it is recommended (for interoperability) that the Broker creates two listening sockets.  Each USP Service will connect/disconnect as necessary and register its data model with the Broker.  One of these sockets is used when the USP Service is acting as an Agent to the Broker's Controller.  The other socket is used when the USP Service is acting as a Controller of the Broker's agent.

### Configuring the Broker's Controller socket
The following well known path should be used to configure the Broker's Controller socket.  OBUSPA will use this information to create a listening socket at the specified path that USP Service's Agents can connect to. 
```
Device.UnixDomainSockets.UnixDomainSocket.1.Alias" "cpe-1"
Device.UnixDomainSockets.UnixDomainSocket.1.Mode" "Listen"
Device.UnixDomainSockets.UnixDomainSocket.1.Path" "/var/run/usp/broker_controller_path"
```
OBUSPA must be run for the first time to configure the database.  Note that OBUSPA will only use these factory default values if no database already exists.  If you wish to change the default parameters then you must remove the existing database.  In the below command, '-f' selects usp_broker.db as the database (instead of the default usp.db) and '-s' selects broker_cli as the CLI socket (instead of the default usp_cli).

```
obuspa -f /usr/local/var/obuspa/usp_broker.db -s /tmp/broker_cli -p -v 4 -r broker_reset.txt -i enp0s3
```
### Configuring a USP Service to connect to the Broker
The USP Service must also be told to connect to the Broker's Controller path. Using factory_reset_example.txt as a starting point, copy and modify to service1_reset.txt and add the following lines:-
```
Device.UnixDomainSockets.UnixDomainSocket.1.Alias "cpe-1"
Device.UnixDomainSockets.UnixDomainSocket.1.Mode "Connect"
Device.UnixDomainSockets.UnixDomainSocket.1.Path "/var/run/usp/broker_controller_path"
Device.LocalAgent.MTP.1.Alias  "cpe-1"
Device.LocalAgent.MTP.1.Protocol  "UDS"
Device.LocalAgent.MTP.1.UDS.UnixDomainSocketRef  "Device.UnixDomainSockets.UnixDomainSocket.1"
Device.LocalAgent.MTP.1.Enable  "true"
Device.LocalAgent.EndpointID "proto::service1"
```
Note the the Endpoint ID is set differently for the USP Service to "proto::service1".  By default the USP Endpoint ID is derived from the network adapter MAC address.  Each Endpoint ID must be unique which will plainly not be the case if we continue to use the default Endpoint ID.  For USP Services we set an appropriate Endpoint ID in the settings database.
```
obuspa -f /usr/local/var/obuspa/usp_service1.db -s /tmp/service1_cli -p -v4 -r service1_reset.txt -i enp0s3
```
Running the above command in a second terminal (whilst the Broker is active in the first terminal) should output some debug that indicates the two instances of OBUSPA are communicating over the socket.

The USP Service should attempt to connect to the Broker:-
```
Sending UDS HANDSHAKE to endpoint_id=UNKNOWN on Broker's Controller path
Received UDS HANDSHAKE from endpoint_id=os::012345-080027352E99 on Broker's Controller path
```
And the Broker should accept the connection from the Service:-
```
Received UDS HANDSHAKE from endpoint_id=proto::service1 on Broker's Controller path
Sending UDS HANDSHAKE to endpoint_id=proto::service1 on Broker's Controller path
```
## Implementing a USP Service vendor backend
A developer may choose to use OBUSPA as the basis for developing an application that is configurable via its registered data model.  This section provides a simple example that demonstrates how this might be achieved.  Note that QUICK_START_GUIDE.md contains more detailed examples of how to add to the data model of OBUSPA.  This section focusses on how this is used in conjunction with USP Internal Services.  

Configuring a network based ACS to manipulate the data model is beyond the scope of this example.  In the short tutorial below we use OBUSPA's built in CLI functionality as a developer tool to connect to the broker and get/set values.  

src\vendor\vendor.c contains a skeleton vendor implementation that does nothing initially. We will modify VENDOR_Init() to create a dummy object whose parameters are stored in the database.  We'll add a callback function to log changes to the value of ParamA.  

We only want to initialise this USP Service object for the Service instance of OBUSPA and not the Broker instance. As both processes will share the same executable binary, it is necessary to use the RUNNING_AS_A_USP_SERVICE() macro to only register the data model parameters in the case where we are running as the Service :-

```
#include "common_defs.h"

int NotifyChange_ServiceA_ParamA(dm_req_t *req, char *value)
{
    USP_LOG_Info("%s enter : value %s", __FUNCTION__, value);
    return USP_ERR_OK;
}

int VENDOR_Init(void)
{
    int err = USP_ERR_OK;
    if (RUNNING_AS_USP_SERVICE())
    {
        err |= USP_REGISTER_Object("Device.Test.ServiceA", NULL, NULL, NULL, NULL, NULL, NULL);
        err |= USP_REGISTER_DBParam_ReadWrite("Device.Test.ServiceA.ParamA", "default_A", NULL, NotifyChange_ServiceA_ParamA, DM_STRING);
    }
    return USP_ERR_OK;
}
```

Finally we need to run the Service and verify that we can query and update our USP Service data model object.  Make sure the Broker is running in one terminal:-
```
obuspa -f /usr/local/var/obuspa/usp_broker.db -s /tmp/broker_cli -p -v 4 -i enp0s3
```
Verify that the Device.Test object is NOT visible in the data model
```
obuspa -s /tmp/broker_cli -c get Device.Test.
DM_PRIV_GetNodeFromPath: Path is invalid: Device.Test
```
Then run the USP Service in a second terminal, this time adding the -R option and specifying the path to the object to register with the Broker:-
```
obuspa -f /usr/local/var/obuspa/usp_service1.db -s /tmp/service1_cli -p -v4 -i enp0s3 -R "Device.Test."
```
And query the Broker again to validate that Device.Test is registered and accessible:-
```
obuspa -s /tmp/broker_cli -c get Device.Test.
Device.Test.ServiceA.ParamA => default_A
```
Use the obuspa CLI to set the value of paramA to something else:-
```
obuspa -s /tmp/broker_cli -c set Device.Test.ServiceA.ParamA obuspa_is_great
Device.Test.ServiceA.ParamA => obuspa_is_great
obuspa -s /tmp/broker_cli -c get Device.Test.
Device.Test.ServiceA.ParamA => obuspa_is_great
```
Check the log output from service1 instance of obuspa to verify that the parameter was changed:-
```
SET : processing at time 2023-09-07T13:26:41Z
NotifyChange_ServiceA_ParamA enter : value obuspa_is_great
```
