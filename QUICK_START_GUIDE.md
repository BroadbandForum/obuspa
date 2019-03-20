# Quick Start Guide
## Audience
This document supports two target audiences:
* Integrator  - Someone who is taking OB-USP-AGENT and integrating it into a device.
                Normally this also involves extending the data model to support the device.
* Contributor - Someone who is enhancing the core functionality of the open source OB-USP-AGENT implementation.


## Document conventions
When referring to source code functions, this document will often use 'XXX' to represent a set of possible function names.
For example,  DEVICE_XXX_Init() refers to a set of functions:
 DEVICE_STOMP_Init()
 DEVICE_MTP_Init()
 DEVICE_CONTROLLER_Init()
 etc


## Building OB-USP-AGENT
1. Install dependencies (Curl, OpenSSL, Sqlite, C-Ares, z-lib) using package manager:
```
$ sudo apt-get install libssl-dev libcurl4-openssl-dev libsqlite3-dev libc-ares-dev libz-dev
```

2. Install libcoap from source:
```
$ wget https://github.com/obgm/libcoap/archive/bsd-licensed.tar.gz
$ tar -xvf bsd-licensed.tar.gz
$ cd libcoap-bsd-licensed
$ ./autogen.sh
$ ./configure --disable-examples
$ make
$ sudo make install
```

3. IMPORTANT: Modify the DEFAULT_WAN_IFNAME define in src/vendor/vendor_defs.h, if you intend to run on
a device which does not have a network interface named "eth0".

4. Install ob_uspagent from source:
```
$ cd ob_uspagent
$ autoreconf --force --install
$ ./configure
$ make
$ sudo make install
```


## Running OB-USP-AGENT for the first time
Before OB-USP-AGENT starts, it needs a database containing the settings of the USP controller to contact.
This is known as the 'factory reset database'.
This database may be created using 'ob_uspagent -c dbset' commands (see next section), or may be created programatically by
ob_uspagent when it first runs (if no database file exists). To start with, use the latter option, as many parameters
in the factory reset database have boiler plate values.

To specify the data model parameters and values used to create the factory reset database, modify the 
code in vendor_factory_reset_example.c. You will need to modify the STOMP connection parameters and the USP EndpointID of
the controller to connect to.

Then to run OB-USP-AGENT with protocol trace, and full trace logging to stdout:
```
$ ob_uspagent -p -v 4
```

If OB-USP-AGENT successfully connected to your STOMP server you should see trace like the following on stdout:

```
   Attempting to connect to host=controller1 (port=61613, unencrypted) from interface=enp0s3
   Connected to 127.0.0.1 (host=controller1, port=61613) from interface=enp0s3
   Sending STOMP frame to (host=controller1, port=61613)
   STOMP
   accept-version:1.2
   host:/
   heart-beat:30000,300000
   endpoint-id:os\c\c002456-0800270B57FF
   login:my_username
   passcode:
   
   
   Received CONNECTED frame from (host=controller1, port=61613)
   CONNECTED
   session:session-1K6NehQnoR3hioRXZgFBBw
   heart-beat:300000,30000
   server:RabbitMQ/3.5.7
   version:1.2
   
   
   Sending SUBSCRIBE frame to (host=controller1, port=61613)
   SUBSCRIBE
   id:0
   destination:/queue/agent-q1
   ack:auto
```

If OB-USP-AGENT failed to connect, review the settings in your factory reset database and the STOMP server.
If you subsequently change the settings in vendor_factory_reset_example.c, then you must delete the database,
in order that the database is re-created the next time you run ob_uspagent.
To delete the database in the default location:
```
$ rm /tmp/usp.db
```

Alternatively you can use the 'ob_uspagent -c dbset' command (see next section) to alter parameters
in the database, and try again.

OB-USP_AGENT also supports an basic implementation of CoAP MTP. As with STOMP MTP, this is enabled
by setting data model parameters in the relevant CoAP MTP data model objects.


## OB-USP-AGENT Command Line Arguments
OB-USP-AGENT supports two modes, a daemon mode (seen above) and a command (or CLI) mode, which supports interactively
querying the data model and setting values in the database. The CLI mode is specified with the '-c' option.

* To see a list of arguments use:
```
$ ob_uspagent --help
```

* To see a list of commands supported in CLI mode use:
```
$ ob_uspagent -c help
```

* To see the currently implemented USP data model use:
```
$ ob_uspagent -c show datamodel
```

* To see all data model parameters stored in the database:
```
$ ob_uspagent -c show database
```

* To set the value of a data model parameter in the database use:
```
$ ob_uspagent -c dbset "parameter" "value"
```
IMPORTANT: This command must only be run when there is no daemon instance of OB-USP-AGENT running,
as it directly alters the value in the database without notifying a running daemon of the change.

* To set the value of a data model parameter when the daemon is running use:
```
$ ob_uspagent -c set "parameter" "value"
```

* To query the value of a parameter when the daemon is running use:
```
$ ob_uspagent -c get "parameter"
```

The "parameter" may contain USP search expressions and partial paths.
For example, to query the value of all parameters in the DeviceInfo object when the daemon is running use:
```
$ ob_uspagent -c get "Device.DeviceInfo."
```

The CLI mode also supports adding and deleting instances of data model objects and running USP commands.

## OB-USP-AGENT Source Tree
The /src directory contains the following sub-directories:
* core       - This implements the core functionality and data model of OB-USP-AGENT.
               Contributors will make code changes in this directory.

* vendor     - This contains code which is intended to be modified by an integrator.
               Integrators extend the data model and core functionality registering vendor hooks (callbacks).

* include    - This defines the publically accessible APIs exported to integrators (USP and VENDOR APIs).
               Contributors may make changes to files in this directory. Integrators must not.

* libjson    - This contains an open source Javascript Object Notation implementation.
               Neither contributors or integrators are likely to need to modify this code.

* protobuf-c - This contains pre-generated code implementing the USP record and USP message protobuf schemas.
               Contributors will only need to re-generate this code if the USP protobuf schema changes.


## OB-USP-AGENT APIs
Two APIs are of interest to an integrator. They are declared in the src/include directory.

* VENDOR API - An integrator must implement this API by modifying the stub functions in the src/vendor directory

* USP API - An integrator makes calls to this API to register the data model and notify OB-USP-AGENT core of changes

For information on the purpose and arguments of an API function, consult the function header comments
where the function is defined (typically src/core/usp_register.c or src/core/usp_api.c).


## OB-USP-AGENT Build Defines
The file src/vendor/vendor_defs.h contains feature switch defines and various other compile time defines.
The following defines are most likely to need modifying:


* DEFAULT_WAN_IFNAME - Name of the network interface to be used for USP communications.

* CONNECT_ONLY_OVER_WAN_INTERFACE - If defined only the network interface specified in DEFAULT_WAN_IFNAME is
                                    used for USP communications. If not defined, the Linux routing tables select
                                    which network interface to use.
                                    IMPORTANT: Even if not defined, DEFAULT_WAN_IFNAME must be a valid network interface.
                                    
* DEFAULT_DATABASE_FILE - The file system location of the database file, if none is specified
                          by the '-f' option when invoking OB-USP-AGENT.

* CLI_UNIX_DOMAIN_FILE - The file system location of a unix domain stream file used for communication
                         between OB-USP-AGENT running in CLI and daemon modes.

* VENDOR_OUI - The value of Device.DeviceInfo.ManufacturerOUI. This may be overridden by a value in the database.

* VENDOR_PRODUCT_CLASS - The value of Device.DeviceInfo.ProductClass
* VENDOR_MANUFACTURER - The value of Device.DeviceInfo.Manufacturer
* VENDOR_MODEL_NAME - The value of Device.DeviceInfo.ModelName


## Extending the Data Model
Use the USP_REGISTER_XXX() set of functions to register USP data model objects, parameters, cammands and Events.
* Integrators should always call USP_REGISTER_XXX() from VENDOR_Init() in src/vendor/vendor.c
* Contributors should create a new device_XXX.c file in src/core, and call USP_REGISTER_XX() from a 
  DEVICE_XXX_Init() located in the new device_XXX.c file.
  The new DEVICE_XXX_Init() must be hooked into the existing core data model from DATA_MODEL_Init() (in src/core/data_model.c).

Example (for Integrators):

```C
int VENDOR_Init(void)
{
    return USP_REGISTER_VendorParam_ReadOnly("Device.DeviceInfo.ModelNumber", GetModelNumber, DM_STRING);
}

int GetModelNumber(dm_req_t *req, char *buf, int len)
{
    strncpy(buf, "MyModelNumber", len);
    return USP_ERR_OK;
}
```

This example registers the Device.DeviceInfo.ModelNumber parameter.
The Get_ModelNumber() vendor hook function is called whenever OB-USP-AGENT core needs to get the value of the parameter.

The error codes to return are defined in src/include/usp_err_codes.h.
If an error occurs, call USP_ERR_SetMessage() to set an error message that will be returned by the USP protocol.

For more complex examples of extending the data model, see the DEVICE_XXX_Init() functions in the src/core/device_XXX.c files

IMPORTANT:
At bootup, the instance numbers of data model objects must be signalled to OB-USP-AGENT core using USP_DM_InformInstance().
* Integrators should call USP_DM_InformInstance() from VENDOR_Start() (in src/vendor/vendor.c).
* Contributors should call USP_DM_InformInstance() from a DEVICE_XXX_Start() function in their device_XXX.c file.

After bootup, changes to object instances should be signalled with the USP_SIGNAL_ObjectAdded() and 
USP_SIGNAL_ObjectDeleted() functions.

For an example of implementing a USP asynchronous command, see src/core/device_selftest_example.c.

USP data model events are registered by USP_REGISTER_Event() and USP_REGISTER_EventArguments().
They are signalled with USP_SIGNAL_DataModelEvent().
Use the USP_ARG_XXX() functions to create the event's argument list.


## Overriding the Core Implementation
The core implementation of OB-USP-AGENT has defaults for many aspects of functionality.
Some aspects have been designed to be overridden by the integrator using callbacks.
To override the default implementation, register a core vendor hook callback by calling
USP_REGISTER_CoreVendorHooks() from VENDOR_Init() (in src/vendor/vendor.c).

Example (for Integrators):

```C
int VENDOR_Init(void)
{
	vendor_hook_cb_t core_callbacks;
	memset(&core_callbacks, 0, sizeof(core_callbacks));
	core_callbacks.get_mtp_password_cb = GetStompPassword;
	return USP_REGISTER_CoreVendorHooks(&core_callbacks);
}

int GetStompPassword(char *buf, int len)
{
	strncpy(buf, "MyPassword", len);
	return USP_ERR_OK;
}
```

The example registers a callback to get the STOMP MTP password.
Other vendor hook callbacks may be registered by setting the relevant callback in the
core_callbacks structure, before calling USP_REGISTER_CoreVendorHooks().

The typedefs for each of the core vendor hook callbacks are declared in src/include/usp_api.h.

The following core vendor hooks are most likely to need overriding:
* reboot_cb - called by OB-USP-AGENT core to reboot the device after receiving a Device.Reboot() command
* factory_reset_cb - called by OB-USP-AGENT core to perform a factory reset after receiving a Device.FactoryReset() command
* get_trust_store_cb - called by OB-USP-AGENT core to get the list of SSL certificates to install in OB-USP-AGENT's trust store
* get_agent_cert_cb - called by OB-USP-AGENT core to get the SSL client certificate associated with this device

Certificates provided to the get_trust_store_cb() and get_agent_cert_cb() must be in DER (binary) form.









