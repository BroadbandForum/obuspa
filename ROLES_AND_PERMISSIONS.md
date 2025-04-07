# OBUSPA Roles and Permissions
This document describes how to configure and use ControllerTrust roles and permissions to limit the data model access of USP Controllers.

## Roles

Each Controller has InheritedRole and AssignedRole parameters (in the [__Device.LocalAgent.Controller.{i}__](https://usp-data-models.broadband-forum.org/tr-181-2-18-1-usp.html#D.Device:2.Device.LocalAgent.Controller.) table).
The InheritedRole is determined from the message transfer protocol (MTP) connection between the Controller and OBUSPA and is read-only,
while the AssignedRole is writable (subject to permissions).

There is an entry for each role in the [__Device.LocalAgent.ControllerTrust.Role.{i}.__](https://usp-data-models.broadband-forum.org/tr-181-2-18-1-usp.html#D.Device:2.Device.LocalAgent.ControllerTrust.Role.) table.
Each role has a set of permissions associated with it.
The permissions that a Controller receives are the union of the permissions granted by the InheritedRole and AssignedRole
(i.e. the Controller has permission, if the permission is granted by either role).



### Default roles
_vendor_defs.h_ contains a number of defines relating to ControllerTrust roles:

* `ROLE_FULL_ACCESS` defines the instance number of the entry in the Role table
which is to be used to grant Controllers full access to the data model. On startup, OBUSPA will create this instance in the table
(configured with full access permissions), if the instance is not present in OBUSPA's database.

* `ROLE_UNTRUSTED` defines the instance number of the entry in the Role table
which is to be used by default to grant Controllers limited access to the data model. On Startup, OBUSPA will create this instance in the table
(configured with limited access permissions), if the instance is not present in OBUSPA's database.

NOTE: It is possible to modify the permissions for these roles by writing to the Role's Permission table.
For example, to slightly restrict full access.



### Inherited Role
The InheritedRole is determined from the MTP connection made with OBUSPA.

1. If the connection is over the Unix Domain Socket (UDS) MTP, then the InheritedRole is determined by the `ROLE_UDS` define in _vendor_defs.h_.

2. If the connection uses TLS, then the InheritedRole is determined by the role assigned to the OBUSPA trust store certificate
in the chain-of-trust with the Controller's certificate.
The role assigned to all trust store certificates loaded using the `obuspa -t` option is set by the 
`ROLE_TRUST_STORE_DEFAULT` define in _vendor_defs.h_.
OBUSPA supports assigning a different role to each certificate in the trust store if the certificates are loaded
using the `get_trust_store_cb_t` vendor hook.

3. If the connection does not use TLS then then the InheritedRole is determined by the `ROLE_NON_SSL` define in _vendor_defs.h_.

4. In the rare case of none of the above applying, the InheritedRole is determined by the `ROLE_DEFAULT` define in _vendor_defs.h_.

The default values for the roles in _vendor_defs.h_ have been selected to allow everything to work. i.e. permissive.
In a real deployment, it would be usual to set the defines to more restrictive roles, and then use AssignedRole to override the
permissions on a per-controller basis.

For example, when using OBUSPA as a USP Broker, define `ROLE_UDS` as `ROLE_UNTRUSTED`, to ensure that containerized Apps
connecting to OBUSPA default to restricted permissions. Then for each trusted internal USP Service, create an entry in the
[__Device.LocalAgent.Controller.{i}__](https://usp-data-models.broadband-forum.org/tr-181-2-18-1-usp.html#D.Device:2.Device.LocalAgent.Controller.)
table in the factory reset file, setting the AssignedRole parameter to the full access role.
When installing containerized Apps, add an entry in the 
[__Device.LocalAgent.Controller.{i}__](https://usp-data-models.broadband-forum.org/tr-181-2-18-1-usp.html#D.Device:2.Device.LocalAgent.Controller.)
table for the App setting its
AssignedRole.



## Permissions

Each role has a set of permissions granted to it. The permissions are configured using parameters in the 
[__Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.__](https://usp-data-models.broadband-forum.org/tr-181-2-18-1-usp.html#D.Device:2.Device.LocalAgent.ControllerTrust.Role.Permission.) table.

The following parameters are of particular interest:

* _Order_ - The permissions are configured in an ordered list. Permissions with a higher value for Order override
permissions with a lower value for Order.

* _Targets_ - Specifies the data model path to which the permissions apply. This may be the partial path to an object or a full path
to a parameter, USP command or USP event. The path may contain wildcards or instance numbers. Search expressions are not
currently supported. If a partial path is supplied, the permissions apply to the object and recursively all data model
elements underneath the object in the instantiated data model. _Targets_ may specify multiple paths using a comma to separate each path.

* _Param_, _Obj_, _InstantiatedObj_ and _CommandEvent_ - Specifies the permission bits associated with the data model elements selected 
by the _Targets_ parameter. The value of each of these parameters is a string of 4 characters where each character represents a 
permission bit (`r` for Read, `w` for Write, `x` for Execute, `n` for Notify). The string is always in the same order (`rwxn`) 
and the lack of a permission is signified by a `-` character (e.g., `r--n`). See 
[TR-181](https://usp-data-models.broadband-forum.org/tr-181-2-18-1-usp.html#D.Device:2.Device.LocalAgent.ControllerTrust.Role.Permission.)
for the meaning of the permission bits in each parameter.


IMPORTANT: You must configure all of the permission bits in the _Param_, _Obj_, _InstantiatedObj_ and _CommandEvent_ parameters.
Leaving a parameter unset, or a permission bit set to `-` means that the associated permission is denied.
It is not possible to specify which of the permission bits override those specified by lower order permissions - all of the permission
bits are applied and override all lower order permission bits with either a granted or prohibited designation for the specified _Targets_.


### Examples

#### Preventing a parameter from being read or written (blacklisting)

| Order | Targets                                   | Param | Obj  | InstantiatedObj | CommandEvent |
|-------|-------------------------------------------|-------|------|-----------------|--------------|
|   1   | Device.                                   | rwxn  | rwxn | rwxn            | rwxn         |
|   2   | Device.WiFi.Radio.*.Status                | --xn  | rwxn | rwxn            | rwxn         |


#### Preventing an object from being accessed (blacklisting)

| Order | Targets                                   | Param | Obj  | InstantiatedObj | CommandEvent |
|-------|-------------------------------------------|-------|------|-----------------|--------------|
|   1   | Device.                                   | rwxn  | rwxn | rwxn            | rwxn         |
|   2   | Device.WiFi.Radio.                        | ----  | ---- | ----            | ----         |


#### Preventing an instance from being accessed (blacklisting)

| Order | Targets                                   | Param | Obj  | InstantiatedObj | CommandEvent |
|-------|-------------------------------------------|-------|------|-----------------|--------------|
|   1   | Device.                                   | rwxn  | rwxn | rwxn            | rwxn         |
|   2   | Device.WiFi.Radio.1.                      | ----  | ---- | ----            | ----         |


#### Allowing an instance to be accessed (whitelisting)

| Order | Targets                                   | Param | Obj  | InstantiatedObj | CommandEvent |
|-------|-------------------------------------------|-------|------|-----------------|--------------|
|   1   | Device.WiFi.Radio.                        | ----  | ---- | ----            | ----         |
|   2   | Device.WiFi.Radio.1.                      | rwxn  | rwxn | rwxn            | rwxn         |

#### Preventing a USP command from being invoked (blacklisting)

| Order | Targets                                   | Param | Obj  | InstantiatedObj | CommandEvent |
|-------|-------------------------------------------|-------|------|-----------------|--------------|
|   1   | Device.                                   | rwxn  | rwxn | rwxn            | rwxn         |
|   2   | Device.Reboot()                           | rwxn  | rwxn | rwxn            | rw-n         |


NOTE: For the sake of clarity in these examples, certain permission bits which are 'don't care' have been set to a value
which emphasizes the permission bit that is important in the example.

