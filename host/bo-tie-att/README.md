The Attribute Protocol

The Attribute Protocol (ATT) is used to expose the attributes of a device through Bluetooth. The
protocol does this though a client-server relationship between two devices. The server contains
the attributes that can be read or modified by the client.

Unsurprisingly this library has [Server] and [Client] as implementations for the server and
client of the Attribute protocol.

# Attribute Protocol Permissions
When an attribute is created it is given permissions to *to determine* access of if by a
client. Permission are *labels for access* to operations, of barriers granting entry for the
client. No permission has any relation with any other permission, and no permission is
inherently given to an attribute or the user by another permission. It is the operations of the
Attribute Protocol or a higher layer protocol that determine what permissions are required to
perform said operation.

Attributes can only be written to or read from. Permissions restrict reads and writes for
attribute protocol operations performed under open access, encryption, authentication, and
authorization. Different operations require different restrictions, but most of the implemented
Attribute Protocol operations check the permissions of an attribute before performing the
operation. Most of these operations require that the attribute either be at least readable or
writeable, but will check if those reads or writes also require either encryption,
authentication, or authorization.

Attribute permissions do not posses hierarchy or hereditary characteristics between one another.
This can lead to seeming odd cases where it would seem that because an attribute was given
a permissions it should have another, but the server will report an access error. If an
attribute was only given the permission `Read(None)`, the server will only read the attribute to
the client when the server grants the client the same permission. If the client had any other
permissions except for `Read(None)`, such as `Read(Encryption(Bits128))`, the server would not
read the attribute and would instead return an error to the client.

## Client Granted Permissions
The server matches the required permissions of an operation against the permissions of the
client. The server does not determine the permissions of the client, this is done by 'giving'
permission to the client through either your application or some higher layer protocol. When a
client requests an operation to be performed for specified attributes, the server will check the
permissions of the attribute and the permissions of the client. The client will need the
permissions required by the operation matched against the permissions of the attribute(s). If a
permission check fails, then the server will return an error giving the reason for the failure.

Operations will generally check a number of permissions (usually every type of Read or Write)
against the permissions of the requested attribute and those given to the client. If any of the
permissions to check for are in both the attribute and client, the operation is successfully
performed for the client.

## Permission Errors
If an operation cannot be performed because the client does not have the permission to access
an attribute, an error is returned to the client describing the permission problem. However,
it is often the case there are multiple types of permissions that a client can have to access
the attribute, but only one of the errors can be described with the error PDU sent from the
server to the client.