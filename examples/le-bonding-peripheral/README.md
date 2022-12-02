Bluetooth LE Bonding as a Peripheral Example

This example expands on the [le-peripheral] example by adding bonding and privacy support.
You will need some kind of test device such as the [nRF Connect] app to drive this example,
and both the central and peripheral devices must contain controllers with the LE features 
'encryption' and 'privacy'. Most Controllers that are capable of Bluetooth 4.2 or higher 
have these features.

The initial process of the example is very similar to 'le-peripheral'. The central device 
should scan and connect to the device with the advertised name "bonding test".

After both devices have connected, the central device should initiate pairing. Depending on
the test application this may be listed as 'pair', but it may also be listed as 'bond'
(for pairing and bonding). Pairing is done via the 'just works' process. All the initiator 
(the central device) needs to do is start pairing with this device, and pairing should run
to completion if nothing goes wrong during the handshaking (try running it again if it does 
fail). After pairing is completed the central device will need to initiate encryption.

Bonding will begin once encryption is established. In this example an Identity Resolving 
Key (IRK) and an identity address is distributed to the central device. It is expected that 
the central device sends its IRK to this device. If it does not then the example exit once
the central disconnects.

Once bonding is completed, instruct the central to disconnect. This peripheral will
begin direct advertising to the central using a resolvable private address (RPA) in 
both the advertiser's and targets address fields. Use the central to reconnect to 
this device.

#### Note
'Just works' means there is no man in the middle protection (MITM). Some third party 
device can act as a go-between for the two devices. Since there is no meaningful 
information in this example this doesn't matter, but it should be something you 
consider.

Both the IRK and identity address are randomly generated every time the example is run. 
This information is also not saved, once the example exits this information is lost. This
is not recommended and most real applications store the bonding information. Once this 
example exits, the bonding information on the central device should be deleted as it 
serves no purpose. 

[nRF Connect]: https://play.google.com/store/apps/details?id=no.nordicsemi.android.mcp&gl=us