Bluetooth LE Peripheral Example

This is an example of a connectible LE device in the peripheral role. It begins by starting
legacy LE advertising as a connectible Bluetooth device. Using something like [nRF Connect] you
can scan for a device advertising with the name "Connection Test" and (assuming there is no one
else running this example or trying to spoof it) connect to this example. Once connected, the
client (if not already done so) can perform a GATT query for the services. However, this example
only has the minimum requirements for a GATT server and so only has the GAP service.

This example uses a new random address and advertises with connectible and scannable
undirected advertising everytime it is run. This means that clients will always need to re-scan
for this example after it has disconnected. Reconnecting is beyond the scope of this example, 
for an examples that can reconnect see [le-bonding-peripheral].

## Runnable Environments
This example can be run on a linux machine.

### Linux
The example can be run with a Bluetooth Controller that can transmit and receive LE PDUs. Change
your path directory of `bo-tie` and exec the commands `cargo build -p le-peripheral && sudo
./target/debug/le-peripheral` to run this on linux.

Exiting the example can be done at any time by sending a `SIGINT` (which can be done by pressing
the keys *ctrl* + *c* at the same time) or having the client disconnect this device.

[nRF Connect]: https://play.google.com/store/apps/details?id=no.nordicsemi.android.mcp&gl=us
[le-bonding-peripheral]: ../le-bonding-peripheral