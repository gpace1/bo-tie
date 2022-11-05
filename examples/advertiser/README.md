Bluetooth LE Advertiser

This is an example of an undirected non-connectible advertising Bluetooth device. Once executed
it will initialize the Bluetooth Controller to use legacy advertising with the device name 
"Adv Test". This example runs until it is killed.

## Runnable Environments
This example can be run on a linux machine.

### Linux
The example can be run with a Bluetooth Controller that can transmit LE PDUs. Change
your path directory of `bo-tie` and exec the commands `cargo build -p le-peripheral && sudo
./target/debug/le-peripheral` to run this on linux.

Exiting the example can be done at any time by sending a `SIGINT` (which can be done by pressing
the keys *ctrl* + *c* at the same time) or having the client disconnect this device.

[nRF Connect]: https://play.google.com/store/apps/details?id=no.nordicsemi.android.mcp&gl=us