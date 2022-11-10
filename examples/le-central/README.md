Bluetooth LE Central Example

This is an example of a connectible LE device in the central role. It begins by starting LE
scanning for other Bluetooth device advertising with a local name. Everytime a device is found
the example will output the name to the terminal. Using something like [nRF Connect] you
can create a connectible advertising device, but make sure to add the local name to the 
advertising data. Scanning will stop by pressing the escape key, and you'll be prompted to
enter the number of the device to try to connect to. Once connected, the example client will 
attempt to scan for and output to the terminal the GATT services on the device. The example
will then continue to run until the user exits the process with `ctrl-c`.

## Runnable Environments
This example can be run on a linux machine.

### Linux
The example can be run with a Bluetooth Controller that can transmit and receive LE PDUs. Change
your path directory of `bo-tie` and exec the commands `cargo build -p le-central && sudo
./target/debug/le-peripheral` to run this on linux.

Exiting the example can be done at any time by sending a `SIGINT` (which can be done by pressing
the keys *ctrl* + *c* at the same time) or having the peripheral disconnect this device.

[nRF Connect]: https://play.google.com/store/apps/details?id=no.nordicsemi.android.mcp&gl=us