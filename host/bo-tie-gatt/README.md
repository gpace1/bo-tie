Generic Attribute Protocol

GATT is a thin wrapper protocol above the attribute (ATT) protocol.

The GATT is mainly a data organization protocol used to help clients to identify what is on
the other device's attribute server. GATT organizes data into groups under a 'service'. Data
within a service is organized into 'characteristic' which contain 'characteristic descriptors'
that further provide meta explanation of the data. Each of these require attributes, so
individual data will use multiple attribute handles in order to contain all the GATT information
associated with it. However, all this GATT information provides a standard way for the
Bluetooth SIG to assign services to provide common data formats.

## GATT server
Building a GATT server is simple as creating the GAP service (mandatory for unless you're a 
server out of specification) and creating a server builder from it.

```rust
 use bo_tie_att::FULL_READ_PERMISSIONS;
 use bo_tie_att::server::NoQueuedWrites;
 use bo_tie_gatt::{GapServiceBuilder, ServerBuilder};
 use bo_tie_gatt::characteristic::{ClientConfiguration, Properties};

 let gap_service = GapServiceBuilder::new("My Device", None);

 let mut server_builder = ServerBuilder::from(gap_service);

 // Adding battery service (that always reports 70%)
 server_builder.new_service(0x190Fu16)
    .add_characteristics()
    .new_characteristic(|characteristic_builder| {
        characteristic_builder
            .set_declaration(|declaration_builder|{
                declaration_builder
                    .set_properties([Properties::Read])
                    .set_uuid(0x2A19u16)
            })
            .set_value(|value_builder| {
                value_builder
                    .set_value(70u8)
                    .set_permissions(FULL_READ_PERMISSIONS)
            })
    })
    .finish_service();

 let server = server_builder.make_server(NoQueuedWrites);
```

## GATT Client
This is not implemented yet