# syntax=docker/dockerfile:1

FROM rust as build-stage

ENV BLUEZ="/bluez"
ENV BINDINGS="/bindings"

RUN apt-get update && \
    apt-get install --yes --no-install-recommends  \
    gcc  \
    libc-dev  \
    llvm-dev  \
    libclang-dev  \
    clang  \
    ca-certificates  \
    git

RUN rustup component add rustfmt

RUN mkdir -p $BLUEZ $BINDINGS $CARGO_HOME $RUSTUP_HOME

RUN cd $BLUEZ && \
    git clone --no-checkout https://github.com/bluez/bluez.git . && \
    git sparse-checkout init --cone && \
    git sparse-checkout set lib && \
    git fetch --tags && \
    git checkout $(git describe --tags $(git rev-list --tags --max-count=1)) && \
    cd

RUN cargo install bindgen-cli

RUN echo "#include \"$BLUEZ/lib/bluetooth.h\"" > "$BINDINGS/bindings.h"
RUN echo "#include \"$BLUEZ/lib/hci.h\"" >> "$BINDINGS/bindings.h"
RUN echo "#include \"$BLUEZ/lib/mgmt.h\"" >> "$BINDINGS/bindings.h"

RUN $CARGO_HOME/bin/bindgen $BINDINGS/bindings.h \
    --allowlist-type hci_dev_list_req \
    --allowlist-type hci_dev_info \
    --allowlist-type sockaddr_hci \
    --allowlist-var HCI_VIRTUAL \
    --allowlist-var HCI_USB \
    --allowlist-var HCI_PCCARD \
    --allowlist-var HCI_UART \
    --allowlist-var HCI_RS232 \
    --allowlist-var HCI_PCI \
    --allowlist-var HCI_SDIO \
    --allowlist-var HCI_SPI \
    --allowlist-var HCI_I2C \
    --allowlist-var HCI_SMD \
    --allowlist-var HCI_VIRTIO \
    --allowlist-var HCI_UP \
    --allowlist-var HCI_RAW \
    --allowlist-var HCIDEVUP \
    --allowlist-var HCIDEVDOWN \
    --allowlist-var HCIGETDEVLIST \
    --allowlist-var HCIGETDEVINFO \
    --allowlist-var HCI_COMMAND_PKT \
    --allowlist-var HCI_ACLDATA_PKT \
    --allowlist-var HCI_SCODATA_PKT \
    --allowlist-var HCI_EVENT_PKT \
    --allowlist-var HCI_ISODATA_PKT \
    --allowlist-var HCI_VENDOR_PKT \
    --allowlist-var HCI_DEV_NONE \
    --allowlist-var HCI_CHANNEL_RAW \
    --allowlist-var HCI_CHANNEL_USER \
    --allowlist-var HCI_CHANNEL_CONTROL \
    --allowlist-var BTPROTO_HCI \
    --allowlist-var MGMT_INDEX_NONE \
    --allowlist-var ^\(MGMT_STATUS_.*\)\$ \
    --allowlist-var ^\(MGMT_OP_.*\)\$ \
    --allowlist-var ^\(MGMT_EV_.*\)\$ \
    --allowlist-type mgmt_hdr \
    --allowlist-type mgmt_rp_read_version \
    --allowlist-type mgmt_rp_read_commands \
    --allowlist-type mgmt_rp_read_index_list \
    --allowlist-type mgmt_rp_read_info \
    --allowlist-type mgmt_rp_read_config_info \
    --allowlist-type mgmt_cp_set_external_config \
    --allowlist-type mgmt_cp_set_public_address \
    --allowlist-type mgmt_rp_read_ext_index_list \
    --allowlist-type mgmt_ev_cmd_complete \
    --allowlist-type mgmt_ev_cmd_status \
    -o $BINDINGS/bindings.rs

RUN rustfmt $BINDINGS/bindings.rs

FROM scratch as export-stage

COPY --from=build-stage "/bindings" /