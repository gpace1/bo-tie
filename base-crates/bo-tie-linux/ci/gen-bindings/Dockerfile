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

RUN $CARGO_HOME/bin/bindgen $BINDINGS/bindings.h \
    --allowlist-type hci_dev_list_req \
    --allowlist-type hci_dev_info \
    --allowlist-type sockaddr_hci \
    --allowlist-var HCIDEVUP \
    --allowlist-var HCIDEVDOWN \
    --allowlist-var HCIGETDEVLIST \
    --allowlist-var HCIGETDEVINFO \
    --allowlist-var HCI_DEV_NONE \
    --allowlist-var HCI_CHANNEL_RAW \
    --allowlist-var HCI_CHANNEL_USER \
    --allowlist-var BTPROTO_HCI \
    -o $BINDINGS/bindings.rs

RUN rustfmt $BINDINGS/bindings.rs

FROM scratch as export-stage

COPY --from=build-stage "/bindings" /