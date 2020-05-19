FROM ubuntu:18.04 as build

RUN mkdir -p /modsec/libs

COPY modsec/libmodsecurity-wrapper.so /modsec/libs/
COPY modsec/libmodsecurity.so /modsec/libs/
COPY modsec/libmodsecurity.so.3 /modsec/libs/
COPY modsec/libmodsecurity.so.3.0.4 /modsec/libs/
COPY modsec/libpcre.so /modsec/libs/
COPY modsec/libpcre.so /modsec/libs/libpcre.so.3
COPY config /modsec/config
COPY collector-config.yaml /modsec/config

FROM gcr.io/distroless/cc-debian10
COPY --from=build ./modsec/libs /libs
COPY --from=build ./modsec/config /config
ENV LD_LIBRARY_PATH /libs
COPY occollector_modsec_linux /
CMD ["/occollector_modsec_linux", "--config", "/config/collector-config.yaml"]