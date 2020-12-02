FROM ubuntu:18.04 as build

RUN mkdir -p /modsec/libs

COPY artifacts/modsec/libmodsecurity-wrapper.so /modsec/libs/
COPY artifacts/config /modsec/config
COPY collector-config.yaml /modsec/config

FROM gcr.io/distroless/cc-debian10
COPY --from=build ./modsec/libs /libs
COPY --from=build ./modsec/config /
ENV LD_LIBRARY_PATH /libs
COPY artifacts/occollector_modsec_linux /occollector_linux
CMD ["/occollector_linux", "--config", "/config/collector-config.yaml"]