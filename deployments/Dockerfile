FROM ubuntu:18.04 as build

RUN mkdir -p /modsec/libs

COPY artifacts/modsec/libmodsecurity-wrapper.so /modsec/libs/
COPY artifacts/modsec/libmodsecurity.so /modsec/libs/
COPY artifacts/modsec/libmodsecurity.so.3 /modsec/libs/
COPY artifacts/modsec/libmodsecurity.so.3.0.4 /modsec/libs/
COPY artifacts/modsec/libpcre.so /modsec/libs/
COPY artifacts/modsec/libpcre.so /modsec/libs/libpcre.so.3
COPY artifacts/config /modsec/config
COPY collector-config.yaml /modsec/config

FROM gcr.io/distroless/cc-debian10
COPY --from=build ./modsec/libs /libs
COPY --from=build ./modsec/config /
ENV LD_LIBRARY_PATH /libs
# https://blog.detectify.com/2019/09/05/how-we-tracked-down-a-memory-leak-in-one-of-our-go-microservices/
ENV GODEBUG madvdontneed=1
COPY artifacts/occollector_modsec_linux /occollector_linux
CMD ["/occollector_linux", "--config", "/config/collector-config.yaml"]