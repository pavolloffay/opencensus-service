FROM alpine:latest as certs
RUN apk --update add ca-certificates

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY occollector_linux /
COPY collector-config.yaml /
ENTRYPOINT ["/occollector_linux"]
EXPOSE 9411
EXPOSE 14267
EXPOSE 14268
EXPOSE 55678
