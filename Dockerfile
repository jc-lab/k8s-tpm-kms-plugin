FROM golang:1.22-alpine3.20 as builder

RUN mkdir -p /build/
COPY . /build/

RUN cd /build/ && \
    ls -al && \
    CGO_ENABLED=0 go build -o /build/k8s-tpm-kms-plugin ./cmd/k8s-tpm-kms-plugin

FROM alpine:3.20
COPY --from=builder /build/k8s-tpm-kms-plugin /k8s-tpm-kms-plugin

# VOLUME /var/lib/k8s-tpm-kms-plugin
# DEVICE /dev/tpmrm0

CMD /k8s-tpm-kms-plugin
