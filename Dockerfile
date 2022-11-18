FROM docker.io/library/alpine:3.16.2 as certs
RUN apk add --update --no-cache ca-certificates

FROM scratch
COPY --from=aquasec/trivy:0.34.0 /usr/local/bin/trivy /bin/trivy
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/bin/trivy-gh"]
COPY trivy-gh /bin/trivy-gh
WORKDIR /workdir
