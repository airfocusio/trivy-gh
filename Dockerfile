FROM aquasec/trivy:0.34.0 as trivy

FROM docker.io/library/alpine:3.16.2 as certs
RUN apk add --update --no-cache ca-certificates

FROM docker.io/library/alpine:3.16.2 as tmp

FROM scratch
COPY --from=trivy /usr/local/bin/trivy /bin/trivy
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=tmp /tmp /tmp
ENTRYPOINT ["/bin/trivy-gh"]
COPY trivy-gh /bin/trivy-gh
WORKDIR /workdir
