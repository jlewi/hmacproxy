# syntax=docker/dockerfile:1.4
# TODO(https://github.com/chainguard-images/go/issues/26) issue with golang's static image
ARG BUILD_IMAGE=golang:1.19
#ARG RUNTIME_IMAGE=cgr.dev/chainguard/static:latest
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian11
FROM ${BUILD_IMAGE} as build

COPY . /work/
WORKDIR /work/

# N.B. since we are using static runtime images we must disable CGO
RUN CGO_ENABLED=0 go build -o /work/hmacproxy github.com/jlewi/hmacproxy


FROM ${RUNTIME_IMAGE}

COPY --from=build /work/hmacproxy /hmacproxy
CMD ["/hmacproxy"]