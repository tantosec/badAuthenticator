FROM golang:1.26.11-alpine3.24@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /badauthenticator ./cmd/badauthenticator

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

RUN addgroup -S badauthenticator && \
    adduser -S badauthenticator -G badauthenticator && \
    mkdir -p /data /public && \
    chown -R badauthenticator:badauthenticator /data

COPY --from=build /badauthenticator /badauthenticator
COPY public/ /public/
COPY LICENSE THIRD-PARTY-NOTICES.md /

WORKDIR /data
USER badauthenticator

EXPOSE 8080
ENTRYPOINT ["/badauthenticator"]
CMD ["--help"]
