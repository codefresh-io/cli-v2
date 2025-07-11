FROM golang:1.24.4-alpine3.22 AS base

WORKDIR /go/src/github.com/codefresh-io/cli-v2

RUN apk -U add --no-cache git ca-certificates && update-ca-certificates

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/home/codefresh" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid 10001 \
    codefresh

RUN --mount=type=secret,id=GITHUB_TOKEN \
    GITHUB_TOKEN=$(cat /run/secrets/GITHUB_TOKEN) \
    git config \
    --global \
    url."https://github:${GITHUB_TOKEN}@github.com".insteadOf \
    "https://github.com"
COPY go.mod .
COPY go.sum .

RUN go mod download -x
RUN go mod verify

############################### CLI ###############################
### Compile
FROM golang:1.24.4-alpine3.22 AS codefresh-build

WORKDIR /go/src/github.com/codefresh-io/cli-v2

RUN apk -U add --no-cache git make bash

COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=base /go/pkg/mod /go/pkg/mod

COPY . .

ENV GOPATH=/go
ENV GOBIN=/go/bin

ARG SEGMENT_WRITE_KEY
RUN make local DEV_MODE=false SEGMENT_WRITE_KEY=${SEGMENT_WRITE_KEY}

### Run
FROM alpine:3.22 AS codefresh

WORKDIR /go/src/github.com/codefresh-io/cli-v2

RUN apk -U add --no-cache git

# copy ca-certs and user details
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=base /etc/passwd /etc/passwd
COPY --from=base /etc/group /etc/group
COPY --chown=codefresh:codefresh --from=codefresh-build /go/src/github.com/codefresh-io/cli-v2/dist/* /usr/local/bin/cf

USER codefresh:codefresh

ENTRYPOINT [ "cf" ]
