# Start from golang v1.12.5 base image
FROM golang:alpine as builder

# Add Maintainer Info
LABEL maintainer="Yogesh Kulkarni <yrkulkarni@live.com>"

ARG currDir=$GOPATH/src/github.com/codeyrk/pkt-demo

# Set the Current Working Directory inside the container
WORKDIR ${currDir}

COPY test-live test-live
COPY load-db load-db

#RUN apt-get update && apt-get install git && apt-get install -y libpcap-dev
RUN apk update && apk add git
RUN apk add build-base
RUN apk add libpcap-dev

WORKDIR ${currDir}/test-live

RUN go mod tidy
RUN go mod verify

## Build the Go app
RUN GOOS=linux GOARCH=amd64 go build -ldflags "-linkmode external -extldflags -static" -o /go/bin/test-live
#RUN GOOS=linux go build -a -installsuffix cgo -o /go/bin/test_live .

WORKDIR ${currDir}/load-db

RUN go mod tidy
RUN go mod verify

## Build the load db go app
RUN GOOS=linux GOARCH=amd64 go build -ldflags "-linkmode external -extldflags -static" -o /go/bin/load-db
#RUN GOOS=linux go build -a -installsuffix cgo -o /go/bin/load_db .

######## Start a new stage from scratch #######
FROM openjdk:8-jdk-alpine

RUN apk --no-cache add ca-certificates
#RUN apk add libpcap-dev
RUN  apk add tshark==2.6.8-r0
RUN apk add bash

WORKDIR /var/src/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /go/bin/test-live test-live/
COPY test_live/conf.json test-live/
RUN chmod +x test-live/test-live
COPY --from=builder /go/bin/load-db load-db/
RUN chmod +x load-db/load-db
COPY java java/
COPY start.sh .

VOLUME /var/data/

CMD ./start.sh