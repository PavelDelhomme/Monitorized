# syntax=docker/dockerfile:1

FROM golang:1.22-alpine AS build
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /monitorized ./cmd/monitorized

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata wget \
  && addgroup -S monitorized && adduser -S monitorized -G monitorized
USER monitorized
WORKDIR /app
COPY --from=build /monitorized /app/monitorized
EXPOSE 8080
VOLUME ["/data"]
ENV MONITORIZED_ADDR=:8080 \
  MONITORIZED_DATA_DIR=/data
ENTRYPOINT ["/app/monitorized"]
