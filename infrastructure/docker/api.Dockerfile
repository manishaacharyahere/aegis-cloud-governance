# syntax=docker/dockerfile:1
# Multi-stage build: static Go binary on a distroless, non-root base image.

FROM golang:1.27.4-alpine3.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/aegis-api ./cmd/aegis-api

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/aegis-api /aegis-api
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/aegis-api"]
