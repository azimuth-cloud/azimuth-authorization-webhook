FROM golang:1.24 AS build-stage

WORKDIR /app

COPY src/go.mod src/go.sum ./
RUN go mod download

COPY src/*.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /azimuth-authorization-webhook

FROM gcr.io/distroless/base-debian11 AS build-release-stage

WORKDIR /

COPY --from=build-stage /azimuth-authorization-webhook /azimuth-authorization-webhook

EXPOSE 8080

ENTRYPOINT ["/azimuth-authorization-webhook"]
