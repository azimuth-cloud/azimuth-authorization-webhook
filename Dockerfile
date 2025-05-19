FROM golang:1.24

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o ./azimuth-authorization-webhook

EXPOSE 8080

CMD [./azimuth-authorization-webhook]
