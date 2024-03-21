FROM golang:1.22-alpine3.19

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /darkmode

EXPOSE 8080

ENV PORT="8080"

CMD ["/darkmode"]
