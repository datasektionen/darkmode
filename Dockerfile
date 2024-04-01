FROM golang:1.22-alpine3.19

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY *.go ./
COPY templates/ templates/
COPY static/ static/

RUN --mount=type=cache,target=/root/.cache/go-build/ \
    CGO_ENABLED=0 GOOS=linux go build -o /darkmode

CMD ["/darkmode"]
