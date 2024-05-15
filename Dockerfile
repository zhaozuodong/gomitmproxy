FROM golang:1.20-buster as base

WORKDIR /go/src/gomitmproxy

COPY . .
RUN export GOPROXY=https://goproxy.io,direct
RUN go mod tidy
RUN go build -o gomitmproxy cmd/main.go


FROM golang:1.20-buster
WORKDIR /go/src/gomitmproxy
COPY --from=base /go/src/gomitmproxy/gomitmproxy .
COPY cert cert
RUN mkdir -p ~/.config/gomitmproxy/ && cp -r cert/* ~/.config/gomitmproxy/
CMD [ "sleep", "3600" ]