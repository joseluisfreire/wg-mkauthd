BINARY   = wg-mkauthd
VERSION  = $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  = -s -w -X main.Version=$(VERSION)
GOFLAGS  = CGO_ENABLED=0 GOOS=linux GOARCH=amd64

.PHONY: all build clean

all: build

build:
$(GOFLAGS) go build -ldflags "$(LDFLAGS)" -trimpath -o $(BINARY) .

clean:
rm -f $(BINARY)
