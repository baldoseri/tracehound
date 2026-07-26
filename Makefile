# tracehound
#
# Everything here is a thin wrapper over the go tool. There is no code
# generation step, no bundler, and no npm: `go build ./cmd/tracehound` is a
# complete build, and this file exists for convenience rather than necessity.

BINARY  := tracehound
PKG     := github.com/baldoseri/tracehound
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# CGO is off everywhere. Capture uses pure-Go AF_PACKET rather than libpcap, so
# the result is a static binary that runs in a scratch container.
export CGO_ENABLED := 0

GO      ?= go
DEMO    := testdata/demo.pcap

.DEFAULT_GOAL := help

## help: list targets
help:
	@echo "tracehound $(VERSION)"
	@echo
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  make /'

## build: compile the binary into bin/
build:
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/$(BINARY)

## demo: generate the synthetic capture and analyse it
demo: build $(DEMO)
	./bin/$(BINARY) replay $(DEMO)

## dashboard: replay the demo at 120x into the live web UI
dashboard: build $(DEMO)
	./bin/$(BINARY) replay $(DEMO) -listen :8080 -speed 120

$(DEMO): build
	./bin/$(BINARY) gen-demo $(DEMO)

## demo-gif: re-render the README animation from live output
##
## The GIF is generated rather than screen-recorded so it cannot drift out of
## date: this re-runs the sensor and redraws whatever it actually printed.
demo-gif: build $(DEMO)
	cd tools/gifgen && go run . \
		-bin ../../bin/$(BINARY) \
		-pcap ../../$(DEMO) \
		-o ../../docs/demo.gif

## readme-samples: regenerate the README's output blocks from the program
##
## The samples are generated for the same reason the GIF is: a hand-written
## sample is a claim about the program that nothing checks, and this one was
## wrong for the entire life of the repo. CI runs this and fails on any diff.
readme-samples: build $(DEMO)
	$(GO) run ./tools/readmegen -bin ./bin/$(BINARY) -pcap $(DEMO)

## test: run the full suite
test:
	$(GO) test ./... -count=1

## race: run the suite under the race detector (needs cgo, hence the override)
race:
	CGO_ENABLED=1 $(GO) test ./... -count=1 -race

## cover: write and summarise a coverage profile
cover:
	$(GO) test ./... -count=1 -coverprofile=coverage.out
	$(GO) tool cover -func=coverage.out | tail -n 1
	@echo "html report: go tool cover -html=coverage.out"

## bench: run benchmarks with allocation counts
bench:
	$(GO) test ./... -run '^$$' -bench . -benchmem

## fuzz: fuzz every parser that reads untrusted input, 60s each
fuzz:
	$(GO) test ./internal/fingerprint -run '^$$' -fuzz FuzzParseClientHello -fuzztime 60s
	$(GO) test ./internal/fingerprint -run '^$$' -fuzz FuzzParseServerHello -fuzztime 60s
	$(GO) test ./internal/quic -run '^$$' -fuzz FuzzParseInitial -fuzztime 60s
	$(GO) test ./internal/quic -run '^$$' -fuzz FuzzParseFrames -fuzztime 60s

## vet: run go vet and check formatting
vet:
	$(GO) vet ./...
	@test -z "$$(gofmt -l . )" || { echo "gofmt needed:"; gofmt -l .; exit 1; }

## check: vet, test, and build — what CI runs
check: vet test build

## cross: build for every supported target
cross:
	@for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
		os=$${t%/*}; arch=$${t#*/}; ext=""; \
		[ "$$os" = "windows" ] && ext=".exe"; \
		echo "  $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
			-o bin/$(BINARY)-$$os-$$arch$$ext ./cmd/$(BINARY) || exit 1; \
	done

## docker: build the container image
docker:
	docker build -t $(BINARY):$(VERSION) -t $(BINARY):latest .

## clean: remove build output
clean:
	rm -rf bin coverage.out $(DEMO)

.PHONY: help build demo demo-gif dashboard readme-samples test race cover bench fuzz vet check cross docker clean
