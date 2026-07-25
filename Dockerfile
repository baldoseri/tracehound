# tracehound container image.
#
# The final stage is scratch. That is possible only because the whole program is
# pure Go with CGO disabled — capture uses AF_PACKET directly instead of
# libpcap, and the dashboard is embedded in the binary with go:embed rather than
# served from a directory. The result is an image with no shell, no package
# manager, and no libc: nothing an attacker who reaches it can pivot through.

# --- build ------------------------------------------------------------------
FROM golang:1.26-alpine AS build

WORKDIR /src

# Dependencies first so the module cache survives source edits.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/tracehound ./cmd/tracehound

# Generate the demo capture at build time rather than committing a megabyte of
# binary to git. It is deterministic, so the image is reproducible.
RUN /out/tracehound gen-demo /out/demo.pcap

# Run the tests inside the image build. A container that ships is a container
# whose tests passed on the same toolchain that produced it.
RUN go test ./... -count=1

# --- runtime ----------------------------------------------------------------
FROM scratch

COPY --from=build /out/tracehound /tracehound
COPY --from=build /out/demo.pcap /demo.pcap

# Live capture needs CAP_NET_RAW. Grant it narrowly:
#   docker run --cap-add=NET_RAW --net=host tracehound sniff -i eth0
# Replay needs no privileges at all.
EXPOSE 8080

ENTRYPOINT ["/tracehound"]
CMD ["replay", "/demo.pcap", "-listen", ":8080", "-speed", "120"]
