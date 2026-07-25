//go:build !linux

package capture

import (
	"errors"
	"fmt"
	"runtime"
)

// ErrLiveUnsupported is returned when live capture is requested on a platform
// where the pure-Go AF_PACKET path is unavailable.
var ErrLiveUnsupported = errors.New("capture: live capture requires Linux")

// OpenLive is unavailable off Linux.
//
// Rather than pull in libpcap/Npcap and a cgo dependency for every platform in
// order to support development machines, tracehound keeps live capture on the
// platform it deploys to and gives everyone else PCAP replay — which is a
// better development workflow anyway, since it is reproducible.
func OpenLive(iface string, promiscuous bool) (Source, error) {
	return nil, fmt.Errorf("%w (this binary is %s/%s); replay a capture file instead: tracehound replay <file.pcap>",
		ErrLiveUnsupported, runtime.GOOS, runtime.GOARCH)
}
