package wireguard

import (
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
)

// LivenessSource decides whether a peer's downstream routes (spec.routes /
// spec.routesV6) should currently be installed. A nil source means "all peers
// live" — i.e. disabled mode, byte-identical to the pre-feature behavior.
type LivenessSource interface {
	IsLive(publicKey string) bool
}

// isLive is the nil-safe accessor used by the route filters.
func isLive(src LivenessSource, publicKey string) bool {
	if src == nil {
		return true
	}
	return src.IsLive(publicKey)
}

// Mode selects the LivenessSource implementation.
type Mode string

const (
	ModeDisabled Mode = "disabled"
	ModePassive  Mode = "passive"
	ModeActive   Mode = "active"
)

// ParseMode maps an env value to a Mode; anything unrecognised (incl. empty)
// is treated as disabled so a misconfig fails safe to current behavior.
func ParseMode(s string) Mode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(ModePassive):
		return ModePassive
	case string(ModeActive):
		return ModeActive
	default:
		return ModeDisabled
	}
}

// rejectAfterTime is WireGuard's REJECT_AFTER_TIME (seconds) — a session key is
// dead after this with no new handshake. Used as the keepalive-less passive
// down threshold.
const rejectAfterTime = 180 // seconds

// peerStat is the liveness-relevant snapshot of one wg peer.
type peerStat struct {
	PublicKey         string
	LastHandshakeTime time.Time
	ReceiveBytes      int64
}

// deviceReader yields a snapshot of all peers' counters. Abstracted so the
// liveness logic is unit-testable without a real wg0 / root / netlink.
type deviceReader interface {
	readPeers() ([]peerStat, error)
}

// wgctrlReader reads the live device via a long-lived wgctrl client.
type wgctrlReader struct {
	client *wgctrl.Client
	iface  string
}

func newWgctrlReader(iface string) (*wgctrlReader, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	return &wgctrlReader{client: c, iface: iface}, nil
}

func (w *wgctrlReader) readPeers() ([]peerStat, error) {
	dev, err := w.client.Device(w.iface)
	if err != nil {
		return nil, err
	}
	out := make([]peerStat, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		out = append(out, peerStat{
			PublicKey:         p.PublicKey.String(),
			LastHandshakeTime: p.LastHandshakeTime,
			ReceiveBytes:      p.ReceiveBytes,
		})
	}
	return out, nil
}

func (w *wgctrlReader) Close() error { return w.client.Close() }
