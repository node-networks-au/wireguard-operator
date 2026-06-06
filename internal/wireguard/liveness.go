package wireguard

import "strings"

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
