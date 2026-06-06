package wireguard

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	routesActiveOnce sync.Once
	routesActiveVec  *prometheus.GaugeVec
)

// routesActiveGauge lazily registers and returns the per-peer gauge that
// reports whether a peer's liveness-gated downstream routes are currently
// installed (1) or withdrawn (0). Registered once (sync.Once) so repeated
// BuildController calls (e.g. in tests) don't double-register.
func routesActiveGauge() *prometheus.GaugeVec {
	routesActiveOnce.Do(func() {
		routesActiveVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "wireguard_peer_routes_active",
			Help: "1 if a peer's downstream routes are currently installed (liveness-gated), else 0.",
		}, []string{"peer"})
		prometheus.MustRegister(routesActiveVec)
	})
	return routesActiveVec
}
