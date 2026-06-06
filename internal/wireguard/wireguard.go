package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/go-logr/logr"

	"github.com/nccloud/wireguard-operator/api/v1alpha1"
	"github.com/nccloud/wireguard-operator/internal/agent"
	"github.com/nccloud/wireguard-operator/internal/ipam"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const MTU = 1420

// wgSyncconfTempDir is the directory used for the short-lived wg-syncconf
// config file. The agent container runs with `securityContext.readOnlyRootFilesystem: true`
// (set by the operator's own deployment template in internal/resources/deployment.go),
// so `/tmp` (the default for os.CreateTemp) is read-only and writes fail with
// `read-only file system`. The operator's deployment template mounts an
// emptyDir named `socket` at `/var/run/wireguard/` (used for the wg control
// socket), which is always writable; reusing that mount keeps the fix
// self-contained without adding a new volume.
const wgSyncconfTempDir = "/var/run/wireguard"

func syncRoute(iface string, cidr string, gw net.IP, family int) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	routes, err := netlink.RouteList(link, family)
	if err != nil {
		return err
	}

	for _, route := range routes {
		if route.LinkIndex == link.Attrs().Index {
			return nil
		}
	}
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	route := netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Gw:        gw,
	}

	err = netlink.RouteAdd(&route)
	if err != nil {
		return err
	}

	return nil
}

func syncAddress(iface string, ipWithMask *net.IPNet, family int) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	addresses, err := netlink.AddrList(link, family)
	if err != nil {
		return nil
	}

	if len(addresses) != 0 {
		return nil
	}

	if err := netlink.AddrAdd(link, &netlink.Addr{
		IPNet: ipWithMask,
	}); err != nil {
		return fmt.Errorf("netlink addr add: %w", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	return nil
}

func createLinkUsingUserspaceImpl(iface string, wgUserspaceImplementationFallback string) error {
	// Ensure /dev/net exists
	if err := os.MkdirAll("/dev/net", 0o755); err != nil {
		return err
	}

	// Ensure /dev/net/tun is a character device; create it if missing
	fi, err := os.Stat("/dev/net/tun")
	if err != nil {
		if os.IsNotExist(err) {
			mode := uint32(syscall.S_IFCHR | 0o666)
			dev := int(unix.Mkdev(10, 200))
			if err := unix.Mknod("/dev/net/tun", mode, dev); err != nil {
				return fmt.Errorf("mknod /dev/net/tun failed: %w", err)
			}
		} else {
			return err
		}
	} else {
		mode := fi.Mode()
		if mode&os.ModeDevice == 0 || mode&os.ModeCharDevice == 0 {
			return fmt.Errorf("/dev/net/tun exists but is not a character device")
		}
	}

	// Launch userspace implementation (e.g., wireguard-go) to create the interface
	cmd := exec.Command(wgUserspaceImplementationFallback, iface)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting userspace implementation %q failed: %w", wgUserspaceImplementationFallback, err)
	}

	return nil
}

func createLinkUsingKernalModule(iface string) error {
	// link not created
	wgLink := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{
			Name: iface,
			MTU:  MTU,
		},
		LinkType: "wireguard",
	}

	if err := netlink.LinkAdd(wgLink); err != nil {
		return err
	}
	return nil
}

func SyncLink(_ agent.State, iface string, wgUserspaceImplementationFallback string, wgUseUserspaceImpl bool) error {
	_, err := netlink.LinkByName(iface)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); !ok {
			return err
		}
	}

	if _, ok := err.(netlink.LinkNotFoundError); ok {
		if wgUseUserspaceImpl {
			err = createLinkUsingUserspaceImpl(iface, wgUserspaceImplementationFallback)

			if err != nil {
				return err
			}

			// Wait briefly for userspace implementation to create the link
			var lastErr error
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				var l netlink.Link
				l, lastErr = netlink.LinkByName(iface)
				if lastErr == nil {
					// Ensure link is up
					if err := netlink.LinkSetUp(l); err != nil {
						return fmt.Errorf("bringing link %q up failed: %w", iface, err)
					}
					lastErr = nil
					break
				}
				time.Sleep(100 * time.Millisecond)
			}

			if lastErr != nil {
				return fmt.Errorf("userspace WireGuard did not create link %q in time: %w; ensure a userspace implementation (e.g., wireguard-go) is running for this interface", iface, lastErr)
			}

		} else {
			err = createLinkUsingKernalModule(iface)

			if err != nil {
				err = createLinkUsingUserspaceImpl(iface, wgUserspaceImplementationFallback)

				if err != nil {
					return err
				}
			}
		}

		// Verify link exists after creation
		link, err := netlink.LinkByName(iface)
		if err != nil {
			return fmt.Errorf("expected link %q after creation, but not found: %w", iface, err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("bringing link %q up failed: %w", iface, err)
		}
	}

	return nil
}

// syncWireguard renders a wg-quick formatted config from `state` and applies
// it by shelling out to `wg syncconf <iface> <tmpfile>`. Phase E replaces the
// previous wgctrl-go `ConfigureDevice` call to fix the multi-CIDR AllowedIPs
// truncation bug: wgctrl's PeerConfig was built with only `<addr>/32`, and
// `ReplaceAllowedIPs=true` made every ~30s reconcile clobber the broader CIDRs
// ops added via `WireguardPeer.spec.allowedIPs`. `wg syncconf` honours the
// supplied AllowedIPs CSV verbatim and only diffs peers that actually changed.
func (wg *Wireguard) syncWireguard(state agent.State, iface string, listenPort int) error {
	cfg, err := BuildWgQuickConfig(state, listenPort, wg.Liveness)
	if err != nil {
		return err
	}

	// Write to a temp file rather than /dev/stdin: `wg syncconf` accepts a
	// path argument; piping stdin works on Linux but is less portable and
	// makes error messages harder to interpret in agent logs.
	tmp, err := os.CreateTemp(wgSyncconfTempDir, "wg-syncconf-*.conf")
	if err != nil {
		return fmt.Errorf("create wg syncconf temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.WriteString(cfg); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write wg syncconf temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close wg syncconf temp file: %w", err)
	}

	cmd := exec.CommandContext(context.Background(), "wg", "syncconf", iface, tmpPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg syncconf %s failed: %w (output: %s)", iface, err, strings.TrimSpace(string(output)))
	}

	wg.Logger.V(2).Info("wg syncconf applied", "iface", iface, "peers", len(state.Peers))
	return nil
}

type Wireguard struct {
	Logger                            logr.Logger
	Iface                             string
	ListenPort                        int
	WgUserspaceImplementationFallback string
	WgUseUserspaceImpl                bool
	// Liveness gates per-peer spec.routes. nil ⇒ all peers live (disabled mode,
	// byte-identical to pre-feature behavior).
	Liveness LivenessSource
}

func (wg *Wireguard) Sync(state agent.State) error {
	wg.Logger.V(2).Info("syncing Wireguard")
	// create wg0 link
	err := SyncLink(state, wg.Iface, wg.WgUserspaceImplementationFallback, wg.WgUseUserspaceImpl)
	if err != nil {
		return err
	}

	spec := state.Server.Spec

	enableV6 := spec.PeerCIDRv6 != ""
	ipv6Only := spec.IPv6Only && enableV6

	// IPv4 configuration (skip in IPv6-only mode).
	if !ipv6Only {
		cidr4 := spec.PeerCIDR
		if cidr4 == "" {
			cidr4 = ipam.DefaultPeerCIDR4
		}
		if cidr4 != "" {
			prefix4, err := netip.ParsePrefix(cidr4)
			if err != nil {
				return fmt.Errorf("failed to parse IPv4 CIDR %q: %w", cidr4, err)
			}

			addr4Net, gw4, err := gatewayIPFromPrefix(prefix4)
			if err != nil {
				return err
			}

			if err := syncAddress(wg.Iface, addr4Net, syscall.AF_INET); err != nil {
				return err
			}
			if err := syncRoute(wg.Iface, cidr4, gw4, syscall.AF_INET); err != nil {
				return err
			}
		}
	}

	// IPv6 configuration.
	if enableV6 {
		cidr6 := spec.PeerCIDRv6

		prefix6, err := netip.ParsePrefix(cidr6)
		if err != nil {
			return fmt.Errorf("failed to parse IPv6 CIDR %q: %w", cidr6, err)
		}

		addr6Net, gw6, err := gatewayIPFromPrefix(prefix6)
		if err != nil {
			return err
		}

		if err := syncAddress(wg.Iface, addr6Net, syscall.AF_INET6); err != nil {
			return err
		}
		if err := syncRoute(wg.Iface, cidr6, gw6, syscall.AF_INET6); err != nil {
			return err
		}
	}

	// sync wg configuration
	err = wg.syncWireguard(state, wg.Iface, wg.ListenPort)
	if err != nil {
		return err
	}

	// Phase G follow-up: install kernel routes for each peer's downstream
	// CIDRs (Spec.Routes / Spec.RoutesV6). Without this, the wg pod's
	// routing table doesn't direct cluster-originated traffic (e.g. a
	// poller hitting a downstream LAN) into wg0 — packets fall through to
	// eth0 and the underlying subnet gateway ICMP-redirects them. We
	// log-and-continue on errors so a single bad CIDR doesn't block the
	// rest of the reconcile (wg syncconf already succeeded).
	if err := syncPeerRoutes(wg.Iface, state, wg.Liveness, wg.Logger); err != nil {
		wg.Logger.Error(err, "failed to sync peer routes")
	}

	return nil
}

// desiredKernelRoutes returns the deduplicated, whitespace-trimmed union of
// every enabled peer's Spec.Routes + Spec.RoutesV6. This is the set of CIDRs
// the agent should install as kernel routes pointing at wg0, so traffic
// originating in the cluster (e.g. a poller pod hitting a downstream LAN
// behind a road-warrior peer) gets delivered into the tunnel rather than
// falling through to eth0 and getting ICMP-redirected by the underlying
// subnet gateway.
//
// Filtering matches peerAllowedIPs / BuildWgQuickConfig: a Disabled or
// PublicKey-less peer can't actually carry packets, so its declared routes
// must not appear in the kernel routing table either. This is a pure
// function so it can be unit-tested without root or netlink.
func desiredKernelRoutes(peers []v1alpha1.WireguardPeer, src LivenessSource) []string {
	seen := map[string]bool{}
	var out []string
	for _, peer := range peers {
		if peer.Spec.Disabled {
			continue
		}
		if peer.Spec.PublicKey == "" {
			continue
		}
		// Liveness gate: mirror the Disabled skip — a not-live peer's downstream
		// routes must not sit in the kernel table either (the RouteDel prune in
		// syncPeerRoutes withdraws them when they drop out of this set). nil src
		// ⇒ all-live (disabled mode, unchanged).
		if !isLive(src, peer.Spec.PublicKey) {
			continue
		}
		for _, r := range peer.Spec.Routes {
			r = strings.TrimSpace(r)
			if r == "" || seen[r] {
				continue
			}
			seen[r] = true
			out = append(out, r)
		}
		for _, r := range peer.Spec.RoutesV6 {
			r = strings.TrimSpace(r)
			if r == "" || seen[r] {
				continue
			}
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// syncPeerRoutes installs the per-peer downstream CIDRs returned by
// desiredKernelRoutes as kernel routes on `iface` (wg0), and prunes any
// stale routes the agent itself previously installed but that are no
// longer desired.
//
// We use netlink.RouteReplace (idempotent — adds if missing, updates if
// present) so re-asserting the desired state every reconcile is cheap
// and tolerates manual `ip route del` interference between reconciles.
//
// Stale-route cleanup is scoped tightly: we only remove routes whose
// Dst CIDR matches the existing "we previously installed" criteria,
// which we approximate by:
//   - LinkIndex == wg0
//   - Dst != nil
//   - Dst != the server's own PeerCIDR / PeerCIDRv6 (managed by syncRoute)
//
// Anything else on wg0 (notably the per-peer /32 + /128 routes wg syncconf
// installs automatically from AllowedIPs) is left alone — those have Dst
// of /32 or /128, which we don't generate from Routes (which are CIDR
// blocks, not host addresses).
//
// Errors on individual route operations are logged and the function
// continues — a single peer's bad CIDR shouldn't block the whole reconcile.
func syncPeerRoutes(iface string, state agent.State, src LivenessSource, logger logr.Logger) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", iface, err)
	}

	desired := desiredKernelRoutes(state.Peers, src)
	desiredSet := map[string]bool{}
	for _, c := range desired {
		desiredSet[c] = true
	}

	// Determine server-managed CIDRs to exclude from stale cleanup.
	excluded := map[string]bool{}
	if cidr := state.Server.Spec.PeerCIDR; cidr != "" {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			excluded[n.String()] = true
		}
	} else {
		// Default PeerCIDR4 path syncRoute also installs.
		if _, n, err := net.ParseCIDR(ipam.DefaultPeerCIDR4); err == nil {
			excluded[n.String()] = true
		}
	}
	if cidr := state.Server.Spec.PeerCIDRv6; cidr != "" {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			excluded[n.String()] = true
		}
	}

	// Install / re-assert desired routes.
	for _, cidr := range desired {
		_, dst, err := net.ParseCIDR(cidr)
		if err != nil {
			logger.Error(err, "skipping invalid CIDR in peer Routes", "cidr", cidr)
			continue
		}
		// No Gw + no Src + LinkIndex set => kernel auto-applies scope link,
		// which is exactly what `ip route add <cidr> dev wg0` produces. We
		// intentionally don't set Scope explicitly so the code compiles on
		// non-Linux (the netlink.SCOPE_* constants live in _linux.go).
		route := netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       dst,
		}
		if err := netlink.RouteReplace(&route); err != nil {
			logger.Error(err, "failed to install peer route", "cidr", cidr, "iface", iface)
			continue
		}
		logger.V(2).Info("peer route installed", "cidr", cidr, "iface", iface)
	}

	// Prune stale routes: anything on wg0 with a Dst that isn't in the desired
	// set and isn't a server-managed CIDR and isn't a host route (/32 or /128,
	// which `wg syncconf` synthesises from AllowedIPs).
	// syscall.AF_UNSPEC (== 0) means "all families" — same value as
	// netlink.FAMILY_ALL, but available cross-platform so the package still
	// compiles on darwin for local dev. The agent only ever runs on Linux.
	existing, err := netlink.RouteList(link, syscall.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("failed to list routes on %s: %w", iface, err)
	}
	for _, r := range existing {
		if r.LinkIndex != link.Attrs().Index || r.Dst == nil {
			continue
		}
		dstStr := r.Dst.String()
		if desiredSet[dstStr] {
			continue
		}
		if excluded[dstStr] {
			continue
		}
		// Skip host routes — wg syncconf-synthesised AllowedIPs entries.
		ones, bits := r.Dst.Mask.Size()
		if (bits == 32 && ones == 32) || (bits == 128 && ones == 128) {
			continue
		}
		if err := netlink.RouteDel(&r); err != nil {
			logger.Error(err, "failed to remove stale peer route", "cidr", dstStr, "iface", iface)
			continue
		}
		logger.V(2).Info("stale peer route removed", "cidr", dstStr, "iface", iface)
	}

	return nil
}

func gatewayIPFromPrefix(prefix netip.Prefix) (*net.IPNet, net.IP, error) {
	prefix = prefix.Masked()
	addr := prefix.Addr()

	switch {
	case addr.Is4():
		gw := addr.Next()
		if !gw.Is4() {
			return nil, nil, fmt.Errorf("failed to derive IPv4 gateway for prefix %q", prefix.String())
		}
		b := gw.As4()
		ip := net.IPv4(b[0], b[1], b[2], b[3])
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, ip, nil

	case addr.Is6() && !addr.Is4():
		gw := addr.Next()
		if !gw.Is6() || gw.Is4() {
			return nil, nil, fmt.Errorf("failed to derive IPv6 gateway for prefix %q", prefix.String())
		}
		b := gw.As16()
		ip := net.IP(b[:])
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, ip, nil

	default:
		return nil, nil, fmt.Errorf("unsupported address family for prefix %q", prefix.String())
	}
}

// peerAllowedIPs returns the AllowedIPs CSV that should land in the [Peer]
// section. Operators can override the default `<addr>/32[,<addrV6>/128]` by
// setting `WireguardPeer.spec.allowedIPs` to a comma-separated list — this is
// how downstream LAN routes (e.g. `10.254.0.0/16` behind a road-warrior peer)
// are advertised to the server. Whitespace between entries is normalised
// because `wg syncconf` is strict about CSV form.
//
// Phase G appends `WireguardPeer.spec.routes` (IPv4) and `spec.routesV6` (IPv6)
// to the resulting CSV. Routes is the declarative counterpart to the freeform
// AllowedIPs CSV — ops can list downstream LAN CIDRs that this peer is
// responsible for, and the operator will splice them into the [Peer].AllowedIPs
// the server enforces. Empty/unset Routes preserves the Phase E/F output
// verbatim (no trailing comma, no extra CIDRs).
func peerAllowedIPs(peer v1alpha1.WireguardPeer, src LivenessSource) string {
	var out []string

	if peer.Spec.AllowedIPs != "" {
		for _, p := range strings.Split(peer.Spec.AllowedIPs, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	} else {
		if peer.Spec.Address != "" {
			out = append(out, peer.Spec.Address+"/32")
		}
		if peer.Spec.AddressV6 != "" {
			out = append(out, peer.Spec.AddressV6+"/128")
		}
	}

	// Liveness gate: spec.routes / spec.routesV6 are the downstream CIDRs and are
	// installed only while the peer is live. The base (above) is always kept so
	// the peer can still handshake and recover. A not-live peer is treated like a
	// Disabled peer FOR ROUTES ONLY. nil src ⇒ all-live (disabled mode, unchanged).
	if isLive(src, peer.Spec.PublicKey) {
		for _, r := range peer.Spec.Routes {
			if r = strings.TrimSpace(r); r != "" {
				out = append(out, r)
			}
		}
		for _, r := range peer.Spec.RoutesV6 {
			if r = strings.TrimSpace(r); r != "" {
				out = append(out, r)
			}
		}
	}

	return strings.Join(out, ",")
}

// BuildWgQuickConfig renders the agent's in-memory desired state to a wg-quick
// formatted config string suitable for `wg syncconf`. It is intentionally a
// pure function (no netlink, no wgctrl) so it can be unit-tested without root,
// without /dev/net/tun, and without an existing wg0 interface.
//
// The returned config contains a single [Interface] section (PrivateKey +
// ListenPort) and one [Peer] section per enabled peer with a PublicKey and at
// least one address. Disabled peers, peers without a PublicKey, and peers
// without any Address/AddressV6 are skipped — this preserves the filtering
// invariants the old wgctrl path enforced.
//
// `wg syncconf` reads [Interface].PrivateKey + ListenPort and applies the
// [Peer] list as a diff: peers absent from the config are removed, peers
// present are added/updated with their exact AllowedIPs CSV. This eliminates
// the multi-CIDR truncation bug that Phase E fixes.
func BuildWgQuickConfig(state agent.State, listenPort int, src LivenessSource) (string, error) {
	if state.ServerPrivateKey == "" {
		return "", fmt.Errorf("server private key is empty")
	}

	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nListenPort = %d\n", state.ServerPrivateKey, listenPort)

	for _, peer := range state.Peers {
		if peer.Spec.Disabled {
			continue
		}
		if peer.Spec.PublicKey == "" {
			continue
		}
		if peer.Spec.Address == "" && peer.Spec.AddressV6 == "" {
			continue
		}

		allowed := peerAllowedIPs(peer, src)
		if allowed == "" {
			continue
		}

		fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", peer.Spec.PublicKey, allowed)

		// Per-peer preshared key (PSK). The controller populates
		// peer.Spec.PresharedKey in-memory from the `<name>-peer` Secret's
		// `presharedKey` key; absent => no line (peers without a PSK keep their
		// config byte-identical). The server enforces the PSK here, so the
		// client's wg-quick blob MUST carry the same PresharedKey or the
		// handshake is silently dropped.
		if peer.Spec.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", peer.Spec.PresharedKey)
		}

		// Intentionally NO PersistentKeepalive on the server-side [Peer] block:
		// the server sits behind a stable LoadBalancer IP (not behind NAT), so
		// it has no mapping to keep alive. The whole design is responder-only —
		// peers initiate everything, the server only replies. PersistentKeepalive
		// belongs on the PEER side (in the wg-quick blob handed to customer
		// devices), where it keeps the peer's outbound NAT/conntrack mapping
		// fresh. Setting it on the server makes the server emit unsolicited
		// keepalive packets every N seconds once a peer has dialed in, which
		// is "active" behavior we explicitly don't want.
	}

	return b.String(), nil
}
