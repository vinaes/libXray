package libXray

// Blackout fallback carrier, re-exported so gomobile binds it into the SAME
// LibXray framework as xray-core → a single Go runtime in the NetworkExtension.
//
// Two independent gomobile runtimes in one process crash: each statically links
// its own copy of the Go runtime, they share the g/TLS slot and signal handlers,
// and entering the second runtime faults in runtime.load_g (EXC_BAD_ACCESS at a
// low address). Folding the carrier in here keeps everything on one runtime.
//
// The method set mirrors wbypass/mobile.Engine 1:1. gomobile exports this as
// ObjC `LibXrayBlackoutEngine` (ctor `LibXrayNewBlackoutEngine()`); the inner
// *wb.Engine is unexported so gomobile ignores it and only sees string/error.

import wb "github.com/vinaes/wbypass/mobile"

// BlackoutEngine is the gomobile handle for the vk-turn packet carrier.
type BlackoutEngine struct {
	e *wb.Engine
}

// NewBlackoutEngine constructs an idle carrier engine.
func NewBlackoutEngine() *BlackoutEngine {
	return &BlackoutEngine{e: wb.NewEngine()}
}

// Start parses configJSON, selects and starts the carrier. Returns once the join
// is initiated; the packet endpoint comes up asynchronously (poll PacketAddr).
func (b *BlackoutEngine) Start(configJSON string) error { return b.e.Start(configJSON) }

// Stop tears the carrier down.
func (b *BlackoutEngine) Stop() error { return b.e.Stop() }

// SocksAddr returns the local SOCKS5 (host:port), or "" for packet carriers.
func (b *BlackoutEngine) SocksAddr() string { return b.e.SocksAddr() }

// PacketAddr returns the local UDP endpoint a WireGuard tunnel dials, or "".
func (b *BlackoutEngine) PacketAddr() string { return b.e.PacketAddr() }

// WGConfig returns the WireGuard config fetched from the exit over the tunnel.
func (b *BlackoutEngine) WGConfig() string { return b.e.WGConfig() }

// WGXrayOutbound builds the xray-core WireGuard OUTBOUND JSON from the fetched
// WG config, with the peer endpoint rewritten to the local packet endpoint.
func (b *BlackoutEngine) WGXrayOutbound() (string, error) { return b.e.WGXrayOutbound() }
