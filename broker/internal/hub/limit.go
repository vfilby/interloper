package hub

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Enrollment is unauthenticated, and each failed attempt costs an fsynced audit line. A client gets EnrollFailBurst
// failures, then one more every EnrollFailEvery; past that its enrollments are refused before any work is done. A
// device that enrolls with a good code never fails, so it is never held up by its own attempts.
const (
	EnrollFailBurst = 20
	EnrollFailEvery = 10 * time.Second
	maxLimitClients = 10000
)

// failLimiter is a token bucket per client, spent by failures only.
type failLimiter struct {
	burst float64
	every time.Duration

	mu      sync.Mutex
	clients map[string]*bucket
}

type bucket struct {
	tokens  float64
	at      time.Time
	limited bool // the client has been told no since its bucket last had a token (one audit line per episode)
}

func newFailLimiter(burst int, every time.Duration) *failLimiter {
	return &failLimiter{burst: float64(burst), every: every, clients: map[string]*bucket{}}
}

func (l *failLimiter) refill(b *bucket, now time.Time) {
	if d := now.Sub(b.at); d > 0 {
		b.tokens = min(l.burst, b.tokens+float64(d)/float64(l.every))
		b.at = now
	}
}

// allow reports whether the client may try; first is true the first time a client is refused in an episode.
func (l *failLimiter) allow(client string, now time.Time) (ok, first bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, found := l.clients[client]
	if !found {
		return true, false
	}
	l.refill(b, now)
	if b.tokens >= 1 {
		b.limited = false
		return true, false
	}
	first = !b.limited
	b.limited = true
	return false, first
}

// fail spends one of the client's tokens.
func (l *failLimiter) fail(client string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.clients[client]
	if !ok {
		if len(l.clients) >= maxLimitClients {
			l.prune(now)
		}
		b = &bucket{tokens: l.burst, at: now}
		l.clients[client] = b
	}
	l.refill(b, now)
	b.tokens = max(0, b.tokens-1)
}

// prune forgets clients whose buckets are full again; if that frees nothing (a flood from many addresses), it forgets
// everyone: the map must not grow without bound, and the burst it hands back is small.
func (l *failLimiter) prune(now time.Time) {
	for k, b := range l.clients {
		if l.refill(b, now); b.tokens >= l.burst {
			delete(l.clients, k)
		}
	}
	if len(l.clients) >= maxLimitClients {
		clear(l.clients)
	}
}

// clientIP is the address the limiter counts by: the peer, or, when the peer is a trusted proxy, the address the
// proxy appended to X-Forwarded-For (the rightmost one that is not itself a trusted proxy). IPv6 clients are counted
// by /64, the block one host usually has to itself.
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	ip := peerIP(r.RemoteAddr)
	if ip.IsValid() && isTrusted(ip, trusted) {
		hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
		for i := len(hops) - 1; i >= 0; i-- {
			hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
			if err != nil {
				break
			}
			ip = hop.Unmap()
			if !isTrusted(ip, trusted) {
				break
			}
		}
	}
	if !ip.IsValid() {
		return r.RemoteAddr
	}
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.String()
	}
	return ip.String()
}

func peerIP(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip, _ := netip.ParseAddr(host)
	return ip.Unmap()
}

func isTrusted(ip netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ParsePrefixes reads a comma-separated list of addresses and CIDR prefixes (the -trusted-proxy flag).
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for f := range strings.SplitSeq(s, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		if strings.Contains(f, "/") {
			p, err := netip.ParsePrefix(f)
			if err != nil {
				return nil, err
			}
			out = append(out, p.Masked())
			continue
		}
		ip, err := netip.ParseAddr(f)
		if err != nil {
			return nil, err
		}
		ip = ip.Unmap()
		out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
	}
	return out, nil
}

// clip shortens a string from an unauthenticated client before it goes into the audit log.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && cut < len(s) && s[cut]&0xC0 == 0x80 { // do not split a UTF-8 sequence
		cut--
	}
	return s[:cut] + "…"
}
