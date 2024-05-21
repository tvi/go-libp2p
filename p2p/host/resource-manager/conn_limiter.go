package rcmgr

import (
	"math"
	"net/netip"
	"slices"
	"sync"
)

type ConnLimitPerSubnet struct {
	// This defines how big the subnet is. For example, a /24 subnet has a
	// BitMask of 24. All IPs that share the same 24 bit prefix are in the same
	// subnet.  Are in the same subnet, and bound to the same limit.
	BitMask int
	// The maximum number of connections allowed for each subnet.
	ConnCount int
}

type CIDRLimit struct {
	// The CIDR prefix for which this limit applies.
	Network netip.Prefix

	// The maximum number of connections allowed for each subnet.
	ConnCount int
}

// 8 for now so that it matches the number of concurrent dials we may do
// in swarm_dial.go. With future smart dialing work we should bring this
// down
var defaultMaxConcurrentConns = 8

var defaultIP4Limit = ConnLimitPerSubnet{
	ConnCount: defaultMaxConcurrentConns,
	BitMask:   32,
}
var defaultIP6Limits = []ConnLimitPerSubnet{
	{
		ConnCount: defaultMaxConcurrentConns,
		BitMask:   56,
	},
	{
		ConnCount: 8 * defaultMaxConcurrentConns,
		BitMask:   48,
	},
}

var DefaultCIDRLimitV4 = sortCIDRLimits([]CIDRLimit{
	{
		// Loopback address for v4 https://datatracker.ietf.org/doc/html/rfc6890#section-2.2.2
		Network:   netip.MustParsePrefix("127.0.0.0/8"),
		ConnCount: math.MaxInt, // Unlimited
	},
})
var DefaultCIDRLimitV6 = sortCIDRLimits([]CIDRLimit{
	{
		// Loopback address for v6 https://datatracker.ietf.org/doc/html/rfc6890#section-2.2.3
		Network:   netip.MustParsePrefix("::1/128"),
		ConnCount: math.MaxInt, // Unlimited
	},
})

// CIDR limits must be sorted by most specific to least specific.  This lets us
// actually use the more specific limits, otherwise only the less specific ones
// would be matched. e.g. 1.2.3.0/24 must come before 1.2.0.0/16.
func sortCIDRLimits(limits []CIDRLimit) []CIDRLimit {
	slices.SortStableFunc(limits, func(a, b CIDRLimit) int {
		return b.Network.Bits() - a.Network.Bits()
	})
	return limits
}

// WithCIDRLimit sets the limits for the number of connections allowed per CIDR
// defined address block.
func WithCIDRLimit(ipv4 []CIDRLimit, ipv6 []CIDRLimit) Option {
	return func(rm *resourceManager) error {
		if ipv4 != nil {
			rm.connLimiter.cidrLimitV4 = sortCIDRLimits(ipv4)
		}
		if ipv6 != nil {
			rm.connLimiter.cidrLimitV6 = sortCIDRLimits(ipv6)
		}
		return nil
	}
}

// WithLimitPeersPerSubnet sets the limits for the number of connections allowed per subnet.
func WithLimitPeersPerSubnet(ipv4 []ConnLimitPerSubnet, ipv6 []ConnLimitPerSubnet) Option {
	return func(rm *resourceManager) error {
		if ipv4 != nil {
			rm.connLimiter.connLimitPerSubnetV4 = ipv4
		}
		if ipv6 != nil {
			rm.connLimiter.connLimitPerSubnetV6 = ipv6
		}
		return nil
	}
}

type connLimiter struct {
	mu sync.Mutex

	// Specific CIDR limits. If these are set, they take precedence over the
	// subnet limits.
	// These must be sorted by most specific to least specific.
	cidrLimitV4    []CIDRLimit
	cidrLimitV6    []CIDRLimit
	connsPerCIDRV4 []int
	connsPerCIDRV6 []int

	// Subnet limits.
	connLimitPerSubnetV4 []ConnLimitPerSubnet
	connLimitPerSubnetV6 []ConnLimitPerSubnet
	ip4connsPerLimit     []map[string]int
	ip6connsPerLimit     []map[string]int
}

func newConnLimiter() *connLimiter {
	return &connLimiter{
		cidrLimitV4: DefaultCIDRLimitV4,
		cidrLimitV6: DefaultCIDRLimitV6,

		connLimitPerSubnetV4: []ConnLimitPerSubnet{defaultIP4Limit},
		connLimitPerSubnetV6: defaultIP6Limits,
	}
}

// addConn adds a connection for the given IP address. It returns true if the connection is allowed.
func (cl *connLimiter) addConn(ip netip.Addr) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cidrLimits := cl.cidrLimitV4
	connsPerCidr := cl.connsPerCIDRV4
	limits := cl.connLimitPerSubnetV4
	connsPerLimit := cl.ip4connsPerLimit
	isIP6 := ip.Is6()
	if isIP6 {
		cidrLimits = cl.cidrLimitV6
		connsPerCidr = cl.connsPerCIDRV6
		limits = cl.connLimitPerSubnetV6
		connsPerLimit = cl.ip6connsPerLimit
	}

	// Check CIDR limits first
	if len(connsPerCidr) == 0 && len(cidrLimits) > 0 {
		// Initialize the counts
		connsPerCidr = make([]int, len(cidrLimits))
	}

	for i, limit := range cidrLimits {
		if limit.Network.Contains(ip) {
			if connsPerCidr[i]+1 > limit.ConnCount {
				return false
			}
			connsPerCidr[i]++
			if isIP6 {
				cl.connsPerCIDRV6 = connsPerCidr
			} else {
				cl.connsPerCIDRV4 = connsPerCidr
			}

			return true
		}
	}

	if len(connsPerLimit) == 0 && len(limits) > 0 {
		connsPerLimit = make([]map[string]int, len(limits))
		if isIP6 {
			cl.ip6connsPerLimit = connsPerLimit
		} else {
			cl.ip4connsPerLimit = connsPerLimit
		}
	}

	for i, limit := range limits {
		prefix, err := ip.Prefix(limit.BitMask)
		if err != nil {
			return false
		}
		masked := prefix.String()
		counts, ok := connsPerLimit[i][masked]
		if !ok {
			if connsPerLimit[i] == nil {
				connsPerLimit[i] = make(map[string]int)
			}
			connsPerLimit[i][masked] = 0
		}
		if counts+1 > limit.ConnCount {
			return false
		}
	}

	// All limit checks passed, now we update the counts
	for i, limit := range limits {
		prefix, _ := ip.Prefix(limit.BitMask)
		masked := prefix.String()
		connsPerLimit[i][masked]++
	}

	return true
}

func (cl *connLimiter) rmConn(ip netip.Addr) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cidrLimits := cl.cidrLimitV4
	connsPerCidr := cl.connsPerCIDRV4
	limits := cl.connLimitPerSubnetV4
	connsPerLimit := cl.ip4connsPerLimit
	isIP6 := ip.Is6()
	if isIP6 {
		cidrLimits = cl.cidrLimitV6
		connsPerCidr = cl.connsPerCIDRV6
		limits = cl.connLimitPerSubnetV6
		connsPerLimit = cl.ip6connsPerLimit
	}

	// Check CIDR limits first

	if len(connsPerCidr) == 0 && len(cidrLimits) > 0 {
		// Initialize just in case. We should have already initialized in
		// addConn, but if the callers calls rmConn first we don't want to panic
		connsPerCidr = make([]int, len(cidrLimits))
	}
	for i, limit := range cidrLimits {
		if limit.Network.Contains(ip) {
			count := connsPerCidr[i]
			if count <= 0 {
				log.Errorf("unexpected conn count for ip %s. Was this not added with addConn first?", ip)
			}
			connsPerCidr[i]--
			if isIP6 {
				cl.connsPerCIDRV6 = connsPerCidr
			} else {
				cl.connsPerCIDRV4 = connsPerCidr
			}

			// Done. We updated the count in the defined CIDR limit.
			return
		}
	}

	if len(connsPerLimit) == 0 && len(limits) > 0 {
		// Initialize just in case. We should have already initialized in
		// addConn, but if the callers calls rmConn first we don't want to panic
		connsPerLimit = make([]map[string]int, len(limits))
		if isIP6 {
			cl.ip6connsPerLimit = connsPerLimit
		} else {
			cl.ip4connsPerLimit = connsPerLimit
		}
	}

	for i, limit := range limits {
		prefix, err := ip.Prefix(limit.BitMask)
		if err != nil {
			// Unexpected since we should have seen this IP before in addConn
			log.Errorf("unexpected error getting prefix: %v", err)
			continue
		}
		masked := prefix.String()
		counts, ok := connsPerLimit[i][masked]
		if !ok || counts == 0 {
			// Unexpected, but don't panic
			log.Errorf("unexpected conn count for %s ok=%v count=%v", masked, ok, counts)
			continue
		}
		connsPerLimit[i][masked]--
		if connsPerLimit[i][masked] <= 0 {
			delete(connsPerLimit[i], masked)
		}
	}
}
