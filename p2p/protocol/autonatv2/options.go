package autonatv2

import (
	"math"
	"time"
)

// autoNATSettings is used to configure AutoNAT
type autoNATSettings struct {
	allowAllAddrs     bool
	serverRPM         int
	serverPerPeerRPM  int
	serverDialDataRPM int
	dataRequestPolicy dataRequestPolicyFunc
	now               func() time.Time
}

func defaultSettings() *autoNATSettings {
	return &autoNATSettings{
		allowAllAddrs: false,
		// TODO: confirm rate limiting defaults
		serverRPM:         math.MaxInt32,
		serverPerPeerRPM:  math.MaxInt32,
		serverDialDataRPM: math.MaxInt32,
		dataRequestPolicy: amplificationAttackPrevention,
		now:               time.Now,
	}
}

type AutoNATOption func(s *autoNATSettings) error

func WithServerRateLimit(rpm, perPeerRPM, dialDataRPM int) AutoNATOption {
	return func(s *autoNATSettings) error {
		s.serverRPM = rpm
		s.serverPerPeerRPM = perPeerRPM
		s.serverDialDataRPM = dialDataRPM
		return nil
	}
}

func withDataRequestPolicy(drp dataRequestPolicyFunc) AutoNATOption {
	return func(s *autoNATSettings) error {
		s.dataRequestPolicy = drp
		return nil
	}
}

func allowAllAddrs(s *autoNATSettings) error {
	s.allowAllAddrs = true
	return nil
}
