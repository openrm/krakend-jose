package jose

import (
	"github.com/luraproject/lura/config"
	"github.com/luraproject/lura/logging"
)

// StatusRejecter defines the interface for the components responsible for rejecting tokens and its reason.
type StatusRejecter interface {
	Reject(map[string]interface{}) (bool, int)
}

// StatusRejecterFunc is an adapter to use functions as rejecters
type StatusRejecterFunc func(map[string]interface{}) (bool, int)

// Reject calls r(v)
func (r StatusRejecterFunc) Reject(v map[string]interface{}) (bool, int) { return r(v) }

// FixedStatusRejecter is a rejecter that always returns the same bool response
type FixedStatusRejecter struct {
	Rejected bool
	StatusCode int
}

// Reject returns f
func (r FixedStatusRejecter) Reject(_ map[string]interface{}) (bool, int) { return r.Rejected, r.StatusCode }

// StatusRejecterFactory is a builder for rejecters
type StatusRejecterFactory interface {
	New(logging.Logger, *config.EndpointConfig) StatusRejecter
}

// StatusRejecterFactoryFunc is an adapter to use a function as rejecter factory
type StatusRejecterFactoryFunc func(logging.Logger, *config.EndpointConfig) StatusRejecter

// New calls f(l, cfg)
func (f StatusRejecterFactoryFunc) New(l logging.Logger, cfg *config.EndpointConfig) StatusRejecter {
	return f(l, cfg)
}

// NopStatusRejecterFactory is a factory returning rejecters accepting all the tokens
type NopStatusRejecterFactory struct{}

// New returns a fixed rejecter that accepts all the tokens
func (NopStatusRejecterFactory) New(_ logging.Logger, _ *config.EndpointConfig) StatusRejecter {
	return FixedStatusRejecter{false, 0}
}
