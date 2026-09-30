//go:build !linux

package flowlog

// StartSampler is a no-op on non-Linux builds.
func StartSampler(stop <-chan struct{}) *Sampler {
	return &Sampler{}
}

// Sampler stub.
type Sampler struct{}
