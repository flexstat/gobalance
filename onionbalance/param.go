package onionbalance

const (
	FrontendDescriptorLifetimeTestnet = 20
	FrontendDescriptorLifetime        = 60 * 60
	HsdirNReplicas                    = 2

	// How many uploads per replica
	// [TODO: Get these from the consensus instead of hardcoded]
	HsdirSpreadStore         = 4
	InstanceDescriptorTooOld = 60 * 60
	NIntrosPerInstance       = 2
)
