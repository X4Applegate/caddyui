package server

// requiredReadinessSteps returns the number of completed operating
// foundations shown by the onboarding and dashboard readiness workflows.
// Identity is always complete for an authenticated user. DNS automation is
// intentionally excluded because it is useful for DNS-01 and record
// management, but it is not required to operate an ordinary proxy host.
func requiredReadinessSteps(serverConnected, totpEnabled, servicePublished bool) int {
	completed := 1
	if serverConnected {
		completed++
	}
	if totpEnabled {
		completed++
	}
	if servicePublished {
		completed++
	}
	return completed
}
