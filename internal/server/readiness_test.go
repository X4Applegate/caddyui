package server

import "testing"

func TestRequiredReadinessSteps(t *testing.T) {
	tests := []struct {
		name                                string
		serverConnected, totp, serviceReady bool
		want                                int
	}{
		{name: "identity only", want: 1},
		{name: "connected", serverConnected: true, want: 2},
		{name: "secured", serverConnected: true, totp: true, want: 3},
		{name: "ready", serverConnected: true, totp: true, serviceReady: true, want: 4},
		{name: "independent signals", totp: true, serviceReady: true, want: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := requiredReadinessSteps(tt.serverConnected, tt.totp, tt.serviceReady)
			if got != tt.want {
				t.Fatalf("requiredReadinessSteps() = %d, want %d", got, tt.want)
			}
		})
	}
}
