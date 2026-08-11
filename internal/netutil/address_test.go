package netutil

import "testing"

func TestIsPublicInternetUnicast(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{name: "public ipv4 dns", ip: "8.8.8.8", want: true},
		{name: "public ipv4", ip: "91.228.165.146", want: true},
		{name: "private ipv4", ip: "10.1.222.1", want: false},
		{name: "multicast igmp", ip: "224.0.0.22", want: false},
		{name: "multicast ssdp", ip: "239.255.255.250", want: false},
		{name: "limited broadcast", ip: "255.255.255.255", want: false},
		{name: "link local", ip: "169.254.10.20", want: false},
		{name: "cgnat", ip: "100.64.0.1", want: false},
		{name: "benchmark", ip: "198.18.0.1", want: false},
		{name: "documentation ipv4", ip: "203.0.113.10", want: false},
		{name: "public ipv6 dns", ip: "2606:4700:4700::1111", want: true},
		{name: "ula ipv6", ip: "fd00::1", want: false},
		{name: "link local ipv6", ip: "fe80::1", want: false},
		{name: "multicast ipv6", ip: "ff02::1", want: false},
		{name: "documentation ipv6", ip: "2001:db8::1", want: false},
		{name: "malformed", ip: "not-an-ip", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPublicInternetUnicast(tt.ip); got != tt.want {
				t.Fatalf("IsPublicInternetUnicast(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}
