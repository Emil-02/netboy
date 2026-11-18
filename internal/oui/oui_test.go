package oui

import (
	"testing"
)

func TestLookup(t *testing.T) {
	tests := []struct {
		name     string
		mac      string
		expected string
	}{
		{
			name:     "Raspberry Pi colon separated",
			mac:      "b8:27:eb:12:34:56",
			expected: "Raspberry Pi Foundation",
		},
		{
			name:     "Espressif hyphen separated",
			mac:      "24-0A-C4-aa-bb-cc",
			expected: "Espressif Systems (ESP32/ESP8266)",
		},
		{
			name:     "Docker Bridge lowercase",
			mac:      "02:42:ac:11:00:02",
			expected: "Docker Container Bridge",
		},
		{
			name:     "MikroTik no separator",
			mac:      "000c42123456",
			expected: "MikroTik",
		},
		{
			name:     "Unknown valid MAC",
			mac:      "ff:ee:dd:cc:bb:aa",
			expected: "Unknown Vendor",
		},
		{
			name:     "Invalid MAC too short",
			mac:      "12:34",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Lookup(tc.mac)
			if got != tc.expected {
				t.Errorf("Lookup(%q) = %q; want %q", tc.mac, got, tc.expected)
			}
		})
	}
}
