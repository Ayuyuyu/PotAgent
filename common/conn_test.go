package common

import (
	"testing"
)

func TestSplitConnIPAndPort(t *testing.T) {
	cases := []struct {
		in       string
		wantIP   string
		wantPort uint16
		wantErr  bool
	}{
		{"192.168.1.1:22", "192.168.1.1", 22, false},
		{"0.0.0.0:445", "0.0.0.0", 445, false},
		{"[::1]:445", "::1", 445, false},                   // IPv6 loopback，带括号
		{"[2001:db8::1]:5901", "2001:db8::1", 5901, false}, // IPv6 全局地址
		{"localhost", "", 0, true},                         // 无端口 → 报错
	}
	for _, c := range cases {
		got, err := splitConnIPAndPort(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("splitConnIPAndPort(%q): expected error, got nil", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitConnIPAndPort(%q): unexpected error: %v", c.in, err)
			continue
		}
		if got.IP != c.wantIP || got.Port != c.wantPort {
			t.Errorf("splitConnIPAndPort(%q) = {%q, %d}, want {%q, %d}",
				c.in, got.IP, got.Port, c.wantIP, c.wantPort)
		}
	}
}
