package server

import (
	"testing"

	"github.com/agynio/networks/internal/store"
)

func TestValidatePortMapping(t *testing.T) {
	tests := []struct {
		name           string
		targetPorts    []int32
		interceptPorts []int32
		wantErr        bool
	}{
		{name: "valid positional multi port", targetPorts: []int32{5432, 5433}, interceptPorts: []int32{15432, 15433}},
		{name: "empty", targetPorts: nil, interceptPorts: nil, wantErr: true},
		{name: "cardinality mismatch", targetPorts: []int32{5432}, interceptPorts: []int32{15432, 15433}, wantErr: true},
		{name: "invalid target port", targetPorts: []int32{0}, interceptPorts: []int32{15432}, wantErr: true},
		{name: "duplicate intercept port", targetPorts: []int32{5432, 5433}, interceptPorts: []int32{15432, 15432}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePortMapping(tt.targetPorts, tt.interceptPorts)
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateInterceptHostRejectsReserved(t *testing.T) {
	for _, host := range []string{"localhost", "db.ziti", "api.svc", "api.default.svc.cluster.local", "127.0.0.1", "::1", "100.64.0.10"} {
		t.Run(host, func(t *testing.T) {
			if err := validateInterceptHost(host); err == nil {
				t.Fatal("expected reserved host error")
			}
		})
	}
	if err := validateInterceptHost("db.internal.example.com"); err != nil {
		t.Fatalf("expected host to be allowed: %v", err)
	}
}

func TestValidateProtocolAndPrincipalType(t *testing.T) {
	if err := validateProtocol(store.PrivateResourceProtocolTCP); err != nil {
		t.Fatalf("valid protocol: %v", err)
	}
	if err := validateProtocol("udp"); err == nil {
		t.Fatal("expected invalid protocol error")
	}
	if err := validatePrincipalType(store.PrincipalTypeGroup); err != nil {
		t.Fatalf("valid principal type: %v", err)
	}
	if err := validatePrincipalType("runner"); err == nil {
		t.Fatal("expected invalid principal type error")
	}
}
