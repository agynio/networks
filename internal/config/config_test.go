package config

import "testing"

func TestFromEnvDefaults(t *testing.T) {
	setBaseEnv(t)

	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.GRPCAddress != ":50051" {
		t.Fatalf("expected grpc address %q, got %q", ":50051", cfg.GRPCAddress)
	}
	if cfg.DependencyClientsEnabled {
		t.Fatal("expected dependency clients to be disabled")
	}
	if cfg.AuthorizationGRPCTarget != "authorization:50051" {
		t.Fatalf("expected authorization target %q, got %q", "authorization:50051", cfg.AuthorizationGRPCTarget)
	}
	if cfg.ZitiManagementGRPCTarget != "ziti-management:50051" {
		t.Fatalf("expected ziti management target %q, got %q", "ziti-management:50051", cfg.ZitiManagementGRPCTarget)
	}
	if cfg.IdentityGRPCTarget != "identity:50051" {
		t.Fatalf("expected identity target %q, got %q", "identity:50051", cfg.IdentityGRPCTarget)
	}
	if cfg.GroupsGRPCTarget != "groups:50051" {
		t.Fatalf("expected groups target %q, got %q", "groups:50051", cfg.GroupsGRPCTarget)
	}
	if cfg.NotificationsGRPCTarget != "notifications:50051" {
		t.Fatalf("expected notifications target %q, got %q", "notifications:50051", cfg.NotificationsGRPCTarget)
	}
	if cfg.NATSURL != "" {
		t.Fatalf("expected empty nats url, got %q", cfg.NATSURL)
	}
}

func TestFromEnvRequiresDatabaseURL(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("DATABASE_URL", "")

	_, err := FromEnv()
	if err == nil {
		t.Fatal("expected database url error")
	}
}

func TestFromEnvDependencyClientsEnabled(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("DEPENDENCY_CLIENTS_ENABLED", "true")
	t.Setenv("AUTHORIZATION_GRPC_TARGET", "authorization.internal:50051")
	t.Setenv("ZITI_MANAGEMENT_GRPC_TARGET", "ziti-management.internal:50051")
	t.Setenv("IDENTITY_GRPC_TARGET", "identity.internal:50051")
	t.Setenv("GROUPS_GRPC_TARGET", "groups.internal:50051")
	t.Setenv("NOTIFICATIONS_GRPC_TARGET", "notifications.internal:50051")
	t.Setenv("NATS_URL", "nats://nats:4222")

	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if !cfg.DependencyClientsEnabled {
		t.Fatal("expected dependency clients to be enabled")
	}
	if cfg.AuthorizationGRPCTarget != "authorization.internal:50051" {
		t.Fatalf("expected authorization target override, got %q", cfg.AuthorizationGRPCTarget)
	}
	if cfg.NATSURL != "nats://nats:4222" {
		t.Fatalf("expected nats url override, got %q", cfg.NATSURL)
	}
}

func TestFromEnvDependencyClientsEnabledInvalid(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("DEPENDENCY_CLIENTS_ENABLED", "definitely")

	_, err := FromEnv()
	if err == nil {
		t.Fatal("expected dependency clients parse error")
	}
}

func setBaseEnv(t *testing.T) {
	t.Setenv("GRPC_ADDRESS", "")
	t.Setenv("DATABASE_URL", "postgres://networks:test@localhost:5432/networks")
	t.Setenv("DEPENDENCY_CLIENTS_ENABLED", "")
	t.Setenv("AUTHORIZATION_GRPC_TARGET", "")
	t.Setenv("ZITI_MANAGEMENT_GRPC_TARGET", "")
	t.Setenv("IDENTITY_GRPC_TARGET", "")
	t.Setenv("GROUPS_GRPC_TARGET", "")
	t.Setenv("NOTIFICATIONS_GRPC_TARGET", "")
	t.Setenv("NATS_URL", "")
}
