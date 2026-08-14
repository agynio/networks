package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	GRPCAddress              string
	DatabaseURL              string
	DependencyClientsEnabled bool
	AuthorizationGRPCTarget  string
	ZitiManagementGRPCTarget string
	IdentityGRPCTarget       string
	AgentsGRPCTarget         string
	GroupsGRPCTarget         string
	EgressRulesGRPCTarget    string
	NotificationsGRPCTarget  string
	NATSURL                  string
	TunnelLivenessInterval   time.Duration
	ReconciliationInterval   time.Duration
}

func FromEnv() (Config, error) {
	cfg := Config{}
	cfg.GRPCAddress = os.Getenv("GRPC_ADDRESS")
	if cfg.GRPCAddress == "" {
		cfg.GRPCAddress = ":50051"
	}
	cfg.DatabaseURL = os.Getenv("DATABASE_URL")
	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL must be set")
	}
	clientsEnabled := os.Getenv("DEPENDENCY_CLIENTS_ENABLED")
	if clientsEnabled != "" {
		parsed, err := strconv.ParseBool(clientsEnabled)
		if err != nil {
			return Config{}, fmt.Errorf("parse DEPENDENCY_CLIENTS_ENABLED: %w", err)
		}
		cfg.DependencyClientsEnabled = parsed
	}
	cfg.AuthorizationGRPCTarget = os.Getenv("AUTHORIZATION_GRPC_TARGET")
	if cfg.AuthorizationGRPCTarget == "" {
		cfg.AuthorizationGRPCTarget = "authorization:50051"
	}
	cfg.ZitiManagementGRPCTarget = os.Getenv("ZITI_MANAGEMENT_GRPC_TARGET")
	if cfg.ZitiManagementGRPCTarget == "" {
		cfg.ZitiManagementGRPCTarget = "ziti-management:50051"
	}
	cfg.IdentityGRPCTarget = os.Getenv("IDENTITY_GRPC_TARGET")
	if cfg.IdentityGRPCTarget == "" {
		cfg.IdentityGRPCTarget = "identity:50051"
	}
	cfg.GroupsGRPCTarget = os.Getenv("GROUPS_GRPC_TARGET")
	if cfg.GroupsGRPCTarget == "" {
		cfg.GroupsGRPCTarget = "groups:50051"
	}
	// Resolves environment principals on access grants. An environment is a
	// configuration resource, not an identity, so Identity cannot answer for it.
	cfg.AgentsGRPCTarget = os.Getenv("AGENTS_GRPC_TARGET")
	if cfg.AgentsGRPCTarget == "" {
		cfg.AgentsGRPCTarget = "agents:50051"
	}
	// Referential-integrity guards, mediation re-derivation, and the
	// hostname-collision fast-fail on access grants.
	cfg.EgressRulesGRPCTarget = os.Getenv("EGRESS_RULES_GRPC_TARGET")
	if cfg.EgressRulesGRPCTarget == "" {
		cfg.EgressRulesGRPCTarget = "egress:50051"
	}
	cfg.NotificationsGRPCTarget = os.Getenv("NOTIFICATIONS_GRPC_TARGET")
	if cfg.NotificationsGRPCTarget == "" {
		cfg.NotificationsGRPCTarget = "notifications:50051"
	}
	cfg.NATSURL = os.Getenv("NATS_URL")
	var err error
	cfg.TunnelLivenessInterval, err = durationFromEnv("TUNNEL_LIVENESS_INTERVAL", 30*time.Second)
	if err != nil {
		return Config{}, err
	}
	cfg.ReconciliationInterval, err = durationFromEnv("RECONCILIATION_INTERVAL", time.Minute)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func durationFromEnv(name string, defaultValue time.Duration) (time.Duration, error) {
	value := os.Getenv(name)
	if value == "" {
		return defaultValue, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	return duration, nil
}
