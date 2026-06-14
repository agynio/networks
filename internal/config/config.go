package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	GRPCAddress              string
	DatabaseURL              string
	DependencyClientsEnabled bool
	AuthorizationGRPCTarget  string
	ZitiManagementGRPCTarget string
	IdentityGRPCTarget       string
	GroupsGRPCTarget         string
	NotificationsGRPCTarget  string
	NATSURL                  string
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
	cfg.NotificationsGRPCTarget = os.Getenv("NOTIFICATIONS_GRPC_TARGET")
	if cfg.NotificationsGRPCTarget == "" {
		cfg.NotificationsGRPCTarget = "notifications:50051"
	}
	cfg.NATSURL = os.Getenv("NATS_URL")
	return cfg, nil
}
