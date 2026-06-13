package store

import (
	"strings"
	"testing"

	"github.com/agynio/networks/migrations"
	"github.com/stretchr/testify/require"
)

func TestInitialMigrationDefinesNetworksModel(t *testing.T) {
	content, err := migrations.Files.ReadFile("0001_init.sql")
	require.NoError(t, err)
	sql := string(content)

	for _, expected := range []string{
		"CREATE TYPE provisioning_state AS ENUM ('active', 'failed', 'removing')",
		"CREATE TYPE private_resource_protocol AS ENUM ('tcp', 'http', 'https')",
		"CREATE TYPE private_resource_access_principal_type AS ENUM ('agent', 'user', 'app', 'group')",
		"CREATE TABLE networks",
		"CREATE TABLE tunnel_credentials",
		"CREATE TABLE private_resources",
		"CREATE TABLE private_resource_intercept_ports",
		"CREATE TABLE private_resource_accesses",
		"REFERENCES networks(id) ON DELETE CASCADE",
		"REFERENCES private_resources(id) ON DELETE CASCADE",
		"CHECK (cardinality(target_ports) = cardinality(intercept_ports))",
		"UNIQUE (organization_id, intercept_host, intercept_port)",
		"UNIQUE (private_resource_id, principal_type, principal_id)",
	} {
		require.Contains(t, sql, expected)
	}
	require.False(t, strings.Contains(sql, "runner"))
}
