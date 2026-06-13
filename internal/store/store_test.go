package store

import (
	"context"
	"os"
	"testing"

	"github.com/agynio/networks/internal/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestStoreCRUDAndCascade(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	orgID := uuid.New()
	networkID := uuid.New()
	resourceID := uuid.New()
	credentialID := uuid.New()
	accessID := uuid.New()

	network, err := store.CreateNetwork(ctx, CreateNetworkInput{ID: networkID, OrganizationID: orgID, Name: "corp", Description: "Corp network"})
	require.NoError(t, err)
	require.Equal(t, ProvisioningStateActive, network.ProvisioningState)

	_, err = store.CreateTunnelCredential(ctx, CreateTunnelCredentialInput{ID: credentialID, NetworkID: networkID, OpenZitiIdentityID: "ziti-id", EnrollmentJWTRevealed: true})
	require.NoError(t, err)

	resource, err := store.CreatePrivateResource(ctx, CreatePrivateResourceInput{
		ID:             resourceID,
		OrganizationID: orgID,
		NetworkID:      networkID,
		Name:           "postgres",
		Protocol:       PrivateResourceProtocolTCP,
		TargetHost:     "postgres.internal",
		TargetPorts:    []int32{5432},
		InterceptHost:  "postgres.private.example.com",
		InterceptPorts: []int32{15432},
	})
	require.NoError(t, err)
	require.Equal(t, []int32{5432}, resource.TargetPorts)

	_, err = store.CreatePrivateResourceAccess(ctx, CreatePrivateResourceAccessInput{ID: accessID, PrivateResourceID: resourceID, PrincipalType: PrincipalTypeGroup, PrincipalID: uuid.New()})
	require.NoError(t, err)

	require.NoError(t, store.DeleteNetwork(ctx, networkID))
	_, err = store.GetNetwork(ctx, networkID)
	require.ErrorAs(t, err, new(*NotFoundError))
	_, err = store.GetTunnelCredential(ctx, credentialID)
	require.ErrorAs(t, err, new(*NotFoundError))
	_, err = store.GetPrivateResource(ctx, resourceID)
	require.ErrorAs(t, err, new(*NotFoundError))
}

func TestStoreEnforcesUniqueInterceptPort(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	orgID := uuid.New()
	networkID := uuid.New()
	_, err := store.CreateNetwork(ctx, CreateNetworkInput{ID: networkID, OrganizationID: orgID, Name: "corp"})
	require.NoError(t, err)

	input := CreatePrivateResourceInput{
		ID:             uuid.New(),
		OrganizationID: orgID,
		NetworkID:      networkID,
		Name:           "db1",
		Protocol:       PrivateResourceProtocolTCP,
		TargetHost:     "db1.internal",
		TargetPorts:    []int32{5432},
		InterceptHost:  "db.private.example.com",
		InterceptPorts: []int32{15432},
	}
	_, err = store.CreatePrivateResource(ctx, input)
	require.NoError(t, err)
	input.ID = uuid.New()
	input.Name = "db2"
	input.TargetHost = "db2.internal"
	_, err = store.CreatePrivateResource(ctx, input)
	require.ErrorAs(t, err, new(*AlreadyExistsError))
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	databaseURL := os.Getenv("NETWORKS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("NETWORKS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	_, err = pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`)
	require.NoError(t, err)
	require.NoError(t, db.ApplyMigrations(ctx, pool))
	return New(pool)
}
