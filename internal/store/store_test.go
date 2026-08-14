package store

import (
	"context"
	"os"
	"testing"
	"time"

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

func TestStorePrivateResourceAccessImmutableUnique(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	orgID := uuid.New()
	networkID := uuid.New()
	resourceID := uuid.New()
	principalID := uuid.New()
	_, err := store.CreateNetwork(ctx, CreateNetworkInput{ID: networkID, OrganizationID: orgID, Name: "corp"})
	require.NoError(t, err)
	_, err = store.CreatePrivateResource(ctx, CreatePrivateResourceInput{
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

	input := CreatePrivateResourceAccessInput{ID: uuid.New(), PrivateResourceID: resourceID, PrincipalType: PrincipalTypeUser, PrincipalID: principalID}
	_, err = store.CreatePrivateResourceAccess(ctx, input)
	require.NoError(t, err)
	input.ID = uuid.New()
	_, err = store.CreatePrivateResourceAccess(ctx, input)
	require.ErrorAs(t, err, new(*AlreadyExistsError))
}

func TestStoreUpdatePrivateResourceRewritesInterceptUniqueness(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	orgID := uuid.New()
	networkID := uuid.New()
	resourceID := uuid.New()
	_, err := store.CreateNetwork(ctx, CreateNetworkInput{ID: networkID, OrganizationID: orgID, Name: "corp"})
	require.NoError(t, err)
	_, err = store.CreatePrivateResource(ctx, CreatePrivateResourceInput{
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
	interceptHost := "postgres2.private.example.com"
	updated, err := store.UpdatePrivateResource(ctx, UpdatePrivateResourceInput{ID: resourceID, InterceptHost: &interceptHost})
	require.NoError(t, err)
	require.Equal(t, interceptHost, updated.InterceptHost)

	_, err = store.CreatePrivateResource(ctx, CreatePrivateResourceInput{
		ID:             uuid.New(),
		OrganizationID: orgID,
		NetworkID:      networkID,
		Name:           "postgres-old-host",
		Protocol:       PrivateResourceProtocolTCP,
		TargetHost:     "postgres-old.internal",
		TargetPorts:    []int32{5432},
		InterceptHost:  "postgres.private.example.com",
		InterceptPorts: []int32{15432},
	})
	require.NoError(t, err)
}

func TestStoreProvisioningLivenessAndGroupGrantQueries(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	orgID := uuid.New()
	networkID := uuid.New()
	resourceID := uuid.New()
	credentialID := uuid.New()
	groupID := uuid.New()
	accessID := uuid.New()
	expiresAt := time.Now().UTC().Add(time.Hour)
	enrolledAt := time.Now().UTC()
	lastSeenAt := enrolledAt.Add(time.Minute)

	_, err := store.CreateNetwork(ctx, CreateNetworkInput{ID: networkID, OrganizationID: orgID, Name: "corp"})
	require.NoError(t, err)
	network, err := store.UpdateNetworkProvisioning(ctx, networkID, ProvisioningStateFailed, "bind-policy")
	require.NoError(t, err)
	require.Equal(t, ProvisioningStateFailed, network.ProvisioningState)
	require.Equal(t, "bind-policy", network.OpenZitiBindPolicyID)

	_, err = store.CreateTunnelCredential(ctx, CreateTunnelCredentialInput{ID: credentialID, NetworkID: networkID})
	require.NoError(t, err)
	credential, err := store.UpdateTunnelCredentialProvisioning(ctx, credentialID, ProvisioningStateActive, "identity", true, &expiresAt)
	require.NoError(t, err)
	require.Equal(t, "identity", credential.OpenZitiIdentityID)
	require.True(t, credential.EnrollmentJWTRevealed)
	credential, err = store.UpdateTunnelCredentialLiveness(ctx, UpdateTunnelCredentialLivenessInput{ID: credentialID, EnrollmentState: TunnelEnrollmentStateEnrolled, Connectivity: TunnelConnectivityOnline, EnrolledAt: &enrolledAt, LastSeenAt: &lastSeenAt})
	require.NoError(t, err)
	require.Equal(t, TunnelEnrollmentStateEnrolled, credential.EnrollmentState)
	require.Equal(t, TunnelConnectivityOnline, credential.Connectivity)

	_, err = store.CreatePrivateResource(ctx, CreatePrivateResourceInput{ID: resourceID, OrganizationID: orgID, NetworkID: networkID, Name: "postgres", Protocol: PrivateResourceProtocolTCP, TargetHost: "postgres.internal", TargetPorts: []int32{5432}, InterceptHost: "postgres.private.example.com", InterceptPorts: []int32{15432}})
	require.NoError(t, err)
	resource, err := store.UpdatePrivateResourceProvisioning(ctx, resourceID, ProvisioningStateFailed, "service")
	require.NoError(t, err)
	require.Equal(t, "service", resource.OpenZitiServiceID)

	_, err = store.CreatePrivateResourceAccess(ctx, CreatePrivateResourceAccessInput{ID: accessID, PrivateResourceID: resourceID, PrincipalType: PrincipalTypeGroup, PrincipalID: groupID})
	require.NoError(t, err)
	access, err := store.UpdatePrivateResourceAccessProvisioning(ctx, accessID, ProvisioningStateFailed, "dial-policy")
	require.NoError(t, err)
	require.Equal(t, "dial-policy", access.OpenZitiDialPolicyID)

	networks, err := store.ListAllNetworks(ctx)
	require.NoError(t, err)
	require.Len(t, networks, 1)
	credentials, err := store.ListAllTunnelCredentials(ctx)
	require.NoError(t, err)
	require.Len(t, credentials, 1)
	resources, err := store.ListAllPrivateResources(ctx)
	require.NoError(t, err)
	require.Len(t, resources, 1)
	accesses, err := store.ListAllPrivateResourceAccess(ctx)
	require.NoError(t, err)
	require.Len(t, accesses, 1)
	credentials, err = store.ListAllTunnelCredentialsFiltered(ctx, ListTunnelCredentialsFilter{NetworkID: &networkID})
	require.NoError(t, err)
	require.Len(t, credentials, 1)
	resources, err = store.ListAllPrivateResourcesFiltered(ctx, ListPrivateResourcesFilterAll{NetworkID: &networkID})
	require.NoError(t, err)
	require.Len(t, resources, 1)
	accesses, err = store.ListAllPrivateResourceAccessFiltered(ctx, ListPrivateResourceAccessFilterAll{NetworkID: &networkID})
	require.NoError(t, err)
	require.Len(t, accesses, 1)
	accesses, err = store.ListAllPrivateResourceAccessFiltered(ctx, ListPrivateResourceAccessFilterAll{PrivateResourceID: &resourceID})
	require.NoError(t, err)
	require.Len(t, accesses, 1)
	groupAccesses, err := store.ListPrivateResourceAccessByGroupID(ctx, groupID)
	require.NoError(t, err)
	require.Len(t, groupAccesses, 1)
	require.NoError(t, store.DeletePrivateResourceAccess(ctx, accessID))
	groupAccesses, err = store.ListPrivateResourceAccessByGroupID(ctx, groupID)
	require.NoError(t, err)
	require.Empty(t, groupAccesses)
}

func TestStoreMediationRoundTrip(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	orgID := uuid.New()
	networkID := uuid.New()
	resourceID := uuid.New()

	_, err := store.CreateNetwork(ctx, CreateNetworkInput{ID: networkID, OrganizationID: orgID, Name: "corp"})
	require.NoError(t, err)
	resource, err := store.CreatePrivateResource(ctx, CreatePrivateResourceInput{
		ID: resourceID, OrganizationID: orgID, NetworkID: networkID, Name: "gitlab",
		Protocol: PrivateResourceProtocolHTTPS, TargetHost: "gitlab.lan",
		TargetPorts: []int32{8443, 8080}, InterceptHost: "gitlab.corp", InterceptPorts: []int32{443, 80},
	})
	require.NoError(t, err)
	require.Equal(t, MediationTunnel, resource.Mediation)
	require.Empty(t, resource.OpenZitiUpstreamServiceIDs)

	resource, err = store.UpdatePrivateResourceMediation(ctx, resourceID, MediationEgressGateway, ProvisioningStateActive, map[int32]string{443: "svc-443", 80: "svc-80"}, "policy-1")
	require.NoError(t, err)
	require.Equal(t, MediationEgressGateway, resource.Mediation)
	require.Equal(t, map[int32]string{443: "svc-443", 80: "svc-80"}, resource.OpenZitiUpstreamServiceIDs)
	require.Equal(t, "policy-1", resource.OpenZitiGatewayDialPolicyID)

	fetched, err := store.GetPrivateResource(ctx, resourceID)
	require.NoError(t, err)
	require.Equal(t, map[int32]string{443: "svc-443", 80: "svc-80"}, fetched.OpenZitiUpstreamServiceIDs)

	resource, err = store.UpdatePrivateResourceMediation(ctx, resourceID, MediationTunnel, ProvisioningStateActive, nil, "")
	require.NoError(t, err)
	require.Equal(t, MediationTunnel, resource.Mediation)
	require.Empty(t, resource.OpenZitiUpstreamServiceIDs)

	principals := []Principal{{Type: PrincipalTypeAgent, ID: uuid.New()}}
	reachable, err := store.ListPrivateResourceAccessByPrincipals(ctx, principals)
	require.NoError(t, err)
	require.Empty(t, reachable)
	_, err = store.CreatePrivateResourceAccess(ctx, CreatePrivateResourceAccessInput{ID: uuid.New(), PrivateResourceID: resourceID, PrincipalType: PrincipalTypeAgent, PrincipalID: principals[0].ID})
	require.NoError(t, err)
	reachable, err = store.ListPrivateResourceAccessByPrincipals(ctx, principals)
	require.NoError(t, err)
	require.Len(t, reachable, 1)
	byID, err := store.ListPrivateResourcesByIDs(ctx, []uuid.UUID{resourceID})
	require.NoError(t, err)
	require.Len(t, byID, 1)
	require.Equal(t, "gitlab.corp", byID[0].InterceptHost)
}
