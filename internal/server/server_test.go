package server

import (
	"context"
	"slices"
	"testing"
	"time"

	authorizationv1 "github.com/agynio/networks/.gen/go/agynio/api/authorization/v1"
	groupsv1 "github.com/agynio/networks/.gen/go/agynio/api/groups/v1"
	identityv1 "github.com/agynio/networks/.gen/go/agynio/api/identity/v1"
	networksv1 "github.com/agynio/networks/.gen/go/agynio/api/networks/v1"
	"github.com/agynio/networks/internal/store"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestCreateNetworkRequiresOwner(t *testing.T) {
	store := newFakeStore()
	authz := &fakeAuthorizationClient{allowed: map[string]bool{}}
	server := NewWithClients(store, authz, nil, nil, nil)
	callerID := uuid.New()
	orgID := uuid.New()
	_, err := server.CreateNetwork(callerContext(callerID), &networksv1.CreateNetworkRequest{OrganizationId: orgID.String(), Name: "corp"})
	assertCode(t, err, codes.PermissionDenied)

	authz.allow(identityObject(callerID), organizationOwnerRelation, organizationObject(orgID))
	response, err := server.CreateNetwork(callerContext(callerID), &networksv1.CreateNetworkRequest{OrganizationId: orgID.String(), Name: "corp"})
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if response.GetNetwork().GetOrganizationId() != orgID.String() {
		t.Fatalf("expected org %s, got %s", orgID, response.GetNetwork().GetOrganizationId())
	}
}

func TestCreatePrivateResourceValidatesPortsAndHost(t *testing.T) {
	store := newFakeStore()
	authz := &fakeAuthorizationClient{allowed: map[string]bool{}}
	server := NewWithClients(store, authz, nil, nil, nil)
	callerID := uuid.New()
	orgID := uuid.New()
	network := store.mustCreateNetwork(orgID)
	authz.allow(identityObject(callerID), organizationOwnerRelation, organizationObject(orgID))

	_, err := server.CreatePrivateResource(callerContext(callerID), &networksv1.CreatePrivateResourceRequest{
		NetworkId:      network.Meta.ID.String(),
		Name:           "postgres",
		Protocol:       networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_TCP,
		TargetHost:     "postgres.internal",
		TargetPorts:    []int32{5432},
		InterceptHost:  "postgres.agyn",
		InterceptPorts: []int32{15432},
	})
	assertCode(t, err, codes.InvalidArgument)

	_, err = server.CreatePrivateResource(callerContext(callerID), &networksv1.CreatePrivateResourceRequest{
		NetworkId:      network.Meta.ID.String(),
		Name:           "postgres",
		Protocol:       networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_TCP,
		TargetHost:     "postgres.internal",
		TargetPorts:    []int32{5432},
		InterceptHost:  "postgres.private.example.com",
		InterceptPorts: []int32{15432, 15433},
	})
	assertCode(t, err, codes.InvalidArgument)
}

func TestCreatePrivateResourcePreservesPortMappingOrder(t *testing.T) {
	store := newFakeStore()
	authz := &fakeAuthorizationClient{allowed: map[string]bool{}}
	server := NewWithClients(store, authz, nil, nil, nil)
	callerID := uuid.New()
	orgID := uuid.New()
	network := store.mustCreateNetwork(orgID)
	authz.allow(identityObject(callerID), organizationOwnerRelation, organizationObject(orgID))

	response, err := server.CreatePrivateResource(callerContext(callerID), &networksv1.CreatePrivateResourceRequest{
		NetworkId:      network.Meta.ID.String(),
		Name:           "postgres",
		Protocol:       networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_TCP,
		TargetHost:     "postgres.internal",
		TargetPorts:    []int32{5433, 5432},
		InterceptHost:  "postgres.private.example.com",
		InterceptPorts: []int32{15432, 15433},
	})
	if err != nil {
		t.Fatalf("CreatePrivateResource: %v", err)
	}
	assertInt32Slice(t, response.GetPrivateResource().GetTargetPorts(), []int32{5433, 5432})
	assertInt32Slice(t, response.GetPrivateResource().GetInterceptPorts(), []int32{15432, 15433})
}

func TestUpdatePrivateResourcePreservesPortMappingOrder(t *testing.T) {
	store := newFakeStore()
	authz := &fakeAuthorizationClient{allowed: map[string]bool{}}
	server := NewWithClients(store, authz, nil, nil, nil)
	callerID := uuid.New()
	orgID := uuid.New()
	resource := store.mustCreatePrivateResource(store.mustCreateNetwork(orgID))
	authz.allow(identityObject(callerID), organizationOwnerRelation, organizationObject(orgID))

	response, err := server.UpdatePrivateResource(callerContext(callerID), &networksv1.UpdatePrivateResourceRequest{
		Id:                   resource.Meta.ID.String(),
		TargetPortsUpdate:    &networksv1.PortListUpdate{Ports: []int32{9443, 8443}},
		InterceptPortsUpdate: &networksv1.PortListUpdate{Ports: []int32{443, 8443}},
	})
	if err != nil {
		t.Fatalf("UpdatePrivateResource: %v", err)
	}
	assertInt32Slice(t, response.GetPrivateResource().GetTargetPorts(), []int32{9443, 8443})
	assertInt32Slice(t, response.GetPrivateResource().GetInterceptPorts(), []int32{443, 8443})
}

func TestCreatePrivateResourceAccessRejectsCrossOrgUser(t *testing.T) {
	store := newFakeStore()
	authz := &fakeAuthorizationClient{allowed: map[string]bool{}}
	identity := &fakeIdentityClient{types: map[string]identityv1.IdentityType{}}
	server := NewWithClients(store, authz, identity, nil, nil)
	callerID := uuid.New()
	orgID := uuid.New()
	principalID := uuid.New()
	resource := store.mustCreatePrivateResource(store.mustCreateNetwork(orgID))
	authz.allow(identityObject(callerID), organizationOwnerRelation, organizationObject(orgID))
	identity.types[principalID.String()] = identityv1.IdentityType_IDENTITY_TYPE_USER

	_, err := server.CreatePrivateResourceAccess(callerContext(callerID), &networksv1.CreatePrivateResourceAccessRequest{
		PrivateResourceId: resource.Meta.ID.String(),
		PrincipalType:     networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_USER,
		PrincipalId:       principalID.String(),
	})
	assertCode(t, err, codes.InvalidArgument)
}

func TestCreatePrivateResourceAccessAgentUsesCanEditConfig(t *testing.T) {
	store := newFakeStore()
	authz := &fakeAuthorizationClient{allowed: map[string]bool{}}
	identity := &fakeIdentityClient{types: map[string]identityv1.IdentityType{}}
	server := NewWithClients(store, authz, identity, nil, nil)
	callerID := uuid.New()
	orgID := uuid.New()
	agentID := uuid.New()
	resource := store.mustCreatePrivateResource(store.mustCreateNetwork(orgID))
	identity.types[agentID.String()] = identityv1.IdentityType_IDENTITY_TYPE_AGENT
	authz.allow(identityObject(agentID), organizationMemberRelation, organizationObject(orgID))

	_, err := server.CreatePrivateResourceAccess(callerContext(callerID), &networksv1.CreatePrivateResourceAccessRequest{
		PrivateResourceId: resource.Meta.ID.String(),
		PrincipalType:     networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_AGENT,
		PrincipalId:       agentID.String(),
	})
	assertCode(t, err, codes.PermissionDenied)

	authz.allow(identityObject(callerID), agentCanEditConfigRelation, agentObject(agentID))
	_, err = server.CreatePrivateResourceAccess(callerContext(callerID), &networksv1.CreatePrivateResourceAccessRequest{
		PrivateResourceId: resource.Meta.ID.String(),
		PrincipalType:     networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_AGENT,
		PrincipalId:       agentID.String(),
	})
	if err != nil {
		t.Fatalf("CreatePrivateResourceAccess: %v", err)
	}
}

func TestCreatePrivateResourceAccessRejectsCrossOrgGroup(t *testing.T) {
	store := newFakeStore()
	authz := &fakeAuthorizationClient{allowed: map[string]bool{}}
	groups := &fakeGroupsClient{groups: map[string]*groupsv1.Group{}}
	server := NewWithClients(store, authz, nil, groups, nil)
	callerID := uuid.New()
	orgID := uuid.New()
	otherOrgID := uuid.New()
	groupID := uuid.New()
	resource := store.mustCreatePrivateResource(store.mustCreateNetwork(orgID))
	authz.allow(identityObject(callerID), organizationOwnerRelation, organizationObject(orgID))
	groups.groups[groupID.String()] = &groupsv1.Group{Meta: &groupsv1.EntityMeta{Id: groupID.String()}, OrganizationId: otherOrgID.String()}

	_, err := server.CreatePrivateResourceAccess(callerContext(callerID), &networksv1.CreatePrivateResourceAccessRequest{
		PrivateResourceId: resource.Meta.ID.String(),
		PrincipalType:     networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_GROUP,
		PrincipalId:       groupID.String(),
	})
	assertCode(t, err, codes.InvalidArgument)
}

func callerContext(identityID uuid.UUID) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(identityIDMetadataKey, identityID.String()))
}

func assertCode(t *testing.T, err error, code codes.Code) {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("expected code %s, got %s err=%v", code, status.Code(err), err)
	}
}

func assertInt32Slice(t *testing.T, got []int32, want []int32) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

type fakeAuthorizationClient struct {
	authorizationv1.UnimplementedAuthorizationServiceServer
	allowed map[string]bool
}

func (f *fakeAuthorizationClient) allow(user string, relation string, object string) {
	f.allowed[user+"|"+relation+"|"+object] = true
}

func (f *fakeAuthorizationClient) Check(_ context.Context, request *authorizationv1.CheckRequest, _ ...grpc.CallOption) (*authorizationv1.CheckResponse, error) {
	key := request.GetTupleKey()
	return &authorizationv1.CheckResponse{Allowed: f.allowed[key.GetUser()+"|"+key.GetRelation()+"|"+key.GetObject()]}, nil
}

type fakeIdentityClient struct {
	types map[string]identityv1.IdentityType
}

func (f *fakeIdentityClient) GetIdentityType(_ context.Context, request *identityv1.GetIdentityTypeRequest, _ ...grpc.CallOption) (*identityv1.GetIdentityTypeResponse, error) {
	identityType, ok := f.types[request.GetIdentityId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "identity not found")
	}
	return &identityv1.GetIdentityTypeResponse{IdentityType: identityType}, nil
}

type fakeGroupsClient struct {
	groups       map[string]*groupsv1.Group
	memberGroups map[string][]*groupsv1.Group
}

func (f *fakeGroupsClient) GetGroup(_ context.Context, request *groupsv1.GetGroupRequest, _ ...grpc.CallOption) (*groupsv1.GetGroupResponse, error) {
	group, ok := f.groups[request.GetId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "group not found")
	}
	return &groupsv1.GetGroupResponse{Group: group}, nil
}

func (f *fakeGroupsClient) ListMemberGroupsBatch(_ context.Context, request *groupsv1.ListMemberGroupsBatchRequest, _ ...grpc.CallOption) (*groupsv1.ListMemberGroupsBatchResponse, error) {
	response := &groupsv1.ListMemberGroupsBatchResponse{}
	for _, member := range request.GetMembers() {
		response.Entries = append(response.Entries, &groupsv1.ListMemberGroupsBatchEntry{
			MemberType: member.GetMemberType(),
			MemberId:   member.GetMemberId(),
			Groups:     f.memberGroups[member.GetMemberId()],
		})
	}
	return response, nil
}

type fakeStore struct {
	networks    map[uuid.UUID]store.Network
	resources   map[uuid.UUID]store.PrivateResource
	accesses    map[uuid.UUID]store.PrivateResourceAccess
	credentials map[uuid.UUID]store.TunnelCredential
}

func newFakeStore() *fakeStore {
	return &fakeStore{networks: map[uuid.UUID]store.Network{}, resources: map[uuid.UUID]store.PrivateResource{}, accesses: map[uuid.UUID]store.PrivateResourceAccess{}, credentials: map[uuid.UUID]store.TunnelCredential{}}
}

func (f *fakeStore) mustCreateNetwork(orgID uuid.UUID) store.Network {
	network, err := f.CreateNetwork(context.Background(), store.CreateNetworkInput{ID: uuid.New(), OrganizationID: orgID, Name: uuid.NewString()})
	if err != nil {
		panic(err)
	}
	return network
}

func (f *fakeStore) mustCreatePrivateResource(network store.Network) store.PrivateResource {
	resource, err := f.CreatePrivateResource(context.Background(), store.CreatePrivateResourceInput{ID: uuid.New(), OrganizationID: network.OrganizationID, NetworkID: network.Meta.ID, Name: uuid.NewString(), Protocol: store.PrivateResourceProtocolTCP, TargetHost: "db.internal", TargetPorts: []int32{5432}, InterceptHost: uuid.NewString() + ".example.com", InterceptPorts: []int32{15432}})
	if err != nil {
		panic(err)
	}
	return resource
}

func (f *fakeStore) mustCreateTunnelCredential(network store.Network) store.TunnelCredential {
	credential, err := f.CreateTunnelCredential(context.Background(), store.CreateTunnelCredentialInput{ID: uuid.New(), NetworkID: network.Meta.ID})
	if err != nil {
		panic(err)
	}
	return credential
}

func fakeMeta(id uuid.UUID) store.EntityMeta {
	now := time.Now().UTC()
	return store.EntityMeta{ID: id, CreatedAt: now, UpdatedAt: now}
}

func (f *fakeStore) CreateNetwork(_ context.Context, input store.CreateNetworkInput) (store.Network, error) {
	network := store.Network{Meta: fakeMeta(input.ID), OrganizationID: input.OrganizationID, Name: input.Name, Description: input.Description, ProvisioningState: store.ProvisioningStateActive}
	f.networks[input.ID] = network
	return network, nil
}

func (f *fakeStore) GetNetwork(_ context.Context, id uuid.UUID) (store.Network, error) {
	network, ok := f.networks[id]
	if !ok {
		return store.Network{}, store.NotFound("network")
	}
	return network, nil
}

func (f *fakeStore) ListNetworks(context.Context, uuid.UUID, int32, *store.PageCursor) ([]store.Network, *store.PageCursor, error) {
	return nil, nil, nil
}

func (f *fakeStore) UpdateNetwork(_ context.Context, input store.UpdateNetworkInput) (store.Network, error) {
	network := f.networks[input.ID]
	if input.Name != nil {
		network.Name = *input.Name
	}
	if input.Description != nil {
		network.Description = *input.Description
	}
	f.networks[input.ID] = network
	return network, nil
}

func (f *fakeStore) DeleteNetwork(_ context.Context, id uuid.UUID) error {
	delete(f.networks, id)
	return nil
}

func (f *fakeStore) CreateTunnelCredential(_ context.Context, input store.CreateTunnelCredentialInput) (store.TunnelCredential, error) {
	network := f.networks[input.NetworkID]
	credential := store.TunnelCredential{Meta: fakeMeta(input.ID), NetworkID: input.NetworkID, OrganizationID: network.OrganizationID, OpenZitiIdentityID: input.OpenZitiIdentityID, EnrollmentJWTRevealed: input.EnrollmentJWTRevealed, EnrollmentJWTExpiresAt: input.EnrollmentJWTExpiresAt, EnrollmentState: store.TunnelEnrollmentStatePending, Connectivity: store.TunnelConnectivityOffline, ProvisioningState: input.ProvisioningState}
	f.credentials[input.ID] = credential
	return credential, nil
}

func (f *fakeStore) GetTunnelCredential(_ context.Context, id uuid.UUID) (store.TunnelCredential, error) {
	return f.credentials[id], nil
}
func (f *fakeStore) ListTunnelCredentials(context.Context, uuid.UUID, int32, *store.PageCursor) ([]store.TunnelCredential, *store.PageCursor, error) {
	return nil, nil, nil
}
func (f *fakeStore) DeleteTunnelCredential(context.Context, uuid.UUID) error { return nil }

func (f *fakeStore) CreatePrivateResource(_ context.Context, input store.CreatePrivateResourceInput) (store.PrivateResource, error) {
	resource := store.PrivateResource{Meta: fakeMeta(input.ID), OrganizationID: input.OrganizationID, NetworkID: input.NetworkID, Name: input.Name, Protocol: input.Protocol, TargetHost: input.TargetHost, TargetPorts: input.TargetPorts, InterceptHost: input.InterceptHost, InterceptPorts: input.InterceptPorts, ProvisioningState: store.ProvisioningStateActive}
	f.resources[input.ID] = resource
	return resource, nil
}

func (f *fakeStore) GetPrivateResource(_ context.Context, id uuid.UUID) (store.PrivateResource, error) {
	return f.resources[id], nil
}
func (f *fakeStore) ListPrivateResources(context.Context, store.ListPrivateResourcesFilter, int32, *store.PageCursor) ([]store.PrivateResource, *store.PageCursor, error) {
	return nil, nil, nil
}
func (f *fakeStore) UpdatePrivateResource(_ context.Context, input store.UpdatePrivateResourceInput) (store.PrivateResource, error) {
	resource := f.resources[input.ID]
	if input.Name != nil {
		resource.Name = *input.Name
	}
	if input.Protocol != nil {
		resource.Protocol = *input.Protocol
	}
	if input.TargetHost != nil {
		resource.TargetHost = *input.TargetHost
	}
	if input.InterceptHost != nil {
		resource.InterceptHost = *input.InterceptHost
	}
	if input.UpdatePorts {
		resource.TargetPorts = input.TargetPorts
		resource.InterceptPorts = input.InterceptPorts
	}
	f.resources[input.ID] = resource
	return resource, nil
}
func (f *fakeStore) DeletePrivateResource(context.Context, uuid.UUID) error { return nil }

func (f *fakeStore) CreatePrivateResourceAccess(_ context.Context, input store.CreatePrivateResourceAccessInput) (store.PrivateResourceAccess, error) {
	resource := f.resources[input.PrivateResourceID]
	access := store.PrivateResourceAccess{Meta: fakeMeta(input.ID), PrivateResourceID: input.PrivateResourceID, OrganizationID: resource.OrganizationID, NetworkID: resource.NetworkID, PrincipalType: input.PrincipalType, PrincipalID: input.PrincipalID, ProvisioningState: store.ProvisioningStateActive}
	f.accesses[input.ID] = access
	return access, nil
}

func (f *fakeStore) GetPrivateResourceAccess(_ context.Context, id uuid.UUID) (store.PrivateResourceAccess, error) {
	return f.accesses[id], nil
}
func (f *fakeStore) ListPrivateResourceAccess(context.Context, store.ListPrivateResourceAccessFilter, int32, *store.PageCursor) ([]store.PrivateResourceAccess, *store.PageCursor, error) {
	return nil, nil, nil
}
func (f *fakeStore) DeletePrivateResourceAccess(_ context.Context, id uuid.UUID) error {
	delete(f.accesses, id)
	return nil
}

func (f *fakeStore) UpdateNetworkProvisioning(_ context.Context, id uuid.UUID, state store.ProvisioningState, openZitiBindPolicyID string) (store.Network, error) {
	network := f.networks[id]
	network.ProvisioningState = state
	network.OpenZitiBindPolicyID = openZitiBindPolicyID
	f.networks[id] = network
	return network, nil
}

func (f *fakeStore) UpdateTunnelCredentialProvisioning(_ context.Context, id uuid.UUID, state store.ProvisioningState, openZitiIdentityID string, enrollmentJWTRevealed bool, enrollmentJWTExpiresAt *time.Time) (store.TunnelCredential, error) {
	credential := f.credentials[id]
	credential.ProvisioningState = state
	credential.OpenZitiIdentityID = openZitiIdentityID
	credential.EnrollmentJWTRevealed = enrollmentJWTRevealed
	credential.EnrollmentJWTExpiresAt = enrollmentJWTExpiresAt
	f.credentials[id] = credential
	return credential, nil
}

func (f *fakeStore) UpdatePrivateResourceProvisioning(_ context.Context, id uuid.UUID, state store.ProvisioningState, openZitiServiceID string) (store.PrivateResource, error) {
	resource := f.resources[id]
	resource.ProvisioningState = state
	resource.OpenZitiServiceID = openZitiServiceID
	f.resources[id] = resource
	return resource, nil
}

func (f *fakeStore) UpdatePrivateResourceAccessProvisioning(_ context.Context, id uuid.UUID, state store.ProvisioningState, openZitiDialPolicyID string) (store.PrivateResourceAccess, error) {
	access := f.accesses[id]
	access.ProvisioningState = state
	access.OpenZitiDialPolicyID = openZitiDialPolicyID
	f.accesses[id] = access
	return access, nil
}

var _ Store = (*fakeStore)(nil)

func (f *fakeStore) ListAllNetworksByOrganization(_ context.Context, organizationID uuid.UUID) ([]store.Network, error) {
	values := make([]store.Network, 0, len(f.networks))
	for _, value := range f.networks {
		if value.OrganizationID == organizationID {
			values = append(values, value)
		}
	}
	return values, nil
}

func (f *fakeStore) ListAllNetworks(context.Context) ([]store.Network, error) {
	values := make([]store.Network, 0, len(f.networks))
	for _, value := range f.networks {
		values = append(values, value)
	}
	return values, nil
}

func (f *fakeStore) ListAllTunnelCredentials(context.Context) ([]store.TunnelCredential, error) {
	values := make([]store.TunnelCredential, 0, len(f.credentials))
	for _, value := range f.credentials {
		values = append(values, value)
	}
	return values, nil
}

func (f *fakeStore) UpdateTunnelCredentialLiveness(_ context.Context, input store.UpdateTunnelCredentialLivenessInput) (store.TunnelCredential, error) {
	credential := f.credentials[input.ID]
	credential.EnrollmentState = input.EnrollmentState
	credential.Connectivity = input.Connectivity
	credential.EnrolledAt = input.EnrolledAt
	credential.LastSeenAt = input.LastSeenAt
	f.credentials[input.ID] = credential
	return credential, nil
}

func (f *fakeStore) ListAllPrivateResources(context.Context) ([]store.PrivateResource, error) {
	values := make([]store.PrivateResource, 0, len(f.resources))
	for _, value := range f.resources {
		values = append(values, value)
	}
	return values, nil
}

func (f *fakeStore) ListAllPrivateResourceAccess(context.Context) ([]store.PrivateResourceAccess, error) {
	values := make([]store.PrivateResourceAccess, 0, len(f.accesses))
	for _, value := range f.accesses {
		values = append(values, value)
	}
	return values, nil
}

func (f *fakeStore) ListPrivateResourceAccessByGroupID(_ context.Context, groupID uuid.UUID) ([]store.PrivateResourceAccess, error) {
	values := []store.PrivateResourceAccess{}
	for _, value := range f.accesses {
		if value.PrincipalType == store.PrincipalTypeGroup && value.PrincipalID == groupID {
			values = append(values, value)
		}
	}
	return values, nil
}

func (f *fakeStore) UpdatePrivateResourceMediation(_ context.Context, id uuid.UUID, mediation store.Mediation, state store.ProvisioningState, upstreamServiceIDs map[int32]string, gatewayDialPolicyID string) (store.PrivateResource, error) {
	resource, ok := f.resources[id]
	if !ok {
		return store.PrivateResource{}, store.NotFound("private resource")
	}
	resource.Mediation = mediation
	resource.ProvisioningState = state
	resource.OpenZitiUpstreamServiceIDs = upstreamServiceIDs
	resource.OpenZitiGatewayDialPolicyID = gatewayDialPolicyID
	f.resources[id] = resource
	return resource, nil
}

func (f *fakeStore) ListPrivateResourceAccessByPrincipals(_ context.Context, principals []store.Principal) ([]store.PrivateResourceAccess, error) {
	values := []store.PrivateResourceAccess{}
	for _, value := range f.accesses {
		for _, principal := range principals {
			if value.PrincipalType == principal.Type && value.PrincipalID == principal.ID {
				values = append(values, value)
				break
			}
		}
	}
	return values, nil
}

func (f *fakeStore) ListPrivateResourcesByIDs(_ context.Context, ids []uuid.UUID) ([]store.PrivateResource, error) {
	values := []store.PrivateResource{}
	for _, id := range ids {
		if resource, ok := f.resources[id]; ok {
			values = append(values, resource)
		}
	}
	return values, nil
}

func (f *fakeStore) ListAllTunnelCredentialsFiltered(_ context.Context, filter store.ListTunnelCredentialsFilter) ([]store.TunnelCredential, error) {
	values := []store.TunnelCredential{}
	for _, value := range f.credentials {
		if filter.NetworkID != nil && value.NetworkID != *filter.NetworkID {
			continue
		}
		values = append(values, value)
	}
	return values, nil
}

func (f *fakeStore) ListAllPrivateResourcesFiltered(_ context.Context, filter store.ListPrivateResourcesFilterAll) ([]store.PrivateResource, error) {
	values := []store.PrivateResource{}
	for _, value := range f.resources {
		if filter.NetworkID != nil && value.NetworkID != *filter.NetworkID {
			continue
		}
		values = append(values, value)
	}
	return values, nil
}

func (f *fakeStore) ListAllPrivateResourceAccessFiltered(_ context.Context, filter store.ListPrivateResourceAccessFilterAll) ([]store.PrivateResourceAccess, error) {
	values := []store.PrivateResourceAccess{}
	for _, value := range f.accesses {
		if filter.PrivateResourceID != nil && value.PrivateResourceID != *filter.PrivateResourceID {
			continue
		}
		if filter.NetworkID != nil && value.NetworkID != *filter.NetworkID {
			continue
		}
		values = append(values, value)
	}
	return values, nil
}
