package server

import (
	"context"
	"testing"
	"time"

	groupsv1 "github.com/agynio/networks/.gen/go/agynio/api/groups/v1"
	identityv1 "github.com/agynio/networks/.gen/go/agynio/api/identity/v1"
	networksv1 "github.com/agynio/networks/.gen/go/agynio/api/networks/v1"
	zitimgmtv1 "github.com/agynio/networks/.gen/go/agynio/api/ziti_management/v1"
	"github.com/agynio/networks/internal/store"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNetworkCreateProvisionsBindPolicy(t *testing.T) {
	fakeStore := newFakeStore()
	authz := &fakeAuthorizationClient{allowed: map[string]bool{}}
	ziti := &fakeZitiManagementClient{}
	server := NewWithClients(fakeStore, authz, nil, nil, ziti)
	callerID := uuid.New()
	orgID := uuid.New()
	authz.allow(identityObject(callerID), organizationOwnerRelation, organizationObject(orgID))

	response, err := server.CreateNetwork(callerContext(callerID), &networksv1.CreateNetworkRequest{OrganizationId: orgID.String(), Name: "corp"})
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if response.GetNetwork().GetProvisioningState() != networksv1.ProvisioningState_PROVISIONING_STATE_ACTIVE {
		t.Fatalf("expected active provisioning, got %s", response.GetNetwork().GetProvisioningState())
	}
	policy := ziti.createdServicePolicies[0]
	networkID := response.GetNetwork().GetMeta().GetId()
	assertStringSlice(t, policy.GetIdentityRoles(), []string{"#network-" + networkID})
	assertStringSlice(t, policy.GetServiceRoles(), []string{"#network-resources-" + networkID})
	if policy.GetType() != zitimgmtv1.ServicePolicyType_SERVICE_POLICY_TYPE_BIND {
		t.Fatalf("expected bind policy, got %s", policy.GetType())
	}
}

func TestTunnelCredentialJWTReturnedOnceAndNotStored(t *testing.T) {
	fakeStore := newFakeStore()
	authz := &fakeAuthorizationClient{allowed: map[string]bool{}}
	expiresAt := time.Now().UTC().Add(time.Hour)
	ziti := &fakeZitiManagementClient{tunnelIdentityID: "ziti-tunnel", enrollmentJWT: "secret-jwt", enrollmentExpiresAt: expiresAt}
	server := NewWithClients(fakeStore, authz, nil, nil, ziti)
	callerID := uuid.New()
	orgID := uuid.New()
	network := fakeStore.mustCreateNetwork(orgID)
	authz.allow(identityObject(callerID), organizationOwnerRelation, organizationObject(orgID))
	authz.allow(identityObject(callerID), organizationMemberRelation, organizationObject(orgID))

	created, err := server.CreateTunnelCredential(callerContext(callerID), &networksv1.CreateTunnelCredentialRequest{NetworkId: network.Meta.ID.String()})
	if err != nil {
		t.Fatalf("CreateTunnelCredential: %v", err)
	}
	if created.GetEnrollmentJwt() != "secret-jwt" {
		t.Fatalf("expected enrollment JWT returned once")
	}
	credentialID := created.GetTunnelCredential().GetMeta().GetId()
	read, err := server.GetTunnelCredential(callerContext(callerID), &networksv1.GetTunnelCredentialRequest{Id: credentialID})
	if err != nil {
		t.Fatalf("GetTunnelCredential: %v", err)
	}
	if read.GetTunnelCredential().GetEnrollmentJwtRevealed() != true {
		t.Fatalf("expected revealed flag")
	}
	stored := fakeStore.credentials[uuid.MustParse(credentialID)]
	if stored.OpenZitiIdentityID != "ziti-tunnel" {
		t.Fatalf("expected OpenZiti identity stored")
	}
}

func TestPrivateResourceServiceConfigsPreservePositionalPorts(t *testing.T) {
	fakeStore := newFakeStore()
	authz := &fakeAuthorizationClient{allowed: map[string]bool{}}
	ziti := &fakeZitiManagementClient{serviceID: "ziti-service"}
	server := NewWithClients(fakeStore, authz, nil, nil, ziti)
	callerID := uuid.New()
	orgID := uuid.New()
	network := fakeStore.mustCreateNetwork(orgID)
	authz.allow(identityObject(callerID), organizationOwnerRelation, organizationObject(orgID))

	_, err := server.CreatePrivateResource(callerContext(callerID), &networksv1.CreatePrivateResourceRequest{
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
	request := ziti.createdServices[0]
	assertPortRanges(t, request.GetHostV1Config().GetAllowedPortRanges(), []int32{5433, 5432})
	assertPortRanges(t, request.GetInterceptV1Config().GetPortRanges(), []int32{15432, 15433})
}

func TestAccessGrantDialPolicyRoleAttrs(t *testing.T) {
	cases := []struct {
		principalType networksv1.PrivateResourceAccessPrincipalType
		storeType     store.PrincipalType
		rolePrefix    string
	}{
		{networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_AGENT, store.PrincipalTypeAgent, "#agent-"},
		{networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_USER, store.PrincipalTypeUser, "#user-"},
		{networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_APP, store.PrincipalTypeApp, "#app-"},
		{networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_GROUP, store.PrincipalTypeGroup, "#group-"},
	}
	for _, tc := range cases {
		t.Run(string(tc.storeType), func(t *testing.T) {
			fakeStore := newFakeStore()
			authz := &fakeAuthorizationClient{allowed: map[string]bool{}}
			identity := &fakeIdentityClient{types: map[string]identityv1.IdentityType{}}
			groups := &fakeGroupsClient{groups: map[string]*groupsv1.Group{}}
			ziti := &fakeZitiManagementClient{servicePolicyID: "dial-policy"}
			server := NewWithClients(fakeStore, authz, identity, groups, ziti)
			callerID := uuid.New()
			orgID := uuid.New()
			principalID := uuid.New()
			resource := fakeStore.mustCreatePrivateResource(fakeStore.mustCreateNetwork(orgID))
			authz.allow(identityObject(callerID), organizationOwnerRelation, organizationObject(orgID))
			authz.allow(identityObject(callerID), agentCanEditConfigRelation, agentObject(principalID))
			authz.allow(identityObject(principalID), organizationMemberRelation, organizationObject(orgID))
			if tc.storeType != store.PrincipalTypeGroup {
				identity.types[principalID.String()] = identityTypeForPrincipal(tc.storeType)
			}
			groups.groups[principalID.String()] = &groupsv1.Group{Meta: &groupsv1.EntityMeta{Id: principalID.String()}, OrganizationId: orgID.String()}

			_, err := server.CreatePrivateResourceAccess(callerContext(callerID), &networksv1.CreatePrivateResourceAccessRequest{PrivateResourceId: resource.Meta.ID.String(), PrincipalType: tc.principalType, PrincipalId: principalID.String()})
			if err != nil {
				t.Fatalf("CreatePrivateResourceAccess: %v", err)
			}
			policy := ziti.createdServicePolicies[0]
			assertStringSlice(t, policy.GetIdentityRoles(), []string{tc.rolePrefix + principalID.String()})
			assertStringSlice(t, policy.GetServiceRoles(), []string{"@private-" + resource.Meta.ID.String()})
		})
	}
}

func TestProvisioningFailurePersistsFailedState(t *testing.T) {
	fakeStore := newFakeStore()
	authz := &fakeAuthorizationClient{allowed: map[string]bool{}}
	ziti := &fakeZitiManagementClient{createServiceErr: status.Error(codes.Unavailable, "controller unavailable")}
	server := NewWithClients(fakeStore, authz, nil, nil, ziti)
	callerID := uuid.New()
	orgID := uuid.New()
	network := fakeStore.mustCreateNetwork(orgID)
	authz.allow(identityObject(callerID), organizationOwnerRelation, organizationObject(orgID))

	response, err := server.CreatePrivateResource(callerContext(callerID), &networksv1.CreatePrivateResourceRequest{
		NetworkId:      network.Meta.ID.String(),
		Name:           "postgres",
		Protocol:       networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_TCP,
		TargetHost:     "postgres.internal",
		TargetPorts:    []int32{5432},
		InterceptHost:  "postgres.private.example.com",
		InterceptPorts: []int32{15432},
	})
	if err != nil {
		t.Fatalf("CreatePrivateResource: %v", err)
	}
	if response.GetPrivateResource().GetProvisioningState() != networksv1.ProvisioningState_PROVISIONING_STATE_FAILED {
		t.Fatalf("expected failed provisioning state, got %s", response.GetPrivateResource().GetProvisioningState())
	}
	resourceID := uuid.MustParse(response.GetPrivateResource().GetMeta().GetId())
	if fakeStore.resources[resourceID].OpenZitiServiceID != "" {
		t.Fatalf("did not expect OpenZiti service ID on failed provisioning")
	}
}

func TestDeleteToleratesMissingZitiResources(t *testing.T) {
	fakeStore := newFakeStore()
	authz := &fakeAuthorizationClient{allowed: map[string]bool{}}
	ziti := &fakeZitiManagementClient{deleteServicePolicyErr: status.Error(codes.NotFound, "missing")}
	server := NewWithClients(fakeStore, authz, nil, nil, ziti)
	callerID := uuid.New()
	orgID := uuid.New()
	network := fakeStore.mustCreateNetwork(orgID)
	network.OpenZitiBindPolicyID = "missing-policy"
	fakeStore.networks[network.Meta.ID] = network
	authz.allow(identityObject(callerID), organizationOwnerRelation, organizationObject(orgID))

	_, err := server.DeleteNetwork(callerContext(callerID), &networksv1.DeleteNetworkRequest{Id: network.Meta.ID.String()})
	if err != nil {
		t.Fatalf("DeleteNetwork: %v", err)
	}
}

func identityTypeForPrincipal(principalType store.PrincipalType) identityv1.IdentityType {
	switch principalType {
	case store.PrincipalTypeAgent:
		return identityv1.IdentityType_IDENTITY_TYPE_AGENT
	case store.PrincipalTypeUser:
		return identityv1.IdentityType_IDENTITY_TYPE_USER
	case store.PrincipalTypeApp:
		return identityv1.IdentityType_IDENTITY_TYPE_APP
	case store.PrincipalTypeGroup:
		panic("groups are validated through groups service")
	default:
		panic("unknown principal type")
	}
}

func assertStringSlice(t *testing.T, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}
}

func assertPortRanges(t *testing.T, got []*zitimgmtv1.PortRange, want []int32) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("expected %v port ranges, got %v", want, got)
	}
	for i := range want {
		if got[i].GetLow() != want[i] || got[i].GetHigh() != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}
}

type fakeZitiManagementClient struct {
	createdServices        []*zitimgmtv1.CreateServiceRequest
	updatedServices        []*zitimgmtv1.UpdateServiceRequest
	createdServicePolicies []*zitimgmtv1.CreateServicePolicyRequest
	deletedServicePolicies []string
	deletedServices        []string
	deletedTunnelIdentity  []string
	serviceID              string
	servicePolicyID        string
	tunnelIdentityID       string
	enrollmentJWT          string
	enrollmentExpiresAt    time.Time
	deleteServicePolicyErr error
	deleteServiceErr       error
	deleteTunnelErr        error
	createPolicyErr        error
	createServiceErr       error
	createTunnelErr        error
}

func (f *fakeZitiManagementClient) CreateService(_ context.Context, request *zitimgmtv1.CreateServiceRequest, _ ...grpc.CallOption) (*zitimgmtv1.CreateServiceResponse, error) {
	f.createdServices = append(f.createdServices, request)
	serviceID := f.serviceID
	if serviceID == "" {
		serviceID = "service-id"
	}
	return &zitimgmtv1.CreateServiceResponse{ZitiServiceId: serviceID}, f.createServiceErr
}

func (f *fakeZitiManagementClient) UpdateService(_ context.Context, request *zitimgmtv1.UpdateServiceRequest, _ ...grpc.CallOption) (*zitimgmtv1.UpdateServiceResponse, error) {
	f.updatedServices = append(f.updatedServices, request)
	return &zitimgmtv1.UpdateServiceResponse{}, nil
}

func (f *fakeZitiManagementClient) DeleteService(_ context.Context, request *zitimgmtv1.DeleteServiceRequest, _ ...grpc.CallOption) (*zitimgmtv1.DeleteServiceResponse, error) {
	f.deletedServices = append(f.deletedServices, request.GetZitiServiceId())
	return &zitimgmtv1.DeleteServiceResponse{}, f.deleteServiceErr
}

func (f *fakeZitiManagementClient) CreateServicePolicy(_ context.Context, request *zitimgmtv1.CreateServicePolicyRequest, _ ...grpc.CallOption) (*zitimgmtv1.CreateServicePolicyResponse, error) {
	f.createdServicePolicies = append(f.createdServicePolicies, request)
	policyID := f.servicePolicyID
	if policyID == "" {
		policyID = "policy-id"
	}
	return &zitimgmtv1.CreateServicePolicyResponse{ZitiServicePolicyId: policyID}, f.createPolicyErr
}

func (f *fakeZitiManagementClient) DeleteServicePolicy(_ context.Context, request *zitimgmtv1.DeleteServicePolicyRequest, _ ...grpc.CallOption) (*zitimgmtv1.DeleteServicePolicyResponse, error) {
	f.deletedServicePolicies = append(f.deletedServicePolicies, request.GetZitiServicePolicyId())
	return &zitimgmtv1.DeleteServicePolicyResponse{}, f.deleteServicePolicyErr
}

func (f *fakeZitiManagementClient) CreateTunnelIdentity(_ context.Context, request *zitimgmtv1.CreateTunnelIdentityRequest, _ ...grpc.CallOption) (*zitimgmtv1.CreateTunnelIdentityResponse, error) {
	identityID := f.tunnelIdentityID
	if identityID == "" {
		identityID = "tunnel-id"
	}
	jwt := f.enrollmentJWT
	if jwt == "" {
		jwt = "jwt"
	}
	return &zitimgmtv1.CreateTunnelIdentityResponse{ZitiIdentityId: identityID, EnrollmentJwt: jwt, EnrollmentJwtExpiresAt: timestamppb.New(f.enrollmentExpiresAt)}, f.createTunnelErr
}

func (f *fakeZitiManagementClient) DeleteTunnelIdentity(_ context.Context, request *zitimgmtv1.DeleteTunnelIdentityRequest, _ ...grpc.CallOption) (*zitimgmtv1.DeleteTunnelIdentityResponse, error) {
	f.deletedTunnelIdentity = append(f.deletedTunnelIdentity, request.GetZitiIdentityId())
	return &zitimgmtv1.DeleteTunnelIdentityResponse{}, f.deleteTunnelErr
}
