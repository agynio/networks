package server

import (
	"context"
	"fmt"
	"strings"
	"testing"

	egressv1 "github.com/agynio/networks/.gen/go/agynio/api/egress/v1"
	networksv1 "github.com/agynio/networks/.gen/go/agynio/api/networks/v1"
	"github.com/agynio/networks/internal/store"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeEgressRulesClient struct {
	referencingRuleIDs  []string
	referencingErr      error
	mediatedResourceIDs []string
	mediatedErr         error
	attachedDomains     []*egressv1.AttachedRuleDomain
	attachedErr         error
}

func (f *fakeEgressRulesClient) CountRulesReferencingPrivateResource(_ context.Context, _ *egressv1.CountRulesReferencingPrivateResourceRequest, _ ...grpc.CallOption) (*egressv1.CountRulesReferencingPrivateResourceResponse, error) {
	if f.referencingErr != nil {
		return nil, f.referencingErr
	}
	return &egressv1.CountRulesReferencingPrivateResourceResponse{Count: int32(len(f.referencingRuleIDs)), EgressRuleIds: f.referencingRuleIDs}, nil
}

func (f *fakeEgressRulesClient) ListMediatedPrivateResources(_ context.Context, _ *egressv1.ListMediatedPrivateResourcesRequest, _ ...grpc.CallOption) (*egressv1.ListMediatedPrivateResourcesResponse, error) {
	if f.mediatedErr != nil {
		return nil, f.mediatedErr
	}
	return &egressv1.ListMediatedPrivateResourcesResponse{PrivateResourceIds: f.mediatedResourceIDs}, nil
}

func (f *fakeEgressRulesClient) ListAttachedRuleDomains(_ context.Context, _ *egressv1.ListAttachedRuleDomainsRequest, _ ...grpc.CallOption) (*egressv1.ListAttachedRuleDomainsResponse, error) {
	if f.attachedErr != nil {
		return nil, f.attachedErr
	}
	return &egressv1.ListAttachedRuleDomainsResponse{Domains: f.attachedDomains}, nil
}

func mediatedFixture(t *testing.T) (*fakeStore, *fakeZitiManagementClient, *Server, store.PrivateResource) {
	t.Helper()
	fakeStore := newFakeStore()
	ziti := &fakeZitiManagementClient{}
	server := NewWithClients(fakeStore, nil, nil, nil, ziti)
	network := fakeStore.mustCreateNetwork(uuid.New())
	resource, err := fakeStore.CreatePrivateResource(context.Background(), store.CreatePrivateResourceInput{
		ID: uuid.New(), OrganizationID: network.OrganizationID, NetworkID: network.Meta.ID, Name: "gitlab",
		Protocol: store.PrivateResourceProtocolHTTPS, TargetHost: "gitlab.lan",
		TargetPorts: []int32{8443, 8080}, InterceptHost: "gitlab.corp", InterceptPorts: []int32{443, 80},
	})
	if err != nil {
		t.Fatalf("create resource: %v", err)
	}
	resource, err = fakeStore.UpdatePrivateResourceProvisioning(context.Background(), resource.Meta.ID, store.ProvisioningStateActive, "front-service-id")
	if err != nil {
		t.Fatalf("set service id: %v", err)
	}
	return fakeStore, ziti, server, resource
}

func TestSetPrivateResourceMediationFlipsToGateway(t *testing.T) {
	fakeStore, ziti, server, resource := mediatedFixture(t)

	response, err := server.SetPrivateResourceMediation(context.Background(), &networksv1.SetPrivateResourceMediationRequest{
		Id:        resource.Meta.ID.String(),
		Mediation: networksv1.PrivateResourceMediation_PRIVATE_RESOURCE_MEDIATION_EGRESS_GATEWAY,
	})
	if err != nil {
		t.Fatalf("SetPrivateResourceMediation: %v", err)
	}
	if response.GetPrivateResource().GetMediation() != networksv1.PrivateResourceMediation_PRIVATE_RESOURCE_MEDIATION_EGRESS_GATEWAY {
		t.Fatalf("expected egress_gateway mediation, got %s", response.GetPrivateResource().GetMediation())
	}

	if len(ziti.updatedServices) == 0 {
		t.Fatal("expected the front service to be updated")
	}
	front := ziti.updatedServices[0]
	if front.GetZitiServiceId() != "front-service-id" {
		t.Fatalf("unexpected front service id %s", front.GetZitiServiceId())
	}
	wantRoles := []string{egressServicesRoleAttribute, privateResourceRoleAttribute(resource.Meta.ID)}
	gotRoles := front.GetRoleAttributesUpdate().GetRoleAttributes()
	if len(gotRoles) != 2 || gotRoles[0] != wantRoles[0] || gotRoles[1] != wantRoles[1] {
		t.Fatalf("unexpected front role attributes %v", gotRoles)
	}
	if !front.GetHostV1Config().GetForwardAddress() || !front.GetHostV1Config().GetForwardPort() {
		t.Fatalf("expected forwarding host config, got %+v", front.GetHostV1Config())
	}
	if hosts := front.GetHostV1Config().GetAllowedAddresses(); len(hosts) != 1 || hosts[0] != "gitlab.corp" {
		t.Fatalf("unexpected allowed addresses %v", hosts)
	}

	if len(ziti.createdServices) != 2 {
		t.Fatalf("expected 2 upstream services, got %d", len(ziti.createdServices))
	}
	byName := map[string]int32{}
	for _, created := range ziti.createdServices {
		byName[created.GetName()] = created.GetHostV1Config().GetPort()
		if created.GetTags()["agyn.resource_type"] != "private_resource_upstream" {
			t.Fatalf("unexpected upstream tags %v", created.GetTags())
		}
	}
	if byName[fmt.Sprintf("private-%s-upstream-443", resource.Meta.ID)] != 8443 || byName[fmt.Sprintf("private-%s-upstream-80", resource.Meta.ID)] != 8080 {
		t.Fatalf("upstream services do not encode the positional port pairing: %v", byName)
	}

	if len(ziti.createdServicePolicies) != 1 {
		t.Fatalf("expected 1 gateway dial policy, got %d", len(ziti.createdServicePolicies))
	}
	policy := ziti.createdServicePolicies[0]
	if policy.GetIdentityRoles()[0] != "#egress-gateway-hosts" || policy.GetServiceRoles()[0] != "#"+privateResourceUpstreamsRoleAttribute(resource.Meta.ID) {
		t.Fatalf("unexpected gateway dial policy roles %v -> %v", policy.GetIdentityRoles(), policy.GetServiceRoles())
	}

	stored := fakeStore.resources[resource.Meta.ID]
	if stored.Mediation != store.MediationEgressGateway || stored.ProvisioningState != store.ProvisioningStateActive {
		t.Fatalf("unexpected stored state %+v", stored)
	}
	if len(stored.OpenZitiUpstreamServiceIDs) != 2 || stored.OpenZitiGatewayDialPolicyID == "" {
		t.Fatalf("expected upstream ids and policy id persisted, got %+v", stored)
	}
}

func TestSetPrivateResourceMediationFlipsBackToTunnel(t *testing.T) {
	fakeStore, ziti, server, resource := mediatedFixture(t)
	if _, err := server.SetPrivateResourceMediation(context.Background(), &networksv1.SetPrivateResourceMediationRequest{
		Id:        resource.Meta.ID.String(),
		Mediation: networksv1.PrivateResourceMediation_PRIVATE_RESOURCE_MEDIATION_EGRESS_GATEWAY,
	}); err != nil {
		t.Fatalf("flip to gateway: %v", err)
	}
	mediated := fakeStore.resources[resource.Meta.ID]
	ziti.updatedServices = nil

	if _, err := server.SetPrivateResourceMediation(context.Background(), &networksv1.SetPrivateResourceMediationRequest{
		Id:        resource.Meta.ID.String(),
		Mediation: networksv1.PrivateResourceMediation_PRIVATE_RESOURCE_MEDIATION_TUNNEL,
	}); err != nil {
		t.Fatalf("flip to tunnel: %v", err)
	}

	front := ziti.updatedServices[0]
	roles := front.GetRoleAttributesUpdate().GetRoleAttributes()
	if roles[0] != networkResourcesRoleAttribute(resource.NetworkID) {
		t.Fatalf("expected tunnel binding attribute restored, got %v", roles)
	}
	if front.GetHostV1Config().GetForwardAddress() {
		t.Fatalf("expected static host config, got %+v", front.GetHostV1Config())
	}
	if len(ziti.deletedServicePolicies) != 1 || ziti.deletedServicePolicies[0] != mediated.OpenZitiGatewayDialPolicyID {
		t.Fatalf("expected the gateway dial policy deleted, got %v", ziti.deletedServicePolicies)
	}
	if len(ziti.deletedServices) != 2 {
		t.Fatalf("expected both upstream services deleted, got %v", ziti.deletedServices)
	}
	stored := fakeStore.resources[resource.Meta.ID]
	if stored.Mediation != store.MediationTunnel || len(stored.OpenZitiUpstreamServiceIDs) != 0 || stored.OpenZitiGatewayDialPolicyID != "" {
		t.Fatalf("expected tunnel state cleared, got %+v", stored)
	}
}

func TestSetPrivateResourceMediationIsIdempotent(t *testing.T) {
	fakeStore, ziti, server, resource := mediatedFixture(t)
	for range 2 {
		if _, err := server.SetPrivateResourceMediation(context.Background(), &networksv1.SetPrivateResourceMediationRequest{
			Id:        resource.Meta.ID.String(),
			Mediation: networksv1.PrivateResourceMediation_PRIVATE_RESOURCE_MEDIATION_EGRESS_GATEWAY,
		}); err != nil {
			t.Fatalf("SetPrivateResourceMediation: %v", err)
		}
	}
	stored := fakeStore.resources[resource.Meta.ID]
	if stored.Mediation != store.MediationEgressGateway || len(stored.OpenZitiUpstreamServiceIDs) != 2 {
		t.Fatalf("unexpected stored state after repeat %+v", stored)
	}
	if len(ziti.createdServicePolicies) != 1 {
		t.Fatalf("expected the existing policy reused, got %d creates", len(ziti.createdServicePolicies))
	}
}

func TestDeletePrivateResourceRefusedWhileRuleNamesIt(t *testing.T) {
	fakeStore := newFakeStore()
	server := New(fakeStore).WithEgressRulesClient(&fakeEgressRulesClient{referencingRuleIDs: []string{"rule-1"}})
	resource := fakeStore.mustCreatePrivateResource(fakeStore.mustCreateNetwork(uuid.New()))

	_, err := server.DeletePrivateResource(context.Background(), &networksv1.DeletePrivateResourceRequest{Id: resource.Meta.ID.String()})
	assertCode(t, err, codes.FailedPrecondition)
	if !strings.Contains(status.Convert(err).Message(), "rule-1") {
		t.Fatalf("expected the refusal to list the rules, got %v", err)
	}
	if _, ok := fakeStore.resources[resource.Meta.ID]; !ok {
		t.Fatal("resource must survive a refused delete")
	}
}

func TestUpdatePrivateResourceProtocolChangeGuard(t *testing.T) {
	fakeStore := newFakeStore()
	server := New(fakeStore).WithEgressRulesClient(&fakeEgressRulesClient{referencingRuleIDs: []string{"rule-1"}})
	network := fakeStore.mustCreateNetwork(uuid.New())
	resource, err := fakeStore.CreatePrivateResource(context.Background(), store.CreatePrivateResourceInput{
		ID: uuid.New(), OrganizationID: network.OrganizationID, NetworkID: network.Meta.ID, Name: "gitlab",
		Protocol: store.PrivateResourceProtocolHTTPS, TargetHost: "gitlab.lan",
		TargetPorts: []int32{8443}, InterceptHost: "gitlab.corp", InterceptPorts: []int32{443},
	})
	if err != nil {
		t.Fatalf("create resource: %v", err)
	}

	tcp := networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_TCP
	_, err = server.UpdatePrivateResource(context.Background(), &networksv1.UpdatePrivateResourceRequest{Id: resource.Meta.ID.String(), Protocol: &tcp})
	assertCode(t, err, codes.FailedPrecondition)

	https := networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_HTTP
	if _, err = server.UpdatePrivateResource(context.Background(), &networksv1.UpdatePrivateResourceRequest{Id: resource.Meta.ID.String(), Protocol: &https}); err != nil {
		t.Fatalf("http<->https must stay allowed while referenced: %v", err)
	}
}

func TestCreatePrivateResourceAccessRejectsRuleDomainCollision(t *testing.T) {
	fakeStore := newFakeStore()
	egress := &fakeEgressRulesClient{attachedDomains: []*egressv1.AttachedRuleDomain{{EgressRuleId: "rule-1", DomainPattern: "*.corp", Ports: []int32{443}}}}
	server := New(fakeStore).WithEgressRulesClient(egress)
	network := fakeStore.mustCreateNetwork(uuid.New())
	resource, err := fakeStore.CreatePrivateResource(context.Background(), store.CreatePrivateResourceInput{
		ID: uuid.New(), OrganizationID: network.OrganizationID, NetworkID: network.Meta.ID, Name: "gitlab",
		Protocol: store.PrivateResourceProtocolHTTPS, TargetHost: "gitlab.lan",
		TargetPorts: []int32{8443}, InterceptHost: "gitlab.corp", InterceptPorts: []int32{443},
	})
	if err != nil {
		t.Fatalf("create resource: %v", err)
	}

	_, err = server.CreatePrivateResourceAccess(context.Background(), &networksv1.CreatePrivateResourceAccessRequest{
		PrivateResourceId: resource.Meta.ID.String(),
		PrincipalType:     networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_AGENT,
		PrincipalId:       uuid.NewString(),
	})
	assertCode(t, err, codes.FailedPrecondition)

	// Ports that do not overlap are not a collision.
	egress.attachedDomains = []*egressv1.AttachedRuleDomain{{EgressRuleId: "rule-1", DomainPattern: "gitlab.corp", Ports: []int32{8080}}}
	if _, err = server.CreatePrivateResourceAccess(context.Background(), &networksv1.CreatePrivateResourceAccessRequest{
		PrivateResourceId: resource.Meta.ID.String(),
		PrincipalType:     networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_AGENT,
		PrincipalId:       uuid.NewString(),
	}); err != nil {
		t.Fatalf("non-overlapping ports must pass: %v", err)
	}

	// An unreachable EgressRules service skips the best-effort check.
	egress.attachedErr = status.Error(codes.Unavailable, "down")
	if _, err = server.CreatePrivateResourceAccess(context.Background(), &networksv1.CreatePrivateResourceAccessRequest{
		PrivateResourceId: resource.Meta.ID.String(),
		PrincipalType:     networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_AGENT,
		PrincipalId:       uuid.NewString(),
	}); err != nil {
		t.Fatalf("best-effort check must not block on outage: %v", err)
	}
}

func TestReconcileMediationDerivesFromEgressRules(t *testing.T) {
	fakeStore, ziti, server, resource := mediatedFixture(t)
	_ = ziti
	egress := &fakeEgressRulesClient{mediatedResourceIDs: []string{resource.Meta.ID.String()}}
	server.WithEgressRulesClient(egress)

	if err := server.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if stored := fakeStore.resources[resource.Meta.ID]; stored.Mediation != store.MediationEgressGateway {
		t.Fatalf("expected reconciliation to flip the resource to egress_gateway, got %+v", stored)
	}

	egress.mediatedResourceIDs = nil
	if err := server.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if stored := fakeStore.resources[resource.Meta.ID]; stored.Mediation != store.MediationTunnel {
		t.Fatalf("expected reconciliation to return the resource to tunnel, got %+v", stored)
	}
}
