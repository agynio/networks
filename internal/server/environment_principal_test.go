package server

import (
	"context"
	"errors"
	"testing"

	agentsv1 "github.com/agynio/networks/.gen/go/agynio/api/agents/v1"
	groupsv1 "github.com/agynio/networks/.gen/go/agynio/api/groups/v1"
	identityv1 "github.com/agynio/networks/.gen/go/agynio/api/identity/v1"
	networksv1 "github.com/agynio/networks/.gen/go/agynio/api/networks/v1"
	"github.com/agynio/networks/internal/store"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeAgentsClient struct {
	environments map[string]*agentsv1.Environment
	agents       map[string]*agentsv1.Agent
	err          error
	calls        int
}

func (f *fakeAgentsClient) GetAgent(_ context.Context, request *agentsv1.GetAgentRequest, _ ...grpc.CallOption) (*agentsv1.GetAgentResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	agent, ok := f.agents[request.GetId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "agent not found")
	}
	return &agentsv1.GetAgentResponse{Agent: agent}, nil
}

func (f *fakeAgentsClient) GetEnvironment(_ context.Context, request *agentsv1.GetEnvironmentRequest, _ ...grpc.CallOption) (*agentsv1.GetEnvironmentResponse, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	environment, ok := f.environments[request.GetId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "environment not found")
	}
	return &agentsv1.GetEnvironmentResponse{Environment: environment}, nil
}

// environmentGrantFixture wires the pieces an environment grant needs: a
// resource to grant, a caller who may edit the environment, and an Agents
// service that can resolve it.
type environmentGrantFixture struct {
	server        *Server
	agents        *fakeAgentsClient
	authz         *fakeAuthorizationClient
	ziti          *fakeZitiManagementClient
	callerID      uuid.UUID
	orgID         uuid.UUID
	environmentID uuid.UUID
	resource      store.PrivateResource
}

func newEnvironmentGrantFixture(t *testing.T) *environmentGrantFixture {
	t.Helper()
	fakeStore := newFakeStore()
	authz := &fakeAuthorizationClient{allowed: map[string]bool{}}
	identity := &fakeIdentityClient{types: map[string]identityv1.IdentityType{}}
	groups := &fakeGroupsClient{groups: map[string]*groupsv1.Group{}}
	ziti := &fakeZitiManagementClient{servicePolicyID: "dial-policy"}
	agents := &fakeAgentsClient{environments: map[string]*agentsv1.Environment{}}

	callerID, orgID, environmentID := uuid.New(), uuid.New(), uuid.New()
	resource := fakeStore.mustCreatePrivateResource(fakeStore.mustCreateNetwork(orgID))
	agents.environments[environmentID.String()] = &agentsv1.Environment{
		Meta:           &agentsv1.EntityMeta{Id: environmentID.String()},
		OrganizationId: orgID.String(),
	}

	return &environmentGrantFixture{
		server:        NewWithClients(fakeStore, authz, identity, groups, ziti).WithAgentsClient(agents),
		agents:        agents,
		authz:         authz,
		ziti:          ziti,
		callerID:      callerID,
		orgID:         orgID,
		environmentID: environmentID,
		resource:      resource,
	}
}

func (f *environmentGrantFixture) allowEnvironmentEdit() {
	f.authz.allow(identityObject(f.callerID), environmentCanEditConfigRelation, environmentObject(f.environmentID))
}

func (f *environmentGrantFixture) grant() error {
	_, err := f.server.CreatePrivateResourceAccess(callerContext(f.callerID), &networksv1.CreatePrivateResourceAccessRequest{
		PrivateResourceId: f.resource.Meta.ID.String(),
		PrincipalType:     networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_ENVIRONMENT,
		PrincipalId:       f.environmentID.String(),
	})
	return err
}

// environment-<id> is stamped on every workload identity the Orchestrator
// creates, agent workloads and sandboxes alike, so a grant naming it reaches
// both without any new OpenZiti mechanism.
func TestEnvironmentGrantDialsByEnvironmentRoleAttribute(t *testing.T) {
	f := newEnvironmentGrantFixture(t)
	f.allowEnvironmentEdit()

	if err := f.grant(); err != nil {
		t.Fatalf("CreatePrivateResourceAccess: %v", err)
	}
	policy := f.ziti.createdServicePolicies[0]
	assertStringSlice(t, policy.GetIdentityRoles(), []string{"#environment-" + f.environmentID.String()})
}

// An environment is a configuration resource, so the grant is gated by the
// permission that edits it -- not by organization ownership, which is what
// every non-agent principal used before.
func TestEnvironmentGrantRequiresEnvironmentConfigEditor(t *testing.T) {
	f := newEnvironmentGrantFixture(t)
	// Organization owner is deliberately not enough on its own.
	f.authz.allow(identityObject(f.callerID), organizationOwnerRelation, organizationObject(f.orgID))

	if err := f.grant(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected permission denied, got %v", err)
	}
	if len(f.ziti.createdServicePolicies) != 0 {
		t.Fatal("expected no dial policy for a refused grant")
	}
}

// The cross-org guard resolves through Agents rather than Identity: an
// environment is not in the identity registry at all.
func TestEnvironmentGrantRejectsAnotherOrganizationsEnvironment(t *testing.T) {
	f := newEnvironmentGrantFixture(t)
	f.allowEnvironmentEdit()
	f.agents.environments[f.environmentID.String()].OrganizationId = uuid.New().String()

	if err := f.grant(); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", err)
	}
}

func TestEnvironmentGrantRejectsAnUnknownEnvironment(t *testing.T) {
	f := newEnvironmentGrantFixture(t)
	f.allowEnvironmentEdit()
	delete(f.agents.environments, f.environmentID.String())

	if err := f.grant(); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", err)
	}
}

func TestEnvironmentGrantSurfacesAnAgentsLookupFailure(t *testing.T) {
	f := newEnvironmentGrantFixture(t)
	f.allowEnvironmentEdit()
	f.agents.err = errors.New("agents unreachable")

	if err := f.grant(); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", err)
	}
}

// The environment principal round-trips through the proto enum, which is what
// the Console reads back off the access list.
func TestEnvironmentPrincipalRoundTripsThroughTheProtoEnum(t *testing.T) {
	stored, err := toStorePrincipalType(networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_ENVIRONMENT)
	if err != nil {
		t.Fatalf("toStorePrincipalType: %v", err)
	}
	if stored != store.PrincipalTypeEnvironment {
		t.Fatalf("got %q, want %q", stored, store.PrincipalTypeEnvironment)
	}
	if got := convertPrincipalType(store.PrincipalTypeEnvironment); got != networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_ENVIRONMENT {
		t.Fatalf("got %v", got)
	}
	if err := validatePrincipalType(store.PrincipalTypeEnvironment); err != nil {
		t.Fatalf("validatePrincipalType: %v", err)
	}
}

// Without the client configured the grant still works — the org guard is the
// part that degrades, exactly as it does for groups.
func TestEnvironmentGrantWithoutAnAgentsClientSkipsTheOrgGuard(t *testing.T) {
	f := newEnvironmentGrantFixture(t)
	f.allowEnvironmentEdit()
	f.server.agentsClient = nil

	if err := f.grant(); err != nil {
		t.Fatalf("CreatePrivateResourceAccess: %v", err)
	}
	if f.agents.calls != 0 {
		t.Fatalf("expected no agents call, got %d", f.agents.calls)
	}
}
