package server

import (
	"context"
	"errors"
	"testing"
	"time"

	groupsv1 "github.com/agynio/networks/.gen/go/agynio/api/groups/v1"
	networksv1 "github.com/agynio/networks/.gen/go/agynio/api/networks/v1"
	notificationsv1 "github.com/agynio/networks/.gen/go/agynio/api/notifications/v1"
	zitimgmtv1 "github.com/agynio/networks/.gen/go/agynio/api/ziti_management/v1"
	"github.com/agynio/networks/internal/store"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

func TestTunnelLivenessUpdatesStateAndPublishesTransition(t *testing.T) {
	fakeStore := newFakeStore()
	events := &fakeEventPublisher{}
	notifications := &fakeNotificationsClient{}
	ziti := &fakeZitiManagementClient{liveness: &zitimgmtv1.GetIdentityLivenessResponse{EnrollmentState: zitimgmtv1.IdentityEnrollmentState_IDENTITY_ENROLLMENT_STATE_ENROLLED, HasEdgeRouterConnection: true}}
	server := NewWithDependencies(fakeStore, nil, nil, nil, ziti, notifications, events)
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	server.now = func() time.Time { return now }
	network := fakeStore.mustCreateNetwork(uuid.New())
	credential := fakeStore.mustCreateTunnelCredential(network)
	credential.OpenZitiIdentityID = "ziti-tunnel"
	fakeStore.credentials[credential.Meta.ID] = credential

	if err := server.PollTunnelLiveness(context.Background()); err != nil {
		t.Fatalf("PollTunnelLiveness: %v", err)
	}
	updated := fakeStore.credentials[credential.Meta.ID]
	if updated.EnrollmentState != store.TunnelEnrollmentStateEnrolled || updated.Connectivity != store.TunnelConnectivityOnline {
		t.Fatalf("unexpected liveness state: %s %s", updated.EnrollmentState, updated.Connectivity)
	}
	if updated.EnrolledAt == nil || !updated.EnrolledAt.Equal(now) || updated.LastSeenAt == nil || !updated.LastSeenAt.Equal(now) {
		t.Fatalf("expected enrolled and last seen timestamps")
	}
	if len(events.messages) != 1 || events.messages[0].subject != tunnelOnlineSubject {
		t.Fatalf("expected online event, got %#v", events.messages)
	}
	if events.messages[0].envelope.EventID == credential.Meta.ID.String() {
		t.Fatalf("expected event occurrence message id, got stable entity id")
	}
	if events.messages[0].envelope.Schema != "agynio.api.networks.v1.TunnelOnlineEvent" {
		t.Fatalf("expected schema header value, got %s", events.messages[0].envelope.Schema)
	}
	if len(notifications.requests) != 1 || notifications.requests[0].GetEvent() != tunnelStatusChangedNotification {
		t.Fatalf("expected tunnel status notification")
	}
}

func TestDeleteNetworkCleansAllDependents(t *testing.T) {
	fakeStore := newFakeStore()
	authz := &fakeAuthorizationClient{allowed: map[string]bool{}}
	ziti := &fakeZitiManagementClient{}
	notifications := &fakeNotificationsClient{}
	events := &fakeEventPublisher{}
	server := NewWithDependencies(fakeStore, authz, nil, nil, ziti, notifications, events)
	callerID := uuid.New()
	orgID := uuid.New()
	network := fakeStore.mustCreateNetwork(orgID)
	authz.allow(identityObject(callerID), organizationOwnerRelation, organizationObject(orgID))

	for i := 0; i < int(store.MaxListPageSize)+2; i++ {
		credential := fakeStore.mustCreateTunnelCredential(network)
		credential.OpenZitiIdentityID = uuid.NewString()
		fakeStore.credentials[credential.Meta.ID] = credential
		resource := fakeStore.mustCreatePrivateResource(network)
		resource.OpenZitiServiceID = uuid.NewString()
		fakeStore.resources[resource.Meta.ID] = resource
		access, err := fakeStore.CreatePrivateResourceAccess(context.Background(), store.CreatePrivateResourceAccessInput{ID: uuid.New(), PrivateResourceID: resource.Meta.ID, PrincipalType: store.PrincipalTypeUser, PrincipalID: uuid.New()})
		if err != nil {
			t.Fatalf("CreatePrivateResourceAccess: %v", err)
		}
		access.OpenZitiDialPolicyID = uuid.NewString()
		fakeStore.accesses[access.Meta.ID] = access
	}

	if _, err := server.DeleteNetwork(callerContext(callerID), &networksv1.DeleteNetworkRequest{Id: network.Meta.ID.String()}); err != nil {
		t.Fatalf("DeleteNetwork: %v", err)
	}
	if len(ziti.deletedTunnelIdentity) != int(store.MaxListPageSize)+2 {
		t.Fatalf("expected all tunnel identities deleted, got %d", len(ziti.deletedTunnelIdentity))
	}
	if len(ziti.deletedServices) != int(store.MaxListPageSize)+2 {
		t.Fatalf("expected all services deleted, got %d", len(ziti.deletedServices))
	}
	if len(ziti.deletedServicePolicies) != int(store.MaxListPageSize)+2 {
		t.Fatalf("expected all access policies deleted, got %d", len(ziti.deletedServicePolicies))
	}
	if len(events.messages) != int(store.MaxListPageSize)+2 {
		t.Fatalf("expected all access revoke events, got %d", len(events.messages))
	}
	for _, message := range events.messages {
		if message.subject != accessRevokedSubject {
			t.Fatalf("expected access revoked subject, got %s", message.subject)
		}
	}
	if len(notifications.requests) != (int(store.MaxListPageSize)+2)*3+1 {
		t.Fatalf("expected cascade notifications for access, credentials, resources, and network; got %d", len(notifications.requests))
	}
}

func TestDeletePrivateResourceCleansAllAccessPolicies(t *testing.T) {
	fakeStore := newFakeStore()
	authz := &fakeAuthorizationClient{allowed: map[string]bool{}}
	ziti := &fakeZitiManagementClient{}
	notifications := &fakeNotificationsClient{}
	events := &fakeEventPublisher{}
	server := NewWithDependencies(fakeStore, authz, nil, nil, ziti, notifications, events)
	callerID := uuid.New()
	orgID := uuid.New()
	resource := fakeStore.mustCreatePrivateResource(fakeStore.mustCreateNetwork(orgID))
	resource.OpenZitiServiceID = "service"
	fakeStore.resources[resource.Meta.ID] = resource
	authz.allow(identityObject(callerID), organizationOwnerRelation, organizationObject(orgID))

	for i := 0; i < int(store.MaxListPageSize)+2; i++ {
		access, err := fakeStore.CreatePrivateResourceAccess(context.Background(), store.CreatePrivateResourceAccessInput{ID: uuid.New(), PrivateResourceID: resource.Meta.ID, PrincipalType: store.PrincipalTypeUser, PrincipalID: uuid.New()})
		if err != nil {
			t.Fatalf("CreatePrivateResourceAccess: %v", err)
		}
		access.OpenZitiDialPolicyID = uuid.NewString()
		fakeStore.accesses[access.Meta.ID] = access
	}

	if _, err := server.DeletePrivateResource(callerContext(callerID), &networksv1.DeletePrivateResourceRequest{Id: resource.Meta.ID.String()}); err != nil {
		t.Fatalf("DeletePrivateResource: %v", err)
	}
	if len(ziti.deletedServicePolicies) != int(store.MaxListPageSize)+2 {
		t.Fatalf("expected all access policies deleted, got %d", len(ziti.deletedServicePolicies))
	}
	if len(events.messages) != int(store.MaxListPageSize)+2 {
		t.Fatalf("expected all access revoke events, got %d", len(events.messages))
	}
	for _, message := range events.messages {
		if message.subject != accessRevokedSubject {
			t.Fatalf("expected access revoked subject, got %s", message.subject)
		}
	}
	if len(notifications.requests) != int(store.MaxListPageSize)+3 {
		t.Fatalf("expected access and resource notifications, got %d", len(notifications.requests))
	}
}

func TestTunnelLivenessErrorDoesNotCorruptState(t *testing.T) {
	fakeStore := newFakeStore()
	ziti := &fakeZitiManagementClient{livenessErr: errors.New("ziti unavailable")}
	server := NewWithDependencies(fakeStore, nil, nil, nil, ziti, nil, nil)
	network := fakeStore.mustCreateNetwork(uuid.New())
	credential := fakeStore.mustCreateTunnelCredential(network)
	credential.OpenZitiIdentityID = "ziti-tunnel"
	fakeStore.credentials[credential.Meta.ID] = credential

	if err := server.PollTunnelLiveness(context.Background()); err != nil {
		t.Fatalf("PollTunnelLiveness: %v", err)
	}
	updated := fakeStore.credentials[credential.Meta.ID]
	if updated.EnrollmentState != store.TunnelEnrollmentStatePending || updated.Connectivity != store.TunnelConnectivityOffline {
		t.Fatalf("liveness error changed state: %s %s", updated.EnrollmentState, updated.Connectivity)
	}
}

func TestGroupDeletedCleanupIsIdempotent(t *testing.T) {
	fakeStore := newFakeStore()
	events := &fakeEventPublisher{}
	ziti := &fakeZitiManagementClient{}
	server := NewWithDependencies(fakeStore, nil, nil, nil, ziti, nil, events)
	groupID := uuid.New()
	resource := fakeStore.mustCreatePrivateResource(fakeStore.mustCreateNetwork(uuid.New()))
	access, err := fakeStore.CreatePrivateResourceAccess(context.Background(), store.CreatePrivateResourceAccessInput{ID: uuid.New(), PrivateResourceID: resource.Meta.ID, PrincipalType: store.PrincipalTypeGroup, PrincipalID: groupID})
	if err != nil {
		t.Fatalf("CreatePrivateResourceAccess: %v", err)
	}
	access.OpenZitiDialPolicyID = "dial-policy"
	fakeStore.accesses[access.Meta.ID] = access

	event := &groupsv1.GroupDeletedEvent{GroupId: groupID.String(), OrganizationId: resource.OrganizationID.String()}
	if err := server.HandleGroupDeleted(context.Background(), event); err != nil {
		t.Fatalf("HandleGroupDeleted: %v", err)
	}
	if err := server.HandleGroupDeleted(context.Background(), event); err != nil {
		t.Fatalf("HandleGroupDeleted duplicate: %v", err)
	}
	if _, ok := fakeStore.accesses[access.Meta.ID]; ok {
		t.Fatalf("expected access deleted")
	}
	assertStringSlice(t, ziti.deletedServicePolicies, []string{"dial-policy"})
	if len(events.messages) != 1 || events.messages[0].subject != accessRevokedSubject {
		t.Fatalf("expected one revoked event, got %#v", events.messages)
	}
}

func TestReconcileRecreatesMissingAndDeletesOrphans(t *testing.T) {
	fakeStore := newFakeStore()
	ziti := &fakeZitiManagementClient{
		serviceID:       "service-new",
		servicePolicyID: "policy-new",
		listedServices: []*zitimgmtv1.OpenZitiService{
			{ZitiServiceId: "orphan-service"},
		},
		listedPolicies: []*zitimgmtv1.OpenZitiServicePolicy{
			{ZitiServicePolicyId: "orphan-policy"},
		},
		listedIdentities: []*zitimgmtv1.OpenZitiIdentity{
			{ZitiIdentityId: "orphan-identity"},
		},
	}
	server := NewWithDependencies(fakeStore, nil, nil, nil, ziti, nil, nil)
	network := fakeStore.mustCreateNetwork(uuid.New())
	network.ProvisioningState = store.ProvisioningStateFailed
	fakeStore.networks[network.Meta.ID] = network
	resource := fakeStore.mustCreatePrivateResource(network)
	resource.ProvisioningState = store.ProvisioningStateFailed
	fakeStore.resources[resource.Meta.ID] = resource
	access, err := fakeStore.CreatePrivateResourceAccess(context.Background(), store.CreatePrivateResourceAccessInput{ID: uuid.New(), PrivateResourceID: resource.Meta.ID, PrincipalType: store.PrincipalTypeUser, PrincipalID: uuid.New()})
	if err != nil {
		t.Fatalf("CreatePrivateResourceAccess: %v", err)
	}
	access.ProvisioningState = store.ProvisioningStateFailed
	fakeStore.accesses[access.Meta.ID] = access

	if err := server.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if ziti.listedServices[0].GetTags()[managedByTagKey] != managedByNetworksService {
		t.Fatalf("expected managed tag lookup to use created tag key")
	}
	if fakeStore.networks[network.Meta.ID].ProvisioningState != store.ProvisioningStateActive || fakeStore.networks[network.Meta.ID].OpenZitiBindPolicyID == "" {
		t.Fatalf("expected network reconciled")
	}
	if fakeStore.resources[resource.Meta.ID].ProvisioningState != store.ProvisioningStateActive || fakeStore.resources[resource.Meta.ID].OpenZitiServiceID == "" {
		t.Fatalf("expected resource reconciled")
	}
	if fakeStore.accesses[access.Meta.ID].ProvisioningState != store.ProvisioningStateActive || fakeStore.accesses[access.Meta.ID].OpenZitiDialPolicyID == "" {
		t.Fatalf("expected access reconciled")
	}
	assertStringSlice(t, ziti.deletedServices, []string{"orphan-service"})
	assertStringSlice(t, ziti.deletedServicePolicies, []string{"orphan-policy"})
	assertStringSlice(t, ziti.deletedTunnelIdentity, []string{"orphan-identity"})
}

func TestReconcileRecreatesActiveRowsWithMissingZitiIDs(t *testing.T) {
	fakeStore := newFakeStore()
	ziti := &fakeZitiManagementClient{serviceID: "service-new", servicePolicyID: "policy-new"}
	server := NewWithDependencies(fakeStore, nil, nil, nil, ziti, nil, nil)
	network := fakeStore.mustCreateNetwork(uuid.New())
	network.OpenZitiBindPolicyID = "stale-bind-policy"
	fakeStore.networks[network.Meta.ID] = network
	resource := fakeStore.mustCreatePrivateResource(network)
	resource.OpenZitiServiceID = "stale-service"
	fakeStore.resources[resource.Meta.ID] = resource
	access, err := fakeStore.CreatePrivateResourceAccess(context.Background(), store.CreatePrivateResourceAccessInput{ID: uuid.New(), PrivateResourceID: resource.Meta.ID, PrincipalType: store.PrincipalTypeUser, PrincipalID: uuid.New()})
	if err != nil {
		t.Fatalf("CreatePrivateResourceAccess: %v", err)
	}
	access.OpenZitiDialPolicyID = "stale-dial-policy"
	fakeStore.accesses[access.Meta.ID] = access

	if err := server.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if fakeStore.networks[network.Meta.ID].OpenZitiBindPolicyID == "stale-bind-policy" {
		t.Fatalf("expected stale bind policy replaced")
	}
	if fakeStore.resources[resource.Meta.ID].OpenZitiServiceID == "stale-service" {
		t.Fatalf("expected stale service replaced")
	}
	if fakeStore.accesses[access.Meta.ID].OpenZitiDialPolicyID == "stale-dial-policy" {
		t.Fatalf("expected stale dial policy replaced")
	}
	if len(ziti.deletedServices) != 0 || len(ziti.deletedServicePolicies) != 0 {
		t.Fatalf("did not expect newly recreated resources deleted")
	}
	if len(ziti.createdServices) != 1 || len(ziti.createdServicePolicies) != 2 {
		t.Fatalf("expected stale active rows recreated")
	}
}

func TestManagedTagLookupMatchesCreatedTags(t *testing.T) {
	tags := privateResourceTags(uuid.New(), uuid.New())
	if managedTags()[managedByTagKey] != tags[managedByTagKey] {
		t.Fatalf("managed tag lookup does not match creation tags")
	}
}

func TestAccessPublishFailureReturnsError(t *testing.T) {
	fakeStore := newFakeStore()
	events := &fakeEventPublisher{err: errors.New("nats down")}
	server := NewWithDependencies(fakeStore, nil, nil, nil, nil, nil, events)
	access := store.PrivateResourceAccess{Meta: fakeMeta(uuid.New()), PrivateResourceID: uuid.New(), OrganizationID: uuid.New(), PrincipalType: store.PrincipalTypeUser, PrincipalID: uuid.New()}

	if err := server.publishAccessGranted(context.Background(), access); err == nil {
		t.Fatalf("expected publish error")
	}
	if len(events.messages) != 1 {
		t.Fatalf("expected attempted event publish")
	}
	payload := &networksv1.PrivateResourceAccessGrantedEvent{}
	if err := proto.Unmarshal(events.messages[0].payload, payload); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if payload.GetPrivateResourceAccessId() != access.Meta.ID.String() {
		t.Fatalf("unexpected event payload")
	}
}

func TestGroupDeletedMessageAckPolicies(t *testing.T) {
	fakeStore := newFakeStore()
	server := NewWithDependencies(fakeStore, nil, nil, nil, nil, nil, nil)
	acks := &fakeAcks{}
	server.handleGroupDeletedMessage(context.Background(), []byte("not-proto"), acks.ack, acks.nak, acks.term)
	if acks.termCount != 1 || acks.ackCount != 0 || acks.nakCount != 0 {
		t.Fatalf("expected malformed event terminated, got %#v", acks)
	}

	acks = &fakeAcks{}
	payload, err := proto.Marshal(&groupsv1.GroupDeletedEvent{GroupId: uuid.NewString()})
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	server.handleGroupDeletedMessage(context.Background(), payload, acks.ack, acks.nak, acks.term)
	if acks.ackCount != 1 || acks.nakCount != 0 || acks.termCount != 0 {
		t.Fatalf("expected successful event acked, got %#v", acks)
	}
}

type fakeAcks struct {
	ackCount  int
	nakCount  int
	termCount int
}

func (f *fakeAcks) ack(...nats.AckOpt) error {
	f.ackCount++
	return nil
}

func (f *fakeAcks) nak(...nats.AckOpt) error {
	f.nakCount++
	return nil
}

func (f *fakeAcks) term(...nats.AckOpt) error {
	f.termCount++
	return nil
}

type publishedMessage struct {
	subject  string
	envelope EventEnvelope
	payload  []byte
}

type fakeEventPublisher struct {
	messages []publishedMessage
	err      error
}

func (f *fakeEventPublisher) Publish(_ context.Context, subject string, envelope EventEnvelope, payload []byte) error {
	f.messages = append(f.messages, publishedMessage{subject: subject, envelope: envelope, payload: payload})
	return f.err
}

type fakeNotificationsClient struct {
	requests []*notificationsv1.PublishRequest
}

func (f *fakeNotificationsClient) Publish(_ context.Context, request *notificationsv1.PublishRequest, _ ...grpc.CallOption) (*notificationsv1.PublishResponse, error) {
	f.requests = append(f.requests, request)
	return &notificationsv1.PublishResponse{}, nil
}
