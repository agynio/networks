package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	authorizationv1 "github.com/agynio/networks/.gen/go/agynio/api/authorization/v1"
	groupsv1 "github.com/agynio/networks/.gen/go/agynio/api/groups/v1"
	identityv1 "github.com/agynio/networks/.gen/go/agynio/api/identity/v1"
	networksv1 "github.com/agynio/networks/.gen/go/agynio/api/networks/v1"
	notificationsv1 "github.com/agynio/networks/.gen/go/agynio/api/notifications/v1"
	zitimgmtv1 "github.com/agynio/networks/.gen/go/agynio/api/ziti_management/v1"
	"github.com/agynio/networks/internal/store"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Store interface {
	UpdateNetworkProvisioning(context.Context, uuid.UUID, store.ProvisioningState, string) (store.Network, error)
	UpdateTunnelCredentialProvisioning(context.Context, uuid.UUID, store.ProvisioningState, string, bool, *time.Time) (store.TunnelCredential, error)
	UpdateTunnelCredentialLiveness(context.Context, store.UpdateTunnelCredentialLivenessInput) (store.TunnelCredential, error)
	UpdatePrivateResourceProvisioning(context.Context, uuid.UUID, store.ProvisioningState, string) (store.PrivateResource, error)
	UpdatePrivateResourceAccessProvisioning(context.Context, uuid.UUID, store.ProvisioningState, string) (store.PrivateResourceAccess, error)
	CreateNetwork(context.Context, store.CreateNetworkInput) (store.Network, error)
	GetNetwork(context.Context, uuid.UUID) (store.Network, error)
	ListNetworks(context.Context, uuid.UUID, int32, *store.PageCursor) ([]store.Network, *store.PageCursor, error)
	ListAllNetworks(context.Context) ([]store.Network, error)
	UpdateNetwork(context.Context, store.UpdateNetworkInput) (store.Network, error)
	DeleteNetwork(context.Context, uuid.UUID) error
	CreateTunnelCredential(context.Context, store.CreateTunnelCredentialInput) (store.TunnelCredential, error)
	GetTunnelCredential(context.Context, uuid.UUID) (store.TunnelCredential, error)
	ListTunnelCredentials(context.Context, uuid.UUID, int32, *store.PageCursor) ([]store.TunnelCredential, *store.PageCursor, error)
	ListAllTunnelCredentials(context.Context) ([]store.TunnelCredential, error)
	ListAllTunnelCredentialsFiltered(context.Context, store.ListTunnelCredentialsFilter) ([]store.TunnelCredential, error)
	DeleteTunnelCredential(context.Context, uuid.UUID) error
	CreatePrivateResource(context.Context, store.CreatePrivateResourceInput) (store.PrivateResource, error)
	GetPrivateResource(context.Context, uuid.UUID) (store.PrivateResource, error)
	ListPrivateResources(context.Context, store.ListPrivateResourcesFilter, int32, *store.PageCursor) ([]store.PrivateResource, *store.PageCursor, error)
	ListAllPrivateResources(context.Context) ([]store.PrivateResource, error)
	ListAllPrivateResourcesFiltered(context.Context, store.ListPrivateResourcesFilterAll) ([]store.PrivateResource, error)
	UpdatePrivateResource(context.Context, store.UpdatePrivateResourceInput) (store.PrivateResource, error)
	DeletePrivateResource(context.Context, uuid.UUID) error
	CreatePrivateResourceAccess(context.Context, store.CreatePrivateResourceAccessInput) (store.PrivateResourceAccess, error)
	GetPrivateResourceAccess(context.Context, uuid.UUID) (store.PrivateResourceAccess, error)
	ListPrivateResourceAccess(context.Context, store.ListPrivateResourceAccessFilter, int32, *store.PageCursor) ([]store.PrivateResourceAccess, *store.PageCursor, error)
	ListAllPrivateResourceAccess(context.Context) ([]store.PrivateResourceAccess, error)
	ListAllPrivateResourceAccessFiltered(context.Context, store.ListPrivateResourceAccessFilterAll) ([]store.PrivateResourceAccess, error)
	ListPrivateResourceAccessByGroupID(context.Context, uuid.UUID) ([]store.PrivateResourceAccess, error)
	DeletePrivateResourceAccess(context.Context, uuid.UUID) error
}

type authorizationClient interface {
	Check(context.Context, *authorizationv1.CheckRequest, ...grpc.CallOption) (*authorizationv1.CheckResponse, error)
}

type identityClient interface {
	GetIdentityType(context.Context, *identityv1.GetIdentityTypeRequest, ...grpc.CallOption) (*identityv1.GetIdentityTypeResponse, error)
}

type groupsClient interface {
	GetGroup(context.Context, *groupsv1.GetGroupRequest, ...grpc.CallOption) (*groupsv1.GetGroupResponse, error)
}

type notificationsClient interface {
	Publish(context.Context, *notificationsv1.PublishRequest, ...grpc.CallOption) (*notificationsv1.PublishResponse, error)
}

type eventPublisher interface {
	Publish(context.Context, string, EventEnvelope, []byte) error
}

type Server struct {
	store                Store
	authorizationClient  authorizationClient
	identityClient       identityClient
	groupsClient         groupsClient
	zitiManagementClient zitiManagementClient
	notificationsClient  notificationsClient
	eventPublisher       eventPublisher
	now                  func() time.Time
}

func New(store Store) *Server { return NewWithClients(store, nil, nil, nil, nil) }

func NewWithClients(store Store, authorizationClient authorizationClient, identityClient identityClient, groupsClient groupsClient, zitiManagementClient zitiManagementClient) *Server {
	return NewWithDependencies(store, authorizationClient, identityClient, groupsClient, zitiManagementClient, nil, nil)
}

func NewWithDependencies(store Store, authorizationClient authorizationClient, identityClient identityClient, groupsClient groupsClient, zitiManagementClient zitiManagementClient, notificationsClient notificationsClient, eventPublisher eventPublisher) *Server {
	return &Server{store: store, authorizationClient: authorizationClient, identityClient: identityClient, groupsClient: groupsClient, zitiManagementClient: zitiManagementClient, notificationsClient: notificationsClient, eventPublisher: eventPublisher, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Server) CreateNetwork(ctx context.Context, request *networksv1.CreateNetworkRequest) (*networksv1.CreateNetworkResponse, error) {
	organizationID, err := parseUUIDField("organization_id", request.GetOrganizationId())
	if err != nil {
		return nil, err
	}
	if err := s.requireOrganizationOwner(ctx, organizationID); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(request.GetName())
	if err := validateName(name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid name: %v", err)
	}
	networkID := uuid.New()
	network, err := s.store.CreateNetwork(ctx, store.CreateNetworkInput{ID: networkID, OrganizationID: organizationID, Name: name, Description: request.GetDescription()})
	if err != nil {
		return nil, toStatus(err)
	}
	provisioning := s.provisionNetworkBindPolicy(ctx, networkID)
	network, err = s.store.UpdateNetworkProvisioning(ctx, networkID, provisioning.State, provisioning.BindPolicyID)
	if err != nil {
		return nil, toStatus(err)
	}
	s.publishNetworkUpdated(ctx, network)
	return &networksv1.CreateNetworkResponse{Network: convertNetwork(network)}, nil
}

func (s *Server) GetNetwork(ctx context.Context, request *networksv1.GetNetworkRequest) (*networksv1.GetNetworkResponse, error) {
	id, err := parseUUIDField("id", request.GetId())
	if err != nil {
		return nil, err
	}
	network, err := s.store.GetNetwork(ctx, id)
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.requireOrganizationMember(ctx, network.OrganizationID); err != nil {
		return nil, err
	}
	return &networksv1.GetNetworkResponse{Network: convertNetwork(network)}, nil
}

func (s *Server) ListNetworks(ctx context.Context, request *networksv1.ListNetworksRequest) (*networksv1.ListNetworksResponse, error) {
	organizationID, err := parseUUIDField("organization_id", request.GetOrganizationId())
	if err != nil {
		return nil, err
	}
	if err := s.requireOrganizationMember(ctx, organizationID); err != nil {
		return nil, err
	}
	cursor, err := decodeCursor(request.GetPageToken())
	if err != nil {
		return nil, err
	}
	networks, nextCursor, err := s.store.ListNetworks(ctx, organizationID, request.GetPageSize(), cursor)
	if err != nil {
		return nil, toStatus(err)
	}
	response := &networksv1.ListNetworksResponse{Networks: make([]*networksv1.Network, 0, len(networks)), NextPageToken: encodeCursor(nextCursor)}
	for _, network := range networks {
		response.Networks = append(response.Networks, convertNetwork(network))
	}
	return response, nil
}

func (s *Server) UpdateNetwork(ctx context.Context, request *networksv1.UpdateNetworkRequest) (*networksv1.UpdateNetworkResponse, error) {
	id, err := parseUUIDField("id", request.GetId())
	if err != nil {
		return nil, err
	}
	current, err := s.store.GetNetwork(ctx, id)
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.requireOrganizationOwner(ctx, current.OrganizationID); err != nil {
		return nil, err
	}
	input := store.UpdateNetworkInput{ID: id}
	if request.Name != nil {
		name := strings.TrimSpace(request.GetName())
		if err := validateName(name); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid name: %v", err)
		}
		input.Name = &name
	}
	if request.Description != nil {
		description := request.GetDescription()
		input.Description = &description
	}
	network, err := s.store.UpdateNetwork(ctx, input)
	if err != nil {
		return nil, toStatus(err)
	}
	s.publishNetworkUpdated(ctx, network)
	return &networksv1.UpdateNetworkResponse{Network: convertNetwork(network)}, nil
}

func (s *Server) DeleteNetwork(ctx context.Context, request *networksv1.DeleteNetworkRequest) (*networksv1.DeleteNetworkResponse, error) {
	id, err := parseUUIDField("id", request.GetId())
	if err != nil {
		return nil, err
	}
	network, err := s.store.GetNetwork(ctx, id)
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.requireOrganizationOwner(ctx, network.OrganizationID); err != nil {
		return nil, err
	}
	credentials, err := s.store.ListAllTunnelCredentialsFiltered(ctx, store.ListTunnelCredentialsFilter{NetworkID: &id})
	if err != nil {
		return nil, toStatus(err)
	}
	resources, err := s.store.ListAllPrivateResourcesFiltered(ctx, store.ListPrivateResourcesFilterAll{NetworkID: &id})
	if err != nil {
		return nil, toStatus(err)
	}
	accesses, err := s.store.ListAllPrivateResourceAccessFiltered(ctx, store.ListPrivateResourceAccessFilterAll{NetworkID: &id})
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.deleteNetworkZitiResources(ctx, network, credentials, resources, accesses); err != nil {
		return nil, status.Errorf(codes.Internal, "delete OpenZiti resources: %v", err)
	}
	if err := s.store.DeleteNetwork(ctx, id); err != nil {
		return nil, toStatus(err)
	}
	s.publishNetworkUpdated(ctx, network)
	return &networksv1.DeleteNetworkResponse{}, nil
}

func (s *Server) CreateTunnelCredential(ctx context.Context, request *networksv1.CreateTunnelCredentialRequest) (*networksv1.CreateTunnelCredentialResponse, error) {
	networkID, err := parseUUIDField("network_id", request.GetNetworkId())
	if err != nil {
		return nil, err
	}
	network, err := s.store.GetNetwork(ctx, networkID)
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.requireOrganizationOwner(ctx, network.OrganizationID); err != nil {
		return nil, err
	}
	credentialID := uuid.New()
	zitiIdentityID, enrollmentJWT, enrollmentResponse, err := s.provisionTunnelIdentity(ctx, networkID, credentialID)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "create OpenZiti tunnel identity: %v", err)
	}
	var expiresAt *time.Time
	if enrollmentResponse != nil && enrollmentResponse.GetEnrollmentJwtExpiresAt() != nil {
		value := enrollmentResponse.GetEnrollmentJwtExpiresAt().AsTime()
		expiresAt = &value
	}
	credential, err := s.store.CreateTunnelCredential(ctx, store.CreateTunnelCredentialInput{ID: credentialID, NetworkID: networkID, OpenZitiIdentityID: zitiIdentityID, EnrollmentJWTRevealed: enrollmentJWT != "", EnrollmentJWTExpiresAt: expiresAt, ProvisioningState: store.ProvisioningStateActive})
	if err != nil {
		return nil, toStatus(err)
	}
	s.publishTunnelCredentialUpdated(ctx, credential)
	return &networksv1.CreateTunnelCredentialResponse{TunnelCredential: convertTunnelCredential(credential), EnrollmentJwt: enrollmentJWT}, nil
}

func (s *Server) GetTunnelCredential(ctx context.Context, request *networksv1.GetTunnelCredentialRequest) (*networksv1.GetTunnelCredentialResponse, error) {
	id, err := parseUUIDField("id", request.GetId())
	if err != nil {
		return nil, err
	}
	credential, err := s.store.GetTunnelCredential(ctx, id)
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.requireOrganizationMember(ctx, credential.OrganizationID); err != nil {
		return nil, err
	}
	return &networksv1.GetTunnelCredentialResponse{TunnelCredential: convertTunnelCredential(credential)}, nil
}

func (s *Server) ListTunnelCredentials(ctx context.Context, request *networksv1.ListTunnelCredentialsRequest) (*networksv1.ListTunnelCredentialsResponse, error) {
	networkID, err := parseUUIDField("network_id", request.GetNetworkId())
	if err != nil {
		return nil, err
	}
	network, err := s.store.GetNetwork(ctx, networkID)
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.requireOrganizationMember(ctx, network.OrganizationID); err != nil {
		return nil, err
	}
	cursor, err := decodeCursor(request.GetPageToken())
	if err != nil {
		return nil, err
	}
	credentials, nextCursor, err := s.store.ListTunnelCredentials(ctx, networkID, request.GetPageSize(), cursor)
	if err != nil {
		return nil, toStatus(err)
	}
	response := &networksv1.ListTunnelCredentialsResponse{TunnelCredentials: make([]*networksv1.TunnelCredential, 0, len(credentials)), NextPageToken: encodeCursor(nextCursor)}
	for _, credential := range credentials {
		response.TunnelCredentials = append(response.TunnelCredentials, convertTunnelCredential(credential))
	}
	return response, nil
}

func (s *Server) DeleteTunnelCredential(ctx context.Context, request *networksv1.DeleteTunnelCredentialRequest) (*networksv1.DeleteTunnelCredentialResponse, error) {
	id, err := parseUUIDField("id", request.GetId())
	if err != nil {
		return nil, err
	}
	credential, err := s.store.GetTunnelCredential(ctx, id)
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.requireOrganizationOwner(ctx, credential.OrganizationID); err != nil {
		return nil, err
	}
	if s.zitiManagementClient != nil && credential.OpenZitiIdentityID != "" {
		_, err := s.zitiManagementClient.DeleteTunnelIdentity(ctx, &zitimgmtv1.DeleteTunnelIdentityRequest{ZitiIdentityId: credential.OpenZitiIdentityID})
		if ignoreMissing(nil, err) != nil {
			return nil, status.Errorf(codes.Internal, "delete OpenZiti tunnel identity: %v", err)
		}
	}
	if err := s.store.DeleteTunnelCredential(ctx, id); err != nil {
		return nil, toStatus(err)
	}
	s.publishTunnelCredentialUpdated(ctx, credential)
	return &networksv1.DeleteTunnelCredentialResponse{}, nil
}

func (s *Server) CreatePrivateResource(ctx context.Context, request *networksv1.CreatePrivateResourceRequest) (*networksv1.CreatePrivateResourceResponse, error) {
	networkID, err := parseUUIDField("network_id", request.GetNetworkId())
	if err != nil {
		return nil, err
	}
	network, err := s.store.GetNetwork(ctx, networkID)
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.requireOrganizationOwner(ctx, network.OrganizationID); err != nil {
		return nil, err
	}
	input, err := createPrivateResourceInput(request, network)
	if err != nil {
		return nil, err
	}
	resource, err := s.store.CreatePrivateResource(ctx, input)
	if err != nil {
		return nil, toStatus(err)
	}
	provisioning := s.provisionPrivateResource(ctx, resource)
	resource, err = s.store.UpdatePrivateResourceProvisioning(ctx, resource.Meta.ID, provisioning.State, provisioning.ServiceID)
	if err != nil {
		return nil, toStatus(err)
	}
	s.publishPrivateResourceUpdated(ctx, resource)
	return &networksv1.CreatePrivateResourceResponse{PrivateResource: convertPrivateResource(resource)}, nil
}

func (s *Server) GetPrivateResource(ctx context.Context, request *networksv1.GetPrivateResourceRequest) (*networksv1.GetPrivateResourceResponse, error) {
	id, err := parseUUIDField("id", request.GetId())
	if err != nil {
		return nil, err
	}
	resource, err := s.store.GetPrivateResource(ctx, id)
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.requireOrganizationMember(ctx, resource.OrganizationID); err != nil {
		return nil, err
	}
	return &networksv1.GetPrivateResourceResponse{PrivateResource: convertPrivateResource(resource)}, nil
}

func (s *Server) ListPrivateResources(ctx context.Context, request *networksv1.ListPrivateResourcesRequest) (*networksv1.ListPrivateResourcesResponse, error) {
	filter := store.ListPrivateResourcesFilter{}
	var organizationID uuid.UUID
	if request.OrganizationId != nil {
		parsed, err := parseUUIDField("organization_id", request.GetOrganizationId())
		if err != nil {
			return nil, err
		}
		organizationID = parsed
		filter.OrganizationID = &organizationID
	}
	if request.NetworkId != nil {
		networkID, err := parseUUIDField("network_id", request.GetNetworkId())
		if err != nil {
			return nil, err
		}
		network, err := s.store.GetNetwork(ctx, networkID)
		if err != nil {
			return nil, toStatus(err)
		}
		if filter.OrganizationID != nil && network.OrganizationID != *filter.OrganizationID {
			return nil, status.Error(codes.InvalidArgument, "network does not belong to organization")
		}
		organizationID = network.OrganizationID
		filter.NetworkID = &networkID
	}
	if organizationID == uuid.Nil {
		return nil, status.Error(codes.InvalidArgument, "organization_id or network_id must be provided")
	}
	if err := s.requireOrganizationMember(ctx, organizationID); err != nil {
		return nil, err
	}
	cursor, err := decodeCursor(request.GetPageToken())
	if err != nil {
		return nil, err
	}
	resources, nextCursor, err := s.store.ListPrivateResources(ctx, filter, request.GetPageSize(), cursor)
	if err != nil {
		return nil, toStatus(err)
	}
	response := &networksv1.ListPrivateResourcesResponse{PrivateResources: make([]*networksv1.PrivateResource, 0, len(resources)), NextPageToken: encodeCursor(nextCursor)}
	for _, resource := range resources {
		response.PrivateResources = append(response.PrivateResources, convertPrivateResource(resource))
	}
	return response, nil
}

func (s *Server) UpdatePrivateResource(ctx context.Context, request *networksv1.UpdatePrivateResourceRequest) (*networksv1.UpdatePrivateResourceResponse, error) {
	id, err := parseUUIDField("id", request.GetId())
	if err != nil {
		return nil, err
	}
	current, err := s.store.GetPrivateResource(ctx, id)
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.requireOrganizationOwner(ctx, current.OrganizationID); err != nil {
		return nil, err
	}
	input, err := updatePrivateResourceInput(request, current)
	if err != nil {
		return nil, err
	}
	resource, err := s.store.UpdatePrivateResource(ctx, input)
	if err != nil {
		return nil, toStatus(err)
	}
	provisioningState := s.updatePrivateResourceProvisioning(ctx, resource)
	openZitiServiceID := resource.OpenZitiServiceID
	if s.zitiManagementClient != nil && openZitiServiceID == "" {
		provisioning := s.provisionPrivateResource(ctx, resource)
		provisioningState = provisioning.State
		openZitiServiceID = provisioning.ServiceID
	}
	resource, err = s.store.UpdatePrivateResourceProvisioning(ctx, resource.Meta.ID, provisioningState, openZitiServiceID)
	if err != nil {
		return nil, toStatus(err)
	}
	s.publishPrivateResourceUpdated(ctx, resource)
	return &networksv1.UpdatePrivateResourceResponse{PrivateResource: convertPrivateResource(resource)}, nil
}

func (s *Server) DeletePrivateResource(ctx context.Context, request *networksv1.DeletePrivateResourceRequest) (*networksv1.DeletePrivateResourceResponse, error) {
	id, err := parseUUIDField("id", request.GetId())
	if err != nil {
		return nil, err
	}
	resource, err := s.store.GetPrivateResource(ctx, id)
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.requireOrganizationOwner(ctx, resource.OrganizationID); err != nil {
		return nil, err
	}
	if s.zitiManagementClient != nil {
		accesses, err := s.store.ListAllPrivateResourceAccessFiltered(ctx, store.ListPrivateResourceAccessFilterAll{PrivateResourceID: &id})
		if err != nil {
			return nil, toStatus(err)
		}
		for _, access := range accesses {
			if access.OpenZitiDialPolicyID != "" {
				_, err := s.zitiManagementClient.DeleteServicePolicy(ctx, &zitimgmtv1.DeleteServicePolicyRequest{ZitiServicePolicyId: access.OpenZitiDialPolicyID})
				if ignoreMissing(nil, err) != nil {
					return nil, status.Errorf(codes.Internal, "delete OpenZiti dial policy: %v", err)
				}
			}
		}
		if resource.OpenZitiServiceID != "" {
			_, err := s.zitiManagementClient.DeleteService(ctx, &zitimgmtv1.DeleteServiceRequest{ZitiServiceId: resource.OpenZitiServiceID})
			if ignoreMissing(nil, err) != nil {
				return nil, status.Errorf(codes.Internal, "delete OpenZiti service: %v", err)
			}
		}
	}
	if err := s.store.DeletePrivateResource(ctx, id); err != nil {
		return nil, toStatus(err)
	}
	s.publishPrivateResourceUpdated(ctx, resource)
	return &networksv1.DeletePrivateResourceResponse{}, nil
}

func (s *Server) CreatePrivateResourceAccess(ctx context.Context, request *networksv1.CreatePrivateResourceAccessRequest) (*networksv1.CreatePrivateResourceAccessResponse, error) {
	resourceID, err := parseUUIDField("private_resource_id", request.GetPrivateResourceId())
	if err != nil {
		return nil, err
	}
	resource, err := s.store.GetPrivateResource(ctx, resourceID)
	if err != nil {
		return nil, toStatus(err)
	}
	principalType, err := toStorePrincipalType(request.GetPrincipalType())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "principal_type: %v", err)
	}
	principalID, err := parseUUIDField("principal_id", request.GetPrincipalId())
	if err != nil {
		return nil, err
	}
	if err := s.requireAccessMutationAllowed(ctx, principalType, principalID, resource.OrganizationID); err != nil {
		return nil, err
	}
	if err := s.validatePrincipalSameOrg(ctx, principalType, principalID, resource.OrganizationID); err != nil {
		return nil, err
	}
	access, err := s.store.CreatePrivateResourceAccess(ctx, store.CreatePrivateResourceAccessInput{ID: uuid.New(), PrivateResourceID: resourceID, PrincipalType: principalType, PrincipalID: principalID})
	if err != nil {
		return nil, toStatus(err)
	}
	provisioning := s.provisionPrivateResourceAccess(ctx, access)
	access, err = s.store.UpdatePrivateResourceAccessProvisioning(ctx, access.Meta.ID, provisioning.State, provisioning.DialPolicyID)
	if err != nil {
		return nil, toStatus(err)
	}
	s.publishAccessGranted(ctx, access)
	return &networksv1.CreatePrivateResourceAccessResponse{PrivateResourceAccess: convertPrivateResourceAccess(access)}, nil
}

func (s *Server) DeletePrivateResourceAccess(ctx context.Context, request *networksv1.DeletePrivateResourceAccessRequest) (*networksv1.DeletePrivateResourceAccessResponse, error) {
	id, err := parseUUIDField("id", request.GetId())
	if err != nil {
		return nil, err
	}
	access, err := s.store.GetPrivateResourceAccess(ctx, id)
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.requireAccessMutationAllowed(ctx, access.PrincipalType, access.PrincipalID, access.OrganizationID); err != nil {
		return nil, err
	}
	if s.zitiManagementClient != nil && access.OpenZitiDialPolicyID != "" {
		_, err := s.zitiManagementClient.DeleteServicePolicy(ctx, &zitimgmtv1.DeleteServicePolicyRequest{ZitiServicePolicyId: access.OpenZitiDialPolicyID})
		if ignoreMissing(nil, err) != nil {
			return nil, status.Errorf(codes.Internal, "delete OpenZiti dial policy: %v", err)
		}
	}
	if err := s.store.DeletePrivateResourceAccess(ctx, id); err != nil {
		return nil, toStatus(err)
	}
	s.publishAccessRevoked(ctx, access)
	return &networksv1.DeletePrivateResourceAccessResponse{}, nil
}

func (s *Server) ListPrivateResourceAccess(ctx context.Context, request *networksv1.ListPrivateResourceAccessRequest) (*networksv1.ListPrivateResourceAccessResponse, error) {
	filter, organizationID, err := s.privateResourceAccessFilter(ctx, request)
	if err != nil {
		return nil, err
	}
	if err := s.requireOrganizationMember(ctx, organizationID); err != nil {
		return nil, err
	}
	cursor, err := decodeCursor(request.GetPageToken())
	if err != nil {
		return nil, err
	}
	accesses, nextCursor, err := s.store.ListPrivateResourceAccess(ctx, filter, request.GetPageSize(), cursor)
	if err != nil {
		return nil, toStatus(err)
	}
	response := &networksv1.ListPrivateResourceAccessResponse{PrivateResourceAccess: make([]*networksv1.PrivateResourceAccess, 0, len(accesses)), NextPageToken: encodeCursor(nextCursor)}
	for _, access := range accesses {
		response.PrivateResourceAccess = append(response.PrivateResourceAccess, convertPrivateResourceAccess(access))
	}
	return response, nil
}

func createPrivateResourceInput(request *networksv1.CreatePrivateResourceRequest, network store.Network) (store.CreatePrivateResourceInput, error) {
	name := strings.TrimSpace(request.GetName())
	if err := validateName(name); err != nil {
		return store.CreatePrivateResourceInput{}, status.Errorf(codes.InvalidArgument, "invalid name: %v", err)
	}
	protocol, err := toStoreProtocol(request.GetProtocol())
	if err != nil {
		return store.CreatePrivateResourceInput{}, status.Errorf(codes.InvalidArgument, "protocol: %v", err)
	}
	targetHost := strings.TrimSpace(request.GetTargetHost())
	if err := validateTargetHost(targetHost); err != nil {
		return store.CreatePrivateResourceInput{}, status.Errorf(codes.InvalidArgument, "target_host: %v", err)
	}
	interceptHost := strings.ToLower(strings.TrimSpace(request.GetInterceptHost()))
	if err := validateInterceptHost(interceptHost); err != nil {
		return store.CreatePrivateResourceInput{}, status.Errorf(codes.InvalidArgument, "intercept_host: %v", err)
	}
	if err := validatePortMapping(request.GetTargetPorts(), request.GetInterceptPorts()); err != nil {
		return store.CreatePrivateResourceInput{}, status.Errorf(codes.InvalidArgument, "ports: %v", err)
	}
	return store.CreatePrivateResourceInput{
		ID:             uuid.New(),
		OrganizationID: network.OrganizationID,
		NetworkID:      network.Meta.ID,
		Name:           name,
		Protocol:       protocol,
		TargetHost:     targetHost,
		TargetPorts:    copyPorts(request.GetTargetPorts()),
		InterceptHost:  interceptHost,
		InterceptPorts: copyPorts(request.GetInterceptPorts()),
	}, nil
}

func updatePrivateResourceInput(request *networksv1.UpdatePrivateResourceRequest, current store.PrivateResource) (store.UpdatePrivateResourceInput, error) {
	input := store.UpdatePrivateResourceInput{ID: current.Meta.ID}
	if request.Name != nil {
		name := strings.TrimSpace(request.GetName())
		if err := validateName(name); err != nil {
			return store.UpdatePrivateResourceInput{}, status.Errorf(codes.InvalidArgument, "invalid name: %v", err)
		}
		input.Name = &name
	}
	if request.Protocol != nil {
		protocol, err := toStoreProtocol(request.GetProtocol())
		if err != nil {
			return store.UpdatePrivateResourceInput{}, status.Errorf(codes.InvalidArgument, "protocol: %v", err)
		}
		input.Protocol = &protocol
	}
	if request.TargetHost != nil {
		targetHost := strings.TrimSpace(request.GetTargetHost())
		if err := validateTargetHost(targetHost); err != nil {
			return store.UpdatePrivateResourceInput{}, status.Errorf(codes.InvalidArgument, "target_host: %v", err)
		}
		input.TargetHost = &targetHost
	}
	if request.InterceptHost != nil {
		interceptHost := strings.ToLower(strings.TrimSpace(request.GetInterceptHost()))
		if err := validateInterceptHost(interceptHost); err != nil {
			return store.UpdatePrivateResourceInput{}, status.Errorf(codes.InvalidArgument, "intercept_host: %v", err)
		}
		input.InterceptHost = &interceptHost
	}
	if request.TargetPortsUpdate != nil || request.InterceptPortsUpdate != nil {
		if request.TargetPortsUpdate == nil || request.InterceptPortsUpdate == nil {
			return store.UpdatePrivateResourceInput{}, status.Error(codes.InvalidArgument, "target_ports_update and intercept_ports_update must be provided together")
		}
		if err := validatePortMapping(request.GetTargetPortsUpdate().GetPorts(), request.GetInterceptPortsUpdate().GetPorts()); err != nil {
			return store.UpdatePrivateResourceInput{}, status.Errorf(codes.InvalidArgument, "ports: %v", err)
		}
		input.TargetPorts = copyPorts(request.GetTargetPortsUpdate().GetPorts())
		input.InterceptPorts = copyPorts(request.GetInterceptPortsUpdate().GetPorts())
		input.UpdatePorts = true
	}
	return input, nil
}

func (s *Server) privateResourceAccessFilter(ctx context.Context, request *networksv1.ListPrivateResourceAccessRequest) (store.ListPrivateResourceAccessFilter, uuid.UUID, error) {
	filter := store.ListPrivateResourceAccessFilter{}
	var organizationID uuid.UUID
	if request.PrivateResourceId != nil {
		resourceID, err := parseUUIDField("private_resource_id", request.GetPrivateResourceId())
		if err != nil {
			return filter, uuid.Nil, err
		}
		resource, err := s.store.GetPrivateResource(ctx, resourceID)
		if err != nil {
			return filter, uuid.Nil, toStatus(err)
		}
		organizationID = resource.OrganizationID
		filter.PrivateResourceID = &resourceID
	}
	if request.NetworkId != nil {
		networkID, err := parseUUIDField("network_id", request.GetNetworkId())
		if err != nil {
			return filter, uuid.Nil, err
		}
		network, err := s.store.GetNetwork(ctx, networkID)
		if err != nil {
			return filter, uuid.Nil, toStatus(err)
		}
		if organizationID != uuid.Nil && network.OrganizationID != organizationID {
			return filter, uuid.Nil, status.Error(codes.InvalidArgument, "network does not belong to private resource organization")
		}
		organizationID = network.OrganizationID
		filter.NetworkID = &networkID
	}
	if request.PrincipalType != nil {
		principalType, err := toStorePrincipalType(request.GetPrincipalType())
		if err != nil {
			return filter, uuid.Nil, status.Errorf(codes.InvalidArgument, "principal_type: %v", err)
		}
		filter.PrincipalType = &principalType
	}
	if request.PrincipalId != nil {
		principalID, err := parseUUIDField("principal_id", request.GetPrincipalId())
		if err != nil {
			return filter, uuid.Nil, err
		}
		filter.PrincipalID = &principalID
	}
	if organizationID == uuid.Nil {
		return filter, uuid.Nil, status.Error(codes.InvalidArgument, "private_resource_id or network_id must be provided")
	}
	return filter, organizationID, nil
}

const (
	identityIDMetadataKey       = "x-identity-id"
	legacyIdentityIDMetadataKey = "identity_id"
	identityObjectPrefix        = "identity:"
	organizationObjectPrefix    = "organization:"
	agentObjectPrefix           = "agent:"
	organizationOwnerRelation   = "owner"
	organizationMemberRelation  = "member"
	agentCanEditConfigRelation  = "can_edit_config"
)

func (s *Server) requireOrganizationOwner(ctx context.Context, organizationID uuid.UUID) error {
	return s.requireAllowed(ctx, organizationOwnerRelation, organizationObject(organizationID))
}

func (s *Server) requireOrganizationMember(ctx context.Context, organizationID uuid.UUID) error {
	return s.requireAllowed(ctx, organizationMemberRelation, organizationObject(organizationID))
}

func (s *Server) requireAgentConfigEditor(ctx context.Context, agentID uuid.UUID) error {
	return s.requireAllowed(ctx, agentCanEditConfigRelation, agentObject(agentID))
}

func (s *Server) requireAccessMutationAllowed(ctx context.Context, principalType store.PrincipalType, principalID uuid.UUID, organizationID uuid.UUID) error {
	if principalType == store.PrincipalTypeAgent {
		return s.requireAgentConfigEditor(ctx, principalID)
	}
	return s.requireOrganizationOwner(ctx, organizationID)
}

func (s *Server) requireAllowed(ctx context.Context, relation string, object string) error {
	if s.authorizationClient == nil {
		return nil
	}
	callerID, err := callerIdentityID(ctx)
	if err != nil {
		return err
	}
	response, err := s.authorizationClient.Check(ctx, &authorizationv1.CheckRequest{TupleKey: &authorizationv1.TupleKey{User: identityObject(callerID), Relation: relation, Object: object}})
	if err != nil {
		return status.Errorf(codes.Internal, "authorization check: %v", err)
	}
	if !response.GetAllowed() {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	return nil
}

func (s *Server) validatePrincipalSameOrg(ctx context.Context, principalType store.PrincipalType, principalID uuid.UUID, organizationID uuid.UUID) error {
	if principalType == store.PrincipalTypeGroup {
		if s.groupsClient == nil {
			return nil
		}
		response, err := s.groupsClient.GetGroup(ctx, &groupsv1.GetGroupRequest{Id: principalID.String()})
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "group lookup: %v", err)
		}
		groupOrgID, err := uuid.Parse(response.GetGroup().GetOrganizationId())
		if err != nil {
			return status.Errorf(codes.Internal, "group organization id: %v", err)
		}
		if groupOrgID != organizationID {
			return status.Error(codes.InvalidArgument, "principal does not belong to resource organization")
		}
		return nil
	}
	if s.identityClient != nil {
		response, err := s.identityClient.GetIdentityType(ctx, &identityv1.GetIdentityTypeRequest{IdentityId: principalID.String()})
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "principal identity lookup: %v", err)
		}
		expected := expectedIdentityType(principalType)
		if response.GetIdentityType() != expected {
			return status.Errorf(codes.InvalidArgument, "principal_type does not match identity type %s", response.GetIdentityType().String())
		}
	}
	if s.authorizationClient == nil {
		return nil
	}
	response, err := s.authorizationClient.Check(ctx, &authorizationv1.CheckRequest{TupleKey: &authorizationv1.TupleKey{User: identityObject(principalID), Relation: organizationMemberRelation, Object: organizationObject(organizationID)}})
	if err != nil {
		return status.Errorf(codes.Internal, "principal organization check: %v", err)
	}
	if !response.GetAllowed() {
		return status.Error(codes.InvalidArgument, "principal does not belong to resource organization")
	}
	return nil
}

func callerIdentityID(ctx context.Context) (uuid.UUID, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return uuid.Nil, status.Error(codes.Unauthenticated, "missing identity metadata")
	}
	identityID := firstMetadataValue(md, identityIDMetadataKey)
	if identityID == "" {
		identityID = firstMetadataValue(md, legacyIdentityIDMetadataKey)
	}
	if strings.TrimSpace(identityID) == "" {
		return uuid.Nil, status.Error(codes.Unauthenticated, "missing identity id")
	}
	id, err := uuid.Parse(identityID)
	if err != nil {
		return uuid.Nil, status.Errorf(codes.Unauthenticated, "identity id: %v", err)
	}
	return id, nil
}

func firstMetadataValue(md metadata.MD, key string) string {
	values := md.Get(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func identityObject(id uuid.UUID) string     { return identityObjectPrefix + id.String() }
func organizationObject(id uuid.UUID) string { return organizationObjectPrefix + id.String() }
func agentObject(id uuid.UUID) string        { return agentObjectPrefix + id.String() }

func parseUUIDField(field string, value string) (uuid.UUID, error) {
	id, err := uuid.Parse(value)
	if err != nil {
		return uuid.Nil, status.Errorf(codes.InvalidArgument, "%s must be a uuid", field)
	}
	return id, nil
}

func decodeCursor(pageToken string) (*store.PageCursor, error) {
	if pageToken == "" {
		return nil, nil
	}
	afterID, err := store.DecodePageToken(pageToken)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid page_token")
	}
	return &store.PageCursor{AfterID: afterID}, nil
}

func encodeCursor(cursor *store.PageCursor) string {
	if cursor == nil {
		return ""
	}
	return store.EncodePageToken(cursor.AfterID)
}

func convertNetwork(network store.Network) *networksv1.Network {
	return &networksv1.Network{
		Meta:              &networksv1.EntityMeta{Id: network.Meta.ID.String(), CreatedAt: timestamppb.New(network.Meta.CreatedAt), UpdatedAt: timestamppb.New(network.Meta.UpdatedAt)},
		OrganizationId:    network.OrganizationID.String(),
		Name:              network.Name,
		Description:       network.Description,
		ProvisioningState: convertProvisioningState(network.ProvisioningState),
	}
}

func convertTunnelCredential(credential store.TunnelCredential) *networksv1.TunnelCredential {
	protoCredential := &networksv1.TunnelCredential{
		Meta:                  &networksv1.EntityMeta{Id: credential.Meta.ID.String(), CreatedAt: timestamppb.New(credential.Meta.CreatedAt), UpdatedAt: timestamppb.New(credential.Meta.UpdatedAt)},
		NetworkId:             credential.NetworkID.String(),
		EnrollmentJwtRevealed: credential.EnrollmentJWTRevealed,
		EnrollmentState:       convertTunnelEnrollmentState(credential.EnrollmentState),
		Connectivity:          convertTunnelConnectivity(credential.Connectivity),
		ProvisioningState:     convertProvisioningState(credential.ProvisioningState),
	}
	if credential.EnrollmentJWTExpiresAt != nil {
		protoCredential.EnrollmentJwtExpiresAt = timestamppb.New(*credential.EnrollmentJWTExpiresAt)
	}
	if credential.EnrolledAt != nil {
		protoCredential.EnrolledAt = timestamppb.New(*credential.EnrolledAt)
	}
	if credential.LastSeenAt != nil {
		protoCredential.LastSeenAt = timestamppb.New(*credential.LastSeenAt)
	}
	return protoCredential
}

func convertPrivateResource(resource store.PrivateResource) *networksv1.PrivateResource {
	return &networksv1.PrivateResource{
		Meta:              &networksv1.EntityMeta{Id: resource.Meta.ID.String(), CreatedAt: timestamppb.New(resource.Meta.CreatedAt), UpdatedAt: timestamppb.New(resource.Meta.UpdatedAt)},
		OrganizationId:    resource.OrganizationID.String(),
		NetworkId:         resource.NetworkID.String(),
		Name:              resource.Name,
		Protocol:          convertProtocol(resource.Protocol),
		TargetHost:        resource.TargetHost,
		TargetPorts:       append([]int32{}, resource.TargetPorts...),
		InterceptHost:     resource.InterceptHost,
		InterceptPorts:    append([]int32{}, resource.InterceptPorts...),
		ProvisioningState: convertProvisioningState(resource.ProvisioningState),
	}
}

func convertPrivateResourceAccess(access store.PrivateResourceAccess) *networksv1.PrivateResourceAccess {
	return &networksv1.PrivateResourceAccess{
		Meta:              &networksv1.EntityMeta{Id: access.Meta.ID.String(), CreatedAt: timestamppb.New(access.Meta.CreatedAt), UpdatedAt: timestamppb.New(access.Meta.UpdatedAt)},
		PrivateResourceId: access.PrivateResourceID.String(),
		PrincipalType:     convertPrincipalType(access.PrincipalType),
		PrincipalId:       access.PrincipalID.String(),
		ProvisioningState: convertProvisioningState(access.ProvisioningState),
	}
}

func convertProvisioningState(state store.ProvisioningState) networksv1.ProvisioningState {
	switch state {
	case store.ProvisioningStateActive:
		return networksv1.ProvisioningState_PROVISIONING_STATE_ACTIVE
	case store.ProvisioningStateFailed:
		return networksv1.ProvisioningState_PROVISIONING_STATE_FAILED
	case store.ProvisioningStateRemoving:
		return networksv1.ProvisioningState_PROVISIONING_STATE_REMOVING
	default:
		panic(fmt.Sprintf("unexpected provisioning state: %q", state))
	}
}

func convertTunnelEnrollmentState(state store.TunnelEnrollmentState) networksv1.TunnelEnrollmentState {
	switch state {
	case store.TunnelEnrollmentStatePending:
		return networksv1.TunnelEnrollmentState_TUNNEL_ENROLLMENT_STATE_PENDING
	case store.TunnelEnrollmentStateEnrolled:
		return networksv1.TunnelEnrollmentState_TUNNEL_ENROLLMENT_STATE_ENROLLED
	default:
		panic(fmt.Sprintf("unexpected tunnel enrollment state: %q", state))
	}
}

func convertTunnelConnectivity(connectivity store.TunnelConnectivity) networksv1.TunnelConnectivity {
	switch connectivity {
	case store.TunnelConnectivityOnline:
		return networksv1.TunnelConnectivity_TUNNEL_CONNECTIVITY_ONLINE
	case store.TunnelConnectivityOffline:
		return networksv1.TunnelConnectivity_TUNNEL_CONNECTIVITY_OFFLINE
	default:
		panic(fmt.Sprintf("unexpected tunnel connectivity: %q", connectivity))
	}
}

func convertProtocol(protocol store.PrivateResourceProtocol) networksv1.PrivateResourceProtocol {
	switch protocol {
	case store.PrivateResourceProtocolTCP:
		return networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_TCP
	case store.PrivateResourceProtocolHTTP:
		return networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_HTTP
	case store.PrivateResourceProtocolHTTPS:
		return networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_HTTPS
	default:
		panic(fmt.Sprintf("unexpected private resource protocol: %q", protocol))
	}
}

func toStoreProtocol(protocol networksv1.PrivateResourceProtocol) (store.PrivateResourceProtocol, error) {
	switch protocol {
	case networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_TCP:
		return store.PrivateResourceProtocolTCP, nil
	case networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_HTTP:
		return store.PrivateResourceProtocolHTTP, nil
	case networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_HTTPS:
		return store.PrivateResourceProtocolHTTPS, nil
	default:
		return "", fmt.Errorf("must be tcp, http, or https")
	}
}

func convertPrincipalType(principalType store.PrincipalType) networksv1.PrivateResourceAccessPrincipalType {
	switch principalType {
	case store.PrincipalTypeAgent:
		return networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_AGENT
	case store.PrincipalTypeUser:
		return networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_USER
	case store.PrincipalTypeApp:
		return networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_APP
	case store.PrincipalTypeGroup:
		return networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_GROUP
	default:
		panic(fmt.Sprintf("unexpected principal type: %q", principalType))
	}
}

func toStorePrincipalType(principalType networksv1.PrivateResourceAccessPrincipalType) (store.PrincipalType, error) {
	switch principalType {
	case networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_AGENT:
		return store.PrincipalTypeAgent, nil
	case networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_USER:
		return store.PrincipalTypeUser, nil
	case networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_APP:
		return store.PrincipalTypeApp, nil
	case networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_GROUP:
		return store.PrincipalTypeGroup, nil
	default:
		return "", fmt.Errorf("must be agent, user, app, or group")
	}
}

func expectedIdentityType(principalType store.PrincipalType) identityv1.IdentityType {
	switch principalType {
	case store.PrincipalTypeAgent:
		return identityv1.IdentityType_IDENTITY_TYPE_AGENT
	case store.PrincipalTypeUser:
		return identityv1.IdentityType_IDENTITY_TYPE_USER
	case store.PrincipalTypeApp:
		return identityv1.IdentityType_IDENTITY_TYPE_APP
	case store.PrincipalTypeGroup:
		panic("group principal has no identity type")
	default:
		panic(fmt.Sprintf("unexpected principal type: %q", principalType))
	}
}

func toStatus(err error) error {
	var notFound *store.NotFoundError
	if errors.As(err, &notFound) {
		return status.Error(codes.NotFound, notFound.Error())
	}
	var alreadyExists *store.AlreadyExistsError
	if errors.As(err, &alreadyExists) {
		return status.Error(codes.AlreadyExists, alreadyExists.Error())
	}
	return status.Error(codes.Internal, err.Error())
}
