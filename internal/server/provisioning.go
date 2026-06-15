package server

import (
	"context"
	"errors"
	"fmt"

	zitimgmtv1 "github.com/agynio/networks/.gen/go/agynio/api/ziti_management/v1"
	"github.com/agynio/networks/internal/store"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	managedByNetworksService = "networks-service"
	managedByTagKey          = "agyn.managed_by"
	openZitiProtocolTCP      = "tcp"
)

type zitiManagementClient interface {
	CreateService(context.Context, *zitimgmtv1.CreateServiceRequest, ...grpc.CallOption) (*zitimgmtv1.CreateServiceResponse, error)
	UpdateService(context.Context, *zitimgmtv1.UpdateServiceRequest, ...grpc.CallOption) (*zitimgmtv1.UpdateServiceResponse, error)
	DeleteService(context.Context, *zitimgmtv1.DeleteServiceRequest, ...grpc.CallOption) (*zitimgmtv1.DeleteServiceResponse, error)
	CreateServicePolicy(context.Context, *zitimgmtv1.CreateServicePolicyRequest, ...grpc.CallOption) (*zitimgmtv1.CreateServicePolicyResponse, error)
	DeleteServicePolicy(context.Context, *zitimgmtv1.DeleteServicePolicyRequest, ...grpc.CallOption) (*zitimgmtv1.DeleteServicePolicyResponse, error)
	CreateTunnelIdentity(context.Context, *zitimgmtv1.CreateTunnelIdentityRequest, ...grpc.CallOption) (*zitimgmtv1.CreateTunnelIdentityResponse, error)
	DeleteTunnelIdentity(context.Context, *zitimgmtv1.DeleteTunnelIdentityRequest, ...grpc.CallOption) (*zitimgmtv1.DeleteTunnelIdentityResponse, error)
	PatchIdentityRoleAttributes(context.Context, *zitimgmtv1.PatchIdentityRoleAttributesRequest, ...grpc.CallOption) (*zitimgmtv1.PatchIdentityRoleAttributesResponse, error)
	GetIdentityLiveness(context.Context, *zitimgmtv1.GetIdentityLivenessRequest, ...grpc.CallOption) (*zitimgmtv1.GetIdentityLivenessResponse, error)
	ListServicesByTag(context.Context, *zitimgmtv1.ListServicesByTagRequest, ...grpc.CallOption) (*zitimgmtv1.ListServicesByTagResponse, error)
	ListIdentitiesByTag(context.Context, *zitimgmtv1.ListIdentitiesByTagRequest, ...grpc.CallOption) (*zitimgmtv1.ListIdentitiesByTagResponse, error)
	ListServicePoliciesByTag(context.Context, *zitimgmtv1.ListServicePoliciesByTagRequest, ...grpc.CallOption) (*zitimgmtv1.ListServicePoliciesByTagResponse, error)
}

type networkProvisioningResult struct {
	State        store.ProvisioningState
	BindPolicyID string
}

type tunnelProvisioningResult struct {
	State                  store.ProvisioningState
	OpenZitiIdentityID     string
	EnrollmentJWT          string
	EnrollmentJWTExpiresAt *zitimgmtv1.CreateTunnelIdentityResponse
}

type privateResourceProvisioningResult struct {
	State     store.ProvisioningState
	ServiceID string
}

type accessProvisioningResult struct {
	State        store.ProvisioningState
	DialPolicyID string
}

func (s *Server) provisionNetworkBindPolicy(ctx context.Context, networkID uuid.UUID) networkProvisioningResult {
	if s.zitiManagementClient == nil {
		return networkProvisioningResult{State: store.ProvisioningStateActive}
	}
	response, err := s.zitiManagementClient.CreateServicePolicy(ctx, createNetworkBindPolicyRequest(networkID))
	if err != nil {
		return networkProvisioningResult{State: store.ProvisioningStateFailed}
	}
	return networkProvisioningResult{State: store.ProvisioningStateActive, BindPolicyID: response.GetZitiServicePolicyId()}
}

func (s *Server) provisionTunnelIdentity(ctx context.Context, networkID uuid.UUID, credentialID uuid.UUID) (string, string, *zitimgmtv1.CreateTunnelIdentityResponse, error) {
	if s.zitiManagementClient == nil {
		return "", "", nil, nil
	}
	response, err := s.zitiManagementClient.CreateTunnelIdentity(ctx, &zitimgmtv1.CreateTunnelIdentityRequest{
		NetworkId:          networkID.String(),
		TunnelCredentialId: credentialID.String(),
		Tags:               tunnelCredentialTags(networkID, credentialID),
	})
	if err != nil {
		return "", "", nil, err
	}
	_, err = s.zitiManagementClient.PatchIdentityRoleAttributes(ctx, &zitimgmtv1.PatchIdentityRoleAttributesRequest{
		ZitiIdentityId: response.GetZitiIdentityId(),
		Add:            []string{tunnelRoleAttribute(), networkRoleAttribute(networkID)},
	})
	if err != nil {
		_ = ignoreMissing(s.zitiManagementClient.DeleteTunnelIdentity(ctx, &zitimgmtv1.DeleteTunnelIdentityRequest{ZitiIdentityId: response.GetZitiIdentityId()}))
		return "", "", nil, err
	}
	return response.GetZitiIdentityId(), response.GetEnrollmentJwt(), response, nil
}

func (s *Server) provisionPrivateResource(ctx context.Context, resource store.PrivateResource) privateResourceProvisioningResult {
	if s.zitiManagementClient == nil {
		return privateResourceProvisioningResult{State: store.ProvisioningStateActive}
	}
	response, err := s.zitiManagementClient.CreateService(ctx, createPrivateResourceServiceRequest(resource))
	if err != nil {
		return privateResourceProvisioningResult{State: store.ProvisioningStateFailed}
	}
	return privateResourceProvisioningResult{State: store.ProvisioningStateActive, ServiceID: response.GetZitiServiceId()}
}

func (s *Server) updatePrivateResourceProvisioning(ctx context.Context, resource store.PrivateResource) store.ProvisioningState {
	if s.zitiManagementClient == nil || resource.OpenZitiServiceID == "" {
		return store.ProvisioningStateActive
	}
	_, err := s.zitiManagementClient.UpdateService(ctx, updatePrivateResourceServiceRequest(resource))
	if err != nil {
		return store.ProvisioningStateFailed
	}
	return store.ProvisioningStateActive
}

func (s *Server) provisionPrivateResourceAccess(ctx context.Context, access store.PrivateResourceAccess) accessProvisioningResult {
	if s.zitiManagementClient == nil {
		return accessProvisioningResult{State: store.ProvisioningStateActive}
	}
	response, err := s.zitiManagementClient.CreateServicePolicy(ctx, createResourceAccessDialPolicyRequest(access))
	if err != nil {
		return accessProvisioningResult{State: store.ProvisioningStateFailed}
	}
	return accessProvisioningResult{State: store.ProvisioningStateActive, DialPolicyID: response.GetZitiServicePolicyId()}
}

func (s *Server) deleteNetworkZitiResources(ctx context.Context, network store.Network, credentials []store.TunnelCredential, resources []store.PrivateResource, accesses []store.PrivateResourceAccess) error {
	if s.zitiManagementClient == nil {
		return nil
	}
	var deleteErrors []error
	for _, access := range accesses {
		if access.OpenZitiDialPolicyID != "" {
			deleteErrors = append(deleteErrors, ignoreMissing(s.zitiManagementClient.DeleteServicePolicy(ctx, &zitimgmtv1.DeleteServicePolicyRequest{ZitiServicePolicyId: access.OpenZitiDialPolicyID})))
		}
	}
	for _, resource := range resources {
		if resource.OpenZitiServiceID != "" {
			deleteErrors = append(deleteErrors, ignoreMissing(s.zitiManagementClient.DeleteService(ctx, &zitimgmtv1.DeleteServiceRequest{ZitiServiceId: resource.OpenZitiServiceID})))
		}
	}
	for _, credential := range credentials {
		if credential.OpenZitiIdentityID != "" {
			deleteErrors = append(deleteErrors, ignoreMissing(s.zitiManagementClient.DeleteTunnelIdentity(ctx, &zitimgmtv1.DeleteTunnelIdentityRequest{ZitiIdentityId: credential.OpenZitiIdentityID})))
		}
	}
	if network.OpenZitiBindPolicyID != "" {
		deleteErrors = append(deleteErrors, ignoreMissing(s.zitiManagementClient.DeleteServicePolicy(ctx, &zitimgmtv1.DeleteServicePolicyRequest{ZitiServicePolicyId: network.OpenZitiBindPolicyID})))
	}
	return errors.Join(deleteErrors...)
}

func ignoreMissing(_ any, err error) error {
	if status.Code(err) == codes.NotFound {
		return nil
	}
	return err
}

func createNetworkBindPolicyRequest(networkID uuid.UUID) *zitimgmtv1.CreateServicePolicyRequest {
	return &zitimgmtv1.CreateServicePolicyRequest{
		Type:          zitimgmtv1.ServicePolicyType_SERVICE_POLICY_TYPE_BIND,
		Name:          fmt.Sprintf("network-%s-bind", networkID),
		IdentityRoles: []string{zitiRoleSelector(networkRoleAttribute(networkID))},
		ServiceRoles:  []string{zitiRoleSelector(networkResourcesRoleAttribute(networkID))},
		Tags:          networkBindPolicyTags(networkID),
	}
}

func createPrivateResourceServiceRequest(resource store.PrivateResource) *zitimgmtv1.CreateServiceRequest {
	return &zitimgmtv1.CreateServiceRequest{
		Name:              privateResourceServiceName(resource.Meta.ID),
		RoleAttributes:    []string{networkResourcesRoleAttribute(resource.NetworkID)},
		HostV1Config:      hostV1Config(resource),
		InterceptV1Config: interceptV1Config(resource),
		Tags:              privateResourceTags(resource.NetworkID, resource.Meta.ID),
	}
}

func updatePrivateResourceServiceRequest(resource store.PrivateResource) *zitimgmtv1.UpdateServiceRequest {
	return &zitimgmtv1.UpdateServiceRequest{
		ZitiServiceId:     resource.OpenZitiServiceID,
		HostV1Config:      hostV1Config(resource),
		InterceptV1Config: interceptV1Config(resource),
		TagsUpdate:        &zitimgmtv1.TagsUpdate{Tags: privateResourceTags(resource.NetworkID, resource.Meta.ID)},
	}
}

func createResourceAccessDialPolicyRequest(access store.PrivateResourceAccess) *zitimgmtv1.CreateServicePolicyRequest {
	return &zitimgmtv1.CreateServicePolicyRequest{
		Type:          zitimgmtv1.ServicePolicyType_SERVICE_POLICY_TYPE_DIAL,
		Name:          fmt.Sprintf("private-%s-%s-%s-dial", access.PrivateResourceID, access.PrincipalType, access.PrincipalID),
		IdentityRoles: []string{zitiRoleSelector(principalRoleAttribute(access.PrincipalType, access.PrincipalID))},
		ServiceRoles:  []string{zitiNamedServiceSelector(privateResourceServiceName(access.PrivateResourceID))},
		Tags:          privateResourceAccessTags(access.NetworkID, access.Meta.ID),
	}
}

func hostV1Config(resource store.PrivateResource) *zitimgmtv1.HostV1Config {
	return &zitimgmtv1.HostV1Config{
		Protocol:          openZitiProtocolTCP,
		Address:           resource.TargetHost,
		Port:              firstPort(resource.TargetPorts),
		AllowedProtocols:  []string{openZitiProtocolTCP},
		AllowedAddresses:  []string{resource.TargetHost},
		AllowedPortRanges: portRanges(resource.TargetPorts),
	}
}

func interceptV1Config(resource store.PrivateResource) *zitimgmtv1.InterceptV1Config {
	return &zitimgmtv1.InterceptV1Config{
		Protocols:  []string{openZitiProtocolTCP},
		Addresses:  []string{resource.InterceptHost},
		PortRanges: portRanges(resource.InterceptPorts),
	}
}

func portRanges(ports []int32) []*zitimgmtv1.PortRange {
	ranges := make([]*zitimgmtv1.PortRange, 0, len(ports))
	for _, port := range ports {
		ranges = append(ranges, &zitimgmtv1.PortRange{Low: port, High: port})
	}
	return ranges
}

func firstPort(ports []int32) int32 {
	if len(ports) == 0 {
		panic("validated private resource must have at least one target port")
	}
	return ports[0]
}

func privateResourceServiceName(resourceID uuid.UUID) string {
	return fmt.Sprintf("private-%s", resourceID)
}

func networkRoleAttribute(networkID uuid.UUID) string {
	return fmt.Sprintf("network-%s", networkID)
}

func tunnelRoleAttribute() string { return "tunnels" }

func networkResourcesRoleAttribute(networkID uuid.UUID) string {
	return fmt.Sprintf("network-resources-%s", networkID)
}

func principalRoleAttribute(principalType store.PrincipalType, principalID uuid.UUID) string {
	switch principalType {
	case store.PrincipalTypeAgent:
		return fmt.Sprintf("agent-%s", principalID)
	case store.PrincipalTypeUser:
		return fmt.Sprintf("user-%s", principalID)
	case store.PrincipalTypeApp:
		return fmt.Sprintf("app-%s", principalID)
	case store.PrincipalTypeGroup:
		return fmt.Sprintf("group-%s", principalID)
	default:
		panic(fmt.Sprintf("unknown principal type %s", principalType))
	}
}

func zitiRoleSelector(attribute string) string {
	return "#" + attribute
}

func zitiNamedServiceSelector(name string) string {
	return "@" + name
}

func networkBindPolicyTags(networkID uuid.UUID) map[string]string {
	return baseZitiTags("network_bind_policy", networkID, networkID)
}

func tunnelCredentialTags(networkID uuid.UUID, credentialID uuid.UUID) map[string]string {
	return baseZitiTags("tunnel_credential", credentialID, networkID)
}

func privateResourceTags(networkID uuid.UUID, resourceID uuid.UUID) map[string]string {
	return baseZitiTags("private_resource", resourceID, networkID)
}

func privateResourceAccessTags(networkID uuid.UUID, accessID uuid.UUID) map[string]string {
	return baseZitiTags("resource_access", accessID, networkID)
}

func baseZitiTags(resourceType string, resourceID uuid.UUID, networkID uuid.UUID) map[string]string {
	return map[string]string{
		managedByTagKey:      managedByNetworksService,
		"agyn.resource_type": resourceType,
		"agyn.resource_id":   resourceID.String(),
		"agyn.network_id":    networkID.String(),
	}
}
