package server

import (
	"context"
	"errors"
	"fmt"
	"log"

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
	// Bound by the Egress Gateway via the static egress-gateway-bind policy.
	egressServicesRoleAttribute = "egress-services"
	// The Egress Gateway's identity role, dial side of the upstream policies.
	egressGatewayHostsRoleAttribute = "egress-gateway-hosts"
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
		log.Printf("provision bind policy for network %s failed: %v", networkID, err)
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
		log.Printf("provision service for private resource %s failed: %v", resource.Meta.ID, err)
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
		log.Printf("update service for private resource %s failed: %v", resource.Meta.ID, err)
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
		log.Printf("provision dial policy for resource access %s failed: %v", access.Meta.ID, err)
		return accessProvisioningResult{State: store.ProvisioningStateFailed}
	}
	return accessProvisioningResult{State: store.ProvisioningStateActive, DialPolicyID: response.GetZitiServicePolicyId()}
}

type mediationProvisioningResult struct {
	State               store.ProvisioningState
	UpstreamServiceIDs  map[int32]string
	GatewayDialPolicyID string
}

// materializeMediation converges the resource's OpenZiti objects with its
// mediation column. Idempotent: creates adopt existing objects by name and
// stale upstream services are removed against the current port pairing.
func (s *Server) materializeMediation(ctx context.Context, resource store.PrivateResource) mediationProvisioningResult {
	if s.zitiManagementClient == nil {
		return mediationProvisioningResult{State: store.ProvisioningStateActive}
	}
	if resource.Mediation == store.MediationEgressGateway {
		return s.materializeGatewayMediation(ctx, resource)
	}
	return s.materializeTunnelMediation(ctx, resource)
}

func (s *Server) materializeGatewayMediation(ctx context.Context, resource store.PrivateResource) mediationProvisioningResult {
	desiredPorts := map[int32]bool{}
	for _, port := range resource.InterceptPorts {
		desiredPorts[port] = true
	}
	// Start from the stored ids so a partial failure never forgets an object
	// that exists; stale entries leave the map only once deleted.
	upstreamIDs := map[int32]string{}
	for port, serviceID := range resource.OpenZitiUpstreamServiceIDs {
		if serviceID != "" {
			upstreamIDs[port] = serviceID
		}
	}
	result := mediationProvisioningResult{
		State:               store.ProvisioningStateActive,
		UpstreamServiceIDs:  upstreamIDs,
		GatewayDialPolicyID: resource.OpenZitiGatewayDialPolicyID,
	}
	fail := func(format string, args ...any) mediationProvisioningResult {
		log.Printf(format, args...)
		result.State = store.ProvisioningStateFailed
		return result
	}
	if resource.OpenZitiServiceID != "" {
		if _, err := s.zitiManagementClient.UpdateService(ctx, updatePrivateResourceServiceRequest(resource)); err != nil {
			return fail("rebind front service for private resource %s failed: %v", resource.Meta.ID, err)
		}
	}
	for i, interceptPort := range resource.InterceptPorts {
		response, err := s.zitiManagementClient.CreateService(ctx, &zitimgmtv1.CreateServiceRequest{
			Name:           privateResourceUpstreamServiceName(resource.Meta.ID, interceptPort),
			RoleAttributes: []string{networkResourcesRoleAttribute(resource.NetworkID), privateResourceUpstreamsRoleAttribute(resource.Meta.ID)},
			HostV1Config:   upstreamServiceHostV1Config(resource, resource.TargetPorts[i]),
			Tags:           privateResourceUpstreamTags(resource.NetworkID, resource.Meta.ID),
			ReturnExisting: true,
		})
		if err != nil {
			return fail("provision upstream service for private resource %s port %d failed: %v", resource.Meta.ID, interceptPort, err)
		}
		// An adopted service keeps its old host.v1; converge it to the current
		// target pairing.
		if _, err := s.zitiManagementClient.UpdateService(ctx, &zitimgmtv1.UpdateServiceRequest{
			ZitiServiceId: response.GetZitiServiceId(),
			HostV1Config:  upstreamServiceHostV1Config(resource, resource.TargetPorts[i]),
		}); err != nil {
			return fail("converge upstream service for private resource %s port %d failed: %v", resource.Meta.ID, interceptPort, err)
		}
		upstreamIDs[interceptPort] = response.GetZitiServiceId()
	}
	for interceptPort, serviceID := range resource.OpenZitiUpstreamServiceIDs {
		if desiredPorts[interceptPort] || serviceID == "" {
			continue
		}
		if err := ignoreMissing(s.zitiManagementClient.DeleteService(ctx, &zitimgmtv1.DeleteServiceRequest{ZitiServiceId: serviceID})); err != nil {
			return fail("delete stale upstream service for private resource %s port %d failed: %v", resource.Meta.ID, interceptPort, err)
		}
		delete(upstreamIDs, interceptPort)
	}
	if result.GatewayDialPolicyID == "" {
		response, err := s.zitiManagementClient.CreateServicePolicy(ctx, &zitimgmtv1.CreateServicePolicyRequest{
			Type:           zitimgmtv1.ServicePolicyType_SERVICE_POLICY_TYPE_DIAL,
			Name:           gatewayDialPolicyName(resource.Meta.ID),
			IdentityRoles:  []string{zitiRoleSelector(egressGatewayHostsRoleAttribute)},
			ServiceRoles:   []string{zitiRoleSelector(privateResourceUpstreamsRoleAttribute(resource.Meta.ID))},
			Tags:           gatewayDialPolicyTags(resource.NetworkID, resource.Meta.ID),
			ReturnExisting: true,
		})
		if err != nil {
			return fail("provision gateway dial policy for private resource %s failed: %v", resource.Meta.ID, err)
		}
		result.GatewayDialPolicyID = response.GetZitiServicePolicyId()
	}
	return result
}

func (s *Server) materializeTunnelMediation(ctx context.Context, resource store.PrivateResource) mediationProvisioningResult {
	result := mediationProvisioningResult{State: store.ProvisioningStateActive}
	fail := func(format string, args ...any) mediationProvisioningResult {
		log.Printf(format, args...)
		result.State = store.ProvisioningStateFailed
		result.UpstreamServiceIDs = resource.OpenZitiUpstreamServiceIDs
		result.GatewayDialPolicyID = resource.OpenZitiGatewayDialPolicyID
		return result
	}
	if resource.OpenZitiServiceID != "" {
		if _, err := s.zitiManagementClient.UpdateService(ctx, updatePrivateResourceServiceRequest(resource)); err != nil {
			return fail("rebind front service for private resource %s failed: %v", resource.Meta.ID, err)
		}
	}
	if resource.OpenZitiGatewayDialPolicyID != "" {
		if err := ignoreMissing(s.zitiManagementClient.DeleteServicePolicy(ctx, &zitimgmtv1.DeleteServicePolicyRequest{ZitiServicePolicyId: resource.OpenZitiGatewayDialPolicyID})); err != nil {
			return fail("delete gateway dial policy for private resource %s failed: %v", resource.Meta.ID, err)
		}
	}
	for interceptPort, serviceID := range resource.OpenZitiUpstreamServiceIDs {
		if serviceID == "" {
			continue
		}
		if err := ignoreMissing(s.zitiManagementClient.DeleteService(ctx, &zitimgmtv1.DeleteServiceRequest{ZitiServiceId: serviceID})); err != nil {
			return fail("delete upstream service for private resource %s port %d failed: %v", resource.Meta.ID, interceptPort, err)
		}
	}
	return result
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
		deleteErrors = append(deleteErrors, s.deleteMediationZitiResources(ctx, resource))
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

func (s *Server) deleteMediationZitiResources(ctx context.Context, resource store.PrivateResource) error {
	if s.zitiManagementClient == nil {
		return nil
	}
	var deleteErrors []error
	if resource.OpenZitiGatewayDialPolicyID != "" {
		deleteErrors = append(deleteErrors, ignoreMissing(s.zitiManagementClient.DeleteServicePolicy(ctx, &zitimgmtv1.DeleteServicePolicyRequest{ZitiServicePolicyId: resource.OpenZitiGatewayDialPolicyID})))
	}
	for _, serviceID := range resource.OpenZitiUpstreamServiceIDs {
		if serviceID != "" {
			deleteErrors = append(deleteErrors, ignoreMissing(s.zitiManagementClient.DeleteService(ctx, &zitimgmtv1.DeleteServiceRequest{ZitiServiceId: serviceID})))
		}
	}
	return errors.Join(deleteErrors...)
}

func createNetworkBindPolicyRequest(networkID uuid.UUID) *zitimgmtv1.CreateServicePolicyRequest {
	return &zitimgmtv1.CreateServicePolicyRequest{
		Type:          zitimgmtv1.ServicePolicyType_SERVICE_POLICY_TYPE_BIND,
		Name:          fmt.Sprintf("network-%s-bind", networkID),
		IdentityRoles: []string{zitiRoleSelector(networkRoleAttribute(networkID))},
		ServiceRoles:  []string{zitiRoleSelector(networkResourcesRoleAttribute(networkID))},
		Tags:          networkBindPolicyTags(networkID),
		// Names are unique in Ziti, so a reconcile after a lost response must
		// adopt what is already there instead of conflicting forever.
		ReturnExisting: true,
	}
}

func createPrivateResourceServiceRequest(resource store.PrivateResource) *zitimgmtv1.CreateServiceRequest {
	return &zitimgmtv1.CreateServiceRequest{
		Name:              privateResourceServiceName(resource.Meta.ID),
		RoleAttributes:    frontServiceRoleAttributes(resource),
		HostV1Config:      frontHostV1Config(resource),
		InterceptV1Config: interceptV1Config(resource),
		Tags:              privateResourceTags(resource.NetworkID, resource.Meta.ID),
		ReturnExisting:    true,
	}
}

func updatePrivateResourceServiceRequest(resource store.PrivateResource) *zitimgmtv1.UpdateServiceRequest {
	return &zitimgmtv1.UpdateServiceRequest{
		ZitiServiceId:        resource.OpenZitiServiceID,
		HostV1Config:         frontHostV1Config(resource),
		InterceptV1Config:    interceptV1Config(resource),
		TagsUpdate:           &zitimgmtv1.TagsUpdate{Tags: privateResourceTags(resource.NetworkID, resource.Meta.ID)},
		RoleAttributesUpdate: &zitimgmtv1.RoleAttributesUpdate{RoleAttributes: frontServiceRoleAttributes(resource)},
	}
}

func createResourceAccessDialPolicyRequest(access store.PrivateResourceAccess) *zitimgmtv1.CreateServicePolicyRequest {
	return &zitimgmtv1.CreateServicePolicyRequest{
		Type:          zitimgmtv1.ServicePolicyType_SERVICE_POLICY_TYPE_DIAL,
		Name:          fmt.Sprintf("private-%s-%s-%s-dial", access.PrivateResourceID, access.PrincipalType, access.PrincipalID),
		IdentityRoles: []string{zitiRoleSelector(principalRoleAttribute(access.PrincipalType, access.PrincipalID))},
		// Ziti resolves "@" references by id only, never by name, and an id would
		// go stale if the service is ever recreated. Select by role attribute.
		ServiceRoles:   []string{zitiRoleSelector(privateResourceRoleAttribute(access.PrivateResourceID))},
		Tags:           privateResourceAccessTags(access.NetworkID, access.Meta.ID),
		ReturnExisting: true,
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

// The mediated front service forwards the dialed address and port to the
// Egress Gateway; the intercept->target port mapping lives in the upstream
// services, one per intercept port.
func frontHostV1Config(resource store.PrivateResource) *zitimgmtv1.HostV1Config {
	if resource.Mediation != store.MediationEgressGateway {
		return hostV1Config(resource)
	}
	return &zitimgmtv1.HostV1Config{
		Protocol:          openZitiProtocolTCP,
		ForwardProtocol:   true,
		ForwardAddress:    true,
		ForwardPort:       true,
		AllowedProtocols:  []string{openZitiProtocolTCP},
		AllowedAddresses:  []string{resource.InterceptHost},
		AllowedPortRanges: portRanges(resource.InterceptPorts),
	}
}

func frontServiceRoleAttributes(resource store.PrivateResource) []string {
	if resource.Mediation == store.MediationEgressGateway {
		return []string{egressServicesRoleAttribute, privateResourceRoleAttribute(resource.Meta.ID)}
	}
	return []string{networkResourcesRoleAttribute(resource.NetworkID), privateResourceRoleAttribute(resource.Meta.ID)}
}

func upstreamServiceHostV1Config(resource store.PrivateResource, targetPort int32) *zitimgmtv1.HostV1Config {
	return &zitimgmtv1.HostV1Config{
		Protocol:          openZitiProtocolTCP,
		Address:           resource.TargetHost,
		Port:              targetPort,
		AllowedProtocols:  []string{openZitiProtocolTCP},
		AllowedAddresses:  []string{resource.TargetHost},
		AllowedPortRanges: []*zitimgmtv1.PortRange{{Low: targetPort, High: targetPort}},
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

func privateResourceUpstreamServiceName(resourceID uuid.UUID, interceptPort int32) string {
	return fmt.Sprintf("private-%s-upstream-%d", resourceID, interceptPort)
}

// Shared by every upstream service of one resource, so the gateway's single
// Dial policy survives the per-port services being recreated on a port change.
func privateResourceUpstreamsRoleAttribute(resourceID uuid.UUID) string {
	return fmt.Sprintf("private-resource-upstreams-%s", resourceID)
}

func gatewayDialPolicyName(resourceID uuid.UUID) string {
	return fmt.Sprintf("private-%s-upstreams-egress-gateway-dial", resourceID)
}

func networkRoleAttribute(networkID uuid.UUID) string {
	return fmt.Sprintf("network-%s", networkID)
}

func tunnelRoleAttribute() string { return "tunnels" }

func networkResourcesRoleAttribute(networkID uuid.UUID) string {
	return fmt.Sprintf("network-resources-%s", networkID)
}

func privateResourceRoleAttribute(resourceID uuid.UUID) string {
	return fmt.Sprintf("private-resource-%s", resourceID)
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
	case store.PrincipalTypeEnvironment:
		// Stamped by the Agents Orchestrator on every workload identity it
		// creates -- agent workloads and sandboxes alike -- and already the
		// target of egress rule attachments. Nothing new is provisioned for it.
		return fmt.Sprintf("environment-%s", principalID)
	default:
		panic(fmt.Sprintf("unknown principal type %s", principalType))
	}
}

func zitiRoleSelector(attribute string) string {
	return "#" + attribute
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

func privateResourceUpstreamTags(networkID uuid.UUID, resourceID uuid.UUID) map[string]string {
	return baseZitiTags("private_resource_upstream", resourceID, networkID)
}

func gatewayDialPolicyTags(networkID uuid.UUID, resourceID uuid.UUID) map[string]string {
	return baseZitiTags("gateway_dial_policy", resourceID, networkID)
}

func baseZitiTags(resourceType string, resourceID uuid.UUID, networkID uuid.UUID) map[string]string {
	return map[string]string{
		managedByTagKey:      managedByNetworksService,
		"agyn.resource_type": resourceType,
		"agyn.resource_id":   resourceID.String(),
		"agyn.network_id":    networkID.String(),
	}
}
