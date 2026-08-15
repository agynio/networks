package server

import (
	"context"
	"log"

	egressv1 "github.com/agynio/networks/.gen/go/agynio/api/egress/v1"
	zitimgmtv1 "github.com/agynio/networks/.gen/go/agynio/api/ziti_management/v1"
	"github.com/agynio/networks/internal/store"
	"github.com/google/uuid"
)

func (s *Server) Reconcile(ctx context.Context) error {
	if s.zitiManagementClient == nil {
		return nil
	}
	services, err := s.listManagedServices(ctx)
	if err != nil {
		return err
	}
	identities, err := s.listManagedIdentities(ctx)
	if err != nil {
		return err
	}
	policies, err := s.listManagedServicePolicies(ctx)
	if err != nil {
		return err
	}
	networks, err := s.store.ListAllNetworks(ctx)
	if err != nil {
		return err
	}
	resources, err := s.store.ListAllPrivateResources(ctx)
	if err != nil {
		return err
	}
	accesses, err := s.store.ListAllPrivateResourceAccess(ctx)
	if err != nil {
		return err
	}
	credentials, err := s.store.ListAllTunnelCredentials(ctx)
	if err != nil {
		return err
	}
	for index, network := range networks {
		networks[index] = s.reconcileNetwork(ctx, network, policies)
	}
	resources = s.reconcileMediation(ctx, resources)
	for index, resource := range resources {
		resources[index] = s.reconcilePrivateResource(ctx, resource, services, policies)
	}
	for index, access := range accesses {
		accesses[index] = s.reconcilePrivateResourceAccess(ctx, access, policies)
	}
	s.cleanupOrphanServices(ctx, resources)
	s.cleanupOrphanServicePolicies(ctx, networks, resources, accesses)
	s.cleanupOrphanIdentities(ctx, credentials, identities)
	return nil
}

// Re-derive each resource's desired mediation from the rules that exist, one
// EgressRules call per organization, so a missed SetPrivateResourceMediation
// self-heals instead of stranding the resource in the wrong topology.
func (s *Server) reconcileMediation(ctx context.Context, resources []store.PrivateResource) []store.PrivateResource {
	if s.egressRulesClient == nil {
		return resources
	}
	indexesByOrganization := map[uuid.UUID][]int{}
	for index, resource := range resources {
		indexesByOrganization[resource.OrganizationID] = append(indexesByOrganization[resource.OrganizationID], index)
	}
	for organizationID, indexes := range indexesByOrganization {
		response, err := s.egressRulesClient.ListMediatedPrivateResources(ctx, &egressv1.ListMediatedPrivateResourcesRequest{OrganizationId: organizationID.String()})
		if err != nil {
			log.Printf("list mediated private resources for organization %s failed: %v", organizationID, err)
			continue
		}
		mediated := map[uuid.UUID]bool{}
		for _, id := range response.GetPrivateResourceIds() {
			resourceID, err := uuid.Parse(id)
			if err != nil {
				continue
			}
			mediated[resourceID] = true
		}
		for _, index := range indexes {
			resource := resources[index]
			desired := store.MediationTunnel
			if mediated[resource.Meta.ID] {
				desired = store.MediationEgressGateway
			}
			if resource.Mediation == desired {
				continue
			}
			updated, err := s.store.UpdatePrivateResourceMediation(ctx, resource.Meta.ID, desired, resource.ProvisioningState, resource.OpenZitiUpstreamServiceIDs, resource.OpenZitiGatewayDialPolicyID)
			if err != nil {
				log.Printf("update mediation for private resource %s failed: %v", resource.Meta.ID, err)
				continue
			}
			// The materialization happens in reconcilePrivateResource, which
			// now sees the drifted binding attribute.
			resources[index] = updated
			s.publishPrivateResourceUpdated(ctx, updated)
		}
	}
	return resources
}

func (s *Server) reconcileNetwork(ctx context.Context, network store.Network, policies []*zitimgmtv1.OpenZitiServicePolicy) store.Network {
	if network.OpenZitiBindPolicyID != "" && network.ProvisioningState == store.ProvisioningStateActive && servicePolicyExists(policies, network.OpenZitiBindPolicyID) {
		return network
	}
	provisioning := s.provisionNetworkBindPolicy(ctx, network.Meta.ID)
	updated, err := s.store.UpdateNetworkProvisioning(ctx, network.Meta.ID, provisioning.State, keepID(provisioning.BindPolicyID, network.OpenZitiBindPolicyID))
	if err != nil {
		log.Printf("reconcile network %s failed: %v", network.Meta.ID, err)
		return network
	}
	return updated
}

func (s *Server) reconcilePrivateResource(ctx context.Context, resource store.PrivateResource, services []*zitimgmtv1.OpenZitiService, policies []*zitimgmtv1.OpenZitiServicePolicy) store.PrivateResource {
	frontHealthy := resource.OpenZitiServiceID != "" && resource.ProvisioningState == store.ProvisioningStateActive &&
		serviceHasRoleAttribute(services, resource.OpenZitiServiceID, privateResourceRoleAttribute(resource.Meta.ID)) &&
		serviceHasRoleAttribute(services, resource.OpenZitiServiceID, expectedBindingAttribute(resource))
	if !frontHealthy {
		provisioning := s.provisionPrivateResource(ctx, resource)
		updated, err := s.store.UpdatePrivateResourceProvisioning(ctx, resource.Meta.ID, provisioning.State, keepID(provisioning.ServiceID, resource.OpenZitiServiceID))
		if err != nil {
			log.Printf("reconcile private resource %s failed: %v", resource.Meta.ID, err)
			return resource
		}
		resource = updated
	}
	// Converge mediation objects only over a healthy front service; a failed
	// front re-provision keeps its failed state for the next pass.
	if resource.ProvisioningState == store.ProvisioningStateActive && (!frontHealthy || !s.mediationHealthy(resource, services, policies)) {
		result := s.materializeMediation(ctx, resource)
		updated, err := s.store.UpdatePrivateResourceMediation(ctx, resource.Meta.ID, resource.Mediation, result.State, result.UpstreamServiceIDs, result.GatewayDialPolicyID)
		if err != nil {
			log.Printf("reconcile mediation for private resource %s failed: %v", resource.Meta.ID, err)
			return resource
		}
		resource = updated
	}
	return resource
}

// The attribute deciding who binds the front service: the network's tunnels,
// or the Egress Gateway while some rule names the resource.
func expectedBindingAttribute(resource store.PrivateResource) string {
	if resource.Mediation == store.MediationEgressGateway {
		return egressServicesRoleAttribute
	}
	return networkResourcesRoleAttribute(resource.NetworkID)
}

func (s *Server) mediationHealthy(resource store.PrivateResource, services []*zitimgmtv1.OpenZitiService, policies []*zitimgmtv1.OpenZitiServicePolicy) bool {
	if resource.Mediation != store.MediationEgressGateway {
		// Leftover upstream objects mean an unfinished flip back.
		return resource.OpenZitiGatewayDialPolicyID == "" && len(resource.OpenZitiUpstreamServiceIDs) == 0
	}
	if resource.OpenZitiGatewayDialPolicyID == "" || !servicePolicyExists(policies, resource.OpenZitiGatewayDialPolicyID) {
		return false
	}
	for _, interceptPort := range resource.InterceptPorts {
		serviceID := resource.OpenZitiUpstreamServiceIDs[interceptPort]
		if serviceID == "" || !serviceHasRoleAttribute(services, serviceID, privateResourceUpstreamsRoleAttribute(resource.Meta.ID)) {
			return false
		}
	}
	return len(resource.OpenZitiUpstreamServiceIDs) == len(resource.InterceptPorts)
}

func (s *Server) reconcilePrivateResourceAccess(ctx context.Context, access store.PrivateResourceAccess, policies []*zitimgmtv1.OpenZitiServicePolicy) store.PrivateResourceAccess {
	if access.OpenZitiDialPolicyID != "" && access.ProvisioningState == store.ProvisioningStateActive && servicePolicyExists(policies, access.OpenZitiDialPolicyID) {
		return access
	}
	provisioning := s.provisionPrivateResourceAccess(ctx, access)
	updated, err := s.store.UpdatePrivateResourceAccessProvisioning(ctx, access.Meta.ID, provisioning.State, keepID(provisioning.DialPolicyID, access.OpenZitiDialPolicyID))
	if err != nil {
		log.Printf("reconcile private resource access %s failed: %v", access.Meta.ID, err)
		return access
	}
	return updated
}

// A failed re-provision must not erase the Ziti ID we already recorded.
func keepID(provisioned, existing string) string {
	if provisioned == "" {
		return existing
	}
	return provisioned
}

// Dial policies select the service by this attribute, so a service missing it
// is as unusable as an absent one and must be re-provisioned.
func serviceHasRoleAttribute(services []*zitimgmtv1.OpenZitiService, serviceID, attribute string) bool {
	for _, service := range services {
		if service.GetZitiServiceId() != serviceID {
			continue
		}
		for _, role := range service.GetRoleAttributes() {
			if role == attribute {
				return true
			}
		}
		return false
	}
	return false
}

func servicePolicyExists(policies []*zitimgmtv1.OpenZitiServicePolicy, policyID string) bool {
	for _, policy := range policies {
		if policy.GetZitiServicePolicyId() == policyID {
			return true
		}
	}
	return false
}

func (s *Server) cleanupOrphanServices(ctx context.Context, resources []store.PrivateResource) {
	managed := map[string]struct{}{}
	// Names shield in-flight mediation flips: an upstream service created but
	// not yet persisted would otherwise be swept as an orphan.
	managedNames := map[string]struct{}{}
	for _, resource := range resources {
		if resource.OpenZitiServiceID != "" {
			managed[resource.OpenZitiServiceID] = struct{}{}
		}
		if resource.Mediation != store.MediationEgressGateway {
			continue
		}
		for _, serviceID := range resource.OpenZitiUpstreamServiceIDs {
			if serviceID != "" {
				managed[serviceID] = struct{}{}
			}
		}
		for _, interceptPort := range resource.InterceptPorts {
			managedNames[privateResourceUpstreamServiceName(resource.Meta.ID, interceptPort)] = struct{}{}
		}
	}
	services, err := s.listManagedServices(ctx)
	if err != nil {
		log.Printf("list managed OpenZiti services failed: %v", err)
		return
	}
	for _, service := range services {
		if _, ok := managed[service.GetZitiServiceId()]; ok {
			continue
		}
		if _, ok := managedNames[service.GetName()]; ok {
			continue
		}
		_, err := s.zitiManagementClient.DeleteService(ctx, &zitimgmtv1.DeleteServiceRequest{ZitiServiceId: service.GetZitiServiceId()})
		if err := ignoreMissing(nil, err); err != nil {
			log.Printf("delete orphan OpenZiti service %s failed: %v", service.GetZitiServiceId(), err)
		}
	}
}

func (s *Server) cleanupOrphanServicePolicies(ctx context.Context, networks []store.Network, resources []store.PrivateResource, accesses []store.PrivateResourceAccess) {
	managed := map[string]struct{}{}
	managedNames := map[string]struct{}{}
	for _, network := range networks {
		if network.OpenZitiBindPolicyID != "" {
			managed[network.OpenZitiBindPolicyID] = struct{}{}
		}
	}
	for _, resource := range resources {
		if resource.Mediation != store.MediationEgressGateway {
			continue
		}
		if resource.OpenZitiGatewayDialPolicyID != "" {
			managed[resource.OpenZitiGatewayDialPolicyID] = struct{}{}
		}
		managedNames[gatewayDialPolicyName(resource.Meta.ID)] = struct{}{}
	}
	for _, access := range accesses {
		if access.OpenZitiDialPolicyID != "" {
			managed[access.OpenZitiDialPolicyID] = struct{}{}
		}
	}
	policies, err := s.listManagedServicePolicies(ctx)
	if err != nil {
		log.Printf("list managed OpenZiti service policies failed: %v", err)
		return
	}
	for _, policy := range policies {
		if _, ok := managed[policy.GetZitiServicePolicyId()]; ok {
			continue
		}
		if _, ok := managedNames[policy.GetName()]; ok {
			continue
		}
		_, err := s.zitiManagementClient.DeleteServicePolicy(ctx, &zitimgmtv1.DeleteServicePolicyRequest{ZitiServicePolicyId: policy.GetZitiServicePolicyId()})
		if err := ignoreMissing(nil, err); err != nil {
			log.Printf("delete orphan OpenZiti service policy %s failed: %v", policy.GetZitiServicePolicyId(), err)
		}
	}
}

func (s *Server) cleanupOrphanIdentities(ctx context.Context, credentials []store.TunnelCredential, identities []*zitimgmtv1.OpenZitiIdentity) {
	managed := map[string]struct{}{}
	for _, credential := range credentials {
		if credential.OpenZitiIdentityID != "" {
			managed[credential.OpenZitiIdentityID] = struct{}{}
		}
	}
	for _, identity := range identities {
		if _, ok := managed[identity.GetZitiIdentityId()]; ok {
			continue
		}
		_, err := s.zitiManagementClient.DeleteTunnelIdentity(ctx, &zitimgmtv1.DeleteTunnelIdentityRequest{ZitiIdentityId: identity.GetZitiIdentityId()})
		if err := ignoreMissing(nil, err); err != nil {
			log.Printf("delete orphan OpenZiti identity %s failed: %v", identity.GetZitiIdentityId(), err)
		}
	}
}

func (s *Server) listManagedServices(ctx context.Context) ([]*zitimgmtv1.OpenZitiService, error) {
	var services []*zitimgmtv1.OpenZitiService
	pageToken := ""
	for {
		response, err := s.zitiManagementClient.ListServicesByTag(ctx, &zitimgmtv1.ListServicesByTagRequest{Tags: managedTags(), PageSize: 100, PageToken: pageToken})
		if err != nil {
			return nil, err
		}
		services = append(services, response.GetServices()...)
		pageToken = response.GetNextPageToken()
		if pageToken == "" {
			return services, nil
		}
	}
}

func (s *Server) listManagedIdentities(ctx context.Context) ([]*zitimgmtv1.OpenZitiIdentity, error) {
	var identities []*zitimgmtv1.OpenZitiIdentity
	pageToken := ""
	for {
		response, err := s.zitiManagementClient.ListIdentitiesByTag(ctx, &zitimgmtv1.ListIdentitiesByTagRequest{Tags: managedTags(), PageSize: 100, PageToken: pageToken})
		if err != nil {
			return nil, err
		}
		identities = append(identities, response.GetIdentities()...)
		pageToken = response.GetNextPageToken()
		if pageToken == "" {
			return identities, nil
		}
	}
}

func (s *Server) listManagedServicePolicies(ctx context.Context) ([]*zitimgmtv1.OpenZitiServicePolicy, error) {
	var policies []*zitimgmtv1.OpenZitiServicePolicy
	pageToken := ""
	for {
		response, err := s.zitiManagementClient.ListServicePoliciesByTag(ctx, &zitimgmtv1.ListServicePoliciesByTagRequest{Tags: managedTags(), PageSize: 100, PageToken: pageToken})
		if err != nil {
			return nil, err
		}
		policies = append(policies, response.GetServicePolicies()...)
		pageToken = response.GetNextPageToken()
		if pageToken == "" {
			return policies, nil
		}
	}
}

func managedTags() map[string]string {
	return map[string]string{managedByTagKey: managedByNetworksService}
}
