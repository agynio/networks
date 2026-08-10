package server

import (
	"context"
	"log"

	zitimgmtv1 "github.com/agynio/networks/.gen/go/agynio/api/ziti_management/v1"
	"github.com/agynio/networks/internal/store"
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
	for index, resource := range resources {
		resources[index] = s.reconcilePrivateResource(ctx, resource, services)
	}
	for index, access := range accesses {
		accesses[index] = s.reconcilePrivateResourceAccess(ctx, access, policies)
	}
	s.cleanupOrphanServices(ctx, resources)
	s.cleanupOrphanServicePolicies(ctx, networks, accesses)
	s.cleanupOrphanIdentities(ctx, credentials, identities)
	return nil
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

func (s *Server) reconcilePrivateResource(ctx context.Context, resource store.PrivateResource, services []*zitimgmtv1.OpenZitiService) store.PrivateResource {
	if resource.OpenZitiServiceID != "" && resource.ProvisioningState == store.ProvisioningStateActive && serviceHasRoleAttribute(services, resource.OpenZitiServiceID, privateResourceRoleAttribute(resource.Meta.ID)) {
		return resource
	}
	provisioning := s.provisionPrivateResource(ctx, resource)
	updated, err := s.store.UpdatePrivateResourceProvisioning(ctx, resource.Meta.ID, provisioning.State, keepID(provisioning.ServiceID, resource.OpenZitiServiceID))
	if err != nil {
		log.Printf("reconcile private resource %s failed: %v", resource.Meta.ID, err)
		return resource
	}
	return updated
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
	for _, resource := range resources {
		if resource.OpenZitiServiceID != "" {
			managed[resource.OpenZitiServiceID] = struct{}{}
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
		_, err := s.zitiManagementClient.DeleteService(ctx, &zitimgmtv1.DeleteServiceRequest{ZitiServiceId: service.GetZitiServiceId()})
		if err := ignoreMissing(nil, err); err != nil {
			log.Printf("delete orphan OpenZiti service %s failed: %v", service.GetZitiServiceId(), err)
		}
	}
}

func (s *Server) cleanupOrphanServicePolicies(ctx context.Context, networks []store.Network, accesses []store.PrivateResourceAccess) {
	managed := map[string]struct{}{}
	for _, network := range networks {
		if network.OpenZitiBindPolicyID != "" {
			managed[network.OpenZitiBindPolicyID] = struct{}{}
		}
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
