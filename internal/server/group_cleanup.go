package server

import (
	"context"

	groupsv1 "github.com/agynio/networks/.gen/go/agynio/api/groups/v1"
	zitimgmtv1 "github.com/agynio/networks/.gen/go/agynio/api/ziti_management/v1"
	"github.com/google/uuid"
)

func (s *Server) HandleGroupDeleted(ctx context.Context, event *groupsv1.GroupDeletedEvent) error {
	groupID, err := uuid.Parse(event.GetGroupId())
	if err != nil {
		return err
	}
	accesses, err := s.store.ListPrivateResourceAccessByGroupID(ctx, groupID)
	if err != nil {
		return err
	}
	for _, access := range accesses {
		if s.zitiManagementClient != nil && access.OpenZitiDialPolicyID != "" {
			_, err := s.zitiManagementClient.DeleteServicePolicy(ctx, &zitimgmtv1.DeleteServicePolicyRequest{ZitiServicePolicyId: access.OpenZitiDialPolicyID})
			if err := ignoreMissing(nil, err); err != nil {
				return err
			}
		}
		if err := s.store.DeletePrivateResourceAccess(ctx, access.Meta.ID); err != nil {
			return err
		}
		if err := s.publishAccessRevoked(ctx, access); err != nil {
			return err
		}
	}
	return nil
}
