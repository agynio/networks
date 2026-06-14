package server

import (
	"context"
	"log"

	zitimgmtv1 "github.com/agynio/networks/.gen/go/agynio/api/ziti_management/v1"
	"github.com/agynio/networks/internal/store"
)

func (s *Server) PollTunnelLiveness(ctx context.Context) error {
	if s.zitiManagementClient == nil {
		return nil
	}
	credentials, err := s.store.ListAllTunnelCredentials(ctx)
	if err != nil {
		return err
	}
	for _, credential := range credentials {
		if credential.OpenZitiIdentityID == "" {
			continue
		}
		if err := s.pollTunnelCredentialLiveness(ctx, credential); err != nil {
			log.Printf("poll tunnel liveness %s failed: %v", credential.Meta.ID, err)
		}
	}
	return nil
}

func (s *Server) pollTunnelCredentialLiveness(ctx context.Context, credential store.TunnelCredential) error {
	response, err := s.zitiManagementClient.GetIdentityLiveness(ctx, &zitimgmtv1.GetIdentityLivenessRequest{ZitiIdentityId: credential.OpenZitiIdentityID})
	if err != nil {
		return err
	}
	enrollmentState := tunnelEnrollmentStateFromZiti(response.GetEnrollmentState())
	connectivity := tunnelConnectivityFromZiti(response.GetHasEdgeRouterConnection())
	if credential.EnrollmentState == enrollmentState && credential.Connectivity == connectivity && connectivity == store.TunnelConnectivityOffline {
		return nil
	}
	now := s.now()
	enrolledAt := credential.EnrolledAt
	if enrolledAt == nil && enrollmentState == store.TunnelEnrollmentStateEnrolled {
		enrolledAt = &now
	}
	lastSeenAt := credential.LastSeenAt
	if connectivity == store.TunnelConnectivityOnline {
		lastSeenAt = &now
	}
	updated, err := s.store.UpdateTunnelCredentialLiveness(ctx, store.UpdateTunnelCredentialLivenessInput{
		ID:              credential.Meta.ID,
		EnrollmentState: enrollmentState,
		Connectivity:    connectivity,
		EnrolledAt:      enrolledAt,
		LastSeenAt:      lastSeenAt,
	})
	if err != nil {
		return err
	}
	if credential.Connectivity != updated.Connectivity {
		s.publishTunnelConnectivity(ctx, updated)
	}
	return nil
}

func tunnelEnrollmentStateFromZiti(state zitimgmtv1.IdentityEnrollmentState) store.TunnelEnrollmentState {
	switch state {
	case zitimgmtv1.IdentityEnrollmentState_IDENTITY_ENROLLMENT_STATE_PENDING:
		return store.TunnelEnrollmentStatePending
	case zitimgmtv1.IdentityEnrollmentState_IDENTITY_ENROLLMENT_STATE_ENROLLED:
		return store.TunnelEnrollmentStateEnrolled
	case zitimgmtv1.IdentityEnrollmentState_IDENTITY_ENROLLMENT_STATE_UNSPECIFIED:
		panic("OpenZiti liveness returned unspecified enrollment state")
	default:
		panic("OpenZiti liveness returned unknown enrollment state")
	}
}

func tunnelConnectivityFromZiti(hasEdgeRouterConnection bool) store.TunnelConnectivity {
	if hasEdgeRouterConnection {
		return store.TunnelConnectivityOnline
	}
	return store.TunnelConnectivityOffline
}
