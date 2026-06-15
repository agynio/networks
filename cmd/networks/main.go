package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	authorizationv1 "github.com/agynio/networks/.gen/go/agynio/api/authorization/v1"
	groupsv1 "github.com/agynio/networks/.gen/go/agynio/api/groups/v1"
	identityv1 "github.com/agynio/networks/.gen/go/agynio/api/identity/v1"
	networksv1 "github.com/agynio/networks/.gen/go/agynio/api/networks/v1"
	notificationsv1 "github.com/agynio/networks/.gen/go/agynio/api/notifications/v1"
	zitimgmtv1 "github.com/agynio/networks/.gen/go/agynio/api/ziti_management/v1"
	"github.com/agynio/networks/internal/config"
	"github.com/agynio/networks/internal/db"
	"github.com/agynio/networks/internal/server"
	"github.com/agynio/networks/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("networks-service: %v", err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}

	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("parse database url: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return fmt.Errorf("create connection pool: %w", err)
	}
	defer pool.Close()

	if err := db.ApplyMigrations(ctx, pool); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}

	closeConn := func(conn *grpc.ClientConn) {
		if conn != nil {
			_ = conn.Close()
		}
	}
	var (
		authorizationClient authorizationv1.AuthorizationServiceClient
		identityClient      identityv1.IdentityServiceClient
		groupsClient        groupsv1.GroupsServiceClient
		zitiClient          zitimgmtv1.ZitiManagementServiceClient
		notificationsClient notificationsv1.NotificationsServiceClient
		eventPublisher      server.EventPublisher
		natsConn            server.NATSConn
	)
	if cfg.DependencyClientsEnabled {
		authConn, err := grpc.NewClient(cfg.AuthorizationGRPCTarget, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return fmt.Errorf("connect to authorization: %w", err)
		}
		defer closeConn(authConn)
		authorizationClient = authorizationv1.NewAuthorizationServiceClient(authConn)

		identityConn, err := grpc.NewClient(cfg.IdentityGRPCTarget, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return fmt.Errorf("connect to identity: %w", err)
		}
		defer closeConn(identityConn)
		identityClient = identityv1.NewIdentityServiceClient(identityConn)

		zitiConn, err := grpc.NewClient(cfg.ZitiManagementGRPCTarget, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return fmt.Errorf("connect to ziti management: %w", err)
		}
		defer closeConn(zitiConn)
		zitiClient = zitimgmtv1.NewZitiManagementServiceClient(zitiConn)

		groupsConn, err := grpc.NewClient(cfg.GroupsGRPCTarget, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return fmt.Errorf("connect to groups: %w", err)
		}
		defer closeConn(groupsConn)
		groupsClient = groupsv1.NewGroupsServiceClient(groupsConn)

		notificationsConn, err := grpc.NewClient(cfg.NotificationsGRPCTarget, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return fmt.Errorf("connect to notifications: %w", err)
		}
		defer closeConn(notificationsConn)
		notificationsClient = notificationsv1.NewNotificationsServiceClient(notificationsConn)

		if cfg.NATSURL != "" {
			conn, err := server.ConnectNATS(cfg.NATSURL)
			if err != nil {
				return fmt.Errorf("connect to nats: %w", err)
			}
			natsConn = conn
			defer natsConn.Close()
			eventPublisher, err = server.NewNATSPublisher(natsConn)
			if err != nil {
				return fmt.Errorf("create nats publisher: %w", err)
			}
		}
	}

	grpcServer := grpc.NewServer()
	networksStore := store.New(pool)
	networksServer := server.NewWithDependencies(networksStore, authorizationClient, identityClient, groupsClient, zitiClient, notificationsClient, eventPublisher)
	if err := networksServer.Reconcile(ctx); err != nil {
		return fmt.Errorf("initial reconciliation: %w", err)
	}
	if cfg.DependencyClientsEnabled && cfg.NATSURL != "" {
		networksSubscription, err := networksServer.SubscribeGroupDeleted(ctx, natsConn)
		if err != nil {
			return fmt.Errorf("subscribe group deleted events: %w", err)
		}
		defer func() {
			if err := networksSubscription.Unsubscribe(); err != nil {
				log.Printf("unsubscribe group deleted consumer: %v", err)
			}
		}()
	}
	startPeriodic(ctx, cfg.ReconciliationInterval, func() { _ = networksServer.Reconcile(context.Background()) })
	startPeriodic(ctx, cfg.TunnelLivenessInterval, func() { _ = networksServer.PollTunnelLiveness(context.Background()) })
	networksv1.RegisterNetworksServiceServer(grpcServer, networksServer)

	lis, err := net.Listen("tcp", cfg.GRPCAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.GRPCAddress, err)
	}

	go func() {
		<-ctx.Done()
		grpcServer.GracefulStop()
	}()

	log.Printf("NetworksService listening on %s", cfg.GRPCAddress)
	if err := grpcServer.Serve(lis); err != nil {
		if errors.Is(err, grpc.ErrServerStopped) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

func startPeriodic(ctx context.Context, interval time.Duration, run func()) {
	if interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run()
			}
		}
	}()
}
