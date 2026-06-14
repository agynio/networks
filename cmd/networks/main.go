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
		_ = notificationsv1.NewNotificationsServiceClient(notificationsConn)

		if cfg.NATSURL != "" {
			log.Printf("NetworksService NATS configured at %s; event publisher wiring is deferred to provisioning slices", cfg.NATSURL)
		}
	}

	grpcServer := grpc.NewServer()
	networksv1.RegisterNetworksServiceServer(grpcServer, server.NewWithClients(store.New(pool), authorizationClient, identityClient, groupsClient, zitiClient))

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
