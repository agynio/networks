# Networks

Networks is the control-plane service for Private Networks. This initial skeleton owns the PostgreSQL schema and basic Network CRUD while later slices will add OpenZiti provisioning, durable events, authorization checks, and notifications.

## Configuration

| Environment variable | Default | Required | Description |
| --- | --- | --- | --- |
| `GRPC_ADDRESS` | `:50051` | no | gRPC listen address. |
| `DATABASE_URL` | | yes | PostgreSQL connection string. |
| `DEPENDENCY_CLIENTS_ENABLED` | `false` | no | Enables placeholder gRPC client wiring for downstream dependencies. Keep disabled for skeleton/local startup when dependencies are unavailable. |
| `AUTHORIZATION_GRPC_TARGET` | `authorization:50051` | no | Authorization service target. |
| `ZITI_MANAGEMENT_GRPC_TARGET` | `ziti-management:50051` | no | Ziti Management service target. |
| `GROUPS_GRPC_TARGET` | `groups:50051` | no | Groups service target. |
| `NOTIFICATIONS_GRPC_TARGET` | `notifications:50051` | no | Notifications service target. |
| `NATS_URL` | | no | NATS/JetStream URL for later event publishing slices. |
| `TUNNEL_LIVENESS_INTERVAL` | `1m` | no | Interval for polling tunnel identity enrollment/connectivity from Ziti Management. |
| `RECONCILIATION_INTERVAL` | `5m` | no | Interval for reconciling stored desired state with OpenZiti resources. |

The skeleton applies migrations on startup, registers the Networks gRPC service, and can start without Authorization, Ziti Management, Groups, NATS, or Notifications when `DEPENDENCY_CLIENTS_ENABLED=false`.
