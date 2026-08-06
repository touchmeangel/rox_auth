package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/touchmeangel/rox_auth/config"
	"github.com/touchmeangel/rox_auth/internal/rpc"
	"github.com/touchmeangel/rox_auth/internal/token"
	"github.com/touchmeangel/rox_sdk_go/models/user"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	authpb "github.com/touchmeangel/rox_proto/rox/auth/v1"
)

func createPool(databaseURL string) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}

	poolCfg.MaxConnLifetime = time.Hour
	poolCfg.MaxConnIdleTime = 30 * time.Minute
	poolCfg.HealthCheckPeriod = time.Minute

	pool, err := pgxpool.NewWithConfig(context.Background(), poolCfg)
	if err != nil {
		return nil, err
	}

	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		return nil, err
	}

	return pool, nil
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Error("failed to load config", "error", err)
	}

	pool, err := createPool(cfg.DatabaseURL)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		return
	}
	defer pool.Close()

	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		logger.Error("listen failed", "addr", cfg.ListenAddr, "error", err)
		return
	}

	sem := make(chan struct{}, cfg.MaxConcurrentTasks)

	grpcServer := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.ChainUnaryInterceptor(
			rpc.LoggingInterceptor(logger),
			rpc.ConcurrencyLimiter(sem),
		),
	)

	redis := token.NewRedisTokenStore(cfg.RedisAddr, cfg.RedisPassword)

	srv := rpc.NewServer(
		user.NewUserStore(pool),
		redis,
		cfg.AccessTokenTTL,
		cfg.RefreshTokenTTL,
		cfg.JwtIssuer,
		cfg.JwtAudiences,
	)

	authpb.RegisterAuthServiceServer(grpcServer, srv)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("ready to accept tasks", "addr", cfg.ListenAddr, "max_concurrent", cfg.MaxConcurrentTasks)
		if err := grpcServer.Serve(lis); err != nil {
			logger.Error("grpc server exited with error", "error", err)
		}
	}()

	<-ctx.Done()
	logger.Info("shutdown signal received, draining in-flight tasks")

	done := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		logger.Warn("graceful stop timed out, forcing shutdown")
		grpcServer.Stop()
	}
}
