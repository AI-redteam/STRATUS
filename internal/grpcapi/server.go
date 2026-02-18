// Package grpcapi provides the internal gRPC API for STRATUS.
// This API is shared by the CLI (via unix socket), GUI (via Wails bindings),
// and teamserver (via mTLS network transport).
package grpcapi

import (
	"fmt"
	"net"

	"github.com/stratus-framework/stratus/internal/core"
	"github.com/stratus-framework/stratus/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Server wraps the gRPC server and the STRATUS engine.
type Server struct {
	grpcServer *grpc.Server
	listener   net.Listener
	handler    *Handler
}

// NewServer creates a new gRPC server bound to a unix socket.
func NewServer(socketPath string, engine *core.Engine) (*Server, error) {
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", socketPath, err)
	}

	s := grpc.NewServer()
	svc := NewService(engine)
	h := NewHandler(svc)
	h.RegisterWithGRPC(s)

	return &Server{
		grpcServer: s,
		listener:   lis,
		handler:    h,
	}, nil
}

// NewTCPServer creates a plaintext gRPC server (for local/dev use only).
func NewTCPServer(addr string, engine *core.Engine) (*Server, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", addr, err)
	}

	s := grpc.NewServer()
	svc := NewService(engine)
	h := NewHandler(svc)
	h.RegisterWithGRPC(s)

	return &Server{
		grpcServer: s,
		listener:   lis,
		handler:    h,
	}, nil
}

// TLSConfig holds the mTLS configuration for the teamserver.
type TLSConfig struct {
	ServerCert *pki.CertBundle
	CACertPEM  []byte
}

// NewMTLSServer creates a gRPC server with mutual TLS authentication.
// Client certificates must be signed by the same CA.
func NewMTLSServer(addr string, engine *core.Engine, tlsCfg *TLSConfig) (*Server, error) {
	creds, err := pki.ServerTransportCredentials(tlsCfg.ServerCert, tlsCfg.CACertPEM)
	if err != nil {
		return nil, fmt.Errorf("configuring mTLS: %w", err)
	}

	return newServerWithCreds(addr, engine, creds)
}

func newServerWithCreds(addr string, engine *core.Engine, creds credentials.TransportCredentials) (*Server, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", addr, err)
	}

	s := grpc.NewServer(grpc.Creds(creds))
	svc := NewService(engine)
	h := NewHandler(svc)
	h.RegisterWithGRPC(s)

	return &Server{
		grpcServer: s,
		listener:   lis,
		handler:    h,
	}, nil
}

// Serve starts serving gRPC requests.
func (s *Server) Serve() error {
	return s.grpcServer.Serve(s.listener)
}

// Stop gracefully stops the gRPC server.
func (s *Server) Stop() {
	s.grpcServer.GracefulStop()
}

// GRPCServer returns the underlying gRPC server for service registration.
func (s *Server) GRPCServer() *grpc.Server {
	return s.grpcServer
}

// Handler returns the JSON-RPC handler for direct access.
func (s *Server) Handler() *Handler {
	return s.handler
}
