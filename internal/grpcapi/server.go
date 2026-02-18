// Package grpcapi provides the internal gRPC API skeleton for STRATUS.
// This API is shared by the CLI (via unix socket), GUI (via Wails bindings),
// and teamserver (via mTLS network transport).
package grpcapi

import (
	"fmt"
	"net"

	"google.golang.org/grpc"
)

// Server wraps the gRPC server and the STRATUS engine.
type Server struct {
	grpcServer *grpc.Server
	listener   net.Listener
}

// NewServer creates a new gRPC server bound to a unix socket.
func NewServer(socketPath string) (*Server, error) {
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", socketPath, err)
	}

	s := grpc.NewServer()

	return &Server{
		grpcServer: s,
		listener:   lis,
	}, nil
}

// NewTCPServer creates a gRPC server for teamserver mode (mTLS).
func NewTCPServer(addr string) (*Server, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", addr, err)
	}

	// In production, this would use TLS credentials
	s := grpc.NewServer()

	return &Server{
		grpcServer: s,
		listener:   lis,
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
