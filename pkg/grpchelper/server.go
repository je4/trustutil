package grpchelper

import (
	"context"
	"crypto/tls"
	"emperror.dev/errors"
	"github.com/je4/utils/v2/pkg/zLogger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"net"
)

func NewServer(addr string, tlsConfig *tls.Config, logger zLogger.ZLogger, opts ...grpc.ServerOption) (*Server, error) {
	listenConfig := &net.ListenConfig{
		Control:   nil,
		KeepAlive: 0,
	}
	lis, err := listenConfig.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot listen on %s", addr)
	}
	interceptor := NewInterceptor(logger)
	opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)), grpc.UnaryInterceptor(interceptor.serverInterceptor))
	grpcServer := grpc.NewServer(opts...)
	server := &Server{
		Server:   grpcServer,
		listener: lis,
		logger:   logger,
	}
	return server, nil
}

type Server struct {
	*grpc.Server
	listener net.Listener
	logger   zLogger.ZLogger
}

func (s *Server) Startup() {

	go func() {
		s.logger.Info().Msg("starting server")
		if err := s.Server.Serve(s.listener); err != nil {
			s.logger.Error().Err(err).Msg("cannot serve")
		} else {
			s.logger.Info().Msg("server stopped")
		}
	}()
}

func (s *Server) Shutdown() error {
	s.Server.GracefulStop()
	return errors.Wrap(s.listener.Close(), "cannot close listener")
}