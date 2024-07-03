package grpchelper

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"emperror.dev/errors"
	"github.com/je4/trustutil/v2/pkg/tlsutil"
	"github.com/je4/utils/v2/pkg/zLogger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func NewServer(addr string, tlsConfig *tls.Config, cert, key string, domains []string, logger zLogger.ZLogger, opts ...grpc.ServerOption) (*Server, error) {
	listenConfig := &net.ListenConfig{
		Control:   nil,
		KeepAlive: 0,
	}
	lis, err := listenConfig.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot listen on %s", addr)
	}
	logger.Info().Msgf("listening on %s", lis.Addr().String())
	l2 := logger.With().Str("addr", lis.Addr().String()).Logger()
	interceptor := NewInterceptor(domains, &l2)

	if tlsConfig == nil {
		tlsConfig, err = tlsutil.CreateDefaultServerTLSConfig("devServer", true)
		if err != nil {
			return nil, errors.Wrap(err, "cannot create default server TLS config")
		}
	}
	creds, err := credentials.NewServerTLSFromFile(cert, key)
	if err != nil {
		fmt.Println("credentials.NewServerTLSFromFile err", err)
	}
	// creds2, err := credentials.NewClientTLSFromFile(cert, key)
	// if err != nil {
	// 	fmt.Println("credentials.NewServerTLSFromFile err", err)
	// }
	// creds, err := credentials.Ne(cert, key)
	// fmt.Println("credentials.NewTLS(tlsConfig)", credentials.NewTLS(tlsConfig))

	fmt.Println("\ngrpc.Creds(creds)", (creds))
	// fmt.Println("\ngrpc.Creds(creds)", (credentials.NewTLS(tlsConfig).Info()))
	opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)), grpc.UnaryInterceptor(interceptor.ServerInterceptor))
	// opts = append(opts, grpc.Creds(creds), grpc.UnaryInterceptor(interceptor.ServerInterceptor))
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

func (s *Server) GetAddr() string {
	return s.listener.Addr().String()
}

func (s *Server) Startup() {

	go func() {
		s.logger.Info().Msgf("starting server at %s", s.listener.Addr().String())
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
