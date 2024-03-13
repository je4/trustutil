package grpchelper

import (
	"log"
	"reflect"

	"google.golang.org/grpc"
)

type ServerInterceptor struct {
	grpc.ServerStream
}

// Set up a wrapper to allow us to access the RecvMsg function
func StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		wrapper := &ServerInterceptor{
			ServerStream: ss,
		}
		return handler(srv, wrapper)
	}
}

func (s *ServerInterceptor) RecvMsg(m interface{}) error {
	// Add logic here
	log.Printf("intercepted server stream message, type: %s", reflect.TypeOf(m).String())
	if err := s.ServerStream.RecvMsg(m); err != nil {
		return err
	}
	return nil
}
