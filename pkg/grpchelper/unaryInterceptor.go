package grpchelper

import (
	"context"
	"github.com/je4/utils/v2/pkg/zLogger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"regexp"
	"time"
)

func NewInterceptor(logger zLogger.ZLogger) *Interceptor {
	return &Interceptor{logger: logger}
}

type Interceptor struct {
	logger zLogger.ZLogger
}

var methodRegexp = regexp.MustCompile(`^/([^/]+)/([^/]+)$`)

func (i *Interceptor) ServerInterceptor(ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler) (interface{}, error) {

	matches := methodRegexp.FindStringSubmatch(info.FullMethod)
	if len(matches) != 3 {
		return nil, status.Errorf(codes.Internal, "Invalid method name: %s", info.FullMethod)
	}
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "could not get peer")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "could not get TLSInfo")
	}
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "no client certificate")
	}
	v := tlsInfo.State.PeerCertificates[0]
	uri := "grpc:" + matches[1]
	ok = false
	for _, u := range v.URIs {
		if u.String() == uri || u.String() == "*" {
			ok = true
			break
		}
	}
	if !ok {
		return nil, status.Errorf(codes.PermissionDenied, "client certificate does not match URI: %s", uri)
	}

	start := time.Now()

	// Calls the handler
	h, err := handler(ctx, req)

	// Logging with grpclog (grpclog.LoggerV2)
	i.logger.Debug().Msgf("Request - Method:%s\tDuration:%s\tError:%v\n",
		info.FullMethod,
		time.Since(start),
		err)

	return h, err
}
