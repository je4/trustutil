package grpchelper

import (
	"context"
	"github.com/je4/utils/v2/pkg/zLogger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"regexp"
	"slices"
	"strings"
	"time"
)

func NewInterceptor(domains []string, logger zLogger.ZLogger) *Interceptor {
	if len(domains) == 0 {
		domains = []string{""}
	}
	return &Interceptor{domains: domains, logger: logger}
}

type Interceptor struct {
	logger  zLogger.ZLogger
	domains []string
}

var methodRegexp = regexp.MustCompile(`^/([^/]+)/([^/]+)$`)
var domainRegexp = regexp.MustCompile(`^([a-zA-Z0-9-]+)\.([a-zA-Z0-9-]+)\.([a-zA-Z0-9-]+)`)

func (i *Interceptor) ServerInterceptor(ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler) (interface{}, error) {

	matches := methodRegexp.FindStringSubmatch(info.FullMethod)
	if len(matches) != 3 {
		return nil, status.Errorf(codes.Internal, "Invalid method name: %s", info.FullMethod)
	}
	if matches[2] != "Ping" {
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
		var uris = []string{"*"}
		for _, domain := range i.domains {
			uris = append(uris, "grpc:"+strings.TrimLeft(domain+"."+matches[1], "."))
		}
		//	uri := "grpc:" + matches[1]
		ok = false
		for _, u := range v.URIs {
			if slices.Contains(uris, u.String()) {
				ok = true
				break
			}
		}
		if !ok {
			return nil, status.Errorf(codes.PermissionDenied, "client certificate does not match URIs: %v", uris)
		}
	}
	var domain string
	if meta, ok := metadata.FromIncomingContext(ctx); ok {
		authority := meta.Get(":authority")
		if len(authority) > 0 {
			matches := domainRegexp.FindStringSubmatch(authority[0])
			if len(matches) == 4 {
				domain = matches[1]
				meta.Set("domain", domain)
				ctx = metadata.NewIncomingContext(ctx, meta)
			}
		}
	}

	start := time.Now()

	// Calls the handler
	h, err := handler(ctx, req)

	// Logging with grpclog (grpclog.LoggerV2)
	i.logger.Debug().Err(err).Str("domain", domain).Str("method", info.FullMethod).Dur("duration", time.Since(start))

	return h, err
}
