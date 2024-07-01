package grpchelper

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/je4/utils/v2/pkg/zLogger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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

// authenticateAgent check the client credentials
func GetClientsUris(ctx context.Context) ([]string, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		uris := md["uris"][0]
		return strings.Split(uris, ","), nil
	}
	return []string{}, fmt.Errorf("missing credentials")
}

func (i *Interceptor) ServerInterceptor(ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler) (interface{}, error) {

	matches := methodRegexp.FindStringSubmatch(info.FullMethod)
	if len(matches) != 3 {
		return nil, status.Errorf(codes.Internal, "Invalid method name: %s", info.FullMethod)
	}
	// p, ok := peer.FromContext(ctx)
	// if !ok {
	// 	return nil, status.Errorf(codes.Unauthenticated, "could not get peer")
	// }
	// tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	// if !ok {
	// 	return nil, status.Errorf(codes.Unauthenticated, "could not get TLSInfo")
	// }
	// if len(tlsInfo.State.PeerCertificates) == 0 {
	// 	return nil, status.Errorf(codes.Unauthenticated, "no client certificate")
	// }
	// v := tlsInfo.State.PeerCertificates[0]
	// var uris = []string{"*"}
	// for _, domain := range i.domains {
	// 	uris = append(uris, "grpc:"+strings.TrimLeft(domain+"."+matches[1], "."))
	// }
	// //	uri := "grpc:" + matches[1]
	// ok = false
	// for _, u := range v.URIs {
	// 	if slices.Contains(uris, u.String()) {
	// 		ok = true
	// 		break
	// 	}
	// }
	// if !ok {
	// 	return nil, status.Errorf(codes.PermissionDenied, "client certificate does not match URIs: %v", uris)
	// }

	curis, err := GetClientsUris(ctx)
	if err != nil {
		return nil, err
	}
	var uris = []string{"*"}
	for _, domain := range i.domains {
		uris = append(uris, "grpc:"+strings.TrimLeft(domain+"."+matches[1], "."))
	}
	//	uri := "grpc:" + matches[1]
	ok := false
	for _, u := range curis {
		if slices.Contains(uris, u) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, status.Errorf(codes.PermissionDenied, "client certificate does not match URIs: %v", uris)
	}
	start := time.Now()

	// Calls the handler
	h, err := handler(ctx, req)

	// Logging with grpclog (grpclog.LoggerV2)
	i.logger.Debug().Msgf("Request - Method:%s\tDuration:%s\tError:%v",
		info.FullMethod,
		time.Since(start),
		err)

	return h, err
}
