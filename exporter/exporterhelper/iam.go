package exporterhelper

import (
	"context"
	"crypto/tls"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	iam_v1 "github.com/Traceableai/iam/proto/v1"
)

const tokenEnvVarKey = "TRACEABLEAI_TOKEN"

// GetTokenFromEnv return the token if set as an env var
func GetTokenFromEnv() string {
	return os.Getenv(tokenEnvVarKey)
}

// RefreshJWT set the Authorization header with an updated jwt
func RefreshJWT(iamEndpoint string, token string, headers *map[string]string) error {
	if *headers == nil {
		*headers = make(map[string]string)
	}

	cc, err := grpc.Dial(iamEndpoint, grpc.WithBlock(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	if err != nil {
		return err
	}
	c := iam_v1.NewIamServiceClient(cc)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r, err := c.RefreshAgentToken(ctx, &iam_v1.RefreshAgentTokenRequest{RefreshToken: token})
	if err != nil {
		return err
	}

	(*headers)["Authorization"] = "Bearer " + r.GetJwt()
	return nil
}
