package serverapi

import (
	"net/http"

	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/gorilla/mux"
	awsservices "github.com/itga/ops-aws-vpn/pkg/aws"
	"github.com/itga/ops-aws-vpn/pkg/gsuite"
	"github.com/itga/ops-aws-vpn/pkg/pki"
	awspki "github.com/itga/ops-aws-vpn/pkg/pki/aws"
)

var (
	pkiStorage = awspki.NewAWSStorage(awsservices.NewSecretsManagerClient(), awsservices.NewDynamoDBClient())
	apiPKI     = pki.NewPKI(pkiStorage)
	apiSNS     = awsservices.NewSNSClient()
	apiEC2     = awsservices.NewEC2Client()

	apiSecretsManager = awsservices.NewSecretsManagerClient()
	apiDirectory      = gsuite.NewGoogleDirectory(awsservices.NewAWSServiceAccountProvider(apiSecretsManager, "VPN/GoogleServiceAccount"))
)

func NewRouter() *mux.Router {
	r := mux.NewRouter()
	r.Use(func(handler http.Handler) http.Handler {
		return xray.Handler(xray.NewFixedSegmentNamer("vpn-api-server"), handler)
	})

	r.HandleFunc("/config", apiServerConfig).Methods(http.MethodPost)
	r.HandleFunc("/verify", apiServerVerify).Methods(http.MethodPost)
	r.HandleFunc("/connect", apiServerConnect).Methods(http.MethodPost)
	r.HandleFunc("/disconnect", apiServerDisconnect).Methods(http.MethodPost)

	return r
}
