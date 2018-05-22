// The onthelambda package provides IAM-based Vault authentication for AWS
// Lambda. You must specify the VAULT_ADDR, VAULT_AUTH_PROVIDER, and
// VAULT_AUTH_ROLE environment variables. Then it's best practice to call
// VaultClient() once at the beginning of your Lambda handler function to
// ensure the client has a valid token that will last for the duration of
// the Lambda run.
package onthelambda

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	vault "github.com/hashicorp/vault/api"
	"io/ioutil"
	"os"
	"time"
)

const VaultAuthHeaderName = "X-Vault-AWS-IAM-Server-ID"

var (
	vaultAddr         string
	vaultAuthProvider string
	vaultAuthRole     string
	vaultAuthHeader   string
	vaultClient       *vault.Client
	token             string
	tokenIsRenewable  bool
	tokenExpiration   time.Time     // actual expiration
	tokenTTL          time.Duration // lifetime of the auth token received
	expirationWindow  time.Duration // time to allow to process a token renewal
	renewalWindow     time.Duration // time before expiration when token should be actively renewed
)

func init() {
	vaultAddr = os.Getenv("VAULT_ADDR")
	vaultAuthProvider = os.Getenv("VAULT_AUTH_PROVIDER")
	vaultAuthRole = os.Getenv("VAULT_AUTH_ROLE")
	vaultAuthHeader = os.Getenv("VAULT_AUTH_HEADER")

	expirationWindow = time.Duration(10) * time.Second

	// should be at least the length of the lambda runtime
	renewalWindow = time.Duration(300) * time.Second

	vaultClient, _ = vault.NewClient(nil)
}

// VaultClient() returns a configured and authenticated Vault client object. If
// the client does not yet exist, it is created and authenticated. If it does
// exist but the token is expired or near expiration, the token will be renewed
// if possible, or a new token will be acquired.
func VaultClient() (*vault.Client, error) {
	if isExpired() {
		return vaultClient, VaultAuth()
	}

	if shouldRenew() {
		return vaultClient, RenewToken()
	}

	return vaultClient, nil
}

func isExpired() bool {
	return time.Now().Add(expirationWindow).After(tokenExpiration)
}

func shouldRenew() bool {
	return time.Now().Add(renewalWindow).After(tokenExpiration)
}

// Renew the token if it is renewable. If it isn't, or if it's expired, refresh
// authentication instead. This is typically called internally.
func RenewToken() error {
	if isExpired() || !tokenIsRenewable {
		return VaultAuth()
	}

	resp, err := vaultClient.Auth().Token().RenewSelf(int(tokenTTL))
	if err != nil {
		return err
	}

	return parseToken(resp)
}

func parseToken(resp *vault.Secret) error {
	var err error
	if token, err = resp.TokenID(); err != nil {
		return err
	}

	if tokenIsRenewable, err = resp.TokenIsRenewable(); err != nil {
		return err
	}

	if tokenTTL, err = resp.TokenTTL(); err != nil {
		return err
	}
	tokenExpiration = time.Now().Add(tokenTTL)

	vaultClient.SetToken(token)

	return nil
}

// Call VaultAuth() to authenticate the Lambda execution role to the Vault auth
// context specified by the VAULT_ADDR, VAULT_AUTH_PROVIDER, and VAULT_AUTH_ROLE
// environment variables. If no error is returned, then VaultClient is ready to
// go. This function is typically called internally.
//
// This code was adapted from Hashicorp Vault:
//   https://github.com/hashicorp/vault/blob/e2bb2ec3b93a242a167f763684f93df867bb253d/builtin/credential/aws/cli.go#L78
//
func VaultAuth() error {
	if vaultAddr == "" || vaultAuthProvider == "" || vaultAuthRole == "" {
		return fmt.Errorf("You must set the VAULT_ADDR, VAULT_AUTH_PROVIDER, and VAULT_AUTH_ROLE environment variables.")
	}

	stsSvc := sts.New(session.New())
	req, _ := stsSvc.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})

	if vaultAuthHeader != "" {
		// if supplied, and then sign the request including that header
		req.HTTPRequest.Header.Add(VaultAuthHeaderName, vaultAuthHeader)
	}
	req.Sign()

	headers, err := json.Marshal(req.HTTPRequest.Header)
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(req.HTTPRequest.Body)
	if err != nil {
		return err
	}

	d := make(map[string]interface{})
	d["iam_http_request_method"] = req.HTTPRequest.Method
	d["iam_request_url"] = base64.StdEncoding.EncodeToString([]byte(req.HTTPRequest.URL.String()))
	d["iam_request_headers"] = base64.StdEncoding.EncodeToString(headers)
	d["iam_request_body"] = base64.StdEncoding.EncodeToString(body)
	d["role"] = vaultAuthRole

	resp, err := vaultClient.Logical().Write(fmt.Sprintf("auth/%s/login", vaultAuthProvider), d)
	if err != nil {
		return err
	}
	if resp == nil {
		return fmt.Errorf("Got no response from the %s authentication provider", vaultAuthProvider)
	}

	return parseToken(resp)
}
