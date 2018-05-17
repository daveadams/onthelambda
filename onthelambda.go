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
)

const VaultAuthHeaderName = "X-Vault-AWS-IAM-Server-ID"

var (
	// The Vault client initialized by and authenticated with. Set up with no
	// credentials at init time. When VaultAuth() is successfully called, this
	// client will also be configured with the authenticated session's token.
	VaultClient *vault.Client

	// The address of the Vault server. Set to the value of VAULT_ADDR at init time.
	VaultAddr string

	// The name of the Vault auth provider. Set to the value of VAULT_AUTH_PROVIDER
	// at init time.
	VaultAuthProvider string

	// The name of the Vault auth role. Set to the value of VAULT_AUTH_ROLE at init.
	VaultAuthRole string

	// The (optional, but recommended) value of the X-Vault-AWS-IAM-Server-ID header
	// set by the value of VAULT_AUTH_HEADER at init time.
	VaultAuthHeader string
)

func init() {
	VaultAddr = os.Getenv("VAULT_ADDR")
	VaultAuthProvider = os.Getenv("VAULT_AUTH_PROVIDER")
	VaultAuthRole = os.Getenv("VAULT_AUTH_ROLE")
	VaultAuthHeader = os.Getenv("VAULT_AUTH_HEADER")

	VaultClient, _ = vault.NewClient(nil)
}

// Call VaultAuth() to authenticate the Lambda execution role to the Vault auth
// context specified by the VAULT_ADDR, VAULT_AUTH_PROVIDER, and VAULT_AUTH_ROLE
// environment variables. If no error is returned, then VaultClient is ready to
// go.
//
// This code was adapted from Hashicorp Vault:
//   https://github.com/hashicorp/vault/blob/e2bb2ec3b93a242a167f763684f93df867bb253d/builtin/credential/aws/cli.go#L78
//
func VaultAuth() error {
	if VaultAddr == "" || VaultAuthProvider == "" || VaultAuthRole == "" {
		return fmt.Errorf("You must set the VAULT_ADDR, VAULT_AUTH_PROVIDER, and VAULT_AUTH_ROLE environment variables.")
	}

	stsSvc := sts.New(session.New())
	req, _ := stsSvc.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})

	if VaultAuthHeader != "" {
		// if supplied, and then sign the request including that header
		req.HTTPRequest.Header.Add(VaultAuthHeaderName, VaultAuthHeader)
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
	d["role"] = VaultAuthRole

	resp, err := VaultClient.Logical().Write(fmt.Sprintf("auth/%s/login", VaultAuthProvider), d)
	if err != nil {
		return err
	}
	if resp == nil {
		return fmt.Errorf("Got no response from the %s authentication provider", VaultAuthProvider)
	}

	token, err := resp.TokenID()
	if err != nil {
		return err
	}

	VaultClient.SetToken(token)
	return nil
}
