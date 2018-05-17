# onthelambda

`onthelambda` provides a streamlined way to authenticate your Golang AWS Lambda
function to [Hashicorp Vault](https://www.vaultproject.io).

## Usage Example

    package main

    import (
        "github.com/aws/aws-lambda-go/lambda"
        "github.com/daveadams/onthelambda"
        "log"
    )

    // perform authentication only once for each Lambda instance
    func init() {
        err := onthelambda.VaultAuth()
        if err != nil {
            log.Fatalf("ERROR: %s", err)
        }
    }

    // this handler will use the authentication context established in init()
    // to read the `value` key of `secret/message` from Vault on each invocation
    // (It's more efficient to read all necessary secrets into memory in init()
    // but depending on your use case, this can also work.)
    func LambdaHandler() {
        resp, _ := onthelambda.VaultClient.Logical().Read("secret/message")
        log.Printf("The secret message is '%s'", resp.Data["value"].(string))
    }

    func main() {
        lambda.Start(LambdaHandler)
    }


## Setup

First, you'll need Vault up and running somewhere network-accessible to your
Lambda function. That's out of scope for this README, but please see the
[Vault documentation](https://www.vaultproject.io/docs/install/index.html)
for more.

Then you'll need to set up an AWS authentication provider. You may already have
one configured. If so, you can use that one or you can set up a new one just for
this purpose. You don't need to worry about backend credentials for this
authentication method. It works without any AWS credentials needing to be loaded
into Vault. Or if you do have credentials loaded they don't need to have access
to the AWS account your Lambda is running in.

To establish a new AWS authentication provider, run:

    $ vault auth enable -path lambda -description "IAM auth for Lambdas" aws
    Success! Enabled aws auth method at: lambda/

You will also need to set the `iam_server_id_header_value` if you wish to use
the extra layer of security (as described below):

    $ vault write auth/lambda/config/client \
          iam_server_id_header_value=vault.insops.net

Next, you'll need to establish whatever Vault policies your Lambda will need.
See the [Vault Policies](https://www.vaultproject.io/docs/concepts/policies.html)
documentation for details.

Now you'll need to know the ARN of your Lambda execution role. You can create it
with the Lambda web console or by hand. Either way it should look something like:

    arn:aws:iam::987654321098:role/service-role/MyLambdaRole

*IMPORTANT*: You must remove any non-essential path from the role ARN unless you
have configured your AWS auth provider with IAM permissions to look up roles. In
this example, `service-role/` is the path segment. So the principal ARN you will
be specifying to Vault in the next step will be:

    arn:aws:iam::987654321098:role/MyLambdaRole

Now it's time to create the Vault authentication role. It can be named anything
you wish. In this case, we'll call it `my-vault-role`:

    $ vault write auth/lambda/role/my-vault-role \
          auth_type=iam \
          policies=list-of,vault-policies,separated-by-commas \
          resolve_aws_unique_ids=false \
          bound_iam_principal_arn=arn:aws:iam::987654321098:role/MyLambdaRole

Now you are ready to configure your Lambda.

## Configuration

All configuration is done with environment variables:

* `VAULT_ADDR` (Required) The URL of the Vault instance, eg `https://myvault.example.com`.
* `VAULT_AUTH_PROVIDER` (Required) The relative path of the AWS authentication provider, eg `lambda` for `auth/lambda` in the example above.
* `VAULT_AUTH_ROLE` (Required) The name of the Vault role to authenticate to, eg `my-vault-role` in the example above.
* `VAULT_AUTH_HEADER` (Optional, but recommended) The value of the `X-Vault-AWS-IAM-Server-ID` HTTP header to be included in the signed STS request this code uses to authenticate. This value is often set to the URL or DNS name of the Vault server to prevent potential replay attacks.

That should be all that's required to get up and running.

## License

This software is public domain. No rights are reserved. See LICENSE for more
information.
