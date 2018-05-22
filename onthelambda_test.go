package onthelambda

import (
	vault "github.com/hashicorp/vault/api"
	"testing"
	"time"
)

func Test_isExpired(t *testing.T) {
	tests := []struct {
		ttl     string
		expired bool
	}{
		// expirationWindow is hardcoded to be 10 seconds
		{ttl: "200h", expired: false},
		{ttl: "6m", expired: false},
		{ttl: "4m", expired: false},
		{ttl: "11s", expired: false},
		{ttl: "9s", expired: true},
		{ttl: "0s", expired: true},
		{ttl: "10h", expired: false},
	}

	for _, test := range tests {
		ttl, _ := time.ParseDuration(test.ttl)
		tokenExpiration = time.Now().Add(ttl)
		rv := isExpired()
		if rv != test.expired {
			t.Errorf("Expiration check failed! With %s left, got '%t', expected '%t'.", test.ttl, rv, test.expired)
		}
	}
}

func Test_shouldRenew(t *testing.T) {
	tests := []struct {
		ttl   string
		renew bool
	}{
		// renewalWindow is hardcoded to be 300 seconds
		{ttl: "200h", renew: false},
		{ttl: "6m", renew: false},
		{ttl: "4m", renew: true},
		{ttl: "11s", renew: true},
		{ttl: "9s", renew: true},
		{ttl: "0s", renew: true},
		{ttl: "10h", renew: false},
	}

	for _, test := range tests {
		ttl, _ := time.ParseDuration(test.ttl)
		tokenExpiration = time.Now().Add(ttl)
		rv := shouldRenew()
		if rv != test.renew {
			t.Errorf("Renewal check failed! With %s left, got '%t', expected '%t'.", test.ttl, rv, test.renew)
		}
	}
}

func Test_parseToken(t *testing.T) {
	tests := []struct {
		secret          *vault.Secret
		token           string
		ttlStr          string
		renewable       bool
		roughExpiration time.Time
	}{
		{
			secret: &vault.Secret{
				Auth: &vault.SecretAuth{
					ClientToken:   "banana",
					Renewable:     true,
					LeaseDuration: 3600,
				},
			},
			token:           "banana",
			ttlStr:          "1h",
			renewable:       true,
			roughExpiration: time.Now().Add(time.Hour),
		},
		{
			secret: &vault.Secret{
				Auth: &vault.SecretAuth{
					ClientToken:   "apple",
					Renewable:     false,
					LeaseDuration: 1800,
				},
			},
			token:           "apple",
			ttlStr:          "30m",
			renewable:       false,
			roughExpiration: time.Now().Add(time.Duration(30) * time.Minute),
		},
		{
			secret: &vault.Secret{
				Auth: &vault.SecretAuth{
					ClientToken:   "plum",
					Renewable:     true,
					LeaseDuration: 7200,
				},
			},
			token:           "plum",
			ttlStr:          "2h",
			renewable:       true,
			roughExpiration: time.Now().Add(time.Duration(2) * time.Hour),
		},
	}

	for _, test := range tests {
		ttl, _ := time.ParseDuration(test.ttlStr)
		err := parseToken(test.secret)
		if err != nil {
			t.Errorf("Failed to parse token from secret %#v", test.secret)
			continue
		}

		if token != test.token {
			t.Errorf("Token mismatch. Got %q, expected %q.", token, test.token)
		}

		if tokenIsRenewable != test.renewable {
			t.Errorf("IsRenewable mismatch. Got %t, expected %t.", tokenIsRenewable, test.renewable)
		}

		if tokenTTL != ttl {
			t.Errorf("TTL mismatch. Got %q, expected %q.", tokenTTL, ttl)
		}

		if tokenExpiration.Before(test.roughExpiration.Add(-time.Second)) {
			t.Errorf("Expiration is too early!")
		}

		if tokenExpiration.After(test.roughExpiration.Add(time.Second)) {
			t.Errorf("Expiration is too late!")
		}
	}
}
