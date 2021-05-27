package ldap

import (
	"context"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/waypoint/builtin/vault/internal/auth"
	"github.com/stretchr/testify/assert"
	"net/url"
	"os"
	"testing"
)

func TestLdapAuth_Basic(t *testing.T) {
	username, password := os.Getenv("VAULT_LDAP_USERNAME"), os.Getenv("VAULT_LDAP_PASSWORD")

	authCfg := auth.AuthConfig{
		Logger:    logging.NewVaultLogger(hclog.Trace),
		MountPath: "ldap",
		Config: map[string]interface{}{
			"username": username,
			"password": password,
		},
	}

	a, err := NewLdapAuthMethod(&authCfg)
	if err != nil {
		t.Fatal(err)
	}

	l := a.(*ldapAuthMethod)

	path, _, data, err := l.Authenticate(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "ldap/login/" + url.PathEscape(username), path)
	assert.Equal(t, map[string]interface{}{
		"password": password,
	}, data)
}
