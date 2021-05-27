package ldap

import (
	"context"
	"errors"
	"fmt"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/waypoint/builtin/vault/internal/auth"
	"net/http"
	"net/url"
)

type ldapAuthMethod struct {
	logger    hclog.Logger
	mountPath string

	username string
	password string
}

// NewLdapAuthMethod reads the user configuration and returns a configured
// AuthMethod
func NewLdapAuthMethod(conf *auth.AuthConfig) (auth.AuthMethod, error) {
	if conf == nil {
		return nil, errors.New("empty config")
	}
	if conf.Config == nil {
		return nil, errors.New("empty config data")
	}

	l := &ldapAuthMethod{
		logger:    conf.Logger,
		mountPath: conf.MountPath,
	}

	var err error
	l.username, err = l.getStringConfigElement(conf.Config, "username")
	if err != nil {
		return nil, err
	}
	l.password, err = l.getStringConfigElement(conf.Config, "password")
	if err != nil {
		return nil, err
	}


	return l, nil
}

func (l *ldapAuthMethod) getStringConfigElement(config map[string]interface{}, key string) (string, error) {
	raw, ok := config[key]
	if !ok {
		return "", fmt.Errorf("missing '%s' value", key)
	}

	v, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("unable to cast '%s' as string", key)
	}

	return v, nil
}

func (l *ldapAuthMethod) Authenticate(ctx context.Context, client *api.Client) (string, http.Header, map[string]interface{}, error) {
	l.logger.Trace("beginning authentication")

	return fmt.Sprintf("%s/login/%s", l.mountPath, url.PathEscape(l.username)), nil, map[string]interface{}{
		"password": l.password,
	}, nil
}

func (l *ldapAuthMethod) NewCreds() chan struct{} {
	return nil
}

func (l *ldapAuthMethod) CredSuccess() {
}

func (l *ldapAuthMethod) Shutdown() {
}
