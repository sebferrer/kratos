package saml_test

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	samlstrategy "github.com/ory/kratos/selfservice/strategy/saml"
)

func newReturnTs(t *testing.T, reg driver.Registry) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := reg.SessionManager().FetchFromRequest(r.Context(), r)
		require.NoError(t, err)
		require.Empty(t, sess.Identity.Credentials)
		reg.Writer().Write(w, r, sess)
	}))
	reg.Config(context.Background()).MustSet(config.ViperKeySelfServiceBrowserDefaultReturnTo, ts.URL)
	t.Cleanup(ts.Close)
	return ts
}

func newSAMLProvider(
	t *testing.T,
	kratos *httptest.Server,
	id, label string,
) samlstrategy.Configuration {
	return samlstrategy.Configuration{
		ID:             id,
		Label:          label,
		PublicCertPath: "secret",
		PrivateKeyPath: "/",
		Mapper:         "file://./stub/oidc.hydra.jsonnet",
		//IDPMetadataURL: "",
		//IDPSSOURL:      "",
	}
}

func viperSetProviderConfig(t *testing.T, conf *config.Config, SAMLProvider ...samlstrategy.Configuration) {
	conf.MustSet(config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypeSAML)+".config", &samlstrategy.ConfigurationCollection{SAMLProviders: SAMLProvider})
	conf.MustSet(config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypeSAML)+".enabled", true)
}

func newClient(t *testing.T, jar *cookiejar.Jar) *http.Client {
	if jar == nil {
		j, err := cookiejar.New(nil)
		jar = j
		require.NoError(t, err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			//if debugRedirects {
			//	t.Logf("Redirect: %s", req.URL.String())
			//}
			if len(via) >= 20 {
				for k, v := range via {
					t.Logf("Failed with redirect (%d): %s", k, v.URL.String())
				}
				return errors.New("stopped after 20 redirects")
			}
			return nil
		},
	}
}

// AssertSystemError asserts an error ui response
func AssertSystemError(t *testing.T, errTS *httptest.Server, res *http.Response, body []byte, code int, reason string) {
	require.Contains(t, res.Request.URL.String(), errTS.URL, "%s", body)

	assert.Equal(t, int64(code), gjson.GetBytes(body, "code").Int(), "%s", body)
	assert.Contains(t, gjson.GetBytes(body, "reason").String(), reason, "%s", body)
}
