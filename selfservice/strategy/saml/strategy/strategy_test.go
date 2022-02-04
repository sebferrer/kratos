package strategy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/instana/testify/assert"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/selfservice/strategy/saml"
	"github.com/ory/kratos/x"
	"github.com/ory/x/assertx"
	"github.com/ory/x/urlx"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestStrategy(t *testing.T) {

	if testing.Short() {
		t.Skip()
	}

	var (
		conf, reg        = internal.NewFastRegistryWithMocks(t)
		subject, website string
		scope            []string
	)

	returnTS := newReturnTs(t, reg)
	errTS := testhelpers.NewErrorTestServer(t, reg)
	routerP := x.NewRouterPublic()
	routerA := x.NewRouterAdmin()
	ts, _ := testhelpers.NewKratosServerWithRouters(t, reg, routerP, routerA)

	viperSetProviderConfig(
		t,
		conf,
		newSAMLProvider(t, ts, "testSamlProvider", "labelTestSamlProvider"),
		saml.Configuration{
			ID:             "azerty",
			Label:          "saml-issuer",
			PublicCertPath: "/home/debian/Code/kratos/contrib/quickstart/kratos/email-password/myservice.cert",
			PrivateKeyPath: "/home/debian/Code/kratos/contrib/quickstart/kratos/email-password/myservice.key",
			IDPMetadataURL: "https://samltest.id/saml/idp",
			IDPSSOURL:      "https://samltest.id/idp/profile/SAML2/Redirect/SSO",
			Mapper:         "file:///home/debian/Code/kratos/contrib/quickstart/kratos/email-password/saml.jsonnet",
		},
	)

	conf.MustSet(config.ViperKeySelfServiceRegistrationEnabled, true)
	conf.MustSet(config.ViperKeyDefaultIdentitySchemaURL, "file://./stub/registration.schema.json")
	conf.MustSet(config.HookStrategyKey(config.ViperKeySelfServiceRegistrationAfter,
		identity.CredentialsTypeSAML.String()), []config.SelfServiceHook{{Name: "session"}})

	t.Logf("Kratos Public URL: %s", ts.URL)
	t.Logf("Kratos Error URL: %s", errTS.URL)
	t.Logf("Return URL: %s", returnTS.URL)

	subject = "foo@bar.com"
	scope = []string{}

	var makeRequestWithCookieJar = func(t *testing.T, provider string, fv url.Values, jar *cookiejar.Jar) (*http.Response, []byte) {
		fv.Set("provider", provider)
		res, err := newClient(t, jar).PostForm(action, fv)
		require.NoError(t, err)

		body, err := ioutil.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)

		require.Equal(t, 200, res.StatusCode, "%s: %s\n\t%s", action, res.Request.URL.String(), body)

		return res, body
	}

	var ai = func(t *testing.T, res *http.Response, body []byte) {
		assert.Contains(t, res.Request.URL.String(), returnTS.URL)
		assert.Equal(t, subject, gjson.GetBytes(body, "identity.traits.subject").String(), "%s", body)
	}

	var makeRequest = func(t *testing.T, provider string, fv url.Values) (*http.Response, []byte) {
		return makeRequestWithCookieJar(t, provider, fv, nil)
	}

	var newRegistrationFlow = func(t *testing.T, redirectTo string, exp time.Duration) *registration.Flow {
		// Use NewLoginFlow to instantiate the request but change the things we need to control a copy of it.
		req, err := reg.RegistrationHandler().NewRegistrationFlow(httptest.NewRecorder(),
			&http.Request{URL: urlx.ParseOrPanic(redirectTo)}, flow.TypeBrowser)
		require.NoError(t, err)
		req.RequestURL = redirectTo
		req.ExpiresAt = time.Now().Add(exp)
		require.NoError(t, reg.RegistrationFlowPersister().UpdateRegistrationFlow(context.Background(), req))

		// sanity check
		got, err := reg.RegistrationFlowPersister().GetRegistrationFlow(context.Background(), req.ID)
		require.NoError(t, err)
		require.Len(t, got.UI.Nodes, len(req.UI.Nodes), "%+v", req)

		return req
	}

	var newLoginFlow = func(t *testing.T, redirectTo string, exp time.Duration) (req *login.Flow) {
		// Use NewLoginFlow to instantiate the request but change the things we need to control a copy of it.
		req, err := reg.LoginHandler().NewLoginFlow(httptest.NewRecorder(),
			&http.Request{URL: urlx.ParseOrPanic(redirectTo)}, flow.TypeBrowser)
		require.NoError(t, err)
		req.RequestURL = redirectTo
		req.ExpiresAt = time.Now().Add(exp)
		require.NoError(t, reg.LoginFlowPersister().UpdateLoginFlow(context.Background(), req))

		// sanity check
		got, err := reg.LoginFlowPersister().GetLoginFlow(context.Background(), req.ID)
		require.NoError(t, err)

		require.Len(t, got.UI.Nodes, len(req.UI.Nodes), "%+v", got)

		return
	}

	t.Run("case=register and then login", func(t *testing.T) {
		subject = "register-then-login@ory.sh"
		scope = []string{"saml", "offline"}

		expectTokens := func(t *testing.T, provider string, body []byte) {
			i, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(context.Background(), uuid.FromStringOrNil(gjson.GetBytes(body, "identity.id").String()))
			require.NoError(t, err)
			c := i.Credentials[identity.CredentialsTypeSAML].Config
			assert.NotEmpty(t, gjson.GetBytes(c, "providers.0.initial_access_token").String())
			assertx.EqualAsJSONExcept(
				t,
				json.RawMessage(fmt.Sprintf(`{"providers": [{"subject":"%s","provider":"%s"}]}`, subject, provider)),
				json.RawMessage(c),
				[]string{"providers.0.initial_id_token", "providers.0.initial_access_token", "providers.0.initial_refresh_token"},
			)
		}

		t.Run("case=should pass registration", func(t *testing.T) {
			r := newRegistrationFlow(t, returnTS.URL, time.Minute)
			action := afv(t, r.ID, "labelTestSamlProvider")
			res, body := makeRequest(t, "labelTestSamlProvider", action, url.Values{})
			ai(t, res, body)
			expectTokens(t, "labelTestSamlProvider", body)
		})

		t.Run("case=should pass login", func(t *testing.T) {
			r := newLoginFlow(t, returnTS.URL, time.Minute)
			action := afv(t, r.ID, "labelTestSamlProvider")
			res, body := makeRequest(t, "labelTestSamlProvider", action, url.Values{})
			ai(t, res, body)
			expectTokens(t, "labelTestSamlProvider", body)
		})
	})

}
