package strategy_test

import (
	"context"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/instana/testify/require"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/selfservice/strategy/saml"
	"github.com/ory/kratos/x"
	"github.com/ory/x/urlx"
	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
	"gotest.tools/golden"
)

func TestGetAttributesFromAssertion(t *testing.T) {

}

func TestCreateIdentityFromAssertion(t *testing.T) {

	//Create assertion

}

func TestWithoutMetadata(t *testing.T) {

}

func TestACSEndpoint(t *testing.T) {

	if testing.Short() {
		t.Skip()
	}

	var (
		conf, reg = internal.NewFastRegistryWithMocks(t)
		subject   string
	)

	errTS := testhelpers.NewErrorTestServer(t, reg)
	returnTS := newReturnTs(t, reg)
	routerP := x.NewRouterPublic()
	routerA := x.NewRouterAdmin()
	ts, _ := testhelpers.NewKratosServerWithRouters(t, reg, routerP, routerA)
	subject = "foo@bar.com"

	var attributesMap = make(map[string]string)
	attributesMap["id"] = "mail"
	attributesMap["firstname"] = "givenName"
	attributesMap["lastname"] = "sn"
	attributesMap["email"] = "mail"

	var IDPInformation = make(map[string]string)
	IDPInformation["idp_metadata_url"] = "https://samltest.id/saml/idp"

	viperSetProviderConfig(
		t,
		conf,
		newSAMLProvider(t, ts, "samlProviderTestID", "samlProviderTestLabel"),
		saml.Configuration{
			ID:             "samlProviderTestID",
			Label:          "samlProviderTestLabel",
			PublicCertPath: "file:///home/debian/Code/kratos/contrib/quickstart/kratos/email-password/myservice.cert",
			PrivateKeyPath: "file:///home/debian/Code/kratos/contrib/quickstart/kratos/email-password/myservice.key",
			Mapper:         "file:///home/debian/Code/kratos/contrib/quickstart/kratos/email-password/saml.jsonnet",
			AttributesMap:  attributesMap,
			IDPInformation: IDPInformation,
		},
	)

	conf.MustSet(config.ViperKeySelfServiceRegistrationEnabled, true)
	conf.MustSet(config.ViperKeyDefaultIdentitySchemaURL, "file://../../../strategy/oidc/stub/registration.schema.json/stub/registration.schema.json")
	conf.MustSet(config.HookStrategyKey(config.ViperKeySelfServiceRegistrationAfter,
		identity.CredentialsTypeSAML.String()), []config.SelfServiceHook{{Name: "session"}})

	t.Logf("Kratos Public URL: %s", ts.URL)
	t.Logf("Kratos Error URL: %s", errTS.URL)

	// assert identity (success)
	var ai = func(t *testing.T, res *http.Response, body []byte) {
		assert.Contains(t, res.Request.URL.String(), returnTS.URL)
		assert.Equal(t, subject, gjson.GetBytes(body, "identity.traits.subject").String(), "%s", body)
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

	var makeRequestWithCookieJar = func(t *testing.T, provider string, action string, fv url.Values, jar *cookiejar.Jar) (*http.Response, []byte) {
		fv.Set("provider", provider)
		res, err := newClient(t, jar).PostForm(action, fv)
		require.NoError(t, err, action)

		body, err := ioutil.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)

		require.Equal(t, 200, res.StatusCode, "%s: %s\n\t%s", action, res.Request.URL.String(), body)

		return res, body
	}

	var makeSAMLRequestWithAssertion = func(t *testing.T, provider string, destination string, fv url.Values) (*http.Response, []byte) {
		return makeRequestWithCookieJar(t, provider, destination, fv, nil)
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

	t.Run("case=should pass registration", func(t *testing.T) {
		newRegistrationFlow(t, returnTS.URL, time.Minute)
		res, body := makeSAMLRequestWithAssertion(t, "valid", "ON MET L'URL OU POST", url.Values{})
		ai(t, res, body)
		//expectTokens(t, "valid", body)
	})

	t.Run("case=should pass login", func(t *testing.T) {
		newLoginFlow(t, returnTS.URL, time.Minute)
		res, body := makeSAMLRequestWithAssertion(t, "valid", "ON MET L'URL OU POST", url.Values{})
		ai(t, res, body)
		//expectTokens(t, "valid", body)
	})

}

func TestAuthRequestCreation(t *testing.T) {
	//On créer une requete et on regarde la réponse
}

func TestHandleSAMLResponse(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	var (
		conf, reg = internal.NewFastRegistryWithMocks(t)
	)

	errTS := testhelpers.NewErrorTestServer(t, reg)
	routerP := x.NewRouterPublic()
	routerA := x.NewRouterAdmin()
	ts, _ := testhelpers.NewKratosServerWithRouters(t, reg, routerP, routerA)
	returnTS := newReturnTs(t, reg)
	subject := "foo@bar.com"

	var attributesMap = make(map[string]string)
	attributesMap["id"] = "mail"
	attributesMap["firstname"] = "givenName"
	attributesMap["lastname"] = "sn"
	attributesMap["email"] = "mail"
	var IDPInformation = make(map[string]string)
	IDPInformation["idp_metadata_url"] = "https://samltest.id/saml/idp"

	viperSetProviderConfig(
		t,
		conf,
		newSAMLProvider(t, ts, "samlProviderTestID", "samlProviderTestLabel"),
		saml.Configuration{
			ID:             "samlProviderTestID",
			Label:          "samlProviderTestLabel",
			PublicCertPath: "file:///home/debian/Code/kratos/contrib/quickstart/kratos/email-password/myservice.cert",
			PrivateKeyPath: "file:///home/debian/Code/kratos/contrib/quickstart/kratos/email-password/myservice.key",
			Mapper:         "file:///home/debian/Code/kratos/contrib/quickstart/kratos/email-password/saml.jsonnet",
			AttributesMap:  attributesMap,
			IDPInformation: IDPInformation,
		},
	)

	conf.MustSet(config.ViperKeySelfServiceRegistrationEnabled, true)
	conf.MustSet(config.ViperKeyDefaultIdentitySchemaURL, "file://../../../strategy/oidc/stub/registration.schema.json/stub/registration.schema.json")
	conf.MustSet(config.HookStrategyKey(config.ViperKeySelfServiceRegistrationAfter,
		identity.CredentialsTypeSAML.String()), []config.SelfServiceHook{{Name: "session"}})

	t.Logf("Kratos Public URL: %s", ts.URL)
	t.Logf("Kratos Error URL: %s", errTS.URL)

	// assert identity (success)
	var ai = func(t *testing.T, res *http.Response, body []byte) {
		assert.Contains(t, res.Request.URL.String(), returnTS.URL)
		assert.Equal(t, subject, gjson.GetBytes(body, "identity.traits.subject").String(), "%s", body)
	}

	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Tue Jan 5 17:53:12 UTC 2016")
		return rv
	}

	SamlResponseSimulated := golden.Get(t, "./TestSPCanHandleOneloginResponse_response")
	//IDPMetadata := golden.Get(t, "TestSPCanHandleOneloginResponse_IDPMetadata")

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", string(SamlResponseSimulated))

	res, body := makeRequest(t, ts.URL+"/self-service/methods/saml/acs", req.PostForm)
	// On balance une reponse sur le /ACS et on regarde la réponse
	ai(t, res, body)
}

func TestSendAuthRequest(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	var (
		conf, reg = internal.NewFastRegistryWithMocks(t)
	)

	errTS := testhelpers.NewErrorTestServer(t, reg)
	routerP := x.NewRouterPublic()
	routerA := x.NewRouterAdmin()
	ts, _ := testhelpers.NewKratosServerWithRouters(t, reg, routerP, routerA)

	var attributesMap = make(map[string]string)
	attributesMap["id"] = "mail"
	attributesMap["firstname"] = "givenName"
	attributesMap["lastname"] = "sn"
	attributesMap["email"] = "mail"
	var IDPInformation = make(map[string]string)
	IDPInformation["idp_metadata_url"] = "https://samltest.id/saml/idp"

	viperSetProviderConfig(
		t,
		conf,
		newSAMLProvider(t, ts, "samlProviderTestID", "samlProviderTestLabel"),
		saml.Configuration{
			ID:             "samlProviderTestID",
			Label:          "samlProviderTestLabel",
			PublicCertPath: "file:///home/debian/Code/kratos/contrib/quickstart/kratos/email-password/myservice.cert",
			PrivateKeyPath: "file:///home/debian/Code/kratos/contrib/quickstart/kratos/email-password/myservice.key",
			Mapper:         "file:///home/debian/Code/kratos/contrib/quickstart/kratos/email-password/saml.jsonnet",
			AttributesMap:  attributesMap,
			IDPInformation: IDPInformation,
		},
	)

	conf.MustSet(config.ViperKeySelfServiceRegistrationEnabled, true)
	conf.MustSet(config.ViperKeyDefaultIdentitySchemaURL, "file://../../../strategy/oidc/stub/registration.schema.json/stub/registration.schema.json")
	conf.MustSet(config.HookStrategyKey(config.ViperKeySelfServiceRegistrationAfter,
		identity.CredentialsTypeSAML.String()), []config.SelfServiceHook{{Name: "session"}})

	t.Logf("Kratos Public URL: %s", ts.URL)
	t.Logf("Kratos Error URL: %s", errTS.URL)

	res, _ := newClient(t, nil).Post(ts.URL+"/self-service/methods/saml/metadata", "", nil)

	b, _ := io.ReadAll(res.Body)

	assert.Check(t, is.Equal(http.StatusOK, res.StatusCode))
	assert.Check(t, is.Equal("application/samlmetadata+xml",
		res.Header.Get("Content-type")))

}
