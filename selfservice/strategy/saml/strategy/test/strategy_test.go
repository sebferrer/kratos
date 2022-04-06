package strategy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/ory/kratos/identity"
	samlstrategy "github.com/ory/kratos/selfservice/strategy/saml/strategy"
	"github.com/stretchr/testify/require"

	"gotest.tools/assert"
	gotest "gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestInitMiddleWareWithMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	middleware, _, err := initMiddlewareWithMetadata(t,
		"https://raw.githubusercontent.com/crewjam/saml/d4ed82f19df6a5201af70c25608d1999313ae3d0/testdata/SP_IDPMetadata")

	require.NoError(t, err)
	assert.Check(t, middleware != nil)
	assert.Check(t, middleware.ServiceProvider.IDPMetadata != nil)
}

func TestInitMiddleWareWithoutMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	middleware, _, err := initMiddlewareWithoutMetadata(t,
		"https://samltest.id/idp/profile/SAML2/Redirect/SSO",
		"https://samltest.id/saml/idp",
		"./testdata/samlkratos.crt",
		"https://samltest.id/idp/profile/SAML2/Redirect/SSO")

	require.NoError(t, err)
	assert.Check(t, middleware != nil)
	assert.Check(t, middleware.ServiceProvider.IDPMetadata != nil)
}

func TestGetAndDecryptAssertion(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	middleware, _, _ := initMiddlewareWithMetadata(t,
		"https://raw.githubusercontent.com/crewjam/saml/d4ed82f19df6a5201af70c25608d1999313ae3d0/testdata/SP_IDPMetadata")

	assertion, err := getAndDecryptAssertion(t, "./testdata/SP_SamlResponse.xml", middleware.ServiceProvider.Key)

	require.NoError(t, err)
	assert.Check(t, assertion != nil)
}

func TestGetAttributesFromAssertion(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	middleware, strategy, _ := initMiddlewareWithMetadata(t,
		"https://raw.githubusercontent.com/crewjam/saml/d4ed82f19df6a5201af70c25608d1999313ae3d0/testdata/SP_IDPMetadata")

	assertion, _ := getAndDecryptAssertion(t, "./testdata/SP_SamlResponse.xml", middleware.ServiceProvider.Key)

	mapAttributes, err := strategy.GetAttributesFromAssertion(assertion)

	require.NoError(t, err)
	assert.Check(t, mapAttributes["urn:oid:0.9.2342.19200300.100.1.1"][0] == "myself")
	assert.Check(t, mapAttributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.1"][0] == "Member")
	assert.Check(t, mapAttributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.1"][1] == "Staff")
	assert.Check(t, mapAttributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.6"][0] == "myself@testshib.org")
	assert.Check(t, mapAttributes["urn:oid:2.5.4.4"][0] == "And I")
	assert.Check(t, mapAttributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.9"][0] == "Member@testshib.org")
	assert.Check(t, mapAttributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.9"][1] == "Staff@testshib.org")
	assert.Check(t, mapAttributes["urn:oid:2.5.4.42"][0] == "Me Myself")
	assert.Check(t, mapAttributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.7"][0] == "urn:mace:dir:entitlement:common-lib-terms")
	assert.Check(t, mapAttributes["urn:oid:2.5.4.3"][0] == "Me Myself And I")
	assert.Check(t, mapAttributes["urn:oid:2.5.4.20"][0] == "555-5555")

	t.Log(mapAttributes)
}

func TestCreateAuthRequest(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	middleware, _, _ := initMiddlewareWithMetadata(t,
		"https://raw.githubusercontent.com/crewjam/saml/d4ed82f19df6a5201af70c25608d1999313ae3d0/testdata/SP_IDPMetadata")

	authReq, err := middleware.ServiceProvider.MakeAuthenticationRequest("https://samltest.id/idp/profile/SAML2/Redirect/SSO", "saml.HTTPPostBinding", "saml.HTTPPostBinding")
	require.NoError(t, err)

	matchACS, err := regexp.MatchString(`http://127.0.0.1:\d{5}/self-service/methods/saml/acs`, authReq.AssertionConsumerServiceURL)
	require.NoError(t, err)
	gotest.Check(t, matchACS)

	matchMetadata, err := regexp.MatchString(`http://127.0.0.1:\d{5}/self-service/methods/saml/metadata`, authReq.Issuer.Value)
	require.NoError(t, err)
	gotest.Check(t, matchMetadata)

	gotest.Check(t, is.Equal(authReq.Destination, "https://samltest.id/idp/profile/SAML2/Redirect/SSO"))
}

func TestProvider(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	_, strategy, _ := initMiddlewareWithMetadata(t,
		"https://raw.githubusercontent.com/crewjam/saml/d4ed82f19df6a5201af70c25608d1999313ae3d0/testdata/SP_IDPMetadata")

	provider, err := strategy.Provider(context.Background())
	require.NoError(t, err)
	gotest.Check(t, provider != nil)
	gotest.Check(t, provider.Config().ID == "samlProviderTestID")
	gotest.Check(t, provider.Config().Label == "samlProviderTestLabel")
}

func TestConfig(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	_, strategy, _ := initMiddlewareWithMetadata(t,
		"https://raw.githubusercontent.com/crewjam/saml/d4ed82f19df6a5201af70c25608d1999313ae3d0/testdata/SP_IDPMetadata")

	config, err := strategy.Config(context.Background())
	require.NoError(t, err)
	gotest.Check(t, config != nil)
	gotest.Check(t, len(config.SAMLProviders) == 2)
	gotest.Check(t, config.SAMLProviders[0].ID == "samlProviderTestID")
	gotest.Check(t, config.SAMLProviders[0].Label == "samlProviderTestLabel")
}

func TestID(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	_, strategy, _ := initMiddlewareWithMetadata(t,
		"https://raw.githubusercontent.com/crewjam/saml/d4ed82f19df6a5201af70c25608d1999313ae3d0/testdata/SP_IDPMetadata")

	id := strategy.ID()
	gotest.Check(t, id == "saml")
}

func TestCountActiveCredentials(t *testing.T) {
	_, strategy, _ := initMiddlewareWithMetadata(t,
		"https://raw.githubusercontent.com/crewjam/saml/d4ed82f19df6a5201af70c25608d1999313ae3d0/testdata/SP_IDPMetadata")

	mapCredentials := make(map[identity.CredentialsType]identity.Credentials)

	var b bytes.Buffer
	err := json.NewEncoder(&b).Encode(samlstrategy.CredentialsConfig{
		Providers: []samlstrategy.ProviderCredentialsConfig{
			{
				Subject:  "testUserID",
				Provider: "saml",
			}},
	})
	require.NoError(t, err)

	mapCredentials[identity.CredentialsTypeSAML] = identity.Credentials{
		Type:        identity.CredentialsTypeSAML,
		Identifiers: []string{"saml:testUserID"},
		Config:      b.Bytes(),
	}

	count, err := strategy.CountActiveCredentials(mapCredentials)
	require.NoError(t, err)
	gotest.Check(t, count == 1)
}

func TestGetRegistrationIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	middleware, strategy, _ := initMiddlewareWithMetadata(t,
		"https://raw.githubusercontent.com/crewjam/saml/d4ed82f19df6a5201af70c25608d1999313ae3d0/testdata/SP_IDPMetadata")

	provider, _ := strategy.Provider(context.Background())
	assertion, _ := getAndDecryptAssertion(t, "./testdata/SP_SamlResponse.xml", middleware.ServiceProvider.Key)
	attributes, _ := strategy.GetAttributesFromAssertion(assertion)
	claims, _ := provider.Claims(context.Background(), strategy.D().Config(context.Background()), attributes)

	i, err := strategy.GetRegistrationIdentity(nil, context.Background(), provider, claims, false)
	require.NoError(t, err)
	gotest.Check(t, i != nil)
}
