package strategy_test

import (
	"regexp"
	"testing"

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

	t.Log(mapAttributes)
}

func TestCreateAuthRequest(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	middleware, _, err := initMiddlewareWithMetadata(t,
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
