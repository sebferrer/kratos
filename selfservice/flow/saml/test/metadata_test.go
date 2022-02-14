package saml_test

import (
	"encoding/xml"
	"io"
	"io/ioutil"
	"net/http"
	"reflect"
	"testing"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/kratos/selfservice/strategy/saml"

	"github.com/ory/kratos/x"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

type Metadata struct {
	XMLName         xml.Name `xml:"EntityDescriptor"`
	Text            string   `xml:",chardata"`
	Xmlns           string   `xml:"xmlns,attr"`
	ValidUntil      string   `xml:"validUntil,attr"`
	EntityID        string   `xml:"entityID,attr"`
	SPSSODescriptor struct {
		Text                       string `xml:",chardata"`
		Xmlns                      string `xml:"xmlns,attr"`
		ValidUntil                 string `xml:"validUntil,attr"`
		ProtocolSupportEnumeration string `xml:"protocolSupportEnumeration,attr"`
		AuthnRequestsSigned        string `xml:"AuthnRequestsSigned,attr"`
		WantAssertionsSigned       string `xml:"WantAssertionsSigned,attr"`
		KeyDescriptor              []struct {
			Text    string `xml:",chardata"`
			Use     string `xml:"use,attr"`
			KeyInfo struct {
				Text     string `xml:",chardata"`
				Xmlns    string `xml:"xmlns,attr"`
				X509Data struct {
					Text            string `xml:",chardata"`
					Xmlns           string `xml:"xmlns,attr"`
					X509Certificate struct {
						Text  string `xml:",chardata"`
						Xmlns string `xml:"xmlns,attr"`
					} `xml:"X509Certificate"`
				} `xml:"X509Data"`
			} `xml:"KeyInfo"`
			EncryptionMethod []struct {
				Text      string `xml:",chardata"`
				Algorithm string `xml:"Algorithm,attr"`
			} `xml:"EncryptionMethod"`
		} `xml:"KeyDescriptor"`
		SingleLogoutService struct {
			Text             string `xml:",chardata"`
			Binding          string `xml:"Binding,attr"`
			Location         string `xml:"Location,attr"`
			ResponseLocation string `xml:"ResponseLocation,attr"`
		} `xml:"SingleLogoutService"`
		AssertionConsumerService []struct {
			Text     string `xml:",chardata"`
			Binding  string `xml:"Binding,attr"`
			Location string `xml:"Location,attr"`
			Index    string `xml:"index,attr"`
		} `xml:"AssertionConsumerService"`
	} `xml:"SPSSODescriptor"`
}

func TestXmlMetadataExist(t *testing.T) {

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

	viperSetProviderConfig(
		t,
		conf,
		newSAMLProvider(t, ts, "samlProviderTestID", "samlProviderTestLabel"),
		saml.Configuration{
			ID:             "samlProviderTestID",
			Label:          "samlProviderTestLabel",
			PublicCertPath: "file:///home/debian/Code/kratos/contrib/quickstart/kratos/email-password/myservice.cert",
			PrivateKeyPath: "file:///home/debian/Code/kratos/contrib/quickstart/kratos/email-password/myservice.key",
			IDPMetadataURL: "https://samltest.id/saml/idp",
			IDPSSOURL:      "https://samltest.id/idp/profile/SAML2/Redirect/SSO",
			Mapper:         "file:///home/debian/Code/kratos/contrib/quickstart/kratos/email-password/saml.jsonnet",
			AttributesMap:  attributesMap,
		},
	)

	conf.MustSet(config.ViperKeySelfServiceRegistrationEnabled, true)
	conf.MustSet(config.ViperKeyDefaultIdentitySchemaURL, "file://../../../strategy/oidc/stub/registration.schema.json/stub/registration.schema.json")
	conf.MustSet(config.HookStrategyKey(config.ViperKeySelfServiceRegistrationAfter,
		identity.CredentialsTypeSAML.String()), []config.SelfServiceHook{{Name: "session"}})

	t.Logf("Kratos Public URL: %s", ts.URL)
	t.Logf("Kratos Error URL: %s", errTS.URL)

	res, _ := newClient(t, nil).Get(ts.URL + "/self-service/methods/saml/metadata")

	assert.Check(t, is.Equal(http.StatusOK, res.StatusCode))
	assert.Check(t, is.Equal("application/samlmetadata+xml",
		res.Header.Get("Content-type")))

}

func TestXmlMetadataValues(t *testing.T) {

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

	viperSetProviderConfig(
		t,
		conf,
		newSAMLProvider(t, ts, "samlProviderTestID", "samlProviderTestLabel"),
		saml.Configuration{
			ID:             "samlProviderTestID",
			Label:          "samlProviderTestLabel",
			PublicCertPath: "file:///home/debian/Code/kratos/contrib/quickstart/kratos/email-password/myservice.cert",
			PrivateKeyPath: "file:///home/debian/Code/kratos/contrib/quickstart/kratos/email-password/myservice.key",
			IDPMetadataURL: "https://samltest.id/saml/idp",
			IDPSSOURL:      "https://samltest.id/idp/profile/SAML2/Redirect/SSO",
			Mapper:         "file:///home/debian/Code/kratos/contrib/quickstart/kratos/email-password/saml.jsonnet",
			AttributesMap:  attributesMap,
		},
	)

	conf.MustSet(config.ViperKeySelfServiceRegistrationEnabled, true)
	conf.MustSet(config.ViperKeyDefaultIdentitySchemaURL, "file://../../../strategy/oidc/stub/registration.schema.json/stub/registration.schema.json")
	conf.MustSet(config.HookStrategyKey(config.ViperKeySelfServiceRegistrationAfter,
		identity.CredentialsTypeSAML.String()), []config.SelfServiceHook{{Name: "session"}})

	t.Logf("Kratos Public URL: %s", ts.URL)
	t.Logf("Kratos Error URL: %s", errTS.URL)

	res, _ := newClient(t, nil).Get(ts.URL + "/self-service/methods/saml/metadata")

	b, _ := io.ReadAll(res.Body)

	assert.Check(t, is.Equal(http.StatusOK, res.StatusCode))
	assert.Check(t, is.Equal("application/samlmetadata+xml",
		res.Header.Get("Content-type")))

	expectedMetadata, err := ioutil.ReadFile("./testdata/expected_metadata.xml")
	assert.NilError(t, err)

	//The string is parse to a struct
	var expectedStructMetadata Metadata
	xml.Unmarshal(expectedMetadata, &expectedStructMetadata)
	var obtainedStructureMetadata Metadata
	xml.Unmarshal(b, &obtainedStructureMetadata)

	//We delete data that is likely to change naturally
	expectedStructMetadata.SPSSODescriptor.AssertionConsumerService[0].Location = ""
	expectedStructMetadata.SPSSODescriptor.AssertionConsumerService[1].Location = ""
	obtainedStructureMetadata.SPSSODescriptor.AssertionConsumerService[0].Location = ""
	obtainedStructureMetadata.SPSSODescriptor.AssertionConsumerService[1].Location = ""
	expectedStructMetadata.ValidUntil = ""
	expectedStructMetadata.SPSSODescriptor.ValidUntil = ""
	expectedStructMetadata.ValidUntil = ""
	obtainedStructureMetadata.SPSSODescriptor.ValidUntil = ""

	assert.Check(t, reflect.DeepEqual(expectedStructMetadata, expectedStructMetadata))

}
