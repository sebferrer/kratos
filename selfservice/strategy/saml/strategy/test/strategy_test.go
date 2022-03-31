package strategy_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"regexp"
	"testing"
	"time"

	//"github.com/dgrijalva/jwt-go"

	"github.com/beevik/etree"
	crewjamsaml "github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/crewjam/saml/xmlenc"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/internal/testhelpers"
	samlhandler "github.com/ory/kratos/selfservice/flow/saml"
	"github.com/ory/kratos/selfservice/strategy/saml"
	samlstrat "github.com/ory/kratos/selfservice/strategy/saml/strategy"
	"github.com/ory/kratos/x"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
	gotest "gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"
)

type Response struct {
	XMLName      xml.Name `xml:"Response"`
	Text         string   `xml:",chardata"`
	Saml2p       string   `xml:"saml2p,attr"`
	Destination  string   `xml:"Destination,attr"`
	ID           string   `xml:"ID,attr"`
	InResponseTo string   `xml:"InResponseTo,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Version      string   `xml:"Version,attr"`
	Issuer       struct {
		Text   string `xml:",chardata"`
		Saml2  string `xml:"saml2,attr"`
		Format string `xml:"Format,attr"`
	} `xml:"Issuer"`
	Status struct {
		Text       string `xml:",chardata"`
		StatusCode struct {
			Text  string `xml:",chardata"`
			Value string `xml:"Value,attr"`
		} `xml:"StatusCode"`
	} `xml:"Status"`
	EncryptedAssertion struct {
		Text          string `xml:",chardata"`
		Saml2         string `xml:"saml2,attr"`
		EncryptedData struct {
			Text             string `xml:",chardata"`
			Xenc             string `xml:"xenc,attr"`
			ID               string `xml:"Id,attr"`
			Type             string `xml:"Type,attr"`
			EncryptionMethod struct {
				Text      string `xml:",chardata"`
				Algorithm string `xml:"Algorithm,attr"`
				Xenc      string `xml:"xenc,attr"`
			} `xml:"EncryptionMethod"`
			KeyInfo struct {
				Text         string `xml:",chardata"`
				Ds           string `xml:"ds,attr"`
				EncryptedKey struct {
					Text             string `xml:",chardata"`
					ID               string `xml:"Id,attr"`
					Xenc             string `xml:"xenc,attr"`
					EncryptionMethod struct {
						Text         string `xml:",chardata"`
						Algorithm    string `xml:"Algorithm,attr"`
						Xenc         string `xml:"xenc,attr"`
						DigestMethod struct {
							Text      string `xml:",chardata"`
							Algorithm string `xml:"Algorithm,attr"`
							Ds        string `xml:"ds,attr"`
						} `xml:"DigestMethod"`
					} `xml:"EncryptionMethod"`
					KeyInfo struct {
						Text     string `xml:",chardata"`
						X509Data struct {
							Text            string `xml:",chardata"`
							X509Certificate string `xml:"X509Certificate"`
						} `xml:"X509Data"`
					} `xml:"KeyInfo"`
					CipherData struct {
						Text        string `xml:",chardata"`
						Xenc        string `xml:"xenc,attr"`
						CipherValue string `xml:"CipherValue"`
					} `xml:"CipherData"`
				} `xml:"EncryptedKey"`
			} `xml:"KeyInfo"`
			CipherData struct {
				Text        string `xml:",chardata"`
				Xenc        string `xml:"xenc,attr"`
				CipherValue string `xml:"CipherValue"`
			} `xml:"CipherData"`
		} `xml:"EncryptedData"`
	} `xml:"EncryptedAssertion"`
}

func makeTrackedRequest(id string, middleware samlsp.Middleware) string {
	codec := middleware.RequestTracker.(samlsp.CookieRequestTracker).Codec
	token, err := codec.Encode(samlsp.TrackedRequest{
		Index:         "KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6",
		SAMLRequestID: id,
		URI:           "/frob",
	})
	if err != nil {
		panic(err)
	}
	return token
}

func mustParseCertificate(pemStr []byte) *x509.Certificate {
	b, _ := pem.Decode(pemStr)
	if b == nil {
		panic("cannot parse PEM")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		panic(err)
	}
	return cert
}

func mustParsePrivateKey(pemStr []byte) crypto.PrivateKey {
	b, _ := pem.Decode(pemStr)
	if b == nil {
		panic("cannot parse PEM")
	}
	k, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	if err != nil {
		panic(err)
	}
	return k
}

/*
func TestGetAttributesFromAssertion2(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	conf, reg := internal.NewFastRegistryWithMocks(t)

	strategy := samlstrat.NewStrategy(reg)
	errTS := testhelpers.NewErrorTestServer(t, reg)
	routerP := x.NewRouterPublic()
	routerA := x.NewRouterAdmin()
	ts, _ := testhelpers.NewKratosServerWithRouters(t, reg, routerP, routerA)

	attributesMap := make(map[string]string)
	attributesMap["id"] = "mail"
	attributesMap["firstname"] = "givenName"
	attributesMap["lastname"] = "sn"
	attributesMap["email"] = "mail"
	IDPInformation := make(map[string]string)
	IDPInformation["idp_metadata_url"] = "https://raw.githubusercontent.com/crewjam/saml/main/samlsp/testdata/idp_metadata.xml"

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

	newClient(t, nil).Get(ts.URL + "/self-service/methods/saml/metadata") // Instantiate the MiddleWare

	middleWare, err := samlhandler.GetMiddleware()
	middleWare.ServiceProvider.Key = mustParsePrivateKey(golden.Get(t, "key.pem")).(*rsa.PrivateKey)
	middleWare.ServiceProvider.Certificate = mustParseCertificate(golden.Get(t, "cert.pem"))
	require.NoError(t, err)

	samlResponse, err := ioutil.ReadFile("./testdata/saml_response.xml")
	m1 := regexp.MustCompile(`Destination="https:samlkratos.ovh:4433/self-service/methods/saml/acs"`)
	newResponse := m1.ReplaceAllString(string(samlResponse), "Destination=\""+ts.URL+"/self-service/methods/saml/acs"+"\"")

	v := &url.Values{}
	v.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(newResponse)))
	v.Set("RelayState", "KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6")
	req, _ := http.NewRequest("POST", ts.URL+"/self-service/methods/saml/acs", bytes.NewReader([]byte(v.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", ""+
		"saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+makeTrackedRequest("id-9e61753d64e928af5a7a341a97f420c9", *middleWare))

	crewjamsaml.TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 MST 2006", "Mon Dec 1 01:57:09.123456789 UTC 2015")
		return rv
	}

	//mapAttributes, err := strategy.GetAttributesFromAssertion(assertion)
	//require.NoError(t, err)

	//t.Log(mapAttributes)
}*/

func TestGetAttributesFromAssertion(t *testing.T) {

	if testing.Short() {
		t.Skip()
	}

	conf, reg := internal.NewFastRegistryWithMocks(t)

	strategy := samlstrat.NewStrategy(reg)
	// errTS := testhelpers.NewErrorTestServer(t, reg)
	routerP := x.NewRouterPublic()
	routerA := x.NewRouterAdmin()
	ts, _ := testhelpers.NewKratosServerWithRouters(t, reg, routerP, routerA)

	attributesMap := make(map[string]string)
	attributesMap["id"] = "mail"
	attributesMap["firstname"] = "givenName"
	attributesMap["lastname"] = "sn"
	attributesMap["email"] = "mail"
	IDPInformation := make(map[string]string)
	IDPInformation["idp_metadata_url"] = "https://raw.githubusercontent.com/crewjam/saml/d4ed82f19df6a5201af70c25608d1999313ae3d0/testdata/SP_IDPMetadata"
	// IDPInformation["idp_metadata_url"] = "https://raw.githubusercontent.com/crewjam/saml/main/samlsp/testdata/idp_metadata.xml"
	// IDPInformation["idp_metadata_url"] = "https://sso.federation.ovh/FederationMetadata/2007-06/FederationMetadata.xml"

	// Initiates service provider
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

	// t.Logf("Kratos Public URL: %s", ts.URL)
	// t.Logf("Kratos Error URL: %s", errTS.URL)

	// Instantiates the MiddleWare
	newClient(t, nil).Get(ts.URL + "/self-service/methods/saml/metadata")

	middleWare, err := samlhandler.GetMiddleware()
	middleWare.ServiceProvider.Key = mustParsePrivateKey(golden.Get(t, "key.pem")).(*rsa.PrivateKey)
	middleWare.ServiceProvider.Certificate = mustParseCertificate(golden.Get(t, "cert.pem"))
	require.NoError(t, err)

	// Load saml response test file
	samlResponse, err := ioutil.ReadFile("./testdata/SP_SamlResponse.xml")
	// samlResponse, err := ioutil.ReadFile("./testdata/saml_response.xml")
	// samlResponse, err := ioutil.ReadFile("./testdata/saml_response_adfs.xml")

	// Set the reponse destination to the Kratos server URL
	m1 := regexp.MustCompile(`Destination="https://15661444.ngrok.io/saml2/acs"`)
	// m1 := regexp.MustCompile(`Destination="https://samlkratos.ovh:4433/self-service/methods/saml/acs"`)
	samlResponse = []byte(m1.ReplaceAllString(string(samlResponse), "Destination=\""+ts.URL+"/self-service/methods/saml/acs"+"\""))

	// Simulates the crewjam time to the saml response time
	crewjamsaml.TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", "Mon Dec 1 01:57:09 UTC 2015")
		// rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 MST 2006", "Tue Mar 29 13:54:18.123456789 UTC 2022")
		return rv
	}
	crewjamsaml.Clock = dsig.NewFakeClockAt(crewjamsaml.TimeNow())

	/*
			v := &url.Values{}
			v.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(newResponse)))
			v.Set("RelayState", "KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6")
			req, _ := http.NewRequest("POST", ts.URL+"/self-service/methods/saml/acs", bytes.NewReader([]byte(v.Encode())))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Cookie", ""+
				"saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+makeTrackedRequest("id-9e61753d64e928af5a7a341a97f420c9", *middleWare))

			crewjamsaml.TimeNow = func() time.Time {
				rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 MST 2006", "Mon Dec 1 01:57:09.123456789 UTC 2015")
				return rv
			}

		rawResponseBuf, err := base64.StdEncoding.DecodeString(req.PostForm.Get("SAMLResponse"))
		if err != nil {
			retErr.PrivateErr = fmt.Errorf("cannot parse base64: %s", err)
			return nil, retErr
		}
		retErr.Response = string(rawResponseBuf)
		assertion, err = sp.ParseXMLResponse(rawResponseBuf, possibleRequestIDs)*/

	// possibleRequestIDs := []string{"id-9e61753d64e928af5a7a341a97f420c9"}
	// possibleRequestIDs := []string{"id-9d0c8813ed9219c4b371b82cd6e68578ee0d3f0a"} // adfs

	/*tmp, err := url.Parse("https://15661444.ngrok.io/saml2/acs")
	require.NoError(t, err)
	middleWare.ServiceProvider.AcsURL = *tmp
	require.NoError(t, err)*/

	//// DECRYPT ASSERTION
	key := middleWare.ServiceProvider.Key
	doc := etree.NewDocument()
	err = doc.ReadFromBytes(samlResponse)
	require.NoError(t, err)
	responseEl := doc.Root()
	el := responseEl.FindElement("//EncryptedAssertion/EncryptedData")
	plaintextAssertion, err := xmlenc.Decrypt(key, el)

	fmt.Printf("%s", plaintextAssertion)

	//// UPDATE ASSERTION

	m3 := regexp.MustCompile(`Recipient="https://15661444.ngrok.io/saml2/acs"`)
	plaintextAssertion = []byte(m3.ReplaceAllString(string(plaintextAssertion), "Recipient=\""+ts.URL+"/self-service/methods/saml/acs"+"\""))

	fmt.Printf("%s", plaintextAssertion)

	//// ENCRYPT ASSERTION

	/*	cert := golden.Get(t, "cert.pem")
		b, _ := pem.Decode(cert)
		certificate, err := x509.ParseCertificate(b.Bytes)
		require.NoError(t, err)

		e := xmlenc.OAEP()
		e.BlockCipher = xmlenc.AES128CBC
		e.DigestMethod = &xmlenc.SHA1

		el2, err := e.Encrypt(certificate, []byte(plaintextAssertion), []byte("1234567890AZ"))
		require.NoError(t, err)
		doc2 := etree.NewDocument()
		doc2.SetRoot(el2)
		encryptedAssertion2, err := doc2.WriteToString()
		fmt.Printf("%s", encryptedAssertion2)

		//// REPLACE ENCRYPTED ASSERTION

		fmt.Printf("%s", samlResponse)
		splittedL := strings.Split(string(samlResponse), "<saml2:EncryptedAssertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">")
		splittedR := strings.Split(splittedL[1], "</saml2:EncryptedAssertion>")
		samlResponse = []byte(splittedL[0] + "<saml2:EncryptedAssertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">" +
			encryptedAssertion2 + "</saml2:EncryptedAssertion>" + splittedR[1])
		fmt.Printf("%s", samlResponse)

		////
	*/

	// assertion, err := middleWare.ServiceProvider.ParseXMLResponse(samlResponse, possibleRequestIDs)
	// require.NoError(t, err)

	assertion := &crewjamsaml.Assertion{}
	err = xml.Unmarshal(plaintextAssertion, assertion)
	require.NoError(t, err)

	mapAttributes, err := strategy.GetAttributesFromAssertion(assertion)
	require.NoError(t, err)

	t.Log(mapAttributes)
}

func TestCreateMiddleWareWithoutMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	conf, reg := internal.NewFastRegistryWithMocks(t)

	errTS := testhelpers.NewErrorTestServer(t, reg)
	routerP := x.NewRouterPublic()
	routerA := x.NewRouterAdmin()
	ts, _ := testhelpers.NewKratosServerWithRouters(t, reg, routerP, routerA)

	attributesMap := make(map[string]string)
	attributesMap["id"] = "mail"
	attributesMap["firstname"] = "givenName"
	attributesMap["lastname"] = "sn"
	attributesMap["email"] = "mail"
	IDPInformation := make(map[string]string)
	IDPInformation["idp_sso_url"] = "https://samltest.id/idp/profile/SAML2/Redirect/SSO"
	IDPInformation["idp_entity_id"] = "https://samltest.id/saml/idp"
	IDPInformation["idp_certificate_path"] = "./testdata/samlkratos.crt"
	IDPInformation["idp_logout_url"] = "https://samltest.id/idp/profile/SAML2/Redirect/SSO"

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

	newClient(t, nil).Get(ts.URL + "/self-service/methods/saml/metadata") // Instantiate the MiddleWare

	middleWare, err := samlhandler.GetMiddleware()
	require.NoError(t, err)

	assert.Check(t, middleWare != nil)
	assert.Check(t, middleWare.ServiceProvider.IDPMetadata != nil)
}

func TestCreateAuthRequest(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	conf, reg := internal.NewFastRegistryWithMocks(t)

	errTS := testhelpers.NewErrorTestServer(t, reg)
	routerP := x.NewRouterPublic()
	routerA := x.NewRouterAdmin()
	ts, _ := testhelpers.NewKratosServerWithRouters(t, reg, routerP, routerA)

	attributesMap := make(map[string]string)
	attributesMap["id"] = "mail"
	attributesMap["firstname"] = "givenName"
	attributesMap["lastname"] = "sn"
	attributesMap["email"] = "mail"
	IDPInformation := make(map[string]string)
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

	newClient(t, nil).Get(ts.URL + "/self-service/methods/saml/metadata") // Instantiate the MiddleWare

	middleWare, err := samlhandler.GetMiddleware()
	require.NoError(t, err)

	authReq, err := middleWare.ServiceProvider.MakeAuthenticationRequest("https://samltest.id/idp/profile/SAML2/Redirect/SSO", "saml.HTTPPostBinding", "saml.HTTPPostBinding")
	require.NoError(t, err)

	matchACS, err := regexp.MatchString(`http://127.0.0.1:\d{5}/self-service/methods/saml/acs`, authReq.AssertionConsumerServiceURL)
	require.NoError(t, err)
	gotest.Check(t, matchACS)

	matchMetadata, err := regexp.MatchString(`http://127.0.0.1:\d{5}/self-service/methods/saml/metadata`, authReq.Issuer.Value)
	require.NoError(t, err)
	gotest.Check(t, matchMetadata)

	gotest.Check(t, is.Equal(authReq.Destination, "https://samltest.id/idp/profile/SAML2/Redirect/SSO"))
}
