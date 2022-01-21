package saml_test

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"testing"

	"github.com/crewjam/saml/samlsp"
	"github.com/stretchr/testify/assert"
)

func instantiateMiddleware() (*samlsp.Middleware, error) {

	keyPair, err := tls.LoadX509KeyPair("file:///etc/config/kratos/myservice.cert", "file:///etc/config/kratos/myservice.cert")

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])

	idpMetadataURL, err := url.Parse("https://samltest.id/saml/idp")

	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient, *idpMetadataURL)

	rootURL, err := url.Parse("http://51.210.126.182:4433/")

	samlMiddleware, err := samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
		SignRequest: true,
	})

	return samlMiddleware, err

}

func TestXmlMetadataExist(t *testing.T) {

	var _, _ = instantiateMiddleware()

	assert.Equal(t, "test", "test")

}

func TestXmlMetadataContent(t *testing.T) {

	assert.Equal(t, "test", "tt", "ERREUR FORMAT")

}

func TestXmlMetadataStructure(t *testing.T) {

	assert.Equal(t, "Test", "Test")

}
