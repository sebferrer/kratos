package saml

import (
	"net/url"
)

type Configuration struct {
	// ID is the provider's ID
	ID string `json:"id"`

	// Label represents an optional label which can be used in the UI generation.
	Label string `json:"label"`

	// Represent the path of the certificate of your application
	PublicCertPath string `json:"public_cert_path"`

	// Represent the path of the private key of your application
	PrivateKeyPath string `json:"private_key_path"`

	// Represent the URL of the metadata of your Identity Provider (optionnal)
	IDPMetadataURL string `json:"idp_metadata_url"`

	// IssuerURL is the OpenID Connect Server URL. You can leave this empty if `provider` is not set to `generic`.
	// If set, neither `auth_url` nor `token_url` are required.
	IDPSSOURL string `json:"idp_sso_url"`

	AttributesMap map[string]string `json:"attributes_map"`

	// Mapper specifies the JSONNet code snippet which uses the OpenID Connect Provider's data (e.g. GitHub or Google
	// profile information) to hydrate the identity's data.
	//
	// It can be either a URL (file://, http(s)://, base64://) or an inline JSONNet code snippet.
	Mapper string `json:"mapper_url"`
}

type ConfigurationCollection struct {
	SAMLProviders []Configuration `json:"providers"`
}

func (c ConfigurationCollection) Provider(idpMetadataUrl *url.URL, idpSsoUrl *url.URL) (Provider, error) {
	return NewProviderSAML(idpMetadataUrl, idpSsoUrl, &c.SAMLProviders[len(c.SAMLProviders)-1]), nil

}
