package saml

import (
	"net/url"
)

type Configuration struct {
	// ID is the provider's ID
	ID string `json:"id"`

	// Label represents an optional label which can be used in the UI generation.
	Label string `json:"label"`

	// IssuerURL is the OpenID Connect Server URL. You can leave this empty if `provider` is not set to `generic`.
	// If set, neither `auth_url` nor `token_url` are required.
	IssuerURL string `json:"issuer_url"`

	// Mapper specifies the JSONNet code snippet which uses the OpenID Connect Provider's data (e.g. GitHub or Google
	// profile information) to hydrate the identity's data.
	//
	// It can be either a URL (file://, http(s)://, base64://) or an inline JSONNet code snippet.
	Mapper string `json:"mapper_url"`
}

type ConfigurationCollection struct {
	SAMLProviders Configuration `json:"saml"`
}

func (c ConfigurationCollection) Provider(idpMetadataUrl *url.URL, idpSsoUrl *url.URL) (Provider, error) {
	return NewProviderSAML(idpMetadataUrl, idpSsoUrl, &c.SAMLProviders), nil

}
