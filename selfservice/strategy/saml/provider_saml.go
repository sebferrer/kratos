package saml

import (
	"context"
	"fmt"
	"net/url"

	"github.com/crewjam/saml/samlsp"
)

type ProviderSAML struct {
	idpMetadataUrl *url.URL
	idpSsoUrl      *url.URL
	config         *Configuration
}

func NewProviderSAML(
	idpMetadataUrl *url.URL,
	idpSsoUrl *url.URL,
	config *Configuration,
) *ProviderSAML {
	return &ProviderSAML{
		idpMetadataUrl: idpMetadataUrl,
		idpSsoUrl:      idpSsoUrl,
		config:         config,
	}
}

func (d *ProviderSAML) Claims(ctx context.Context, SAMLAttribute samlsp.Attributes) (*Claims, error) {

	claims := &Claims{
		Issuer:            "saml",
		Subject:           SAMLAttribute.Get("mail"),
		Name:              fmt.Sprintf("%s#%s", SAMLAttribute.Get("username"), SAMLAttribute.Get("discriminator")),
		Nickname:          SAMLAttribute.Get("uid"),
		PreferredUsername: SAMLAttribute.Get("username"),
		Picture:           SAMLAttribute.Get("avatar"),
		Email:             SAMLAttribute.Get("mail"),
		EmailVerified:     true,
		Locale:            SAMLAttribute.Get("locale"),
	}

	return claims, nil
}

func (d *ProviderSAML) Config() *Configuration {
	return d.config
}
