package saml

import (
	"context"
	"fmt"
	"net/url"

	"github.com/crewjam/saml/samlsp"
)

type ProviderSaml struct {
	metadataUrl *url.URL
	idpSsoUrl   *url.URL
}

func (d *ProviderSaml) Claims(ctx context.Context, samlAttribute samlsp.Attributes) (*Claims, error) {

	claims := &Claims{
		Issuer:            "saml",
		Subject:           samlAttribute.Get("id"),
		Name:              fmt.Sprintf("%s#%s", samlAttribute.Get("username"), samlAttribute.Get("discriminator")),
		Nickname:          samlAttribute.Get("username"),
		PreferredUsername: samlAttribute.Get("username"),
		Picture:           samlAttribute.Get("avatar"),
		Email:             samlAttribute.Get("email"),
		EmailVerified:     true,
		Locale:            samlAttribute.Get("locale"),
	}

	return claims, nil
}
