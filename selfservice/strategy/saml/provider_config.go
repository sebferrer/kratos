package saml

type Configuration struct {
	// Provider's ID
	ID string `json:"id"`

	// An optional label which can be used in the UI generation.
	Label string `json:"label"`

	// Path of the certificate of your application
	PublicCertPath string `json:"public_cert_path"`

	// Path of the private key of your application
	PrivateKeyPath string `json:"private_key_path"`

	// Map where you have to name the attributes contained in the SAML response to associate them with their value
	AttributesMap map[string]string `json:"attributes_map"`

	// Information about the IDP like the sso url, slo url, entiy ID, metadata url
	IDPInformation map[string]string `json:"idp_information"`

	// Mapper specifies the JSONNet code snippet
	// It can be either a URL (file://, http(s)://, base64://) or an inline JSONNet code snippet.
	Mapper string `json:"mapper_url"`
}

type ConfigurationCollection struct {
	SAMLProviders []Configuration `json:"providers"`
}

func (c ConfigurationCollection) Provider(id string, label string) (Provider, error) {
	return NewProviderSAML(id, label, &c.SAMLProviders[len(c.SAMLProviders)-1]), nil

}
