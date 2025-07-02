package services

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"os"

	"github.com/crewjam/saml/samlsp"
)

func SetupSamlService() (*samlsp.Middleware, error) {
	keyPair, err := tls.LoadX509KeyPair("services/myservice.cert", "services/myservice.key")
	if err != nil {
		panic(err) // TODO handle error
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err) // TODO handle error
	}

	/*
		idpMetadataURL, err := url.Parse("https://samltest.id/saml/idp")
		if err != nil {
			panic(err) // TODO handle error
		}

		idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
			*idpMetadataURL)

		if err != nil {
			panic(err) // TODO handle error
		}
	*/
	metadataFile, err := os.ReadFile("services/fed_idp_Metadata.xml")
	if err != nil {
		panic(err)
	}

	idpMetadata, err := samlsp.ParseMetadata(metadataFile)
	if err != nil {
		panic(err)
	}

	rootURL, err := url.Parse("http://localhost:8080")
	if err != nil {
		panic(err) // TODO handle error
	}

	SamlSP, _ := samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
	})
	return SamlSP, nil
}
