package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudkms/v1"
)

var (
	oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
)

func main() {
	keyFlag := flag.String("key", "", "Resource path to the Google Cloud Key Version. Mandatory")
	outFlag := flag.String("out", "out.csr", "Path to the output CSR file. Defaults to out.csr")
	commonNameFlag := flag.String("common-name", "", "Common Name element of the CSR subject. Mandatory")
	orgFlag := flag.String("org", "", "Organization element of the CSR subject. Omitted if unspecified")
	emailFlag := flag.String("email", "", "Email element of the CSR subject. Omitted if unspecified")
	unitFlag := flag.String("unit", "", "Organizational Unit element of the CSR subject. Omitted if unspecified")
	countryFlag := flag.String("country", "", "Country element of the CSR subject. Omitted if unspecified")
	provinceFlag := flag.String("province", "", "Province element of the CSR subject. Omitted if unspecified")
	localityFlag := flag.String("locality", "", "Locality element of the CSR subject. Omitted if unspecified")
	signatureAlgorithmFlag := flag.String("sign-algo", "SHA256WithRSA", "SHA256WithRSA, SHA256WithRSAPSS, ECDSAWithSHA256. Defaults to SHA256WithRSA")

	flag.Parse()

	oauthClient, err := google.DefaultClient(context.Background(), cloudkms.CloudPlatformScope)
	if err != nil {
		log.Fatal(err)
	}

	kmsService, err := cloudkms.New(oauthClient)
	if err != nil {
		log.Fatal(err)
	}

	s, err := NewGoogleKMSSigner(kmsService, *keyFlag)
	if err != nil {
		log.Fatal(err)
	}

	if *commonNameFlag == "" {
		log.Fatal("common-name must be specified")
	}
	subj := pkix.Name{
		CommonName:         *commonNameFlag,
		Organization:       OptionalDnElement(*orgFlag),
		OrganizationalUnit: OptionalDnElement(*unitFlag),
		Country:            OptionalDnElement(*countryFlag),
		Province:           OptionalDnElement(*provinceFlag),
		Locality:           OptionalDnElement(*localityFlag),
	}

	rawSubj := subj.ToRDNSequence()
	template := &x509.CertificateRequest{}

	if *emailFlag != "" {
		rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
			{Type: oidEmailAddress, Value: *emailFlag},
		})

		template.EmailAddresses = []string{*emailFlag}
	}

	asn1Subj, err := asn1.Marshal(rawSubj)
	if err != nil {
		log.Fatal(err)
	}

	template.RawSubject = asn1Subj

	// TODO Make this a flag or read from s.PublicKey?
	//      https://cloud.google.com/kms/docs/algorithms
	//      https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys#CryptoKeyVersionTemplate

	if *signatureAlgorithmFlag == "SHA256WithRSA" {
		template.SignatureAlgorithm = x509.SHA256WithRSA
	} else if *signatureAlgorithmFlag == "SHA256WithRSAPSS" {
		template.SignatureAlgorithm = x509.SHA256WithRSAPSS
	} else if *signatureAlgorithmFlag == "ECDSAWithSHA256" {
		template.SignatureAlgorithm = x509.ECDSAWithSHA256
	} else {
		log.Fatal("Sign-algorithm " + *signatureAlgorithmFlag + " is not supported")
	}

	// template.SignatureAlgorithm = x509.ECDSAWithSHA256 // x509.SHA256WithRSAPSS

	f, err := os.Create(*outFlag)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	if err := CreateCertificateRequest(f, template, s); err != nil {
		log.Fatal(err)
	}
}

func OptionalDnElement(s string) []string {
	if s == "" {
		return nil
	} else {
		return []string{s}
	}
}

func CreateCertificateRequest(w io.Writer, template *x509.CertificateRequest, signer crypto.Signer) error {
	out, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return err
	}

	return pem.Encode(w, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: out})
}

type GoogleKMS struct {
	Client        *cloudkms.Service
	keyResourceId string
	publicKey     crypto.PublicKey
}

func NewGoogleKMSSigner(client *cloudkms.Service, keyResourceId string) (*GoogleKMS, error) {
	g := &GoogleKMS{
		keyResourceId: keyResourceId,
		Client:        client,
	}

	err := g.getAsymmetricPublicKey()
	if err != nil {
		return nil, err
	}

	return g, nil
}

// Public returns the Public Key from Google Cloud KMS
func (g *GoogleKMS) Public() crypto.PublicKey {
	return g.publicKey
}

// Sign calls Google Cloud KMS API and performs AsymmetricSign
func (g *GoogleKMS) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	// API expects the digest to be base64 encoded
	digest64 := base64.StdEncoding.EncodeToString(digest)

	req := &cloudkms.AsymmetricSignRequest{
		Digest: &cloudkms.Digest{
			Sha256: digest64, // TODO: sha256 needs to follow sign algo
		},
	}

	response, err := g.Client.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
		AsymmetricSign(g.keyResourceId, req).Context(context.Background()).Do()
	if err != nil {
		return nil, err
	}

	// The response signature is base64 encoded
	return base64.StdEncoding.DecodeString(response.Signature)
}

// getAsymmetricPublicKey pulls public key from Google Cloud KMS API
func (g *GoogleKMS) getAsymmetricPublicKey() error {
	response, err := g.Client.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
		GetPublicKey(g.keyResourceId).Context(context.Background()).Do()
	if err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(response.Pem))
	if block == nil || block.Type != "PUBLIC KEY" {
		return fmt.Errorf("not a public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	g.publicKey = publicKey
	return nil
}
