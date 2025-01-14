package applepay

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

type (
	// Response is the full response from the user's device after an Apple
	// Pay request
	Response struct {
		ShippingContact Contact        `json:"shippingContact,omitempty"`
		BillingContact  Contact        `json:"billingContact,omitempty"`
		Token           PKPaymentToken `json:"token"`
	}

	// Contact is the struct that contains billing/shipping information from an
	// Apple Pay response
	Contact struct {
		GivenName             string   `json:"givenName,omitempty"`
		FamilyName            string   `json:"familyName,omitempty"`
		EmailAddress          string   `json:"emailAddress,omitempty"`
		AddressLines          []string `json:"addressLines,omitempty"`
		AdministrativeArea    string   `json:"administrativeArea,omitempty"`
		Locality              string   `json:"locality,omitempty"`
		PostalCode            string   `json:"postalCode,omitempty"`
		Country               string   `json:"country,omitempty"`
		CountryCode           string   `json:"countryCode,omitempty"`
		PhoneNumber           string   `json:"phoneNumber,omitempty"`
		SubAdministrativeArea string   `json:"subAdministrativeArea,omitempty"`
		SubLocality           string   `json:"subLocality,omitempty"`
	}
)

// extractMerchantHash extracts the merchant hash stored in a certificate. It is
// stored by Apple during the signature of the certificate.
// It is the merchant ID hashed with SHA-256 and represented in hexadecimal
func extractMerchantHash(cert tls.Certificate) ([]byte, error) {
	if cert.Certificate == nil {
		return nil, errors.New("nil certificate")
	}

	// Parse the leaf certificate of the certificate chain
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, errors.Wrap(err, "certificate parsing error")
	}

	extValue, err := extractExtension(leaf, merchantIDHashOID)
	if err != nil {
		return nil, errors.Wrap(err, "error finding the hash extension")
	}
	// First two bytes are "@."
	if len(extValue) != 66 {
		return nil, errors.New("invalid hash length")
	}
	merchantIDString, err := hex.DecodeString(string(extValue[2:]))
	if err != nil {
		return nil, errors.Wrap(err, "invalid hash hex")
	}
	return []byte(merchantIDString), nil
}

// extractExtension returns the value of a certificate extension if it exists
func extractExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) (
	[]byte, error) {

	if cert == nil {
		return nil, errors.New("nil certificate")
	}

	var res []byte
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oid) {
			continue
		}
		res = ext.Value
	}
	if res == nil {
		return nil, errors.New("extension not found")
	}

	return res, nil
}

// mustParseASN1ObjectIdentifier calls parseASN1ObjectIdentifier and panics if
// it returns an error
func mustParseASN1ObjectIdentifier(id string) asn1.ObjectIdentifier {
	oid, err := parseASN1ObjectIdentifier(id)
	if err != nil {
		panic(errors.Wrap(err, "error parsing the OID"))
	}
	return oid
}

// parseASN1ObjectIdentifier parses an ASN.1 object identifier string of the
// form x.x.x.x.x.x.x.x into a Go asn1.ObjectIdentifier
func parseASN1ObjectIdentifier(id string) (asn1.ObjectIdentifier, error) {
	idSplit := strings.Split(id, ".")
	oid := make([]int, len(idSplit))
	for i, str := range idSplit {
		r, err := strconv.Atoi(str)
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing %s", str)
		}
		oid[i] = r
	}
	return oid, nil
}
