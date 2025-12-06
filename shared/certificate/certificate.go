package certificate

import (
	"crypto/rsa"
    "encoding/pem"
	"crypto/x509"
	"errors"

	"github.com/rs/zerolog"
)

// About convert a key pem string in rsa key
func ParsePemToRSAPriv(private_key *string,
					   logger *zerolog.Logger) (*rsa.PrivateKey, error){
	logger.Info().
			Str("func","ParsePemToRSAPriv").Send()

	block, _ := pem.Decode([]byte(*private_key))
	if block == nil || block.Type != "PRIVATE KEY" {
		logger.Error().
			   Err(errors.New("erro PRIVATE KEY Decode")).Send()
		return nil, errors.New("erro PRIVATE KEY Decode")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		logger.Error().
			   Err(err).Send()
		return nil, err
	}

	key_rsa := privateKey.(*rsa.PrivateKey)

	return key_rsa, nil
}

// About convert a key pem string in rsa key
func ParsePemToRSAPub(public_key *string,
						logger *zerolog.Logger) (*rsa.PublicKey, error){
	logger.Info().
			Str("func","ParsePemToRSAPub").Send()

	block, _ := pem.Decode([]byte(*public_key))
	if block == nil || block.Type != "PUBLIC KEY" {
		logger.Error().
			   Err(errors.New("erro PUBLIC KEY Decode")).Send()
		return nil, errors.New("erro PUBLIC KEY Decode")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		logger.Error().
			   Err(err).Send()
		return nil, err
	}

	key_rsa := pubInterface.(*rsa.PublicKey)

	return key_rsa, nil
}

// About convert a cert pem string in cert x509
func ParsePemToCertx509(certX509pem *string,
									  logger *zerolog.Logger) (*x509.Certificate, error) {
	logger.Info().
			Str("func","ParsePemToCertx509").Send()

	block, _ := pem.Decode([]byte(*certX509pem))
	if block == nil || block.Type != "CERTIFICATE" {
		logger.Error().
			   Err(errors.New("erro CERT X509 Decode")).Send()
		return nil, errors.New("erro CERT X509 Decode")
	}

	certX509, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
		logger.Error().
			   Err(err).Send()
        return nil, err
    }

	return certX509, nil
}