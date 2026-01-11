package model

import (
	"time"
	"crypto/rsa"
	
	"github.com/golang-jwt/jwt/v5"
	go_core_otel_trace "github.com/eliezerraj/go-core/v2/otel/trace"
)

type AppServer struct {
	Application 		*Application	`json:"application"`
	AwsService			*AwsService		`json:"aws_service"`
	RsaKey				*RsaKey			`json:"rsa_key"`
	EnvTrace			*go_core_otel_trace.EnvTrace	`json:"env_trace"`
}

type Application struct {
	Name				string 	`json:"name"`
	Version				string 	`json:"version"`
	Account				string 	`json:"account,omitempty"`
	AuthenticationModel	string  `json:"authentication_model,RSA,omitempty"`	
	OsPid				string 	`json:"os_pid"`
	IPAddress			string 	`json:"ip_address"`
	Env					string 	`json:"enviroment,omitempty"`
	LogLevel			string 	`json:"log_level,omitempty"`
	OtelTraces			bool   	`json:"otel_traces"`
	OtelMetrics			bool   	`json:"otel_metrics"`
	OtelLogs			bool   	`json:"otel_logs"`
	StdOutLogGroup 		bool   	`json:"stdout_log_group"`
	LogGroup			string 	`json:"log_group,omitempty"`
}

type AwsService struct {
	AwsRegion			string `json:"aws_region"`
	DynamoTableName		string `json:"dynamo_table_name"`
	Kid					string 	`json:"kid"`	
	SecretName			string `json:"secret_name"`
	BucketNameRSAKey	string `json:"bucket_rsa_key,omitempty"`
	FilePathRSA			string `json:"path_rsa_key,omitempty"`
	FileNameRSAPrivKey	string `json:"file_name_rsa_private_key,omitempty"`
	FileNameRSAPubKey	string `json:"file_name_rsa_public_key,omitempty"`
	FileNameCrlKey		string `json:"file_name_crl_key"`
}

type Credential struct {
	ID				string	`json:"ID,omitempty"`
	SK				string	`json:"SK,omitempty"`
	User			string	`json:"user,omitempty"`
	Password		string	`json:"password,omitempty"`
	Token			string 	`json:"token,omitempty"`
	Tier			string 	`json:"tier,omitempty"`
	ApiAccessKey	string 	`json:"api_access_key,omitempty"`
	Updated_at  	time.Time 	`json:"updated_at,omitempty"`
	CredentialScope	*CredentialScope `json:"credential_scope,omitempty"`
	JwtKey			interface{}
	JwtKeySign		interface{}
}

type CredentialScope struct {
	ID				string		`json:"ID"`
	SK				string		`json:"SK"`
	User			string		`json:"user,omitempty"`
	Scope			[]string	`json:"scope,omitempty"`
	Updated_at  	time.Time 	`json:"updated_at,omitempty"`
}

type RsaKey struct{
	AuthenticationModel	string			`json:"authentication_model"`
	HsaKey				string			`json:"hsa_key"`
	RsaPrivatePem		string			`json:"rsa_private_pem"`
	RsaPublicPem 		string			`json:"rsa_public_pem"`
	Kid					string 			`json:"kid"`
	CrlPem 				string			`json:"crl_pem"`
	CaCert				string			`json:"ca_cert"` 
	RsaPrivate 			*rsa.PrivateKey `json:"rsa_private"`
	RsaPublic 			*rsa.PublicKey	`json:"rsa_public"`
}

type Authentication struct {
	Token			string	`json:"token,omitempty"`
	TokenEncrypted	string	`json:"token_encrypted,omitempty"`
	ExpirationTime	time.Time `json:"expiration_time,omitempty"`
}

type JwtData struct {
	TokenUse		string 	`json:"token_use"`
	ISS				string 	`json:"iss"`
	Version			string 	`json:"version"`
	Username		string 	`json:"username"`
	JwtId			string 	`json:"jwt_id"`
	Kid				string 	`json:"kid"`
	Tier			string 	`json:"tier,omitempty"`				// use in plan usage rate-limit
	ApiAccessKey	string 	`json:"api_access_key,omitempty"` 	// use in plan usage rate-limit
	Scope	  		[]string `json:"scope"`
	jwt.RegisteredClaims
}

type Jwks struct{
	JwtKeyInfo	[]JwtKeyInfo `json:"keys"`
}

type JwtKeyInfo struct{
	Type		string 	`json:"kty"`
	Algorithm	string 	`json:"alg"`
	Kid			string 	`json:"kid"`
	NBase64		string 	`json:"n"`
}