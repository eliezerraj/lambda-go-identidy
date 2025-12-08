package service

import (
	"fmt"
	"time"
	"context"
	"encoding/base64"

	"github.com/rs/zerolog"
	"github.com/google/uuid"
	"github.com/golang-jwt/jwt/v5"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"

	"github.com/lambda-go-identidy/internal/domain/model"
	"github.com/lambda-go-identidy/shared/erro"

	go_core_aws_dynamoDB "github.com/eliezerraj/go-core/v2/aws/dynamoDB"
	go_core_otel_trace "github.com/eliezerraj/go-core/v2/otel/trace"
)

var tracerProvider go_core_otel_trace.TracerProvider

type WorkerService struct {
	appServer *model.AppServer
	dynamoDB  *go_core_aws_dynamoDB.DatabaseDynamoDB
	logger 	  *zerolog.Logger

	createdToken func(	interface{}, 
						time.Time, 
						model.JwtData,
						*zerolog.Logger ) (*model.Authentication, error)

	tokenSignedValidation func(string, 
							   interface{},
							   *zerolog.Logger) (*model.JwtData, error)
}

// ------------------------- RSA ------------------------------/
// About create a jwt token with rsa key
func createdTokenRSA(rsaPrivate interface{}, 
					expirationTime time.Time, 
					jwtData model.JwtData,
					logger *zerolog.Logger) (*model.Authentication, error){
	logger.Info().
			Str("func","createdTokenRSA").Send()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtData)
	tokenString, err := token.SignedString(rsaPrivate)
	if err != nil {
		return nil, err
	}

	authentication := model.Authentication{	Token: tokenString, 
											ExpirationTime: expirationTime}

	return &authentication ,nil
}

// About check token RSA expired/signature and claims
func tokenValidationRSA(bearerToken string, 
						rsaPubKey interface{},
						logger *zerolog.Logger)( *model.JwtData, error){
	logger.Info().
			Str("func","tokenValidationRSA").Send()

	claims := &model.JwtData{}
	tkn, err := jwt.ParseWithClaims(bearerToken, 
								  claims, func(token *jwt.Token) (interface{}, error) {
		return rsaPubKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, erro.ErrStatusUnauthorized
		}
		return nil, erro.ErrTokenExpired
	}

	if !tkn.Valid {
		return nil, erro.ErrStatusUnauthorized
	}

	return claims, nil
}

// -------------------------------H 256 ---------------
// About create token HS256
func createdTokenHS256( Hs256Key interface{}, 
						expirationTime time.Time, 
						jwtData model.JwtData,
						logger *zerolog.Logger) (*model.Authentication, error){
	logger.Info().
			Str("func","createdTokenHS256").Send()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtData)
	tokenString, err := token.SignedString([]byte(fmt.Sprint(Hs256Key)))
	if err != nil {
		return nil, err
	}

	authentication := model.Authentication{Token: tokenString, 
								ExpirationTime: expirationTime}

	return &authentication ,nil
}

// About check token HS256 expired/signature and claims
func tokenValidationHS256(bearerToken string, 
						  hs256Key interface{},
						  logger *zerolog.Logger) ( *model.JwtData, error){

	logger.Info().
			Str("func","TokenValidationHS256").Send()

	claims := &model.JwtData{}
	tkn, err := jwt.ParseWithClaims(bearerToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(fmt.Sprint(hs256Key)), nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, erro.ErrStatusUnauthorized
		}
		return nil, erro.ErrTokenExpired
	}

	if !tkn.Valid {
		return nil, erro.ErrStatusUnauthorized
	}

	return claims, nil
}
// ------------------------- Support ------------------------------/
// About new worker service
func NewWorkerService(appServer *model.AppServer,
					  dynamoDB  *go_core_aws_dynamoDB.DatabaseDynamoDB,	
					  appLogger *zerolog.Logger) *WorkerService{

	logger := appLogger.With().
						Str("package", "domain.service").
						Logger()
	logger.Info().
			Str("func","NewWorkerService").Send()

	var createdToken func(interface{}, time.Time, model.JwtData, *zerolog.Logger) (*model.Authentication, error) 
	var tokenSignedValidation func(string, interface{}, *zerolog.Logger) (*model.JwtData, error)

	if appServer.Application.AuthenticationModel == "RSA" {
		createdToken =	createdTokenRSA
		tokenSignedValidation = tokenValidationRSA
	} else {
		createdToken =	createdTokenHS256
		tokenSignedValidation = tokenValidationHS256
	}

	return &WorkerService{
		appServer: appServer,
		dynamoDB: dynamoDB,
		logger: &logger,
		createdToken: createdToken,
		tokenSignedValidation: tokenSignedValidation,
	}
}

//-------------------------- Identidy ---------------------------------------
// About create a new credential
func (w *WorkerService) SignIn(ctx context.Context, 
								credential model.Credential) (*model.Credential, error){
	w.logger.Info().
			 Str("func","SignIn").Send()

	// Trace
	ctx, span := tracerProvider.SpanCtx(ctx, "service.SignIn")
	defer span.End()

	// Prepare ID and SK
	credential.ID = fmt.Sprintf("USER-%s", credential.User)
	credential.SK = fmt.Sprintf("USER-%s", credential.User)
	credential.Updated_at 	= time.Now()

	// Put item dynamo
	err := w.dynamoDB.PutItem(ctx, 
							  &w.appServer.AwsService.DynamoTableName,  
							  credential)
	if err != nil {
		return nil, err
	}

	return &credential, nil
}

// About get credential data
func (w *WorkerService) GetCredential(ctx context.Context, 
									  credential model.Credential) (*model.Credential, error){
	w.logger.Info().
			 Str("func","GetCredential").Send()

	// Trace
	ctx, span := tracerProvider.SpanCtx(ctx, "service.GetCredential")
	defer span.End()

	// Prepare ID and SK
	id := fmt.Sprintf("USER-%s", credential.User)
	sk := fmt.Sprintf("USER-%s", credential.User)

	// Get user from dynamo
	res_credential, err := w.dynamoDB.QueryInput(ctx, 
												&w.appServer.AwsService.DynamoTableName, 
												id, 
												sk)
	if err != nil {
		return nil, err
	}
	if len(res_credential) == 0 {
		return nil, erro.ErrNotFound
	}

	un_credential := []model.Credential{}
	err = attributevalue.UnmarshalListOfMaps(res_credential, &un_credential)
    if err != nil {
		return nil, err
	}
	
	// Prepare SK
	sk = "SCOPE-001"
	// Get credential from dynamo
	res_credential_scope, err := w.dynamoDB.QueryInput( ctx, 
														&w.appServer.AwsService.DynamoTableName, 
														id, 
														sk)
	if err != nil {
		return nil, err
	}
	credential_scope := []model.CredentialScope{}
	if len(res_credential_scope) > 0 {
		err = attributevalue.UnmarshalListOfMaps(res_credential_scope, &credential_scope)
		if err != nil {
			return nil, err
		}
		un_credential[0].CredentialScope = &credential_scope[0]
	}
	
	return &un_credential[0], nil
}

// About add a scope
func (w *WorkerService) AddScope(ctx context.Context, 
								credential_scope model.CredentialScope) (*model.CredentialScope, error){
	w.logger.Info().
			Str("func","AddScope").Send()

	// Trace
	ctx, span := tracerProvider.SpanCtx(ctx, "service.AddScope")
	defer span.End()

	// Prepare ID and SK
	credential_scope.ID = fmt.Sprintf("USER-%s", credential_scope.User)
	credential_scope.SK = "SCOPE-001"
	credential_scope.Updated_at = time.Now()

	// Put item dynamo
	err := w.dynamoDB.PutItem(ctx, 
							  &w.appServer.AwsService.DynamoTableName, 
							  credential_scope)
	if err != nil {
		return nil, err
	}

	return &credential_scope, nil
}

//-------------------------- JWT subjects ---------------------------------------
// About Login
func (w *WorkerService) OAUTHCredential(ctx context.Context, 
										credential model.Credential) (*model.Authentication, error){
	w.logger.Info().
			Str("func","OAUTHCredential").Send()

	// Trace
	ctx, span := tracerProvider.SpanCtx(ctx, "service.OAUTHCredential")
	defer span.End()

	// Prepare ID and SK
	id := fmt.Sprintf("USER-%s", credential.User)
	sk := fmt.Sprintf("USER-%s", credential.User)

	// Get credentials for dynamo
	res_credential, err := w.dynamoDB.QueryInput(ctx, 
												&w.appServer.AwsService.DynamoTableName, 
												id, 
												sk)
	if err != nil {
		return nil, err
	}
	if len(res_credential) == 0 {
		return nil, erro.ErrNotFound
	}
	un_credential := []model.Credential{}
	err = attributevalue.UnmarshalListOfMaps(res_credential, &un_credential)
    if err != nil {
		return nil, err
	}

	// Check Password (NAIVE)
	if credential.Password != un_credential[0].Password {
		return nil, erro.ErrCredentials
	}

	// Prepare ID and SK
	id = fmt.Sprintf("USER-%s", credential.User)
	sk = "SCOPE-001"

	// get scopes associated with a credential
	res_credential_scope, err := w.dynamoDB.QueryInput(ctx, 
														&w.appServer.AwsService.DynamoTableName,  
														id, 
														sk)
	if err != nil {
		return nil, err
	}
	if len(res_credential_scope) == 0 {
		return nil, erro.ErrNotFound
	}
	
	credential_scope := []model.CredentialScope{}
	err = attributevalue.UnmarshalListOfMaps(res_credential_scope, &credential_scope)
	if err != nil {
		return nil, err
	}

	// Set a JWT expiration date 
	expirationTime := time.Now().Add(7200 * time.Minute) // 5 days

	newUUID := uuid.New()
	uuidString := newUUID.String()

	// Create a JWT Oauth 2.0 with all scopes and expiration date
	jwtData := &model.JwtData{	Username: 	credential.User,
								Scope: 		credential_scope[0].Scope,
								ISS: 		w.appServer.Application.Name,
								Version: 	w.appServer.Application.Version,
								JwtId: 		uuidString,
								TokenUse: 	"access",
								Tier: 		un_credential[0].Tier,
								ApiAccessKey: un_credential[0].ApiAccessKey,
								RegisteredClaims: jwt.RegisteredClaims{
									ExpiresAt: jwt.NewNumericDate(expirationTime), 	// JWT expiry time is unix milliseconds
								},
	}

	// Create token Function via parameter (see router decision)
	_, span01 := tracerProvider.SpanCtx(ctx, "service.createdToken")
	authentication, err := w.createdToken(credential.JwtKey, 
										  expirationTime, 
										  *jwtData,
										  w.logger)
	span01.End()

	if err != nil {
		return nil, err
	}
	return authentication, nil
}

// About check a token expitation date
func (w *WorkerService) TokenValidation(ctx context.Context, credential model.Credential) (bool, error){
	w.logger.Info().
			 Str("func","TokenValidation").Send()

	// Trace
	ctx, span := tracerProvider.SpanCtx(ctx, "service.TokenValidation")
	defer span.End()
	
	// Validate token - Function via parameter (see router decision)
	_, err := w.tokenSignedValidation(credential.Token, 
									  credential.JwtKeySign, 
									  w.logger)
	if err != nil {
		return false, err
	}

	return true, nil
}

// About wellKnown
func (w *WorkerService) WellKnown(ctx context.Context) (*model.Jwks, error){
	w.logger.Info().
			Str("func","WellKnown").Send()

	// Trace
	ctx, span := tracerProvider.SpanCtx(ctx, "service.WellKnown")
	defer span.End()

	// Convert B64 pub key
	nBase64 := base64.URLEncoding.
					  WithPadding(base64.NoPadding).
					  EncodeToString([]byte(w.appServer.RsaKey.RsaPublicPem))

	// prepate jkws
	jKey := model.JwtKeyInfo{
		Type: "RSA",
		Algorithm: "RS256",
		JwtId: "1",
		NBase64: nBase64,
	}
	
	// set all jkws (in this example we hava just one)
	var arrJKey []model.JwtKeyInfo
	arrJKey = append(arrJKey, jKey)

	jwks := model.Jwks{JwtKeyInfo: arrJKey}
	
	return &jwks ,nil
}

// About refresh token
func (w *WorkerService) RefreshToken(ctx context.Context, 
									credential model.Credential) (*model.Authentication, error){
	w.logger.Info().
			Str("func","RefreshToken").Send()

	// Trace
	ctx, span := tracerProvider.SpanCtx(ctx, "service.RefreshToken")
	defer span.End()

	// Validate token and extract claims
	jwtData := &model.JwtData{}

	// Validate token
	jwtData, err := w.tokenSignedValidation(credential.Token, 
											credential.JwtKeySign,
										    w.logger)
	if err != nil {
		return nil, err
	}
	// Set a new tokens claims
	expirationTime := time.Now().Add(2880 * time.Minute)
	jwtData.ExpiresAt = jwt.NewNumericDate(expirationTime)
	jwtData.ISS = w.appServer.Application.Name + "-refreshed"

	// Create token Function via parameter (see router decision)
	authentication, err := w.createdToken(credential.JwtKey, 
										  expirationTime, 
										  *jwtData,
										  w.logger)
	if err != nil {
		return nil, err
	}

	return authentication ,nil
}
