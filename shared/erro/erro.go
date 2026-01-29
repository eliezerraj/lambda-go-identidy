//---------------------------------------
// Component is charge of defined message errors
//---------------------------------------
package erro

import (
	"errors"
)

var (
	ErrNotFound 		= errors.New("item not found")
	ErrBadRequest 		= errors.New("check parameters")
	ErrUpdate			= errors.New("update unsuccessful")
	ErrInsert 			= errors.New("insert data error")
	ErrUnmarshal 		= errors.New("unmarshal json error")
	ErrUnauthorized 	= errors.New("not authorized")
	ErrServer		 	= errors.New("server identified error")
	ErrHTTPForbiden		= errors.New("forbiden request")
	ErrTimeout			= errors.New("timeout: context deadline exceeded")
	ErrHealthCheck		= errors.New("health check services required failed")

	ErrParseCert 	= errors.New("unable to parse x509 cert")
	ErrDecodeCert 	= errors.New("failed to decode pem-encoded cert")
	ErrDecodeKey 	= errors.New("error decode rsa key")
	ErrTokenExpired	= errors.New("token expired")
	ErrStatusUnauthorized 	= errors.New("invalid Token")
	ErrBearTokenFormad 		= errors.New("unauthorized token not informed")
	ErrPreparedQuery  		= errors.New("erro prepare query for dynamo")
	ErrQuery 		= errors.New("query table error")
	ErrSignatureInvalid = errors.New("signature error")
	ErrMethodNotAllowed	= errors.New("method not allowed")
	ErrQueryEmpty	= errors.New("query parameters missing")
	ErrCertRevoked	= errors.New("error cert revoke")
	ErrCredentials	= errors.New("credential informed is invalid (user or password) ")
)
