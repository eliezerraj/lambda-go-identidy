package lambda

import(
	"time"
	"context"
	"net/http"
	"strings"
	"encoding/json"

	"github.com/rs/zerolog"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/codes"

	"github.com/lambda-go-identidy/shared/erro"
	"github.com/lambda-go-identidy/internal/domain/model"
	"github.com/lambda-go-identidy/internal/domain/service"

	go_core_otel_trace "github.com/eliezerraj/go-core/v2/otel/trace"
	go_core_midleware "github.com/eliezerraj/go-core/v2/middleware" // used to get request ID from context
)

type LambdaRouters struct {
	appServer		*model.AppServer
	workerService 	*service.WorkerService
	logger 			*zerolog.Logger
	tracerProvider 	*go_core_otel_trace.TracerProvider
}

type LambdaError struct {
	StatusCode	int    `json:"statusCode"`
	Error		string `json:"message"`
	RequestID	string `json:"request-id,omitempty"`
}

// Above create routers
func NewLambdaRouters(appServer 		*model.AppServer,
					  workerService 	*service.WorkerService, 
					  appLogger 		*zerolog.Logger,
					  tracerProvider 	*go_core_otel_trace.TracerProvider) *LambdaRouters {

	logger := appLogger.With().
		Str("package", "adapter.").
		Logger()

	logger.Info().
		Str("func","NewLambdaRouters").Send()

	return &LambdaRouters{
		workerService: workerService,
		appServer: appServer,
		logger: &logger,
		tracerProvider: tracerProvider,
	}
}

// -------------------------------------------
// Helper to extract context with timeout and setup span
func (r *LambdaRouters) withContext(ctx context.Context, spanName string) (context.Context, context.CancelFunc, trace.Span) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(10) * time.Second)

	r.logger.Info().
			Ctx(ctx).
			Str("func", spanName).Send()
	
	ctx, span := r.tracerProvider.SpanCtx(ctx, "adapter."+spanName, trace.SpanKindInternal)
	return ctx, cancel, span
}

//------------------------------------- Support methods --------------------------------------------
// About response
func (r *LambdaRouters) LambdaResponse (statusCode int, body interface{}) (*events.APIGatewayProxyResponse, error){

	stringBody, err := json.Marshal(&body)
	if err != nil {
		return nil, erro.ErrUnmarshal
	}

	return &events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: string(stringBody),
	}, nil
}

// About unhandled method
func (r *LambdaRouters) UnhandledMethod() (*events.APIGatewayProxyResponse, error){
	r.logger.Info().
			Str("func","UnhandledMethod").Send()

	return r.LambdaResponse(http.StatusMethodNotAllowed, 
							LambdaError{
										Error: *aws.String(erro.ErrMethodNotAllowed.Error()),
							})
}

// About handle error
func (r *LambdaRouters) ErrorHandler(requestID string, err error) *LambdaError {

	var httpStatusCode int = http.StatusInternalServerError

	if strings.Contains(err.Error(), "token expired") {
    	httpStatusCode = http.StatusUnauthorized
	}

	if strings.Contains(err.Error(), "context deadline exceeded") {
    	httpStatusCode = http.StatusGatewayTimeout
	}

	if strings.Contains(err.Error(), "check parameters") {
    	httpStatusCode = http.StatusBadRequest
	}

	if strings.Contains(err.Error(), "not found") {
    	httpStatusCode = http.StatusNotFound
	}

	if strings.Contains(err.Error(), "informed is invalid") {
    	httpStatusCode = http.StatusBadRequest
	}

	if strings.Contains(err.Error(), "duplicate key") || 
	   strings.Contains(err.Error(), "unique constraint") {
   		httpStatusCode = http.StatusBadRequest
	}

	// Create LambdaError struct
	lambdaError := LambdaError{ StatusCode: httpStatusCode, 
							    RequestID: requestID, 
								Error: err.Error(), }

	return &lambdaError
}

// Helper to get trace ID from context using middleware function
func (r *LambdaRouters) getRequestID(ctx context.Context) string {
	return go_core_midleware.GetRequestID(ctx)
}

// ----------------------------------------------------------------
// About get into
func (r *LambdaRouters) GetInfo(ctx context.Context) (*events.APIGatewayProxyResponse, error) {
	ctx, cancel, span := r.withContext(ctx, "GetInfo")
	defer cancel()
	defer span.End()

	handlerResponse, err := r.LambdaResponse(http.StatusOK, r.appServer)
	if err != nil {
		span.RecordError(err) 
        span.SetStatus(codes.Error, err.Error())
		return r.LambdaResponse(http.StatusInternalServerError, r.ErrorHandler(r.getRequestID(ctx), err))
	}

	return handlerResponse, nil
}

//-------------------------------------  Identidy  --------------------------------------------
// About get credential
func (r *LambdaRouters) GetCredential(ctx context.Context, req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
		 
	ctx, cancel, span := r.withContext(ctx, "GetCredential")
	defer cancel()
	defer span.End()

	// prepare
	id := req.PathParameters["id"]
	if len(id) == 0 {
		span.RecordError(erro.ErrQueryEmpty) 
        span.SetStatus(codes.Error, erro.ErrQueryEmpty.Error())
		return r.LambdaResponse(http.StatusBadRequest, r.ErrorHandler(r.getRequestID(ctx), erro.ErrQueryEmpty))
	}

	credential := model.Credential{User: id}
	
	//call service
	response, err := r.workerService.GetCredential(ctx, credential)
	if err != nil {
		lambdaError := r.ErrorHandler(r.getRequestID(ctx), err)
		return r.LambdaResponse(lambdaError.StatusCode, lambdaError)
	}
	
	return r.LambdaResponse(http.StatusOK, response)
}

// About AddScope
func (r *LambdaRouters) AddScope(ctx context.Context, 
								 req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	
	ctx, cancel, span := r.withContext(ctx, "AddScope")
	defer cancel()
	defer span.End()

	// prepare
	credential_scope := model.CredentialScope{}
    if err := json.Unmarshal([]byte(req.Body), &credential_scope); err != nil {
		return r.LambdaResponse(http.StatusBadRequest, r.ErrorHandler(r.getRequestID(ctx), erro.ErrQueryEmpty))
    }

	//call service
	response, err := r.workerService.AddScope(ctx, credential_scope)
	if err != nil {
		lambdaError := r.ErrorHandler(r.getRequestID(ctx), err)
		return r.LambdaResponse(lambdaError.StatusCode, lambdaError)
	}
	
	return r.LambdaResponse(http.StatusOK, response)
}

// About SignIn
func (r *LambdaRouters) SignIn(ctx context.Context, 
								req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	
	ctx, cancel, span := r.withContext(ctx, "SignIn")
	defer cancel()
	defer span.End()

	// prepare
	credential := model.Credential{}
    if err := json.Unmarshal([]byte(req.Body), &credential); err != nil {
		return r.LambdaResponse(http.StatusBadRequest, r.ErrorHandler(r.getRequestID(ctx), erro.ErrQueryEmpty))
    }

	//call service
	response, err := r.workerService.SignIn(ctx, credential)
	if err != nil {
		lambdaError := r.ErrorHandler(r.getRequestID(ctx), err)
		return r.LambdaResponse(lambdaError.StatusCode, lambdaError)
	}

	return r.LambdaResponse(http.StatusOK, response)
}

//------------------------------------- Jwt and signatures --------------------------------------------
// About sign-in
func (r *LambdaRouters) OAUTHCredential(ctx context.Context, req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {	
	ctx, cancel, span := r.withContext(ctx, "OAUTHCredential")
	defer cancel()
	defer span.End()

	// prepare
	credential := model.Credential{}
    if err := json.Unmarshal([]byte(req.Body), &credential); err != nil {
		return r.LambdaResponse(http.StatusBadRequest, r.ErrorHandler(r.getRequestID(ctx), erro.ErrQueryEmpty))
    }

	if r.appServer.Application.AuthenticationModel == "RSA" {
		credential.JwtKey 	  = r.appServer.RsaKey.RsaPrivate
		credential.JwtKeySign = r.appServer.RsaKey.RsaPublic
	} else {
		credential.JwtKey 	  = r.appServer.RsaKey.HsaKey
		credential.JwtKeySign = r.appServer.RsaKey.HsaKey
	}

	//call service
	response, err := r.workerService.OAUTHCredential(ctx, credential)
	if err != nil {
		lambdaError := r.ErrorHandler(r.getRequestID(ctx), err)
		return r.LambdaResponse(lambdaError.StatusCode, lambdaError)
	}
	
	return r.LambdaResponse(http.StatusOK, response)
}

// About WellKnown
func (r *LambdaRouters) WellKnown(ctx context.Context, 
								  req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	
	ctx, cancel, span := r.withContext(ctx, "WellKnown")
	defer cancel()
	defer span.End()

	//call service
	response, err := r.workerService.WellKnown(ctx)
	if err != nil {
		lambdaError := r.ErrorHandler(r.getRequestID(ctx), err)
		return r.LambdaResponse(lambdaError.StatusCode, lambdaError)
	}
	
	return r.LambdaResponse(http.StatusOK, response)
}

// About TokenValidation
func (r *LambdaRouters) TokenValidation(ctx context.Context, req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	
	ctx, cancel, span := r.withContext(ctx, "TokenValidation")
	defer cancel()
	defer span.End()

	// prepare
	credential := model.Credential{}
    if err := json.Unmarshal([]byte(req.Body), &credential); err != nil {
		return r.LambdaResponse(http.StatusBadRequest, r.ErrorHandler(r.getRequestID(ctx), erro.ErrQueryEmpty))
    }

	// Check which type of authentication method 
	if r.appServer.Application.AuthenticationModel == "RSA" {
		credential.JwtKey 	  = r.appServer.RsaKey.RsaPrivate
		credential.JwtKeySign = r.appServer.RsaKey.RsaPublic
	} else {
		credential.JwtKey 	  = r.appServer.RsaKey.HsaKey
		credential.JwtKeySign = r.appServer.RsaKey.HsaKey
	}

	//call service
	response, err := r.workerService.TokenValidation(ctx, credential)
	if err != nil {
		lambdaError := r.ErrorHandler(r.getRequestID(ctx), err)
		return r.LambdaResponse(lambdaError.StatusCode, lambdaError)
	}
	
	return r.LambdaResponse(http.StatusOK, response)
}

// About refresh
func (r *LambdaRouters) RefreshToken(ctx context.Context, 
									req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	ctx, cancel, span := r.withContext(ctx, "TokenValidation")
	defer cancel()
	defer span.End()

	// prepare
	credential := model.Credential{}
    if err := json.Unmarshal([]byte(req.Body), &credential); err != nil {
		return r.LambdaResponse(http.StatusBadRequest, r.ErrorHandler( r.getRequestID(ctx), erro.ErrQueryEmpty))
    }

	// Check which type of authentication method 
	if r.appServer.Application.AuthenticationModel == "RSA" {
		credential.JwtKey 	  = r.appServer.RsaKey.RsaPrivate
		credential.JwtKeySign = r.appServer.RsaKey.RsaPublic
	} else {
		credential.JwtKey 	  = r.appServer.RsaKey.HsaKey
		credential.JwtKeySign = r.appServer.RsaKey.HsaKey
	}

	//call service
	response, err := r.workerService.RefreshToken(ctx, credential)
	if err != nil {
		lambdaError := r.ErrorHandler(r.getRequestID(ctx), err)
		return r.LambdaResponse(lambdaError.StatusCode, lambdaError)
	}
	
	return r.LambdaResponse(http.StatusOK, response)
}