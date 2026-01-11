package lambda

import(
	"fmt"
	"context"
	"net/http"
	"strings"
	"encoding/json"

	"github.com/rs/zerolog"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/lambda-go-identidy/shared/erro"
	"github.com/lambda-go-identidy/internal/domain/model"
	"github.com/lambda-go-identidy/internal/domain/service"

	go_core_otel_trace "github.com/eliezerraj/go-core/v2/otel/trace"	
)

var tracerProvider go_core_otel_trace.TracerProvider

type LambdaRouters struct {
	appServer	*model.AppServer
	workerService *service.WorkerService
	logger *zerolog.Logger
}

type LambdaError struct {
	StatusCode	int    `json:"statusCode"`
	TraceId		string `json:"request-id,omitempty"`
	Error		string `json:"message"`
}

func NewLambdaRouters(appServer *model.AppServer,
					  workerService *service.WorkerService, 
					  appLogger 	*zerolog.Logger) *LambdaRouters {

	logger := appLogger.With().
						Str("package", "adapter.lambda").
						Logger()
	logger.Info().
			Str("func","NewLambdaRouters").Send()

	return &LambdaRouters{
		workerService: workerService,
		appServer: appServer,
		logger: &logger,
	}
}

//------------------------------------- Support methods --------------------------------------------
// About response
func (r *LambdaRouters) LambdaResponse(statusCode int, 
									   body interface{}) (*events.APIGatewayProxyResponse, error){
	r.logger.Info().
			 Str("func","ApiHandlerResponse").Send()

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
func (r *LambdaRouters) ErrorHandler(ctx context.Context, err error) *LambdaError {

	trace_id := fmt.Sprintf("%v",ctx.Value("request-id"))

	var httpStatusCode int = http.StatusInternalServerError

	if strings.Contains(err.Error(), "context deadline exceeded") {
    	httpStatusCode = http.StatusGatewayTimeout
	}

	if strings.Contains(err.Error(), "check parameters") {
    	httpStatusCode = http.StatusBadRequest
	}

	if strings.Contains(err.Error(), "not found") {
    	httpStatusCode = http.StatusNotFound
	}

	if strings.Contains(err.Error(), "duplicate key") || 
	   strings.Contains(err.Error(), "unique constraint") {
   		httpStatusCode = http.StatusBadRequest
	}

	lambdaError := LambdaError{ StatusCode: httpStatusCode, 
							    TraceId: trace_id, 
								Error: err.Error(), }

	return &lambdaError
}

// About get into
func (r *LambdaRouters) GetInfo(ctx context.Context) (*events.APIGatewayProxyResponse, error) {
	r.logger.Info().
			 Str("func","GetInfo").Send()
	
	//trace
	ctx, span := tracerProvider.SpanCtx(ctx, "adapter.api.GetInfo")
	defer span.End()

	handlerResponse, err := r.LambdaResponse( http.StatusOK,  
											  r.appServer)
	
	if err != nil {
		return r.LambdaResponse(http.StatusInternalServerError, 
								r.ErrorHandler(ctx, err),)
	}

	return handlerResponse, nil
}

//-------------------------------------  Identidy  --------------------------------------------
// About get credential
func (r *LambdaRouters) GetCredential(ctx context.Context, 
									 req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	r.logger.Info().
			 Str("func","GetCredential").Send()

	//trace
	ctx, span := tracerProvider.SpanCtx(ctx, "adapter.lambda.GetCredential")
	defer span.End()

	// prepare
	id := req.PathParameters["id"]
	if len(id) == 0 {
		return r.LambdaResponse(http.StatusBadRequest, 
								r.ErrorHandler( ctx, erro.ErrQueryEmpty))
	}

	credential := model.Credential{User: id}
	
	//call service
	response, err := r.workerService.GetCredential(ctx,
												   credential)
	if err != nil {
		switch err {
		case erro.ErrNotFound:
			return r.LambdaResponse(http.StatusNotFound, 
								    r.ErrorHandler(ctx, err ) )
		default:
			return r.LambdaResponse(http.StatusInternalServerError, 
								    r.ErrorHandler(ctx, err) )
		}
	}
	
	handlerResponse, err := r.LambdaResponse(http.StatusOK, 
											 response)
	if err != nil {
		return r.LambdaResponse(http.StatusInternalServerError, 
								r.ErrorHandler(ctx, err) )
	}

	return handlerResponse, nil
}

// About AddScope
func (r *LambdaRouters) AddScope(ctx context.Context, 
								 req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	r.logger.Info().
			Str("func","AddScope").Send()
	
	//trace
	ctx, span := tracerProvider.SpanCtx(ctx, "adapter.lambda.AddScope")
	defer span.End()

	// prepare
	credential_scope := model.CredentialScope{}
    if err := json.Unmarshal([]byte(req.Body), &credential_scope); err != nil {
		return r.LambdaResponse(http.StatusBadRequest, 
								r.ErrorHandler( ctx, erro.ErrQueryEmpty))
    }

	//call service
	response, err := r.workerService.AddScope(ctx, credential_scope)
	if err != nil {
		switch err {
		case erro.ErrNotFound:
			return r.LambdaResponse(http.StatusNotFound, 
								    r.ErrorHandler(ctx, err ) )
		default:
			return r.LambdaResponse(http.StatusInternalServerError, 
								    r.ErrorHandler(ctx, err) )
		}
	}
	
	handlerResponse, err := r.LambdaResponse(http.StatusOK, response)
	if err != nil {
		return r.LambdaResponse(http.StatusInternalServerError, 
								r.ErrorHandler(ctx, err) )
	}

	return handlerResponse, nil
}

// About SignIn
func (r *LambdaRouters) SignIn(ctx context.Context, 
								req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	r.logger.Info().
			 Str("func","SignIn").Send()
	
	//trace
	ctx, span := tracerProvider.SpanCtx(ctx, "adapter.lambda.SignIn")
	defer span.End()

	// prepare
	credential := model.Credential{}
    if err := json.Unmarshal([]byte(req.Body), &credential); err != nil {
		return r.LambdaResponse(http.StatusBadRequest, 
								r.ErrorHandler( ctx, erro.ErrQueryEmpty))
    }

	//call service
	response, err := r.workerService.SignIn(ctx, credential)
	if err != nil {
		switch err {
		case erro.ErrNotFound:
			return r.LambdaResponse(http.StatusNotFound, 
								    r.ErrorHandler(ctx, err ) )
		default:
			return r.LambdaResponse(http.StatusInternalServerError, 
								    r.ErrorHandler(ctx, err) )
		}
	}

	handlerResponse, err := r.LambdaResponse(http.StatusOK, response)
	if err != nil {
		return r.LambdaResponse(http.StatusInternalServerError, 
								r.ErrorHandler(ctx, err) )
	}

	return handlerResponse, nil
}

//------------------------------------- Jwt and signatures --------------------------------------------
// About sign-in
func (r *LambdaRouters) OAUTHCredential(ctx context.Context, req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	r.logger.Info().
			Str("func","OAUTHCredential").Send()
	
	//trace
	ctx, span := tracerProvider.SpanCtx(ctx, "adapter.lambda.OAUTHCredential")
	defer span.End()

	// prepare
	credential := model.Credential{}
    if err := json.Unmarshal([]byte(req.Body), &credential); err != nil {
		return r.LambdaResponse(http.StatusBadRequest, 
								r.ErrorHandler( ctx, erro.ErrQueryEmpty))
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
		switch err {
		case erro.ErrNotFound:
			return r.LambdaResponse(http.StatusNotFound, 
								    r.ErrorHandler(ctx, err ) )
		default:
			return r.LambdaResponse(http.StatusInternalServerError, 
								    r.ErrorHandler(ctx, err) )
		}
	}
	
	handlerResponse, err := r.LambdaResponse(http.StatusOK, response)
	if err != nil {
		return r.LambdaResponse(http.StatusInternalServerError, 
								r.ErrorHandler(ctx, err) )
	}

	return handlerResponse, nil
}

// About WellKnown
func (r *LambdaRouters) WellKnown(ctx context.Context, 
								  req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	r.logger.Info().
			Str("func","WellKnown").Send()

	//trace
	ctx, span := tracerProvider.SpanCtx(ctx, "adapter.lambda.WellKnown")
	defer span.End()

	//call service
	response, err := r.workerService.WellKnown(ctx)
	if err != nil {
		switch err {
		case erro.ErrNotFound:
			return r.LambdaResponse(http.StatusNotFound, 
								    r.ErrorHandler(ctx, err ) )
		default:
			return r.LambdaResponse(http.StatusInternalServerError, 
								    r.ErrorHandler(ctx, err) )
		}
	}
	
	handlerResponse, err :=  r.LambdaResponse(http.StatusOK, response)
	if err != nil {
		return r.LambdaResponse(http.StatusInternalServerError, 
								r.ErrorHandler(ctx, err) )
	}

	return handlerResponse, nil
}

// About TokenValidation
func (r *LambdaRouters) TokenValidation(ctx context.Context, req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	r.logger.Info().
			 Str("func","TokenValidation").Send()
	
	//trace
	ctx, span := tracerProvider.SpanCtx(ctx, "adapter.lambda.TokenValidation")
	defer span.End()

	// prepare
	credential := model.Credential{}
    if err := json.Unmarshal([]byte(req.Body), &credential); err != nil {
		return r.LambdaResponse(http.StatusBadRequest, 
								r.ErrorHandler( ctx, erro.ErrQueryEmpty))
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
		switch err {
		case erro.ErrTokenExpired:
			return r.LambdaResponse(http.StatusUnauthorized, 
								    r.ErrorHandler(ctx, err ) )
		case erro.ErrStatusUnauthorized:
			return r.LambdaResponse(http.StatusUnauthorized, 
								    r.ErrorHandler(ctx, err ) )
		default:
			return r.LambdaResponse(http.StatusInternalServerError, 
								    r.ErrorHandler(ctx, err) )
		}
	}
	
	handlerResponse, err := r.LambdaResponse(http.StatusOK, response)
	if err != nil {
		return r.LambdaResponse(http.StatusInternalServerError, 
								r.ErrorHandler(ctx, err) )
	}

	return handlerResponse, nil
}

// About refresh
func (r *LambdaRouters) RefreshToken(ctx context.Context, 
									req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	r.logger.Info().
			Str("func","RefreshToken").Send()
	
	//trace
	ctx, span := tracerProvider.SpanCtx(ctx, "adapter.api.RefreshToken")
	defer span.End()

	// prepare
	credential := model.Credential{}
    if err := json.Unmarshal([]byte(req.Body), &credential); err != nil {
		return r.LambdaResponse(http.StatusBadRequest, 
								r.ErrorHandler( ctx, erro.ErrQueryEmpty))
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
		switch err {
		case erro.ErrTokenExpired:
			return r.LambdaResponse(http.StatusUnauthorized, 
								    r.ErrorHandler(ctx, err ) )
		case erro.ErrStatusUnauthorized:
			return r.LambdaResponse(http.StatusUnauthorized, 
								    r.ErrorHandler(ctx, err ) )
		default:
			return r.LambdaResponse(http.StatusInternalServerError, 
								    r.ErrorHandler(ctx, err) )
		}
	}
	
	handlerResponse, err := r.LambdaResponse(http.StatusOK, response)
	if err != nil {
		return r.LambdaResponse(http.StatusInternalServerError, 
								r.ErrorHandler(ctx, err) )
	}

	return handlerResponse, nil
}