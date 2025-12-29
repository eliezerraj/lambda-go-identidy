package server

import(
	"context"

	"github.com/rs/zerolog"
	"github.com/aws/aws-lambda-go/events"

	lambdaRouter "github.com/lambda-go-identidy/internal/infrastructure/adapter/lambda"	
	"github.com/lambda-go-identidy/internal/infrastructure/adapter/lambda"	
)

var response *events.APIGatewayProxyResponse

type Server struct {
	lambdaRouters	*lambda.LambdaRouters
	logger *zerolog.Logger
}

// About inicialize handler
func NewLambdaServer(lambdaRouters *lambdaRouter.LambdaRouters,
					 appLogger *zerolog.Logger) *Server {

	logger := appLogger.With().
						Str("package", "infrastructure.server").
						Logger()
	logger.Info().
			Str("func","NewLambdaServer").Send()

    return &Server{
		lambdaRouters: lambdaRouters,
		logger: &logger,
    }
}

// About handle the request
func (s *Server) LambdaHandlerRequest(ctx context.Context,
									  request events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
	s.logger.Info().
			 Str("func","LambdaHandlerRequest").Send()

	// get the resquest-id and put in inside the 
	ctx = context.WithValue(ctx, "request-id", request.RequestContext.RequestID)

	// Check the http method and path
	switch request.HTTPMethod {
		case "GET":
			if request.Resource == "/credential/{id}" {  
				response, _ = s.lambdaRouters.GetCredential(ctx, request)
			}else if request.Resource == "/info"{
				response, _ = s.lambdaRouters.GetInfo(ctx)
			}else if request.Resource == "/wellKnown/1" {
				response, _ =  s.lambdaRouters.WellKnown(ctx, request) 
			}else {
				response, _ = s.lambdaRouters.UnhandledMethod()
			}
		case "POST":
			if request.Resource == "/oauth_credential"{  
				response, _ = s.lambdaRouters.OAUTHCredential(ctx, request) // Login
			}else if request.Resource == "/refreshToken" {
				response, _ = s.lambdaRouters.RefreshToken(ctx, request) // Refresh Token
			}else if request.Resource == "/tokenValidation" {
				response, _ = s.lambdaRouters.TokenValidation(ctx, request) // Do a JWT validation (signature and expiration date)
			}else if request.Resource == "/signIn" {
				response, _ = s.lambdaRouters.SignIn(ctx, request) // Create a new credentials
			}else if request.Resource == "/addScope" {
				response, _ =  s.lambdaRouters.AddScope(ctx, request) // Add scopes to the credential
			}else {
				response, _ = s.lambdaRouters.UnhandledMethod()
			}
		case "DELETE":
			response, _ = s.lambdaRouters.UnhandledMethod()
		case "PUT":
			response, _ = s.lambdaRouters.UnhandledMethod()
		default:
			response, _ = s.lambdaRouters.UnhandledMethod()
	}	

	return response, nil
}					