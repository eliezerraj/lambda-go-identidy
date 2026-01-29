package main

import(
	"fmt"
	"os"
	"io"
	"context"

	"github.com/rs/zerolog"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	
	"github.com/lambda-go-identidy/shared/log"
	"github.com/lambda-go-identidy/shared/certificate"
	"github.com/lambda-go-identidy/internal/domain/service"
	"github.com/lambda-go-identidy/internal/domain/model"
	"github.com/lambda-go-identidy/internal/infrastructure/config"
	
	 lambdaRouter "github.com/lambda-go-identidy/internal/infrastructure/adapter/lambda"	
	"github.com/lambda-go-identidy/internal/infrastructure/server"	

	go_core_otel_trace 	 "github.com/eliezerraj/go-core/v2/otel/trace"
	go_core_aws_dynamoDB "github.com/eliezerraj/go-core/v2/aws/dynamoDB"
	go_core_aws_s3		"github.com/eliezerraj/go-core/v2/aws/s3"

	// traces
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/contrib/propagators/aws/xray"
	
	"github.com/aws/aws-lambda-go/lambda" //enable this line for run in AWS
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda" //enable this line for run in AWS
	// ---------------------------  use it for a mock local ---------------------------
	//"encoding/json"  
	//"github.com/aws/aws-lambda-go/events" 
	// ---------------------------  use it for a mock local ---------------------------	
)

// Global variables
type AppContext struct {
	Logger           zerolog.Logger
	Server           *model.AppServer
	DynamoDB         *go_core_aws_dynamoDB.DatabaseDynamoDB
	TracerProvider   *go_core_otel_trace.TracerProvider
}

// Global logger for init and main entry point only
var initLogger zerolog.Logger

// init sets up global logger for startup
func init(){
	// Load application info
	application := config.GetApplicationInfo()
	
	// Log setup	
	writers := []io.Writer{os.Stdout}

	if application.StdOutLogGroup {
		file, err := os.OpenFile(application.LogGroup, 
								os.O_APPEND|os.O_CREATE|os.O_WRONLY, 
								0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: failed to open log file '%s': %v\n", application.LogGroup, err)
		} else {
			writers = append(writers, file)
		}
	} 
	multiWriter := io.MultiWriter(writers...)

	// log level
	switch application.LogLevel {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "warning": 
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error": 
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// prepare log
	initLogger = zerolog.New(multiWriter).
						With().
						Timestamp().
						Str("component", application.Name).
						Logger().
						Hook(log.TraceHook{}) // hook the app shared log
}

// setupAppContext initializes all application dependencies
func setupAppContext(ctx context.Context) (*AppContext, error) {
	logger := initLogger.With().
			Str("package", "main").
			Logger()

	// Load all configurations with proper error handling
	configLoader := config.NewConfigLoader(&initLogger)
	
	allConfigs, err := configLoader.LoadAll()
	if err != nil {
		return nil, fmt.Errorf("configuration loading FAILED: %w", err)
	}

	// Build AppServer
	appServer := &model.AppServer{
		Application:    allConfigs.Application,
		AwsService:     allConfigs.AwsService,
		EnvTrace:       allConfigs.OtelTrace,
	}

	// Setup OTEL tracer if enabled
	var tracerProvider *go_core_otel_trace.TracerProvider
	if appServer.Application.OtelTraces {
		tracerProvider = setupTracerProvider(ctx, appServer, &logger)
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(appServer.AwsService.AwsRegion))
	if err != nil {
		return nil, fmt.Errorf("configuration awsCfg: %w", err)
	}

	// Open prepare database
	dynamoDB, err := go_core_aws_dynamoDB.NewDatabaseDynamo(&awsCfg,
															&logger)
	if err != nil {
		return nil, fmt.Errorf("configuration dynamoDB: %w", err)
	}

	// Load application keys
	bucketS3, err := go_core_aws_s3.NewAwsBucketS3(	&awsCfg,
										      		&logger)
	if err != nil {
		return nil, fmt.Errorf("configuration s3: %w", err)
	}

	// Load the private key
	rsaKey := model.RsaKey{}
	privateKey, err := bucketS3.GetObject( ctx, 
											appServer.AwsService.BucketNameRSAKey,
											appServer.AwsService.FilePathRSA,
											appServer.AwsService.FileNameRSAPrivKey )
	if err != nil{
		return nil, fmt.Errorf("configuration get priv keys from s3: %w", err)
	}

	rsaPrivate, err := certificate.ParsePemToRSAPriv(privateKey,
													 &logger)
	if err != nil{
		return nil, fmt.Errorf("configuration parse priv keys to pem: %w", err)
	}

	// Load the private key
	publicKey, err := bucketS3.GetObject(ctx, 
										 appServer.AwsService.BucketNameRSAKey,
										 appServer.AwsService.FilePathRSA,
										 appServer.AwsService.FileNameRSAPubKey)
	if err != nil{
		return nil, fmt.Errorf("configuration get pub keys from s3: %w", err)
	}

	rsaPublic, err := certificate.ParsePemToRSAPub(publicKey,
												   &logger)
	if err != nil{
		return nil, fmt.Errorf("configuration parse pub keys to pem: %w", err)
	}

	// Load everything in rsa key model
	rsaKey.AuthenticationModel = appServer.Application.AuthenticationModel
	rsaKey.Kid = appServer.AwsService.Kid

	rsaKey.HsaKey 		= "SECRET-12345" // for simplicity 
	rsaKey.RsaPublic 	= rsaPublic
	rsaKey.RsaPrivate 	= rsaPrivate
	rsaKey.RsaPrivatePem = string(*privateKey)
	rsaKey.RsaPublicPem = string(*publicKey)
	appServer.RsaKey 	= &rsaKey	

	return &AppContext{
		Logger:         logger,
		Server:         appServer,
		DynamoDB:       dynamoDB,
		TracerProvider: tracerProvider,
	}, nil
}

// setupTracerProvider initializes OpenTelemetry tracer
func setupTracerProvider(ctx context.Context, appServer *model.AppServer, logger *zerolog.Logger) *go_core_otel_trace.TracerProvider {
	appInfoTrace := go_core_otel_trace.InfoTrace{
		Name:        appServer.Application.Name,
		Version:     appServer.Application.Version,
		ServiceType: "lambda-workload",
		Env:         appServer.Application.Env,
		Account:     appServer.Application.Account,
	}

	tracerProvider := go_core_otel_trace.NewTracerProvider(	ctx,
															*appServer.EnvTrace,
															appInfoTrace,
															logger)

	otel.SetTextMapPropagator(
    	propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{}, // W3C
			xray.Propagator{},          // AWS
			propagation.Baggage{},
    	),
	)
	otel.SetTracerProvider(tracerProvider.TracerProvider)

	return tracerProvider
}

// About main
func main (){
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize all dependencies
	appCtx, err := setupAppContext(ctx)
	if err != nil {
		initLogger.Fatal().
			Err(err).
			Msg("FAILED to initialize application context")
	}

	appCtx.Logger.Info().
		Msgf("STARTING workload version: %s", appCtx.Server.Application.Version)

	appCtx.Logger.Info().
		Interface("server", appCtx.Server).
		Send()
	
	// Cancel everything
	// Setup graceful shutdown and cleanup
	defer func() {
		appCtx.Logger.Info().
			Msg("Shutting down application")

		// Shutdown tracer provider
		if appCtx.TracerProvider != nil && appCtx.TracerProvider.TracerProvider != nil {
			if err := appCtx.TracerProvider.TracerProvider.Shutdown(ctx); err != nil {
				appCtx.Logger.Error().
					Ctx(ctx).
					Err(err).
					Msg("Error shutting down tracer provider")
			}
		}

		// Cancel context
		cancel()

		appCtx.Logger.Info().
			Msgf("workload ** %s ** shutdown completed SUCCESSFULLY", appCtx.Server.Application.Name)
	}()

	// Wire 
	workerService := service.NewWorkerService(appCtx.Server,
											appCtx.DynamoDB,
											&appCtx.Logger,
											appCtx.TracerProvider,)

	// Create Lambda Routers
	lambdaRouters := lambdaRouter.NewLambdaRouters(	appCtx.Server,
		  										   	workerService, 
										           	&appCtx.Logger,
													appCtx.TracerProvider)

	// Create Lambda Server											   
	lambdaServer := server.NewLambdaServer(lambdaRouters,
	 									   &appCtx.Logger)

	// ----------------------------------------------------------------------	
	/*mockEvent := events.APIGatewayProxyRequest{
		HTTPMethod: "POST",
		Resource:    "/signIn",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: `{"user": "admin-test-03", "password":"admin-test-03", "tier": "tier1"}`,
	}*/

	/*mockEvent := events.APIGatewayProxyRequest{
		HTTPMethod: "POST",
		Resource:    "/addScope",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: `{"user": "admin-test-03", "scope": ["test.read","test.write", "admin"] }`,
	}*/

	/*mockEvent := events.APIGatewayProxyRequest{
		HTTPMethod: "POST",
		Resource:    "/oauth_credential",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: `{"user": "admin-test-03", "password":"admin-test-03"}`,
	}*/

	/*mockEvent := events.APIGatewayProxyRequest{
		HTTPMethod: "GET",
		Resource:    "/.well-known/jwks.json",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}*/

	/*mockEvent := events.APIGatewayProxyRequest{
		HTTPMethod: "GET",
		Resource:    "/credential/{id}",
		RequestContext: events.APIGatewayProxyRequestContext{
			RequestID: "mock-request-id-12345",
		},
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		PathParameters: map[string]string{"id": "admin-test"},
	}*/

	/*mockEvent := events.APIGatewayProxyRequest{
		HTTPMethod: "GET",
		Resource:    "/info", 
		RequestContext: events.APIGatewayProxyRequestContext{
			RequestID: "mock-request-id-12345",
		},
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		PathParameters: map[string]string{"id": "admin-test"},
	}*/

	/*(mockEvent := events.APIGatewayProxyRequest{
		HTTPMethod: "POST",
		Resource:    "/tokenValidation", 
		RequestContext: events.APIGatewayProxyRequestContext{
			RequestID: "mock-request-id-12345",
		},
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: `{"token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...c_HniTL36o9nyZlc2KuLF9nKEZTQRPsg"}`,
	}*/

	/*res, err := lambdaServer.LambdaHandlerRequest(ctx, 
									 			mockEvent)
	if err != nil {
		appCtx.Logger.
			Error().
			Err(err).Send()
	}else {
		s, _ := json.MarshalIndent(res, "", "\t")
		fmt.Println(string(s))
	}*/
	// ----------------------------------------------------------------------	

	
	lambda.Start(otellambda.InstrumentHandler(lambdaServer.LambdaHandlerRequest))

}