package main

import(
	"fmt"
	"os"
	"io"
	"context"

	"github.com/rs/zerolog"
	"github.com/aws/aws-lambda-go/lambda" //enable this line for run in AWS
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
	go_core_aws_s3 "github.com/eliezerraj/go-core/v2/aws/s3"

	// traces
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-sdk-go-v2/otelaws"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda"
	"go.opentelemetry.io/contrib/propagators/aws/xray"
	// ---------------------------  use it for a mock local ---------------------------
	//"encoding/json"  
	//"github.com/aws/aws-lambda-go/events" 
	// ---------------------------  use it for a mock local ---------------------------	
)

// Global variables
var ( 
	appLogger 	zerolog.Logger
	logger		zerolog.Logger
	appServer	model.AppServer

	appInfoTrace 		go_core_otel_trace.InfoTrace
	appTracerProvider 	go_core_otel_trace.TracerProvider
	sdkTracerProvider 	*sdktrace.TracerProvider
)

// About init
func init(){
	// Load application info
	application := config.GetApplicationInfo()
	awsService 	:= config.GetAwsServiceEnv()

	appServer.Application = &application
	appServer.AwsService = &awsService

	// Log setup	
	writers := []io.Writer{os.Stdout}

	if	application.StdOutLogGroup {
		file, err := os.OpenFile(application.LogGroup, 
								os.O_APPEND|os.O_CREATE|os.O_WRONLY, 
								0644)
		if err != nil {
			panic(fmt.Sprintf("Failed to open log file: %v", err))
		}
		writers = append(writers, file)
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
	appLogger = zerolog.New(multiWriter).
						With().
						Timestamp().
						Str("component", application.Name).
						Logger().
						Hook(log.TraceHook{}) // hook the app shared log

	// set a logger
	logger = appLogger.With().
						Str("package", "main").
						Logger()


	// load configs					
	otelTrace 	:= config.GetOtelEnv()
	appServer.EnvTrace = &otelTrace	
}

// About main
func main (){
	logger.Info().
			Msgf("STARTING APP version: %s",appServer.Application.Version)
	logger.Info().
			Interface("appServer", appServer).Send()
			
	// create context and otel log provider
	ctx, cancel := context.WithCancel(context.Background())

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(appServer.AwsService.AwsRegion))
	if err != nil {
		logger.Fatal().
			   Err(err).Send()
		os.Exit(3)
	}

	if appServer.Application.OtelTraces {
		// Otel over aws services
		otelaws.AppendMiddlewares(&awsCfg.APIOptions)

		appInfoTrace.Name = appServer.Application.Name
		appInfoTrace.Version = appServer.Application.Version
		appInfoTrace.ServiceType = "lambda-workload"
		appInfoTrace.Env = appServer.Application.Env
		appInfoTrace.Account = appServer.Application.Account

		sdkTracerProvider = appTracerProvider.NewTracerProvider(ctx, 
																*appServer.EnvTrace, 
																appInfoTrace,
																&appLogger)

		otel.SetTextMapPropagator(
    		propagation.NewCompositeTextMapPropagator(
				propagation.TraceContext{}, // W3C
				xray.Propagator{},          // AWS
				propagation.Baggage{},
    		),
		)

		otel.SetTracerProvider(sdkTracerProvider)
		sdkTracerProvider.Tracer(appServer.Application.Name)
	}

	// Open prepare database
	dynamoDB, err := go_core_aws_dynamoDB.NewDatabaseDynamo(&awsCfg,
															&appLogger)
	if err != nil {
		logger.Fatal().
			   Err(err).Send()
		os.Exit(3)
	}

	// Load application keys
	bucketS3, err := go_core_aws_s3.NewAwsBucketS3(	&awsCfg,
										      		&appLogger)
	if err != nil {
		logger.Fatal().
			   Err(err).Send()
		os.Exit(3)
	}

	// Load the private key
	rsaKey := model.RsaKey{}
	privateKey, err := bucketS3.GetObject( ctx, 
											appServer.AwsService.BucketNameRSAKey,
											appServer.AwsService.FilePathRSA,
											appServer.AwsService.FileNameRSAPrivKey )
	if err != nil{
		logger.Fatal().
			   Err(err).Send()
		os.Exit(3)
	}

	rsaPrivate, err := certificate.ParsePemToRSAPriv(privateKey,
													 &appLogger)
	if err != nil{
		logger.Fatal().
			   Err(err).Send()
		os.Exit(3)
	}

	// Load the private key
	publicKey, err := bucketS3.GetObject( ctx, 
											appServer.AwsService.BucketNameRSAKey,
											appServer.AwsService.FilePathRSA,
											appServer.AwsService.FileNameRSAPubKey )
	if err != nil{
		logger.Fatal().
			   Err(err).Send()
		os.Exit(3)
	}

	rsaPublic, err := certificate.ParsePemToRSAPub(publicKey,
												   &appLogger)
	if err != nil{
		logger.Fatal().
			   Err(err).Send()
		os.Exit(3)
	}

	// Load everything in rsa key model
	rsaKey.HsaKey 		= "SECRET-12345" // for simplicity 
	rsaKey.RsaPublic 	= rsaPublic
	rsaKey.RsaPrivate 	= rsaPrivate
	rsaKey.RsaPrivatePem = string(*privateKey)
	rsaKey.RsaPublicPem = string(*publicKey)
	appServer.RsaKey 	= &rsaKey	

	// Wire 
	workerService := service.NewWorkerService(&appServer,
											  dynamoDB,
											  &appLogger)
	
	// Cancel everything
	defer func() {
		// cancel log provider
		if sdkTracerProvider != nil {
			err := sdkTracerProvider.Shutdown(ctx)
			if err != nil{
				logger.Error().
				       Ctx(ctx).
					   Err(err). 
					   Msg("Erro to shutdown tracer provider")
			}
		}
		
		// cancel context
		cancel()

		logger.Info().
			   Ctx(ctx).
			   Msgf("App %s Finalized SUCCESSFULL !!!", appServer.Application.Name)
	}()

	// Create Lambda Routers
	lambdaRouters := lambdaRouter.NewLambdaRouters(&appServer,
		  										   workerService, 
										           &appLogger)

	// Create Lambda Server											   
	lambdaServer := server.NewLambdaServer(lambdaRouters,
	 									   &appLogger)

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
		Resource:    "/wellKnown/1",
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
	
	/*res, err := lambdaServer.LambdaHandlerRequest(ctx, 
									 			 mockEvent)
	if err != nil {
		logger.Error().
			   Err(err).Send()
	}else {
		s, _ := json.MarshalIndent(res, "", "\t")
		fmt.Println(string(s))
	}*/
	// ----------------------------------------------------------------------	

	lambda.Start(
		otellambda.InstrumentHandler(lambdaServer.LambdaHandlerRequest),
	)
}