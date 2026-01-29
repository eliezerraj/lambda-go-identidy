package config

import(
	"os"
	"github.com/rs/zerolog"

	"github.com/lambda-go-identidy/internal/domain/model"
)

var	logger = zerolog.New(os.Stdout).
					With().
					Str("component","lambda-go-identidy").
					Str("package","infrastructure.config").
					Timestamp().
					Logger()

// Load the Application configuration
func GetApplicationInfo() (model.Application) {
	logger.Info().
		Str("func","GetApplicationInfo").Send()

	var application model.Application

	if os.Getenv("VERSION") !=  "" {
		application.Version = os.Getenv("VERSION")
	}
	if os.Getenv("APP_NAME") !=  "" {
		application.Name = os.Getenv("APP_NAME")
	}
	if os.Getenv("ACCOUNT") !=  "" {	
		application.Account = os.Getenv("ACCOUNT")
	}
	if os.Getenv("ENV") !=  "" {	
		application.Env = os.Getenv("ENV")
	}
	if os.Getenv("AUTHENTICATION_MODEL") !=  "" {	
		application.AuthenticationModel = os.Getenv("AUTHENTICATION_MODEL")
	}

	if os.Getenv("OTEL_STDOUT_LOG_GROUP") ==  "true" {
		application.StdOutLogGroup = true
	} else {
		application.StdOutLogGroup = false
	}	
	if os.Getenv("LOG_GROUP") !=  "" {	
		application.LogGroup = os.Getenv("LOG_GROUP")
	}
	if os.Getenv("LOG_LEVEL") !=  "" {	
		application.LogLevel = os.Getenv("LOG_LEVEL")
	}

	if os.Getenv("OTEL_TRACES") ==  "true" {
		application.OtelTraces = true
	} else {
		application.OtelTraces = false
	}

	if os.Getenv("OTEL_LOGS") ==  "true" {
		application.OtelLogs = true
	} else {
		application.OtelLogs = false
	}
	if os.Getenv("OTEL_METRICS") ==  "true" {
		application.OtelMetrics = true
	} else {
		application.OtelMetrics = false
	}
	
	return application
}
