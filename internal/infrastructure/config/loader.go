package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog"

	"github.com/lambda-go-identidy/internal/domain/model"
	go_core_otel_trace "github.com/eliezerraj/go-core/v2/otel/trace"
)

var (
	envOnce sync.Once
	envLoaded bool
)

// AllConfig aggregates all configuration
type AllConfig struct {
	Application *model.Application
	AwsService  *model.AwsService
	OtelTrace   *go_core_otel_trace.EnvTrace
}

// ConfigLoader handles loading and validating all configurations
type ConfigLoader struct {
	logger *zerolog.Logger
}

// NewConfigLoader creates a new config loader and loads .env once
func NewConfigLoader(logger *zerolog.Logger) *ConfigLoader {
	envOnce.Do(func() {
		envLoaded = true
	})

	return &ConfigLoader{
		logger: logger,
	}
}

// LoadAll loads and validates all configurations
func (cl *ConfigLoader) LoadAll() (*AllConfig, error) {
	cl.logger.Info().Msg("Loading all configurations")

	app, err := cl.loadApplication()
	if err != nil {
		return nil, fmt.Errorf("FAILED to load application config: %w", err)
	}

	awsService, err := cl.loadAws()
	if err != nil {
		return nil, fmt.Errorf("FAILED to load aws config: %w", err)
	}

	otel, err := cl.loadOtel()
	if err != nil {
		return nil, fmt.Errorf("FAILED to load OTEL config: %w", err)
	}

	return &AllConfig{
		Application:	app,
		AwsService:		awsService,
		OtelTrace:		otel,
	}, nil
}

// loadApplication loads application configuration
func (cl *ConfigLoader) loadApplication() (*model.Application, error) {
	cl.logger.Debug().Msg("Loading application configuration")

	app := &model.Application{
		Version:       getEnvString("VERSION", "unknown"),
		Name:          getEnvString("APP_NAME", "go-cart"),
		Account:       getEnvString("ACCOUNT", ""),
		Env:           getEnvString("ENV", "dev"),
		StdOutLogGroup: getEnvBool("OTEL_STDOUT_LOG_GROUP", false),
		LogGroup:      getEnvString("LOG_GROUP", ""),
		LogLevel:      getEnvString("LOG_LEVEL", "info"),
		OtelTraces:    getEnvBool("OTEL_TRACES", false),
		OtelLogs:      getEnvBool("OTEL_LOGS", false),
		OtelMetrics:   getEnvBool("OTEL_METRICS", false),
	}

	cl.logger.Info().
		Interface("application", app).
		Msg("Application configuration loaded SUCCESSFULLY")

	return app, nil
}

// loadDatabase loads database configuration
func (cl *ConfigLoader) loadAws() (*model.AwsService, error) {
	cl.logger.Debug().Msg("Loading aws configuration")

	awsService := &model.AwsService{
		AwsRegion: getEnvString("REGION", "us-east-2"),
		SecretName: getEnvString("SECRET_NAME", "default-secret"),
		DynamoTableName: getEnvString("DYNAMO_TABLE_NAME", "default-table"),
		Kid: getEnvString("KID", ""),
		BucketNameRSAKey: getEnvString("RSA_BUCKET_NAME_KEY", ""),
		FilePathRSA: getEnvString("RSA_FILE_PATH", ""),
		FileNameRSAPrivKey: getEnvString("RSA_PRIV_FILE_KEY", ""),
		FileNameRSAPubKey: getEnvString("RSA_PUB_FILE_KEY", ""),
		FileNameCrlKey: getEnvString("CRL_FILE_KEY", ""),
	}

	cl.logger.Info().
		Interface("awsService", awsService).
		Msg("Aws configuration loaded SUCCESSFULLY")

	return awsService, nil
}

// loadOtel loads OTEL configuration
func (cl *ConfigLoader) loadOtel() (*go_core_otel_trace.EnvTrace, error) {
	cl.logger.Debug().Msg("Loading OTEL configuration")

	otel := &go_core_otel_trace.EnvTrace{
		OtelExportEndpoint:      getEnvString("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317"),
		UseStdoutTracerExporter: getEnvBool("OTEL_STDOUT_TRACER", false),
		UseOtlpCollector:        getEnvBool("OTEL_COLLECTOR", true),
		TimeInterval:            1,
		TimeAliveIncrementer:    1,
		TotalHeapSizeUpperBound: 100,
		ThreadsActiveUpperBound: 10,
		CpuUsageUpperBound:      100,
		SampleAppPorts:          []string{},
		AWSCloudWatchLogGroup:   []string{},
	}

	if logGroup := os.Getenv("LOG_GROUP"); logGroup != "" {
		otel.AWSCloudWatchLogGroup = strings.Split(logGroup, ",")
	}

	cl.logger.Info().
		Interface("otel", otel).
		Msg("OTEL configuration loaded SUCCESSFULLY")

	return otel, nil
}

// Helper functions
// getEnvString retrieves environment variable as string with default
func getEnvString(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// getEnvBool retrieves environment variable as boolean with default
func getEnvBool(key string, defaultVal bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	return strings.ToLower(val) == "true"
}

// getEnvInt retrieves environment variable as integer with error handling
func getEnvInt(key string, defaultVal int) (int, error) {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal, nil
	}

	intVal, err := strconv.Atoi(val)
	if err != nil {
		return 0, fmt.Errorf("FAILED to parse %s as integer: %w", key, err)
	}

	return intVal, nil
}
