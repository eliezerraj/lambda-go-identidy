# Define environment variables
export VERSION=1.0
export ACCOUNT=aws:localhost
export APP_NAME=lambda-go-identidy.localhost
export ENV=dev

export AUTHENTICATION_MODEL=RSA
export REGION=us-east-2
export SECRET_NAME=SECRET-12345
export DYNAMO_TABLE_NAME=user_login_2
export KID=auth-key:server-public.key

export RSA_BUCKET_NAME_KEY=docktech-eliezer-908671954593-truststore-mtls
export RSA_FILE_PATH=/
export RSA_PRIV_FILE_KEY=server-private.key
export RSA_PUB_FILE_KEY=server-public.key
export CRL_FILE_KEY=crl-ca.crl

export LOG_LEVEL=info #info, error, warning
export OTEL_EXPORTER_OTLP_ENDPOINT = localhost:4317

export OTEL_METRICS=true
export OTEL_STDOUT_TRACER=false
export OTEL_TRACES=true

export OTEL_LOGS=true
export OTEL_STDOUT_LOG_GROUP=true
export LOG_GROUP=/mnt/c/Eliezer/log/lambda-go-identidy.log
# Default target
all: run

# Show environment variables
env:
	@echo "Current Environment Variables:"
	@echo "VERSION=$(VERSION)"
	@echo "APP_NAME=$(APP_NAME)"
	@echo "MODEL_SIGN=$(MODEL_SIGN)"

# Run the Go application
run:
	@echo "Running application with environment variables..."
	@go run main.go

# Clean build cache
clean:
	@echo "Cleaning build cache..."
	@go clean

.PHONY: all env run clean