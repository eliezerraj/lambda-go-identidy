# lambda-go-identidy

    lambda-go-identidy

## Manually compile the function

    New Version
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bootstrap ./cmd/main.go
    zip main.zip bootstrap collector.yaml

    Check file
    unzip -l main.zip

    aws lambda update-function-code \
        --region us-east-2 \
        --function-name lambda-go-identidy \
        --zip-file fileb:///mnt/c/Eliezer/workspace/github.com/lambda-go-identidy/main.zip \
        --publish
