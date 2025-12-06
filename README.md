# lambda-go-identidy
lambda-go-identidy


## Manually compile the function

      New Version
      GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bootstrap ./cmd/main.go
      zip main.zip bootstrap

    aws lambda update-function-code \
        --region us-east-2 \
        --function-name go-oauth-apigw-authorizer-lambda \
        --zip-file fileb:///mnt/c/Eliezer/workspace/github.com/go-oauth-apigw-authorizer-lambda/main.zip \
        --publish
