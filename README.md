## lambda-go-identidy

   This is workload for POC purpose such as load stress test, gitaction, etc.

   The main purpose is handle all identidy lifecycle (create a user, refresh token, token validation, login and etc)

   There are 2 methods of JWT signature
   RSA (private key)
   HSA (symetric key)

## Integration

   This is workload requires a dynamo table (for the user data and scopes ) and a S3 bucket (private/public key)

## Enviroments

   For local test, create a AWS credentials and run the make file

    make

## Endpoints

    curl --location 'https://mydomain.com/identidy/info'
    curl --location 'https://mydomain.com/identidy/credential/admin-003'

    curl --location 'https://mydomain.com/identidy/oauth_credential' \
    --header 'Content-Type: application/json' \
    --data '{
        "user":"admin-003",
        "password":"admin-003"
    }'

    curl --location 'https://mydomain.com/identidy/refreshToken' \
    --data '{
        "token": "eyJhbGc....dbg"
    }'

    curl --location 'https://mydomain.com/identidy/tokenValidation' \
    --data '{
        "token": "eyJhbG...Psg"
    }'

    curl --location 'https://mydomain.com/identidy/signIn' \
    --header 'Content-Type: application/json' \
    --data '{
        "user":"admin-003",
        "password":"admin-003",
        "tier": "tier2",
        "api_access_key" : "API_ACCESS_KEY_ADMIN_003"
    }'

    curl --location 'https://mydomain.com/identidy/addScope' \
    --data '{
        "user": "admin-003",
        "scope": ["test.read","test.write", "admin"]
    }'

## Manually compile the function and update it (without run a ci/cd)

Compile

    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bootstrap ./cmd/main.go
    zip main.zip bootstrap collector.yaml

Check file

    unzip -l main.zip

Update function

    aws lambda update-function-code \
        --region us-east-2 \
        --function-name lambda-go-identidy \
        --zip-file fileb:///mnt/c/Eliezer/workspace/github.com/lambda-go-identidy/main.zip \
        --publish
