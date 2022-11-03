# S3 API Frontend for Globus

This project provides a minimal implementation of the [Amazon Simple Storage Service (S3) REST API][s3-api], allowing a Globus collection to be accessed as an S3 bucket.

This is more of a proof-of-concept than something you should actually use.

  [s3-api]: https://docs.aws.amazon.com/AmazonS3/latest/API/


## Supported S3 API Actions

  * `HeadBucket`
  * `HeadObject`
  * `GetObject`


## Registration

You must [register a new Globus app][register-app] and obtain a client ID and secret, which are read from the `GLOBUS_CLIENT_ID` and `GLOBUS_CLIENT_SECRET` environment variables, respectively.

The redirect callback should be formatted like `https://example.com/?auth-callback`. For development, you can use `http://localhost:8000/?auth-callback`.

  [register-app]: https://docs.globus.org/api/auth/developer-guide/#register-app


## Authentication

Making a request to `https://example.com/endpoint-id/?auth` or `https://endpoint-id.example.com/?auth` will start the browser-based OAuth2 authentication flow to grant access to files on the endpoint.

Once authorized, the server returns a blob which is to be used as the AWS Access Key ID. The AWS Access Key Secret can be any value; it is used for signing the S3 API requests, but those signatures are not checked.

The blob is an opaque, encrypted structure that contains the Globus access tokens needed to interact with the endpoint. The encryption key is not persisted; restart the service will effectively invalidate previous credentials.

The server never deliberately holds onto access tokens. Currently, there is no way for the client to refresh tokens.


## Example

Run the server in development mode with:

    export GLOBUS_CLIENT_ID=<your client ID>
    export GLOBUS_CLIENT_SECRET=<your client secret>
    python3 globus-s3-frontend.py

Proceed through the authorization flow for a particular collection, e.g., `http://localhost:8000/a3556905-3ec6-460c-b464-67cdccbd021c/?auth`.

    export AWS_ACCESS_KEY_ID=<result of above>
    export AWS_ACCESS_KEY_SECRET=bogus

Make a request to download a file from the collection using the [AWS CLI][aws-cli]:

    aws --endpoint http://localhost:8000 \
        s3 cp s3://a3556905-3ec6-460c-b464-67cdccbd021c/example.txt .

  [aws-cli]: https://aws.amazon.com/cli/
