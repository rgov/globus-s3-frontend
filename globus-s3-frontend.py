#!/usr/bin/env python3
'''
S3 API Frontend for Globus

Provides a minimal implementation of the Amazon Simple Storage Service (S3)
REST API, allowing a Globus collection to be accessed as an S3 bucket.
'''

import argparse
import json
import logging
import os
import re
import sys
import time
import urllib.parse

import cryptography.fernet
import fastapi
import globus_sdk
import httpx

from typing import Union


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('globus-s3')


def make_url_port_explicit(parsed_url: urllib.parse.ParseResult):
    if parsed_url.port is None:
        port = {'http': 80, 'https': 443}[parsed_url.scheme]
        parsed_url = parsed_url._replace(netloc=f'{parsed_url.netloc}:{port}')
    return parsed_url


# Parse command line arguments
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--base-url',
                    help='Base URL for the S3 API server',
                    default='http://localhost:8000')
parser.add_argument('--client-id',
                    help='Globus Auth application client ID',
                    default=os.getenv('GLOBUS_CLIENT_ID',
                                      '7e67f787-15aa-4db1-a881-a3dc29cc6609'))
args = parser.parse_args()


# Parse the base URL
args.base_url = urllib.parse.urlparse(args.base_url)
args.base_url = make_url_port_explicit(args.base_url)

if args.base_url.scheme not in ('http', 'https'):
    print('Base URL must begin with https://', file=sys.stderr)
    exit(1)


# Check for the Globus Auth application client secret, which we only accept from
# the environment due to security concerns. Remove it from the environment so
# subprocesses cannot read it.
args.client_secret = os.getenv('GLOBUS_CLIENT_SECRET')
del os.environ['GLOBUS_CLIENT_SECRET']
if not args.client_secret:
    print('Missing GLOBUS_CLIENT_SECRET environment variable', file=sys.stderr)
    exit(1)


# Use symmetric encryption for protecting tokens. They will not be reusable
# across restarts of the service.
fernet = cryptography.fernet.Fernet(cryptography.fernet.Fernet.generate_key())


api = fastapi.FastAPI()


# FastAPI dependency helper for decrypting tokens
def need_tokens(authorization: Union[str, None] = fastapi.Header(default=None),
                authz_query: Union[str, None] =
                    fastapi.Query(default=None, alias='X-Amz-Credential')):

    # Parse the AWS authorization header
    credential = None
    if authorization is not None:
        m = re.search(r'(?:^|\s)Credential=([^/]+)', authorization)
        if m is not None:
            credential = m[1]
    elif authz_query is not None:
        # Fall back to query parameter if Authorization header is missing
        credential = authz_query

    # Decrypt and deserialize the tokens
    tokens = {}
    try:
        tokens = json.loads(fernet.decrypt((credential or '').encode()))
    except cryptography.fernet.InvalidToken:
        logger.exception('Could not decrypt tokens')
        pass

    return tokens


# FastAPI dependency helper for figuring out what endpoint we're talking about
def need_endpoint(object: str,
                  request: fastapi.Request,
                  host: Union[str, None] = fastapi.Header(default=None)):

    # Figure out what endpoint we are trying to access. See
    # https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html
    m = re.match(rf'^(.*)\.{re.escape(args.base_url.netloc)}$',
                 make_url_port_explicit(request.url).netloc)
    if m is not None:
        endpoint = m[1]  # subdomain
    elif host == args.base_url.netloc or host == args.base_url.hostname:
        endpoint, _, object = object.partition('/')  # first path component
    else:
        # Note: We don't support the endpoint name in the Host header, because
        # the endpoint is a UUID and not a FQDN.
        raise fastapi.HTTPException(status_code=400,
                                    detail='Unexpected Host header value')

    return {'endpoint': endpoint, 'object': object}


def start_auth(endpoint: str):
    logger.info(f'Starting authorization flow for endpoint {endpoint}')    

    # Create the Auth API client and start the OAuth flow
    client = globus_sdk.ConfidentialAppAuthClient(
        args.client_id,
        args.client_secret,
    )
    client.oauth2_start_flow(
        redirect_uri=urllib.parse.urlunparse(args.base_url._replace(
            path='/',
            query='auth-callback'
        )),
        requested_scopes=[
            globus_sdk.scopes.GCSCollectionScopeBuilder(endpoint).https,
            globus_sdk.TransferClient.scopes.all,
        ]
    )

    return fastapi.responses.RedirectResponse(client.oauth2_get_authorize_url())



def complete_auth(request: fastapi.Request):
    # Create the Auth API client again
    client = globus_sdk.ConfidentialAppAuthClient(
        args.client_id,
        args.client_secret,
    )
    client.oauth2_start_flow(
        redirect_uri=urllib.parse.urlunparse(args.base_url._replace(
            path='/',
            query='auth-callback'
        ))
    )  # required even though we are mid-flow

    # Exchange the authorization code for a token 
    code = request.query_params.get('code')
    if not code:
        raise fastapi.HTTPException(status_code=400)

    tokens = client.oauth2_exchange_code_for_tokens(code)
    tokens = tokens.by_resource_server  # much easier to work with

    # Encrypt the tokens into an opaque blob that the client can pass back to us
    # when it makes requests for objects. Already Base64 encoded.
    encrypted = fernet.encrypt(json.dumps(tokens).encode())

    # Return the access token as an AWS Access Key ID
    return fastapi.Response(content=encrypted)


@api.get('/{object:path}')
async def get(request: fastapi.Request,
              background_tasks: fastapi.background.BackgroundTasks,
              tokens: dict = fastapi.Depends(need_tokens),
              endpoint: dict = fastapi.Depends(need_endpoint)):

    # Unpack values from our dependencies
    endpoint, object = endpoint['endpoint'], endpoint['object']


    # FastAPI does not do routing based on query parameters, so we need to do it
    # ourselves based on the parameters provided.

    # These are custom actions to perform OAuth authentication and return a
    # token to the client.
    if 'auth' in request.query_params:
        return start_auth(endpoint)
    elif 'auth-callback' in request.query_params:
        return complete_auth(request)

    # All other types of requests must carry auth tokens. We don't validate
    # them, we just pass them through to Globus.
    if not tokens:
        raise fastapi.HTTPException(status_code=401)


    # This is taken to be a GetObject request
    return await get_object(request, endpoint, object, tokens, background_tasks)


async def get_object(request: fastapi.Request,
                     endpoint: str, object: str, tokens: dict,
                     background_tasks: fastapi.background.BackgroundTasks):

    # Look up the HTTPS URL for this endpoint. This also tests that our tokens
    # are likely valid.
    endpoint_url = get_endpoint_url(endpoint, tokens)

    # Relay the request to the HTTPS server
    return await relay_request(request, endpoint, object, endpoint_url, tokens,
                               background_tasks)


@api.head('/{object:path}')
async def head(request: fastapi.Request,
               background_tasks: fastapi.background.BackgroundTasks,
               tokens: dict = fastapi.Depends(need_tokens),
               endpoint: dict = fastapi.Depends(need_endpoint)):

    # Unpack values from our dependencies
    endpoint, object = endpoint['endpoint'], endpoint['object']

    # Ensure we have tokens to pass through to the Globus APIs
    if not tokens:
        raise fastapi.HTTPException(status_code=401)


    # Look up the HTTPS URL for this endpoint. This also tests that our tokens
    # are likely valid.
    endpoint_url = get_endpoint_url(endpoint, tokens)


    # If we got an endpoint with no object path, this is a HeadBucket request.
    # We've validated that we have access to the endpoint, so just return a
    # happy response.
    if object == '':
        return fastapi.Response()


    # From here forward we take this as a HeadObject request


    # Relay the request to the HTTPS server
    return await relay_request(request, endpoint, object, endpoint_url, tokens,
                               background_tasks)


def get_endpoint_url(endpoint: str, tokens: dict):
    # Use the Transfer API to get the HTTPS URL for the endpoint
    transfer_client = globus_sdk.TransferClient(
        authorizer=globus_sdk.AccessTokenAuthorizer(
            tokens['transfer.api.globus.org']['access_token'])
    )

    return transfer_client.get_endpoint(endpoint)['https_server']


async def relay_request(request: fastapi.Request,
                        endpoint: str, object: str, endpoint_url: str,
                        tokens: dict,
                        background_tasks: fastapi.background.BackgroundTasks):

    # Replace the inbound Authorization header with the HTTPS access token
    headers = [
        (key, value) for key, value in request.headers.raw
        if key.lower() not in set([b'authorization', b'host'])
    ]
    headers.append((
        b'authorization',
        b'Bearer ' + tokens[endpoint]['access_token'].encode()
    ))

    # Forward the request to the remote endpoint, and pass the response back.
    # See https://github.com/tiangolo/fastapi/issues/1788
    client = httpx.AsyncClient(base_url=endpoint_url)
    request = client.build_request(
        request.method,
        f'/{object}',
        headers=headers,
        content=await request.body()
    )
    response = await client.send(request, stream=True)
    background_tasks.add_task(response.aclose)  # close when finished

    # The S3 API requires a Last-Modified header, which Globus doesn't provide.
    # Pretend it was just updated.
    headers = response.headers
    headers['Last-Modified'] = \
        time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())

    return fastapi.responses.StreamingResponse(
        response.aiter_raw(),
        status_code=response.status_code,
        headers=headers
    )


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(api, host='0.0.0.0', port=8000)
