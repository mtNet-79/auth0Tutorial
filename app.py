from flask import Flask, request, abort
import json
from functools import wraps
from jose import jwt
from urllib.request import urlopen

AUTH0_DOMAIN = 'mtdev108.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'image'


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


def get_token_auth_header():

    auth_header = request.headers.get('Authorization', None)
    print(auth_header)
    if not auth_header:
        raise AuthError({
            'code': 'authorization_header_missing',
            'description': 'Authorization header is expected.'
        }, 401)

    auth_parts = auth_header.split(' ')
    print(auth_parts)

#     auth_header = request.headers['Authorization']
# # get the token
#     header_parts = auth_header.split(' ')

    if len(auth_parts) == 1:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Token not found.'
        }, 401)

    elif len(auth_parts) > 2:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must be bearer token.'
        }, 401)
    elif auth_parts[0].lower() != 'bearer':
        raise AuthError({
            'code': 'invalid'
        })

    return auth_parts[1]


def verify_decode_jwt(token):
    
    jsonurl = urlopen(f'https://mtdev108.us.auth0.com/.well-known/jwks.json')

    jwks = json.loads(jsonurl.read())
    print(f' $$ {jwks}')
    unverified_header = jwt.get_unverified_header(token)
    print(f'this is unverified header {unverified_header}')
    rsa_key = {}
    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )

            return payload
        except jwt.ExpiredSignatureError:
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            })

        except jwt.JWTClaimsError:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please, check the audience and issuer.'
            }, 401)
        except Exception:
            raise AuthError({
                'code': 'invalid_clamis',
                'description': 'Unable to parse authentication token.'
            }, 401)
    raise AuthError({
        'code': 'invalid_header',
        'description': 'Unable to find the appropriate key.'
    }, 400)


app = Flask(__name__)


def requires_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        jwt = get_token_auth_header()
        print(f'jwt is {jwt}')
        try:
            payload = verify_decode_jwt(jwt)
        except:
            abort(403)
        return f(payload, *args, **kwargs)
    return wrapper


@app.route('/headers')
@requires_auth
def headers(payload):

    print(payload)
    return 'Access Granted'
