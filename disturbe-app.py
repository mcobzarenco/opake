#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function, division
import argparse
import inspect
import json
import logging
import math
import re
import sys

import jsonschema
import redis
import riak
import nacl.utils
from nacl.encoding import URLSafeBase64Encoder as Base64Encoder
from nacl.public import PrivateKey, PublicKey, Box
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError

import bottle
from bottle import Bottle, route, template, static_file, request, view, \
    post, redirect, error, abort, HTTPError, PluginError


HTTP_BAD_REQUEST = 400
HTTP_INTERNAL_SERVER_ERROR = 500

DEFAULT_BIND = '127.0.0.1:8080'
DEFAULT_REDIS = '127.0.0.1:6379'
DEFAULT_RIAK = ['127.0.0.1:8087']
DEFAULT_WORKERS = 4

DEFAULT_COOKIE_PREFIX = 'cookie:'
DEFAULT_MINUTE_KEY_EXPIRY_SECS = 30

DIST_INDEX = 'dist.html'
DEBUG_INDEX = 'debug.html'

CURVE25519_KEY_BYTES = 32
SERVER_PUBLIC_KEY = 'kC_rSIO7t1ryhux1sn_LrtTrLyVZNd08BCXnSHQjgmA='
SERVER_PRIVATE_KEY = 'qc_YLigJ6Sm7loGoipLQx0KZfBPqOpmZfxcoHCRBPUI='


logging.basicConfig(format='%(asctime)s - %(levelname)s] %(message)s',
                    datefmt="%Y-%m-%d %H:%M:%S")
log = logging.getLogger()
log.setLevel(logging.DEBUG)


class InvalidClientRequest(Exception):
    """ Signals an invalid client request """


class MissingCookie(Exception):
    """ Signals a missing cookie in Redis """


class BottlePlugin(object):
    def __init__(self, plugin_name, keyword, obj):
        self._name = plugin_name
        self._obj = obj
        self._keyword = keyword
        self.api = 2

    def setup(self, app):
        ''' Make sure that other installed plugins don't affect the same
            keyword argument.'''
        for other in app.plugins:
            if hasattr(other, '_keyword') and other._keyword == self._keyword:
                raise PluginError("Found another plugin with " \
                                  "conflicting settings (non-unique keyword).")

    def apply(self, callback, route):
        # Override global configuration with route-specific values
        conf = route.app.config.get(self._name) or {}
        keyword = conf.get('keyword', self._keyword)

        # Test if the original callback accepts the required keyword
        # Ignore it if it does not need a handler to _obj
        args = inspect.getargspec(route.callback)[0]
        if keyword not in args:  return callback

        def wrapper(*args, **kwargs):
            kwargs[keyword] = self._obj
            rv = callback(*args, **kwargs)
            return rv
        # Replace the route callback with the wrapped one
        return wrapper


class RiakKey(str):
    """Workaround necessary because the Riak client
    idiotically doesn't support binary keys"""
    def encode(self, ignored):
        return self


def parse_and_verify_json(json_string, schema):
    try:
        parsed = json.loads(json_string)
        jsonschema.validate(parsed, schema)
        return parsed
    except jsonschema.ValidationError as e:
        raise InvalidClientRequest(e)
    except ValueError as e:
        raise InvalidClientRequest('Invalid JSON in the request.')


def expect_json_request(request, schema=None):
    schema = schema or {}
    if 'application/json' not in request.content_type:
        raise InvalidClientRequest(
            'content-type was "%s", it should be "application/json"' %
            request.content_type)
    return parse_and_verify_json(request._get_body_string(), schema)


def redis_set_cookie(redis_client, cookie, minute_key,
                     expiry_secs=DEFAULT_MINUTE_KEY_EXPIRY_SECS):
    cookie_with_prefix = DEFAULT_COOKIE_PREFIX + cookie
    redis_client.set(cookie_with_prefix, minute_key, ex=expiry_secs)


def redis_get_cookie(redis_client, cookie):
    cookie_with_prefix = DEFAULT_COOKIE_PREFIX + cookie
    minute_key = redis_client.getset(cookie_with_prefix, '')
    if minute_key is None:
        raise MissingCookie('No such cookie.')
    elif minute_key == '':
        redis_client.delete(cookie_with_prefix)
        raise MissingCookie('No such cookie.')
    redis_client.delete(cookie_with_prefix)
    return minute_key


#######                           Routes                               #######


BASE64_REGEX = r'^(?:[A-Za-z0-9\-_]{4})*(?:[A-Za-z0-9\-_]{2}==|[A-Za-z0-9\-_]{3}=)?$'

HELLO_PADDING_BYTES = 64
HELLO_PADDING_BASE64_BYTES = int(math.ceil(HELLO_PADDING_BYTES / 3.0)) * 4
HELLO_CLIENT_TRANSIENT_PKEY_FIELD = 'client_tpkey'
HELLO_PADDING_FIELD = 'padding'
HELLO_ZEROS_BOX_FIELD = 'zeros_box'

HELLO_SCHEMA = {
    'type': 'object',
    'properties': {
        HELLO_CLIENT_TRANSIENT_PKEY_FIELD: {
            'type': 'string',
            'pattern': BASE64_REGEX
        },
        HELLO_PADDING_FIELD: {
            'type': 'string',
            'pattern': BASE64_REGEX,
            'minLength': HELLO_PADDING_BASE64_BYTES,
            'maxLength': HELLO_PADDING_BASE64_BYTES
        },
        HELLO_ZEROS_BOX_FIELD: {
            'type': 'string',
            'pattern': BASE64_REGEX
        }
    },
    'additionalProperties': False,
    'required': [HELLO_CLIENT_TRANSIENT_PKEY_FIELD,
                 HELLO_PADDING_FIELD,
                 HELLO_ZEROS_BOX_FIELD]
}

COOKIE_SERVER_TRANSIENT_PKEY_FIELD = 'server_tpkey'
COOKIE_COOKIE_FIELD = 'cookie'
COOKIE_COOKIE_BASE64_BYTES = 140
COOKIE_COOKIE_BOX_FIELD = 'cookie_box'

COOKIE_SCHEMA = {
    'type': 'object',
    'properties': {
        COOKIE_COOKIE_BOX_FIELD: {
            'type': 'string',
            'pattern': BASE64_REGEX
        },
    },
    'additionalProperties': False,
    'required': [COOKIE_COOKIE_BOX_FIELD]
}

INITIATE_CLIENT_TRANSIENT_PKEY_FIELD = HELLO_CLIENT_TRANSIENT_PKEY_FIELD
INITIATE_COOKIE_FIELD = 'cookie'
INITIATE_COOKIE_BASE64_BYTES = COOKIE_COOKIE_BASE64_BYTES
INITIATE_VOUCH_FIELD = 'vouch'

INITIATE_SCHEMA = {
    'type': 'object',
    'properties': {
        INITIATE_CLIENT_TRANSIENT_PKEY_FIELD: {
            'type': 'string',
            'pattern': BASE64_REGEX
        },
        INITIATE_COOKIE_FIELD: {
            'type': 'string',
            'pattern': BASE64_REGEX,
            'minLength': INITIATE_COOKIE_BASE64_BYTES,
            'maxLength': INITIATE_COOKIE_BASE64_BYTES
        },
        INITIATE_VOUCH_FIELD: {
            'type': 'string',
            'pattern': BASE64_REGEX
        }
    },
    'additionalProperties': False,
    'required': [INITIATE_CLIENT_TRANSIENT_PKEY_FIELD,
                 INITIATE_COOKIE_FIELD,
                 INITIATE_VOUCH_FIELD]
}

VOUCH_CLIENT_PKEY_FIELD = 'client_pkey'
VOUCH_TRANSIENT_KEY_BOX_FIELD = 'transient_key_box'
VOUCH_DOMAIN_NAME_FIELD = 'domain_name'
VOUCH_MESSAGE_FIELD = 'message'

VOUCH_SCHEMA = {
    'type': 'object',
    'properties': {
        VOUCH_CLIENT_PKEY_FIELD: {
            'type': 'string',
            'pattern': BASE64_REGEX
        },
        VOUCH_TRANSIENT_KEY_BOX_FIELD: {
            'type': 'string',
            'pattern': BASE64_REGEX,
        },
        VOUCH_DOMAIN_NAME_FIELD: {
            'type': 'string'
        },
        VOUCH_MESSAGE_FIELD: {
            'type': 'object'
        }
    },
    'additionalProperties': False,
    'required': [VOUCH_CLIENT_PKEY_FIELD,
                 VOUCH_TRANSIENT_KEY_BOX_FIELD,
                 VOUCH_DOMAIN_NAME_FIELD,
                 VOUCH_MESSAGE_FIELD]
}


def open_box(nonceCipher, private_key, public_key, encoder=Base64Encoder):
    box = Box(private_key, public_key)
    return box.decrypt(str(nonceCipher), encoder=encoder)


def check_exact_length(value, value_name, expected_len):
        if len(value) != expected_len:
            raise InvalidClientRequest('%s should be exactly %d bytes long' %
                                       (value_name, expected_len))

@route('/')
@route('/static/<filepath:path>')
def server_static(filepath=DIST_INDEX):
    return static_file(filepath, root='static/')


@route('/debug')
def debug_version():
    return static_file(DEBUG_INDEX, root='static/')


@route('/handshake/hello', method='POST')
def handshake_hello(private_key, redis_client):
    try:
        request = expect_json_request(bottle.request, HELLO_SCHEMA)
        client_transient_pkey = PublicKey(
            str(request[HELLO_CLIENT_TRANSIENT_PKEY_FIELD]), Base64Encoder)

        zeros = open_box(request[HELLO_ZEROS_BOX_FIELD],
                         private_key, client_transient_pkey)
        if len(zeros) != HELLO_PADDING_BYTES:
            raise InvalidClientRequest(
                'zeros_box should contain exactly %d bytes of padding' %
                HELLO_PADDING_BYTES)

        transient_skey = PrivateKey.generate()
        cookie_plain = client_transient_pkey.encode() + \
                       transient_skey.encode()
        cookie_nonce = nacl.utils.random(SecretBox.NONCE_SIZE)
        symmetric_key = nacl.utils.random(SecretBox.KEY_SIZE)
        cookie_sbox = SecretBox(symmetric_key)
        cookie = cookie_sbox.encrypt(
            cookie_plain, cookie_nonce, encoder=Base64Encoder)
        redis_set_cookie(redis_client, cookie, symmetric_key)

        cookie_box = Box(private_key, client_transient_pkey)
        cookie_box_nonce = nacl.utils.random(Box.NONCE_SIZE)
        server_tpkey = transient_skey.public_key.encode(Base64Encoder)
        cookie_box_cipher = cookie_box.encrypt(json.dumps({
            COOKIE_SERVER_TRANSIENT_PKEY_FIELD: server_tpkey,
            COOKIE_COOKIE_FIELD: cookie
        }), cookie_box_nonce, encoder=Base64Encoder)

        response = {COOKIE_COOKIE_BOX_FIELD: cookie_box_cipher}
        jsonschema.validate(response, COOKIE_SCHEMA)
        return response
    except jsonschema.ValidationError:
        log.exception(e)
        bottle.response.status = HTTP_INTERNAL_SERVER_ERROR
        return {'error': 'A packet with an invalid JSON schema was generated.'}
    except InvalidClientRequest as e:
        log.exception(e)
        bottle.response.status = HTTP_BAD_REQUEST
        return {'error': str(e)}
    except CryptoError as e:
        log.exception(e)
        bottle.response.status = HTTP_BAD_REQUEST
        return {'error': 'bad encryption'}
    return {'error': ''}


@route('/handshake/initiate', method='POST')
def handshake_initiate(private_key, redis_client):
    try:
        request = expect_json_request(bottle.request, INITIATE_SCHEMA)

        symmetric_key = redis_get_cookie(
            redis_client, request[INITIATE_COOKIE_FIELD])
        cookie_sbox = SecretBox(symmetric_key)
        cookie = cookie_sbox.decrypt(
            str(request[INITIATE_COOKIE_FIELD]), encoder=Base64Encoder)

        if len(cookie) != 2 * CURVE25519_KEY_BYTES:
            bottle.response.status = HTTP_INTERNAL_SERVER_ERROR
            return {'error': 'An invalid cookie was sent to the client.'}
        client_transient_pkey = PublicKey(cookie[0:CURVE25519_KEY_BYTES])
        transient_skey = PrivateKey(cookie[CURVE25519_KEY_BYTES:])

        if request[INITIATE_CLIENT_TRANSIENT_PKEY_FIELD] != \
           client_transient_pkey.encode(Base64Encoder):
            raise InvalidClientRequest(
                'Initiate: non matching transient public keys.')

        vouch_json = open_box(request[INITIATE_VOUCH_FIELD],
                              transient_skey, client_transient_pkey)
        vouch = parse_and_verify_json(vouch_json, VOUCH_SCHEMA)

        client_pkey = PublicKey(
            str(vouch[VOUCH_CLIENT_PKEY_FIELD]), encoder=Base64Encoder)
        vouch_for_transient_pkey = open_box(
            vouch[VOUCH_TRANSIENT_KEY_BOX_FIELD], private_key, client_pkey)
        if vouch_for_transient_pkey != client_transient_pkey.encode():
            raise InvalidClientRequest(
                'Initiate: non matching transient public keys.')

        resp = 'I believe you are {} and you want {}'.format(
            client_pkey.encode(Base64Encoder), vouch[VOUCH_MESSAGE_FIELD])
        print(resp)
        response_nonce = nacl.utils.random(Box.NONCE_SIZE)
        response_box = Box(transient_skey, client_transient_pkey)
        response_box_cipher = response_box.encrypt(
            resp, response_nonce, encoder=Base64Encoder)
        return {'response': response_box_cipher}
    except jsonschema.ValidationError as e:
        log.exception(e)
        bottle.response.status = HTTP_BAD_REQUEST
        return {'error': str(e)}
    except InvalidClientRequest as e:
        log.exception(e)
        bottle.response.status = HTTP_BAD_REQUEST
        return {'error': str(e)}
    except MissingCookie as e:
        log.exception(e)
        bottle.response.status = HTTP_BAD_REQUEST
        return {'error': str(e)}
    except CryptoError as e:
        log.exception(e)
        bottle.response.status = HTTP_BAD_REQUEST
        return {'error': 'Bad encryption in handshake.'}
    return {'error': ''}


def parse_hostport(hostport):
    RX = r'^(?P<host>[A-Za-z0-9-_.]+):(?P<port>[0-9]+)$'
    match = re.match(RX, hostport)
    if not match:
        log.error('string "%s" is not of form host:port' % hostport)
        sys.exit(1)
    groups = match.groupdict()
    groups['port'] = int(groups['port'])
    return groups


if __name__ == '__main__' or True:
    parser = argparse.ArgumentParser(
        description='disturbe webapp')
    _arg = parser.add_argument
    _arg('--bind', type=str, default=DEFAULT_BIND, action='store',
         metavar='host:port', help='where to bind - host:port - default: %s'
         % DEFAULT_BIND)
    _arg('--redis', type=str, default=DEFAULT_REDIS, action='store',
         metavar='host:port', help='Redis endpoint used to store minute keys '
          'specified as host:port - default: %s' % DEFAULT_REDIS)
    _arg('--riak', type=str, default=DEFAULT_RIAK, action='store',
         metavar='host:port', nargs='*', help='what Riak nodes to use -'
         ' host:port - can be used multiple times - default: %s'
         % DEFAULT_RIAK)
    _arg('--debug', action='store_true', help='run in debug mode with '
         'restart on code change, template recompilation, error reporting '
         'and increased verbosity')
    _arg('--workers', type=int, action='store', default=DEFAULT_WORKERS,
         help='num of gunicorn workers - ignored in debug mode - default: %d'
         % DEFAULT_WORKERS, metavar='N')
    program_name, args = sys.argv[0], parser.parse_args()

    bind = parse_hostport(args.bind)
    app = bottle.app()
    app.install(BottlePlugin('redis_client', 'redis_client',
                             redis.StrictRedis(**parse_hostport(args.redis))))

    riak_nodes = []
    for hostport in args.riak:
        node = parse_hostport(hostport)
        riak_nodes.append({'host': node['host'], 'pb_port': node['port']})
    riak_client = riak.RiakClient(protocol='pbc', nodes=riak_nodes)
    app.install(BottlePlugin('riak_client', 'riak_client', riak_client))

    private_key = PrivateKey(SERVER_PRIVATE_KEY, Base64Encoder)
    app.install(BottlePlugin('private_key', 'private_key', private_key))

    if args.debug:
        bottle.run(app=app, host=bind['host'], port=bind['port'],
                   debug=True, quiet=False, reloader=True)
    else:
        sys.argv = [program_name]
        bottle.run(app=app, host=bind['host'], port=bind['port'],
                   debug=False, quiet=False, reloader=False,
                   server='gunicorn', workers=args.workers,
                   worker_class='gevent')
