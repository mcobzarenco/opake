#!/usr/bin/env python
from __future__ import print_function, division
import argparse
from hashlib import sha512
import json
import sys

import nacl.utils
from nacl.encoding import URLSafeBase64Encoder as Base64Encoder
from nacl.public import PrivateKey, PublicKey, Box
from nacl.secret import SecretBox

import scrypt


DEFAULT_PASSWD = 'anaaremere'
DEFAULT_EMAIL = 'test@test.io'

SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_BUFLEN = 32


# def log_stdout(msg=''):
#     sys.stdout.write(msg, file=sys.stdout)


def log_stderr(msg=''):
    print(msg, file=sys.stderr)


def log_keyvalue(key, value, file=sys.stderr):
    print('{0:<26}: {1:<50}'.format(key, value), file=file)


def credentials_to_secret_key(passwd, email):
    passwd_hash = sha512(passwd).digest()
    scrypt_hash = scrypt.hash(
        passwd_hash, email, N=SCRYPT_N, r=SCRYPT_R,
        p=SCRYPT_P, buflen=SCRYPT_BUFLEN)
    return PrivateKey(scrypt_hash)


def encrypt(sender_skey, recipient_pkey, message):
    transient_skey = PrivateKey.generate()
    nonce_headers = nacl.utils.random(Box.NONCE_SIZE)
    symmetric_key = nacl.utils.random(SecretBox.KEY_SIZE)

    sender_box = Box(sender_skey, recipient_pkey)
    transient_box = Box(transient_skey, recipient_pkey)
    headers = {
        # Use a different nonce:
        'symmetric_key': sender_box.encrypt(
            symmetric_key, nonce_headers, Base64Encoder).ciphertext,
        'sender': sender_skey.public_key.encode(Base64Encoder),
    }
    headers_enc = transient_box.encrypt(
        json.dumps(headers), nonce_headers, Base64Encoder)

    secret_box = SecretBox(symmetric_key)
    body_nonce = nacl.utils.random(SecretBox.NONCE_SIZE)
    message_enc = secret_box.encrypt(
        message, body_nonce, encoder=Base64Encoder)
    return {
        'public_key': transient_skey.public_key.encode(Base64Encoder),
        'headers_nonce': Base64Encoder.encode(nonce_headers),
        'headers': headers_enc.ciphertext,
        'body_nonce': Base64Encoder.encode(body_nonce),
        'body': message_enc.ciphertext
    }


def decrypt(private_key, cipher_json):
    b64decode_str = lambda s: str(b64decode(str(s)))
    cipher = json.loads(cipher_json)
    for k, v in cipher.iteritems():
        cipher[k] = str(v)

    headers_enc = cipher['headers']
    headers_nonce = Base64Encoder.decode(cipher['headers_nonce'])
    transient_pkey = PublicKey(cipher['public_key'], Base64Encoder)
    headers_box = Box(private_key, transient_pkey)
    headers_json = headers_box.decrypt(
        headers_enc, headers_nonce, Base64Encoder)

    headers = json.loads(headers_json)
    log_stderr(headers)
    sender_pkey = PublicKey(str(headers['sender']), Base64Encoder)
    receiver_box = Box(private_key, sender_pkey)
    symmetric_key = receiver_box.decrypt(
        str(headers['symmetric_key']), headers_nonce, Base64Encoder)

    body = Base64Encoder.decode(cipher['body'])
    body_nonce = Base64Encoder.decode(cipher['body_nonce'])
    secret_box = SecretBox(symmetric_key)
    message = secret_box.decrypt(body, body_nonce)

    return {'sender': sender_pkey,
            'message': message}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=
        """Encrypts files for a list of curve25519 public keys.
        The private key is derived with scrypt from a password/email pair.""")
    _arg = parser.add_argument
    _arg('--email', type=str, action='store', metavar='EMAIL',
         default=DEFAULT_EMAIL, help='Email address (default=%s for demo)' %
         DEFAULT_EMAIL)
    _arg('--passwd', type=str, action='store', metavar='PASSWD',
         default=DEFAULT_PASSWD, help='Password (default=%s for demo)' %
         DEFAULT_PASSWD)
    _arg('-d', action='store_true', help='decrypt the file')
    _arg('-e', type=str, action='store', nargs='+',
         help='encrypt the file for a curve25519 public key (base64)')
    _arg('-f', type=str, action='store', metavar='FILE', default=None,
         help='File to encrypt/decrypt. If not specified stdin is used')
    args = parser.parse_args()

    user_skey = credentials_to_secret_key(args.email, args.passwd)
    log_keyvalue('Email', args.email)
    log_keyvalue('Password', args.passwd)
    log_keyvalue('Public Key', user_skey.public_key.encode(Base64Encoder))

    if args.e is not None:
        print(args.e)
        recipient_pkeys = (PublicKey(key, Base64Encoder)
                           for key in (args.e or []))
        stream = sys.stdin if args.f is None else open(args.f, 'rb')
        log_stderr('\n*** Message ***')
        message = stream.read()
        log_keyvalue('Length message (bytes)', len(message))

        for i, recipient_pkey in enumerate(recipient_pkeys):
            log_keyvalue("Recipient %d (public key)" % (i + 1),
                         recipient_pkey.encode(Base64Encoder))
            enc = encrypt(user_skey, recipient_pkey, message)
            sys.stdout.write(json.dumps(enc) + '\n')

    if args.d:
        stream = sys.stdin if args.f is None else open(args.f, 'rb')
        log_stderr('\n*** Message ***')
        message = stream.read()

        plain = decrypt(user_skey, message)
        log_stderr()
        log_keyvalue('Sender (public key)',
                     plain['sender'].encode(Base64Encoder))
        sys.stdout.write(plain['message'])
