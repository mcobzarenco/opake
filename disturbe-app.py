#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function, division

import argparse
import json
import re
import sys

import riak
import bottle
from bottle import Bottle, route, template, static_file, request, view, \
    post, redirect, error, abort


DEFAULT_BIND = '127.0.0.1:8080'
DEFAULT_RIAK = ['127.0.0.1:8087']
DEFAULT_WORKERS = 4

DISTURBE_HTML = 'disturbe.html'


@route('/')
@route('/<filepath:path>')
def server_static(filepath=DISTURBE_HTML):
    return static_file(filepath, root='static/')


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

    if args.debug:
        bottle.run(app=app, host=bind['host'], port=bind['port'],
                   debug=True, quiet=False, reloader=True)
    else:
        sys.argv = [program_name]
        # TODO: (marius) it hangs on forever, see:
        # https://jira.mongodb.org/browse/PYTHON-607
        # https://github.com/surfly/gevent/issues/349

        bottle.run(app=app, host=bind['host'], port=bind['port'],
                   debug=False, quiet=True, reloader=False,
                   server='gunicorn', workers=args.workers,
                   worker_class='gevent')
