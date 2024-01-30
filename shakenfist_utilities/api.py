# gunicorn / flask / JWT centric helpers

import flask
import flask_restful
from flask_jwt_extended.exceptions import (
    JWTDecodeError, NoAuthorizationError, InvalidHeaderError, WrongTokenError,
    RevokedTokenError, FreshTokenRequired, CSRFError
)
from flask_jwt_extended import decode_token, get_jwt_identity, unset_jwt_cookies
import json
from jwt.exceptions import PyJWTError, DecodeError, ExpiredSignatureError
from shakenfist_utilities import logs
import sys
import traceback


LOG, _ = logs.setup(__name__)
TESTING = False


def error(status_code, message, suppress_traceback=False):
    global TESTING

    body = {
        'error': message,
        'status': status_code
    }

    _, _, tb = sys.exc_info()
    formatted_trace = traceback.format_exc()

    if TESTING and tb:
        body['traceback'] = formatted_trace

    resp = flask.Response(json.dumps(body), mimetype='application/json')
    resp.status_code = status_code

    if not suppress_traceback:
        LOG.info('Returning API error: %d, %s\n    %s'
                 % (status_code, message,
                    '\n    '.join(formatted_trace.split('\n'))))
    else:
        LOG.info('Returning API error: %d, %s (traceback suppressed by caller)'
                 % (status_code, message))

    return resp


def flask_get_post_body():
    j = {}
    try:
        j = flask.request.get_json(force=True)
    except Exception:
        if flask.request.data:
            try:
                j = json.loads(flask.request.data)
            except Exception:
                pass
    return j


def generic_wrapper(func):
    def wrapper(*args, **kwargs):
        try:
            j = flask_get_post_body()

            if j:
                for key in j:
                    if key == 'uuid':
                        destkey = 'passed_uuid'
                    else:
                        destkey = key
                    kwargs[destkey] = j[key]

            formatted_headers = []
            for header in flask.request.headers:
                formatted_headers.append(str(header))

            # Ensure key does not appear in logs
            kwargs_log = kwargs.copy()
            if 'key' in kwargs_log:
                kwargs_log['key'] = '*****'

            # Redact a password if any
            if 'password' in kwargs_log:
                kwargs_log['password'] = '*****'

            # Redact the JWT auth token in headers as well
            headers_log = dict(flask.request.headers)
            if 'Authorization' in headers_log:
                headers_log = 'Bearer *****'

            # Attempt to lookup the identity from JWT token. This doesn't use
            # the usual get_jwt_identity() because that requires that the
            # require_jwt() decorator has been run, and that is not the case
            # for all paths this wrapper covers. Its ok for there to be no
            # identity here, for example unprotected paths.
            identity = None
            try:
                auth = flask.request.headers.get('Authorization')
                if auth:
                    token = auth.split(' ')[1]
                    dt = decode_token(token)
                    identity = dt.get('identity')
            except Exception:
                pass

            log = LOG.with_fields({
                'request-id': flask.request.environ.get('FLASK_REQUEST_ID', 'none'),
                'identity': identity,
                'method': flask.request.method,
                'url': flask.request.url,
                'path': flask.request.path,
                'args': args,
                'kwargs': kwargs_log,
                'headers': headers_log
            })
            if flask.request.path == '/':
                # This is likely a load balancer health check
                log.debug('API request parsed')
            else:
                log.info('API request parsed')

            return func(*args, **kwargs)

        except TypeError as e:
            return error(400, str(e), suppress_traceback=False)

        except DecodeError:
            # Send a more informative message than 'Not enough segments'. If this
            # is a web browser, redirect them back to the root URL. Otherwise just
            # return a 401.
            if flask.request.headers.get('Accept', 'text/html').find('text/html') != -1:
                resp = flask.redirect('/', code=302)
                unset_jwt_cookies(resp)
                return resp
            return error(401, 'invalid JWT in Authorization header',
                         suppress_traceback=True)

        except ExpiredSignatureError as e:
            # The JWT looked valid, except it has expired. If this is a web
            # browser, redirect them back to the root URL. Otherwise just return
            # a 401.
            if flask.request.headers.get('Accept', 'text/html').find('text/html') != -1:
                resp = flask.redirect('/', code=302)
                unset_jwt_cookies(resp)
                return resp
            return error(401, str(e), suppress_traceback=True)

        except (JWTDecodeError,
                NoAuthorizationError,
                InvalidHeaderError,
                WrongTokenError,
                RevokedTokenError,
                FreshTokenRequired,
                CSRFError,
                PyJWTError,
                ) as e:
            return error(401, str(e), suppress_traceback=True)

        except Exception as e:
            LOG.exception('Server error')
            return error(500, 'server error: %s' % repr(e),
                         suppress_traceback=True)

    return wrapper


class Resource(flask_restful.Resource):
    method_decorators = [generic_wrapper]
