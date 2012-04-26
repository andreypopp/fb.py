"""

    fb.py -- Python bindings Facebook Graph API
    ===========================================

    Initialize API, creating persistent connection pool to
    https://graph.facebook.com::

        >>> api = API(APP_ID, APP_SECRET)

    Make a request using application access token::

        >>> result = api["3123153128831/feed"].using_app.get()

    It authenticates app first and caches response. Now try to use another
    access token::

        >>> result = api["me/feed"].using("iuyfsf78ast9GYUGyuas2423423").get()

    Methods ``.post()`` and ``.delete()`` are also available on locations.

"""

# TODO: binary attachments via multipart POST requests
# TODO: batch requests with dependencies
# TODO: Extract authc and authz into separate library

try:
    import simplejson as json
except ImportError:
    import json

import re
import collections
import logging
import urllib
import urlparse
from datetime import datetime, timedelta

import urllib3
from urllib3.exceptions import SSLError, TimeoutError

__all__ = (
    "FacebookError", "TechnicalFacebookError",
    "UnknownFacebookError", "OAuthException", "GraphMethodException",

    "TimelineIsNotActivated", "UniqueActionAlreadyExists", "AccessTokenError",
    "StaledAccessTokenError", "AuthCodeError", "PermissionRequired",

    "API", "OpenGraphLocation",
    "retry_on_error",)

log = logging.getLogger("fb.py")

class cached_property(object):

    def __init__(self, func):
        self.func = func
        self.__name__ = func.__name__
        self.__doc__ = func.__doc__

    def __get__(self, obj, cls):
        if obj is None:
            return self
        v = self.func(obj)
        obj.__dict__[self.__name__] = v
        return v

class FacebookError(Exception):
    """ Common base class for Facebook API errors"""

    def __init__(self, message, data, http_status_code):
        super(FacebookError, self).__init__(message, data, http_status_code)
        self.message = message
        self.data = data
        self.http_status_code = http_status_code

    @property
    def _pretty_data(self):
        if isinstance(self.data, basestring):
            return self.data
        return json.dumps(self.data, sort_keys=True, indent=2)

    @property
    def _pretty_message(self):
        if self.message and not self.message.endswith("."):
            return self.message + "."
        return self.message

    @property
    def short(self):
        return "%s: %s" % (self.__class__.__name__, self.message)

    def __str__(self):
        return "%s HTTP status code: %d. Response was:\n%s" % (
                self._pretty_message, self.http_status_code, self._pretty_data)

    @classmethod
    def specialize(cls, message, data, status):
        return cls(message, data, status)

class TechnicalFacebookError(FacebookError):
    """ Errors of this types are retriable"""

class UnknownFacebookError(FacebookError):
    """ Unkown error"""

class OAuthException(FacebookError):
    """ OAuth exception"""

    TIMELINE_ISNOT_ACTIVATED = re.compile(
        "\(#100\) User [0-9]+ is not allowed to create actions of custom"
        " action type because their Timeline is not activated")

    UNIQUE_ASSOCIATION_ALREADY_EXISTS = re.compile(
        "\(#3501\) [a-zA-Z]+ is already associated to a [a-zA-Z ]+ object"
        " on a unique action type [^\.]+. Original Action ID: ([0-9]*)")

    PERMISSION_REQUIRED = re.compile("\(#200\) Requires extended permission:")

    ACCESS_TOKEN_SESSION_EXPIRED = re.compile(
        "Error invalidating access token: Session has expired at unix time")

    USER_GEOBLOCKED = re.compile(
        "\(#200\) User is not in an allowed country for this app")

    USER_HAS_NOT_AUTHORIZED_APP = re.compile(
        "Error validating access token: User [0-9]+ "
        "has not authorized application [0-9]+")

    UNEXPECTED_ERROR = re.compile(
        "An unexpected error has occurred. Please retry your request later")

    UNKNOWN_ERROR = re.compile(
        "An unknown error has occurred")

    SERVICE_TEMPORARY_UNAVAILABLE = re.compile(
        "(#2) Service temporarily unavailable")

    INVALID_ACCESS_TOKEN_SIGNATURE = re.compile(
        "Invalid access token signature")

    ERROR_VALIDATING_ACCESS_TOKEN = re.compile(
        "Error validating access token:")

    ERROR_VALIDATING_APPLICATION = re.compile(
        "Error validating application")

    INVALID_OAUTH_ACCESS_TOKEN = re.compile(
        "Invalid OAuth access token")

    INACTIVE_ACCESS_TOKEN = re.compile(
        "An active access token must be used")

    USER_MUST_HAVE_ACCEPTED_TOS = re.compile(
        "\(#200\) User must have accepted TOS")

    THE_USER_HASNT_AUTHORIZED_APP = re.compile(
        "\(#200\) The user hasn't authorized the "
        "application to perform this action")

    INVALID_AUTH_CODE = re.compile(
        "Code was invalid or expired")

    AUTH_CODE_VALIDATION_FAILED = re.compile(
        "Error validating verification code")

    PERMISSION_REQURIED = re.compile(
        "\(#282\) Requires extended permission: [a-zA-Z0-9\-_]+")

    @classmethod
    def specialize(cls, message, data, status):
        m = cls.TIMELINE_ISNOT_ACTIVATED.match(message)
        if m:
            return TimelineIsNotActivated(message, data, status)
        m = cls.UNIQUE_ASSOCIATION_ALREADY_EXISTS.match(message)
        if m:
            return UniqueActionAlreadyExists(message, data, status)
        m = cls.PERMISSION_REQUIRED.match(message)
        if m:
            return AccessTokenError(message, data, status)
        m = cls.ACCESS_TOKEN_SESSION_EXPIRED.match(message)
        if m:
            return StaledAccessTokenError(message, data, status)
        m = cls.USER_GEOBLOCKED.match(message)
        if m:
            return AccessTokenError(message, data, status)
        m = cls.USER_HAS_NOT_AUTHORIZED_APP.match(message)
        if m:
            return AccessTokenError(message, data, status)
        m = cls.UNEXPECTED_ERROR.match(message)
        if m:
            return TechnicalFacebookError(message, data, status)
        m = cls.INVALID_ACCESS_TOKEN_SIGNATURE.match(message)
        if m:
            return AccessTokenError(message, data, status)
        m = cls.ERROR_VALIDATING_ACCESS_TOKEN.match(message)
        if m:
            return AccessTokenError(message, data, status)
        m = cls.INVALID_OAUTH_ACCESS_TOKEN.match(message)
        if m:
            return AccessTokenError(message, data, status)
        m = cls.INACTIVE_ACCESS_TOKEN.match(message)
        if m:
            return AccessTokenError(message, data, status)
        m = cls.USER_MUST_HAVE_ACCEPTED_TOS.match(message)
        if m:
            return AccessTokenError(message, data, status)
        m = cls.SERVICE_TEMPORARY_UNAVAILABLE.match(message)
        if m:
            return TechnicalFacebookError(message, data, status)
        m = cls.UNKNOWN_ERROR.match(message)
        if m:
            return TechnicalFacebookError(message, data, status)
        m = cls.ERROR_VALIDATING_APPLICATION.match(message)
        if m:
            return AccessTokenError(message, data, status)
        m = cls.THE_USER_HASNT_AUTHORIZED_APP.match(message)
        if m:
            return AccessTokenError(message, data, status)
        m = cls.INVALID_AUTH_CODE.match(message)
        if m:
            return AuthCodeError(message, data, status)
        m = cls.AUTH_CODE_VALIDATION_FAILED.match(message)
        if m:
            return AuthCodeError(message, data, status)
        m = cls.PERMISSION_REQUIRED.match(message)
        if m:
            return PermissionRequired(message, data, status)
        return cls(message, data, status)

class PermissionRequired(OAuthException):
    """ Permission required"""

class AccessTokenError(OAuthException):
    """ Errors related to access token"""

class StaledAccessTokenError(AccessTokenError):
    """ Errors related to access token which require to renew access token"""

class AuthCodeError(OAuthException):
    """ Errors related to auth code"""

class TimelineIsNotActivated(OAuthException):
    """ User's timeline isn't activated"""

class UniqueActionAlreadyExists(OAuthException):
    """ Unique action already provided for these arguments"""

class GraphMethodException(FacebookError):
    """ Inappropriate usage of graph API"""

class GraphBatchException(FacebookError):
    """ Invalid batch API call"""

def retry_on_error(retries=3):
    """ Decorator for retrying function invocation on errors

    Only `TechnicalFacebookError` and `UnknownFacebookError` errors are handled.

    :keyword retries:
        Number of attempts before giving up (default to 3)
    """
    # TODO: possibly we should make it configurable on per-request basis
    # TODO: what about retrying on json.JSONDecodeError?
    def decorator(func):
        def wrapper(*args, **kwargs):
            for num in range(retries + 1):
                try:
                    return func(*args, **kwargs)
                except (SSLError, TimeoutError), e:
                    log.debug("got timeout error, retrying: %s", e)
                    if num >= retries:
                        raise
                except (TechnicalFacebookError, UnknownFacebookError), e:
                    if num >= retries:
                        raise
                    log.info("got error, retrying: %s", e.short)
                    continue
        return wrapper
    return decorator

class RequestHandler(object):
    """ Syntactical sugar for calling `request`"""

    def get(self, uri, params, access_token=None, use_app_access_token=False):
        return self.request("GET", uri, params,
                access_token=access_token,
                use_app_access_token=use_app_access_token)

    def post(self, uri, params, access_token=None, use_app_access_token=False):
        return self.request("POST", uri, params,
                access_token=access_token,
                use_app_access_token=use_app_access_token)

    def delete(self, uri, params, access_token=None,use_app_access_token=False):
        return self.request("DELETE", uri, params,
                access_token=access_token,
                use_app_access_token=use_app_access_token)

    def request(self, method, uri, params, access_token=None,
            use_app_access_token=False):
        raise NotImplementedError("method not implemented")

class LocationAware(object):
    """ Syntactical sugar for building locations

    The class you use this mixin with should also implement `RequestHandler`
    interface.
    """

    def __getitem__(self, loc):
        return self.loc(loc)

    @property
    def me(self):
        """ Shortcut for `/me` location"""
        return self.loc("me")

    @property
    def using_app(self):
        return self.loc("", use_app_access_token=True)

    def using(self, access_token):
        return self.loc("", access_token=access_token)

    def loc(self, loc, access_token=None, use_app_access_token=False):
        return OpenGraphLocation(self, loc, access_token=access_token,
                use_app_access_token=use_app_access_token)

class API(RequestHandler, LocationAware):
    """ Facebook API

    :param app_id:
        application ID
    :param app_secret:
        application secret
    :keyword app_access_token:
        application access token
    :keyword access_token:
        access token to use
    :keyword connection:
        some object which is capable of doing ``urlopen`` calls
    :keyword retries:
        number of retries to perform
    """

    API_HOST = "graph.facebook.com"
    API_PORT = 443

    EXCEPTION_TYPES = {
        "OAuthException": OAuthException,
        "GraphMethodException": GraphMethodException,
        "GraphBatchException": GraphBatchException,
        None: UnknownFacebookError
    }

    def __init__(self, app_id, app_secret, access_token=None,
            app_access_token=False, app_namespace=None,
            connection=None, retries=3):

        self.connection = connection or self.connect()
        self.retries = retries

        self.app_id = app_id
        self.app_secret = app_secret

        if app_access_token:
            self.app_access_token = app_access_token
        self.access_token = access_token

        self.app_namespace = app_namespace

    @cached_property
    def app_access_token(self):
        """ Application access token"""
        return self.get_app_access_token(self.app_id, self.app_secret)

    def user_access_token(self, redirect_uri, code):
        """ Query for user access token"""
        return self.get_access_token(
            self.app_id, self.app_secret, redirect_uri, code)

    def get_app_access_token(self, app_id, app_secret):
        """ Get the access token for the app

        :param app_id:
            retrieved from the developer page
        :param app_secret:
            retrieved from the developer page
        """
        params = {
            "client_id": app_id,
            "client_secret": app_secret,
            "grant_type": "client_credentials",
        }

        data = self.request("GET", "/oauth/access_token", params,
                json_result=False)
        return data.split("=")[1]

    def exchange_access_token(self, access_token):
        """ Exchange ``access_token`` for an extended one

        See [1] for more info.

        :param access_token:
            access token to exchange

        :return:
            newly issued access token with extended validness date

        [1]: https://developers.facebook.com/docs/authentication/access-token-expiration/
        """
        params = {
            "client_id": self.app_id,
            "client_secret": self.app_secret,
            "grant_type": "fb_exchange_token",
            "fb_exchange_token": access_token
        }

        data = self.request("GET", "/oauth/access_token", params,
                json_result=False)

        parsed = urlparse.parse_qs(data)
        return parsed["access_token"][0]

    def get_access_token(self, app_id, app_secret, redirect_uri, code):
        """ Get the access token for `code`

        :param app_id:
            retrieved from the developer page
        :param app_secret:
            retrieved from the developer page
        :param redirect_uri:
            URI on which use was redirected after Facebook OAuth done
        :param code:
            Facebook OAuth code
        """
        params = {
            "client_id": app_id,
            "client_secret": app_secret,
            "redirect_uri": redirect_uri,
            "code": code,
        }

        data = self.request("GET", "/oauth/access_token",
            params, json_result=False)
        parsed = urlparse.parse_qs(data)

        if "expires" in parsed:
            expires = parsed["expires"][0]
            expires = ((datetime.utcnow() + timedelta(seconds=int(expires)))
                if expires and expires.isdigit()
                else None)
            return parsed["access_token"][0], expires
        else:
            return parsed["access_token"][0], None

    @retry_on_error(retries=3)
    def request(self, method, uri, params, access_token=None,
            use_app_access_token=False, json_result=True):
        """ Make request to Facebook API

        :param method:
            HTTP methods
        :param uri:
            URI to make request to
        :param params:
            a dictionary of parameters
        :keyword json_result:
            if we need to treat result as JSON encoded string (default to True)
        :keyword access_token:
            access token to use
        :keyword use_app_access_token:
            use application access token (default to False)
        """
        if not access_token:
            if use_app_access_token:
                access_token = self.app_access_token
            else:
                access_token = self.access_token

        if access_token:
            params["access_token"] = access_token

        log.info("request %s %s with %s", method, uri, params)

        r = self.connection.request(
                method, uri, params, retries=self.retries, redirect=False)

        return self.adapt_response(r, json_result=json_result)

    def adapt_response(self, r, json_result=True):
        """ Adapt response to result or exception"""
        if r.status == 200:
            if not json_result:
                return r.data
            result = json.loads(r.data)

            # XXX: see facebook bug
            # [1]: https://developers.facebook.com/bugs/313906438682002
            if isinstance(result, bool) and not result:
                raise UnknownFacebookError("returned 'false' value", None, r.status)
            return result

        else:
            d = json.loads(r.data)
            if isinstance(d, dict) and "error" in d:
                error = d["error"]
                message = error.get("message", "unknown error")

                ecls = self.EXCEPTION_TYPES.get(
                    error.get("type", None), UnknownFacebookError)

                raise ecls.specialize(message, d, r.status)

            # XXX: see facebook bug
            # [1]: https://developers.facebook.com/bugs/313906438682002
            elif isinstance(d, bool) and not d:
                raise UnknownFacebookError("returned 'false' value", None, r.status)
            else:
                raise UnknownFacebookError("unknown error", d, r.status)

    def batch(self, use_app_access_token=False):
        """ Return a new batch call builder"""
        return BatchCall(self, use_app_access_token=use_app_access_token)

    @classmethod
    def connect(cls, **kwargs):
        if not "host" in kwargs:
            kwargs["host"] = cls.API_HOST
        if not "port" in kwargs:
            kwargs["port"] = cls.API_PORT
        return urllib3.HTTPSConnectionPool(**kwargs)

class OpenGraphLocation(object):
    """ Represents location inside Facebook OpenGraph"""

    SANITIZE_RE = re.compile("//+")

    def __init__(self, api, loc, access_token=None, use_app_access_token=False):
        self._api = api
        self._loc = loc
        self._use_app_access_token = use_app_access_token
        self._access_token = access_token

    def __getattr__(self, loc):
        return self[loc]

    def __getitem__(self, loc):
        return OpenGraphLocation(self._api, "%s/%s" % (self._loc, loc),
                access_token=self._access_token,
                use_app_access_token=self._use_app_access_token)

    @property
    def using_app(self):
        """ Return location configured to use application access token"""
        return OpenGraphLocation(self._api, self._loc,
                use_app_access_token=True)

    def using(self, access_token):
        """ Return location configured to use `access_token`"""
        return OpenGraphLocation(self._api, self._loc,
                access_token=access_token)

    @property
    def loc(self):
        return self.SANITIZE_RE.sub("/", "/" + self._loc) or "/"

    def action(self, action, namespace=None):
        namespace = namespace or self._api.app_namespace
        if not namespace:
            raise ValueError(
                "no namespace defined for action, use 'namespace'"
                " argument or specify 'app_namespace' in API")
        return self["%s:%s" % (namespace, action)]

    def create(self, **kwargs):
        return self._api.post(self.loc, kwargs,
                access_token=self._access_token,
                use_app_access_token=self._use_app_access_token)

    update = create

    def get(self, **kwargs):
        return self._api.get(self.loc, kwargs,
                access_token=self._access_token,
                use_app_access_token=self._use_app_access_token)

    def delete(self, **kwargs):
        return self._api.delete(self.loc, kwargs,
                access_token=self._access_token,
                use_app_access_token=self._use_app_access_token)

    def __repr__(self):
        return "<OpenGraphLocation %s>" % self.loc

    __str__ = __repr__

ResponseLike = collections.namedtuple(
    "ResponseLike", ["status", "headers", "data"])

class BatchCall(RequestHandler, LocationAware):
    """ Facebook API batch call builder"""

    def __init__(self, api, use_app_access_token=False):
        self.api = api
        self.use_app_access_token = use_app_access_token
        self.calls = []

    def request(self, method, uri, params, access_token=None,
            use_app_access_token=False):
        self.calls.append((method,uri,params,access_token,use_app_access_token))

    def batch_params(self):
        batch_params = []

        for method,uri,params, access_token, use_app_access_token in self.calls:
            call_params = {"relative_url": uri, "method": method}
            params = urllib.urlencode(params)

            if params:
                if method in ("GET", "DELETE"):
                    call_params["relative_url"] = (
                        call_params["relative_url"] + "?" +  params)
                else:
                    call_params["body"] = params

            if not access_token:
                access_token = self.api.access_token
            if not access_token and use_app_access_token:
                access_token = self.api.app_access_token

            if access_token:
                call_params["access_token"] = access_token

            batch_params.append(call_params)

        return batch_params

    def __call__(self):
        batch_params = self.batch_params()
        params = {
            "batch": json.dumps(batch_params),
            "access_token": self.api.access_token \
                if not self.use_app_access_token else self.api.app_access_token
        }
        response = self.api.request("POST", "/", params)
        for r in response:
            r = ResponseLike(r["code"], r["headers"], r["body"])
            # XXX:
            #   if adapt_response raises error we cannot access other results...
            yield self.api.adapt_response(r)
