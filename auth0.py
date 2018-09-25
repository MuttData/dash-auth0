
# from .auth import Auth

from dash_auth.auth import Auth
import flask
from flask import redirect
from flask import session
from authlib.flask.client import OAuth
from six.moves.urllib.parse import urlencode


class Auth0Auth(Auth):
    """Implements auth via Auth0."""

    def __init__(
        self, app,
        AUTH0_CALLBACK_URL,
        AUTH0_CLIENT_ID,
        AUTH0_CLIENT_SECRET,
        AUTH0_DOMAIN,
        AUTH0_AUDIENCE,
        AUTH0_LOGOUT_REDIRECT_URL,
        SECRET_KEY,
        LOGIN_URL='/login',
        LOGOUT_URL='/logout',
        CALLBACK_URL='/callback',
        JWT_PAYLOAD='jwt_payload',
        PROFILE_KEY='profile'
    ):
        self.AUTH0_CALLBACK_URL = AUTH0_CALLBACK_URL
        self.AUTH0_CLIENT_ID = AUTH0_CLIENT_ID
        self.AUTH0_CLIENT_SECRET = AUTH0_CLIENT_SECRET
        self.AUTH0_DOMAIN = AUTH0_DOMAIN
        self.AUTH0_BASE_URL = 'https://' + AUTH0_DOMAIN
        self.AUTH0_AUDIENCE = AUTH0_AUDIENCE

        if self.AUTH0_AUDIENCE is '':
            self.AUTH0_AUDIENCE = self.AUTH0_BASE_URL + '/userinfo'

        self.AUTH0_LOGOUT_REDIRECT_URL = AUTH0_LOGOUT_REDIRECT_URL

        self.SECRET_KEY = SECRET_KEY
        self.LOGIN_URL = LOGIN_URL
        self.LOGOUT_URL = LOGOUT_URL
        self.CALLBACK_URL = CALLBACK_URL
        self.JWT_PAYLOAD = JWT_PAYLOAD
        self.PROFILE_KEY = PROFILE_KEY

        self.app = app
        app.server.secret_key = self.SECRET_KEY
        Auth.__init__(self, app, authorization_hook=self.CALLBACK_URL)
        self.oauth = OAuth(app)

        self.auth0 = self.oauth.register(
            'auth0',
            client_id=self.AUTH0_CLIENT_ID,
            client_secret=self.AUTH0_CLIENT_SECRET,
            api_base_url=self.AUTH0_BASE_URL,
            access_token_url=self.AUTH0_BASE_URL + '/oauth/token',
            authorize_url=self.AUTH0_BASE_URL + '/authorize',
            client_kwargs={
                'scope': 'openid profile',
            },
        )

        app.server.add_url_rule(
            self.LOGIN_URL,
            view_func=self.login,
            methods=['get']
        )

        app.server.add_url_rule(
            self.LOGOUT_URL,
            view_func=self.logout,
            methods=['get']
        )

        app.server.add_url_rule(
            self.CALLBACK_URL,
            # '{}_dash-callback'.format(app.config['routes_pathname_prefix']),
            view_func=self.callback,
            methods=['get']
        )

    def login(self):
        self.secret_key = self.SECRET_KEY
        return self.auth0.authorize_redirect(redirect_uri=self.AUTH0_CALLBACK_URL, audience=self.AUTH0_AUDIENCE)

    def logout(self):
        session.clear()
        params = {'returnTo': self.AUTH0_LOGOUT_REDIRECT_URL, 'client_id': self.AUTH0_CLIENT_ID}
        return redirect(self.auth0.api_base_url + '/v2/logout?' + urlencode(params))

    def callback(self):
        self.auth0.authorize_access_token()
        resp = self.auth0.get('userinfo')
        userinfo = resp.json()

        session[self.JWT_PAYLOAD] = userinfo
        session[self.PROFILE_KEY] = {
            'user_id': userinfo['sub'],
            'name': userinfo['name'],
            'picture': userinfo['picture']
        }
        return redirect('/home')

    def is_authorized(self):
        if flask.request.path == self.CALLBACK_URL:
            return True
        if self.PROFILE_KEY in session:
            return True
        return False

    def login_request(self):
        return redirect(self.LOGIN_URL)

    def auth_wrapper(self, f):
        def wrap(*args, **kwargs):
            if not self.is_authorized():
                return redirect(self.LOGIN_URL, code=403)

            response = f(*args, **kwargs)
            return response
        return wrap

    def index_auth_wrapper(self, original_index):
        def wrap(*args, **kwargs):
            if self.is_authorized():
                return original_index(*args, **kwargs)
            else:
                return self.login_request()
        return wrap
