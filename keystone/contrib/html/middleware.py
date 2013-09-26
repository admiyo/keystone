# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import webob

from keystone.common import config
from keystone.common import serializer
from keystone.common import wsgi
from keystone.contrib.html import serializer as html_serializer

from keystone.auth import controllers as auth_controllers
from keystone import exception
from keystone import identity
from keystone import token
from keystone.token import provider

from keystone.openstack.common import jsonutils
from keystone.openstack.common import log

CONF = config.CONF
LOG = log.getLogger(__name__)
# Header used to transmit the auth token
AUTH_TOKEN_HEADER = 'X-Auth-Token'


# Header used to transmit the subject token
SUBJECT_TOKEN_HEADER = 'X-Subject-Token'


# Environment variable used to pass the request context
CONTEXT_ENV = wsgi.CONTEXT_ENV


# Environment variable used to pass the request params
PARAMS_ENV = wsgi.PARAMS_ENV


class BasicAuthMiddleware(wsgi.Middleware):
    token_provider = provider.Manager()
    identity_api = identity.Manager()
    token_api = token.Manager()

    def parse_auth_data(self, auth):
        scheme, data = auth.split(None, 1)
        if (scheme.lower() != 'basic'):
            raise exception.Unauthorized()
        username, password = data.decode('base64').split(':', 1)
        domain_id = CONF.identity.default_domain_id
        return username, password, domain_id

    def build_password_auth(self, user_id=None, username=None,
                            user_domain_id=None, user_domain_name=None,
                            password=None):
        password_data = {'user': {}}
        if user_id:
            password_data['user']['id'] = user_id
        else:
            password_data['user']['name'] = username
            if user_domain_id or user_domain_name:
                password_data['user']['domain'] = {}
                if user_domain_id:
                    password_data['user']['domain']['id'] = user_domain_id
                else:
                    password_data['user']['domain']['name'] = user_domain_name
        password_data['user']['password'] = password
        return password_data

    def build_auth(self, username, password, domain_id):
        password_auth = self.build_password_auth(username=username,
                                                 password=password,
                                                 user_domain_id=domain_id)
        auth = {'identity':
                {'methods': ['password'],
                 'password': password_auth},
                #TODO figure out how to do get default project_id
                'scope': {'project': {'name': 'admin',
                                      'domain': {'id': domain_id}}}}
        return auth

    def create_token(self, username, password, domain_id):
        auth = self.build_auth(username, password, domain_id)
        auth_controller = auth_controllers.Auth()
        token_id, token_data = auth_controller.authenticate_and_create_token(
            {}, auth, False)
        return self.token_api.unique_id(token_id)

    def error_response(self, request):
        response = webob.Response()
        response.status_code = 401
        response.headers['WWW-Authenticate'] = 'Basic realm="%s"' % "Keystone"
        return response

    def is_valid_referer(self, request):
        referer = request.headers.get('Referer', '')
        return (referer.startswith(CONF.public_endpoint % CONF) or
                referer.startswith(CONF.admin_endpoint % CONF))

    #Either reuses a token from a cookie,
    #or authenticates via basic-auth
    #TODO(ayoung):support REMOTE_USER
    def token_from_http_data(self, request, token):
        #TODO(ayoung): make sure this logic is correct
        if self.is_valid_referer(request):
            token = request.cookies.get('token_id')
        if token:
            try:
                self.token_provider.validate_token(token)
            except Exception:
                token = None
        if token is None:
            authorization = request.headers.get('Authorization', '')
            if authorization:
                auth = request.environ.get('HTTP_AUTHORIZATION')
                if auth:
                    username, password, domain_id = self.parse_auth_data(auth)
                    try:
                        token = self.create_token(username,
                                                  password,
                                                  domain_id)
                    except Exception:
                        token = None
        return token

    def process_request(self, request):
        token = request.headers.get(AUTH_TOKEN_HEADER)
        if token is None:
            token = self.token_from_http_data(request, token)
        else:
            return self.error_response(request)
        context = request.environ.get(CONTEXT_ENV, {})
        context['token_id'] = token
        if SUBJECT_TOKEN_HEADER in request.headers:
            context['subject_token_id'] = (
                request.headers.get(SUBJECT_TOKEN_HEADER))
        request.environ[CONTEXT_ENV] = context

    def process_response(self, request, response):
        headers = response.headers
        headers['Referer'] = request.url
        context = request.environ.get(CONTEXT_ENV, {})
        token_id = context['token_id']
        #TODO(ayoung): use secure cookie and get age from config file
        if (token_id):
            response.set_cookie("token_id", token_id, max_age=60)
        #path='/', domain='localhost', secure=True)

        return response


class ContentTypesMiddleware(wsgi.Middleware):
    """De/serializes HTML to/from JSON."""

    def process_request(self, request):
        """Transform the request from x-www-form-urlencoded to JSON."""
        if not request.body:
            return
        if ('application/x-www-form-urlencoded' in
                str(request.content_type)):
            request.content_type = 'application/json'
            try:
                request.body = jsonutils.dumps(
                    html_serializer.from_html(request.body))
            except Exception:
                LOG.exception('Serializer failed')
                e = exception.ValidationError(attribute='valid HTML',
                                              target='request body')
                return wsgi.render_exception(e)
        elif 'application/xml' in str(request.content_type):
            try:
                params_parsed = serializer.from_xml(request.body)

            except Exception:
                LOG.exception('Serializer failed')
                e = exception.ValidationError(attribute='valid XML',
                                              target='request body')
                return wsgi.render_exception(e)
        elif request.content_type in ('application/json', ''):
            try:
                params_parsed = jsonutils.loads(request.body)
            except ValueError:
                e = exception.ValidationError(attribute='valid JSON',
                                              target='request body')
                return wsgi.render_exception(e)
        else:
            e = exception.ValidationError(attribute='application/json',
                                          target='Content-Type header')
            return wsgi.render_exception(e)
        if not params_parsed:
            params_parsed = {}
        params = {}
        for k, v in params_parsed.iteritems():
            if k in ('self', 'context'):
                continue
            if k.startswith('_'):
                continue
            params[k] = v

        request.environ[wsgi.PARAMS_ENV] = params

    def process_response(self, request, response):
        """Transform the response from JSON to value from accept header."""
        if not response.body:
            return response
        if 'text/html' in str(request.accept):
            request.accept = 'text/html'
            response.content_type = 'text/html'
            try:
                body_obj = jsonutils.loads(response.body)
                response.charset = request.charset
                response.text = html_serializer.to_html(body_obj)
            except Exception:
                LOG.exception('Serializer failed')
                e = exception.ValidationError(attribute='valid HTML',
                                              target='request body')
                return wsgi.render_exception(e)
        elif 'application/xml' in str(request.accept):
            response.content_type = 'application/xml'
            try:
                body_obj = jsonutils.loads(response.body)
                response.body = serializer.to_xml(body_obj)
            except Exception:
                LOG.exception('Serializer failed')
                raise exception.Error(message=response.body)
        return response
