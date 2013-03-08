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

from keystone.common import config
from keystone.common import serializer
from keystone.common import wsgi
from keystone.contrib.html import serializer as html_serializer

from keystone import exception
from keystone.openstack.common import jsonutils
from keystone.openstack.common import log

CONF = config.CONF
LOG = log.getLogger(__name__)


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
