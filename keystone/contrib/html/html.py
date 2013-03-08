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

import webob.dec

from keystone.common import config
from keystone.common import logging
from keystone.common import utils
from keystone.common import wsgi
from keystone.contrib.html import serializer
from keystone import exception
from keystone.openstack.common import jsonutils


CONF = config.CONF
LOG = logging.getLogger(__name__)


class HtmlBodyMiddleware(wsgi.Middleware):
    """De/serializes HTML to/from JSON."""

    def process_request(self, request):
        #Make sure that the HTML middleware is executed on
        #the way out
        outgoing_html = 'text/html' in str(request.accept)
        if outgoing_html:
            request.accept = 'text/html'
        """Transform the request from XML to JSON."""
        incoming_html = ('application/x-www-form-urlencoded' in
                         str(request.content_type))
        if incoming_html and request.body:
            request.content_type = 'application/json'
            try:
                request.body = jsonutils.dumps(
                    serializer.from_xml(request.body))
            except Exception:
                LOG.exception('Serializer failed')
                e = exception.ValidationError(attribute='valid HTML',
                                              target='request body')
                return wsgi.render_exception(e)

    def process_response(self, request, response):
        """Transform the response from JSON to XML."""
        outgoing_html = 'text/html' in str(request.accept)
        if outgoing_html and response.body:
            request.accept = 'text/html'
            response.content_type = 'text/html'
            try:
                body_obj = jsonutils.loads(response.body)
                response.charset = request.charset
                response.text = serializer.to_html(body_obj)
            except Exception:
                LOG.exception('Serializer failed')
                e = exception.ValidationError(attribute='valid XML',
                                              target='request body')
                return wsgi.render_exception(e)
        return response
