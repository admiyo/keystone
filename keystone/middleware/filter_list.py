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

import importlib

import webob.dec

from keystone.openstack.common import log
LOG = log.getLogger(__name__)


''' Filter list extension to Paste

This class implements a reusable list of filters specified by
factory.  Each one in the list will be evaluated per a pipeline, but instead of
terminating at a service, this class is also a filter, and thus the next
filter or application specified by paste will be called instead. '''


class FilterList(object):
    """Base WSGI middleware.

    These classes require an application to be
    initialized that will be called next.  By default the middleware will
    simply call its wrapped app, or you can override __call__ to customize its
    behavior.

    """

    @classmethod
    def factory(cls, global_config, **local_config):
        """Used for paste app factories in paste.deploy config files.

        Any local configuration (that is, values under the [filter:APPNAME]
        section of the paste config) will be passed into the `__init__` method
        as kwargs.

        A hypothetical configuration would look like:

            [filter:analytics]
            redis_host = 127.0.0.1
            paste.filter_factory = keystone.analytics:Analytics.factory

        which would result in a call to the `Analytics` class as

            import keystone.analytics
            keystone.analytics.Analytics(app, redis_host='127.0.0.1')

        You could of course re-implement the `factory` method in subclasses,
        but using the kwarg passing it shouldn't be necessary.

        """
        def _factory(app):
            conf = global_config.copy()
            conf.update(local_config)
            return cls(app, **local_config)
        return _factory

    ''' This uses the constructor to create the subordinate filters,
        not the factory, as it is not inside the paste config parser.'''
    def __init__(self, application, filters):
        self.filters = []
        filter_names = []
        self.application = application
        for line in filters.split('\n'):
            for filter in line.split(' '):
                if filter:
                    if filter in filter_names:
                        continue
                    LOG.debug(filter_names)
                    segments = filter.split(':')
                    m = importlib.import_module(segments[0])
                    c_name = segments[1].split('.')[0]
                    LOG.debug('package = %s class = %s',
                              segments[0], c_name)
                    c = getattr(m, c_name)
                    self.filters.append(c(application))

    @webob.dec.wsgify()
    def __call__(self, request):
        for filter in self.filters:
            response = filter.process_request(request)
            if response:
                LOG.debug('returning early')
                return response
        response = request.get_response(self.application)
        for filter in reversed(self.filters):
            filter.process_response(request, response)
        return response
