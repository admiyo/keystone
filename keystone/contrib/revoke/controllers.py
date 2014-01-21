# vim: tabstop=4 shiftwidth=4 softtabstop=4

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


from keystone.common import controller
from keystone.common import dependency


@dependency.requires('revoke_api')
class RevokeController(controller.V3Controller):

    def describe(self, context):
        container = {"revoke": ""}
        container['links'] = {
            'next': None,
            'self': RevokeController.base_url(path=context['path']),
            'revoked_tokens': RevokeController.base_url(
                path=context['path'] + "/events"),
            'previous': None}
        return container

    #Not @controller.protected() to allow this to be publicly callable.
    def list_events(self, context):
        events = self.revoke_api.get_events(filter)
        #TODO(ayoung): fill in the links
        events = {'events': [event.to_dict() for event in events],
                  'links': []}
        return events
