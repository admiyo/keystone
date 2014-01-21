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

import uuid

from keystone.common import dependency
from keystone.contrib.revoke import model
from keystone.openstack.common import timeutils
from keystone import tests
from keystone import token
from keystone.tests import test_v3


@dependency.requires('revoke_api')
class OSRevokeTests(test_v3.RestfulTestCase):
    EXTENSION_NAME = 'revoke'
    EXTENSION_TO_ADD = 'revoke_extension'

    def test_get_empty_list(self):
        resp = self.get('/OS-REVOKE/events')
        self.assertEqual(resp.json_body, {"events": [], "links": []})

    def _blank_event(self):
        return {unicode('domain_id'): None, unicode('user_id'): None,
                unicode('project_id'): None, unicode('role_id'): None}

    def test_revoked_token_in_list(self):
        user_id = uuid.uuid4().hex
        expires_at = token.default_expire_time()
        sample = self._blank_event()
        sample['user_id'] = unicode(user_id)
        sample['expires_at'] = unicode(timeutils.isotime(expires_at,
                                                         subsecond=True))
        self.revoke_api.revoke_by_expiration(user_id, expires_at)
        resp = self.get('/OS-REVOKE/events')
        events = resp.json_body['events']
        self.assertEqual(len(events), 1)
        event = events[0]
        sample['issued_before'] = event['issued_before']
        self.assertEqual(sample, event)

    def test_disabled_project_in_list(self):
        project_id = uuid.uuid4().hex
        sample = self._blank_event()
        sample['project_id'] = unicode(project_id)

        self.revoke_api.revoke(
            model.RevokeEvent(project_id=project_id))

        resp = self.get('/OS-REVOKE/events')
        events = resp.json_body['events']
        self.assertEqual(len(events), 1)
        event = events[0]
        sample['issued_before'] = event['issued_before']
        self.assertEqual(event, sample)

    def test_disabled_domain_in_list(self):
        domain_id = uuid.uuid4().hex
        sample = self._blank_event()
        sample['domain_id'] = unicode(domain_id)

        self.revoke_api.revoke(
            model.RevokeEvent(domain_id=domain_id))

        resp = self.get('/OS-REVOKE/events')
        events = resp.json_body['events']
        self.assertEqual(len(events), 1)
        event = events[0]
        sample['issued_before'] = event['issued_before']
        self.assertEqual(event, sample)
