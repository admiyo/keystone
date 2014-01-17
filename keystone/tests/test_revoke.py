# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation
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


import datetime

from keystone import config
from keystone.contrib import revoke
from keystone.contrib.revoke import model
from keystone.openstack.common import timeutils
from keystone import tests


CONF = config.CONF


class RevokeTests(object):

    def test_list(self):
        self.revoke_api.revoke_by_user(user_id=1)
        self.assertEqual(1, len(self.revoke_api.get_events()))

        self.revoke_api.revoke_by_user(user_id=2)
        self.assertEqual(2, len(self.revoke_api.get_events()))

    def test_past_expiry_are_removed(self):
        expire_delta = datetime.timedelta(seconds=1000)
        future_time = timeutils.utcnow() + expire_delta

        user_id = 1
        self.revoke_api.revoke_by_expiration(user_id, future_time)
        self.assertEqual(1, len(self.revoke_api.get_events()))

        expire_delta = datetime.timedelta(days=-1000)
        past_time = timeutils.isotime(timeutils.utcnow() + expire_delta)

        event = model.RevokeEvent(model.EventIdentifier())
        event.revoked_at = past_time
        self.revoke_api.revoke(event)
        self.assertEqual(1, len(self.revoke_api.get_events()))

    def assertSortedByScopeId(self, events):
        cur = 0
        nxt = 1
        while nxt < len(events):
            self.assertLess(events[cur].scope_id, events[nxt].scope_id)
            cur += 1
            nxt += 1


class KvsRevokeTests(tests.TestCase, RevokeTests):
    def setUp(self):
        super(KvsRevokeTests, self).setUp()
        self.config([tests.dirs.etc('keystone.conf.sample'),
                     tests.dirs.tests(
                         'test_token_provider_revoke_by_id_false.conf')])
        self.load_backends()

        self.revoke_api = revoke.Manager()
        self.revoke_api.driver._clear()
