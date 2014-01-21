# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack Foundation
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


import uuid


from keystone.openstack.common import timeutils


class RevokeEvent(object):
    def __init__(self, id,
                 user_id=None,
                 role_id=None,
                 issued_before=None,
                 expires_at=None,
                 domain_id=None,
                 project_id=None,
                 trust_id=None,
                 consumer_id=None,
                 access_token_id=None):
        for k, v in locals().copy().iteritems():
            setattr(self, k, v)
        self.revoked_at = timeutils.utcnow()
        if issued_before is None and expires_at is None:
            self.issued_before = self.revoked_at

    def to_dict(self):
        keys = ['user_id',
                'role_id',
                'domain_id',
                'project_id']
        event = dict((key, self.__dict__[key]) for key in keys)
        event['id'] = self.id.__str__()
        if self.trust_id is not None:
            event['OS-TRUST:trust_id'] = self.trust_id
        if self.consumer_id is not None:
            event['OS-OAUTH1:consumer_id'] = self.consumer_id
        if self.consumer_id is not None:
            event['OS-OAUTH1:access_token_id'] = self.access_token_id
        if self.expires_at is not None:
            event['expires_at'] = timeutils.isotime(self.expires_at,
                                                    subsecond=True)
        if self.issued_before is not None:
            event['issued_before'] = timeutils.isotime(self.issued_before,
                                                       subsecond=True)
        return event


class EventIdentifier(object):
    def __init__(self, value=None):
        self._value = value or uuid.uuid4()

    def __str__(self):
        return str(self._value)
