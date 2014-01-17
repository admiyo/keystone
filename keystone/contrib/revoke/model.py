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
                 consumer_id=None):
        for k, v in locals().copy().iteritems():
            setattr(self, k, v)
        self.revoked_at = timeutils.isotime()

    def to_dict(self):
        event = dict((key, value) for key, value in self.__dict__.iteritems()
                     if not callable(value) and
                     not key.startswith('__') and
                     not key == "self")
        event['id'] = self.id.__str__()
        return event


class EventIdentifier():
    def __init__(self, value=None):
        if value is None:
            self._value = uuid.uuid4()
        else:
            self._value = value

    def __str__(self):
        return self._value.__str__()
