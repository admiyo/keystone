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

import copy
import datetime

from keystone import config
from keystone.contrib import revoke
from keystone.openstack.common import timeutils

CONF = config.CONF


class Revoke(revoke.Driver):

    def __init__(self):
        self._events = []

    def _prune_expired_events(self):
        pruned = []
        expire_delta = datetime.timedelta(seconds=CONF.token.expiration)
        oldest = timeutils.utcnow() - expire_delta

        for event in self._events:
            revoked_at = event.revoked_at
            if revoked_at > oldest:
                pruned.append(event)
        self._events = copy.copy(pruned)
        return pruned

    def get_events(self, filter=None):
        """List Revocation Events.

        :param filter: Ignored
        :raises: None
        :returns: A list of keystone.contrib.revoke.model.RevocationEvents

        """
        return self._prune_expired_events()

    def revoke(self, event):
        """register a revocation event

        :param event: An instance of
            keystone.contrib.revoke.model.RevocationEvent

        """
        self._prune_expired_events()
        self._events.append(event)
