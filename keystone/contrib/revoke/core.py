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


import abc
import six

from keystone.common import dependency
from keystone.common import extension
from keystone.common import manager
from keystone import config
from keystone.contrib.revoke import model
from keystone import exception
from keystone import notifications
from keystone.openstack.common import log

CONF = config.CONF
LOG = log.getLogger(__name__)


EXTENSION_DATA = {
    'name': 'OpenStack REVOKE API',
    'namespace': 'http://docs.openstack.org/identity/api/ext/'
                 'OS-REVOKE/v1.0',
    'alias': 'OS-REVOKE',
    'updated': '2013-07-07T12:00:0-00:00',
    'description': 'OpenStack Revoked Token Reporting mechanism.',
    'links': [
        {
            'rel': 'describedby',
            'type': 'text/html',
            'href': ('https://github.com/openstack/identity-api/blob/master/' +
                     'openstack-identity-api/v3/src/markdown/' +
                     'identity-api-v3-os-revoke-ext.md'),
        }, {
            'rel': 'LIST',
            'type': 'application/JSON',
            'href': ('OS-REVOKE/events'),
        }
    ]}
extension.register_admin_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)
extension.register_public_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)


@dependency.provider('revoke_api')
class Manager(manager.Manager):
    """Revoke API Manager.

    Performs common logic for recording revocations.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.revoke.driver)
        self._register_listeners()

    def _user_callback(self, service, resource_type, operation,
                       payload):
        self.revoke_by_user(payload['resource_info'])

    def _role_callback(self, service, resource_type, operation,
                       payload):
        self.driver.revoke(
            model.RevokeEvent(role_id=payload['resource_info']))

    def _project_callback(self, service, resource_type, operation,
                          payload):
        self.driver.revoke(
            model.RevokeEvent(project_id=payload['resource_info']))

    def _domain_callback(self, service, resource_type, operation,
                         payload):
        self.driver.revoke(
            model.RevokeEvent(domain_id=payload['resource_info']))

    def _trust_callback(self, service, resource_type, operation,
                        payload):
        self.driver.revoke(
            model.RevokeEvent(trust_id=payload['resource_info']))

    def _consumer_callback(self, service, resource_type, operation,
                           payload):
        self.driver.revoke(
            model.RevokeEvent(consumer_id=payload['resource_info']))

    def _access_token_callback(self, service, resource_type, operation,
                               payload):
        self.driver.revoke(
            model.RevokeEvent(access_token_id=payload['resource_info']))

    def _register_listeners(self):
        callbacks = [
            ['deleted', 'OS-TRUST:trust', self._trust_callback],
            ['deleted', 'OS-OAUTH1:consumer', self._consumer_callback],
            ['deleted', 'OS-OAUTH1:access_token',
             self._access_token_callback],
            ['deleted', 'role', self._role_callback],
            ['deleted', 'user', self._user_callback],
            ['disabled', 'user', self._user_callback],
            ['deleted', 'project', self._project_callback],
            ['disabled', 'project', self._project_callback],
            ['disabled', 'domain', self._domain_callback]]
        for cb in callbacks:
            notifications.register_event_callback(cb[0], cb[1], cb[2])

    def revoke_by_user(self, user_id):
        return self.driver.revoke(model.RevokeEvent(user_id=user_id))

    def revoke_by_expiration(self, user_id, expires_at):
        self.driver.revoke(
            model.RevokeEvent(user_id=user_id,
                              expires_at=expires_at))

    def revoke_by_grant(self, role_id, user_id=None,
                        domain_id=None, project_id=None):
        self.driver.revoke(
            model.RevokeEvent(user_id=user_id,
                              role_id=role_id,
                              domain_id=domain_id,
                              project_id=project_id))

    def revoke_by_user_and_project(self, user_id, project_id):
        self.driver.revoke(
            model.RevokeEvent(project_id=project_id,
                              user_id=user_id))

    def revoke_by_project_role_assignment(self, project_id, role_id):
        self.driver.revoke(model.RevokeEvent(project_id=project_id,
                                             role_id=role_id))

    def revoke_by_domain_role_assignment(self, domain_id, role_id):
        self.driver.revoke(model.RevokeEvent(domain_id=domain_id,
                                             role_id=role_id))

    def check_token(self, token_values):
        """Checks the values from a token against the revocation list

        :param  token_values dictionary of values from a token,
        normalized for differences between v2 and v3. The checked values are a
         subset of the attributes of model.TokenEvent
        :raises exception.TokenNotFound if the token is invalid
        :returns no value returned
         """

        events = self.get_events(filter=None)
        for event in events:
            if model.matches(event, token_values):
                raise exception.TokenNotFound(_('Failed to validate token'))


@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    """Interface for recording and reporting revocation Events."""

    @abc.abstractmethod
    def get_events(self, filter=None):
        """return the revocation events, as a list of  objects

        :param filter:   Not yet supported.
        :raises: keystone.exception,
        :returns: A list of keystone.contrib.revoke.model.RevokeEvent
                  that match the filter.
                  If no filter is specified, returns all events
                  for tokens issued after the expiration cutoff.


        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def revoke(self, event):
        """register a revocation event

        :param event: An instance of
            keystone.contrib.revoke.model.RevocationEvent

        """
        raise exception.NotImplemented()
