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
from keystone.openstack.common import log as logging
from oslo.config import cfg

CONF = config.CONF
LOG = logging.getLogger(__name__)

revoke_opts = [
    cfg.StrOpt('driver',
               default='keystone.contrib.revoke.backends.kvs.Revoke'),
]
CONF.register_group(cfg.OptGroup(name='revoke',
                                 title='Token Revocation List'))
CONF.register_opts(revoke_opts, group='revoke')


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
extension.register_v3_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)


@dependency.provider('revoke_api')
class Manager(manager.Manager):
    """Example Manager.

    See :mod:`keystone.common.manager.Manager` for more details on
    how this dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.revoke.driver)

    def revoke_by_expiration(self, user_id, expires_at):
        event = model.RevokeEvent(id=model.EventIdentifier(),
                                  user_id=user_id,
                                  expires_at=expires_at)
        self.driver.revoke(event)

    def revoke_by_user(self, user_id):
        event = model.RevokeEvent(id=model.EventIdentifier(),
                                  user_id=user_id)
        self.driver.revoke(event)

    def revoke_by_domain(self, domain_id):
        event = model.RevokeEvent(id=model.EventIdentifier(),
                                  domain_id=domain_id)
        self.driver.revoke(event)

    def revoke_by_user_and_project(self, user_id, project_id):
        event = model.RevokeEvent(model.EventIdentifier(),
                                  project_id=project_id,
                                  user_id=user_id)
        self.driver.revoke(event)

    def revoke_by_project(self, project_id):
        event = model.RevokeEvent(model.EventIdentifier(),
                                  project_id=project_id)
        self.driver.revoke(event)

    def revoke_by_trust(self, trust_id):
        raise exception.NotImplemented()

    def revoke_by_project_role_assignment(self, project_id, role_id):
        event = model.RevokeEvent(id=model.EventIdentifier(),
                                  project_id=project_id,
                                  role_id=role_id)
        self.driver.revoke(event)

    def revoke_by_domain_role_assignment(self, domain_id, role_id):
        event = model.RevokeEvent(id=model.EventIdentifier(),
                                  domain_id=domain_id,
                                  role_id=role_id)
        self.driver.revoke(event)

    def check_token(self, token_values):
        def revoke_matches(event, token_values):
            #something has to match in order to revoke the token
            matched = False
            if event.user_id is not None:
                if event.user_id != token_values['user_id']:
                    return False
                else:
                    matched = True

            if event.project_id is not None:
                if event.project_id != token_values['project_id']:
                    return False
                else:
                    matched = True

            if event.domain_id is not None:
                if event.domain_id != token_values['domain_id']:
                    return False
                else:
                    matched = True

            if event.expires_at is not None:
                token_date = token_values['expires_at']
                if event.expires_at != token_date:
                    return False
                else:
                    matched = True
            return matched
        events = self.get_events(filter=None)
        for event in events:
            if revoke_matches(event, token_values):
                #TODO(ayoung): I18N
                raise exception.TokenNotFound(_('Failed to validate token'))


@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    """Interface description for Example driver."""

    @abc.abstractmethod
    def get_events(self, filter=None):
        """return the revocation events,

        :param filter:
        :raises: keystone.exception,
        :returns: Set of revocation events that match the filter.
                   If no filter is specified, returns all events
                   for tokens issued after the expiration cutoff.


        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def revoke(self, event):
        """return the revocation events,

        :param revocation:
        :raises: keystone.exception,
        :returns: The revocatione_event with an updated values

        """
        raise exception.NotImplemented()
