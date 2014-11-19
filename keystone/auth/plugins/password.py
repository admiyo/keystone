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

import sys

import six

from keystone import auth
from keystone.common import dependency
from keystone import exception
from keystone.i18n import _
from keystone.openstack.common import log

METHOD_NAME = 'password'

LOG = log.getLogger(__name__)


@dependency.requires('assignment_api', 'identity_api','policy_api')
class UserAuthInfo(object):
    @staticmethod
    def create(auth_payload):
        user_auth_info = UserAuthInfo()
        user_auth_info._validate_and_normalize_auth_data(auth_payload)
        return user_auth_info

    def __init__(self):
        self.user_id = None
        self.password = None
        self.user_ref = None

    def _assert_domain_is_enabled(self, domain_ref):
        try:
            self.assignment_api.assert_domain_enabled(
                domain_id=domain_ref['id'],
                domain=domain_ref)
        except AssertionError as e:
            LOG.warning(e)
            six.reraise(exception.Unauthorized, exception.Unauthorized(e),
                        sys.exc_info()[2])

    def _assert_user_is_enabled(self, user_ref):
        try:
            self.identity_api.assert_user_enabled(
                user_id=user_ref['id'],
                user=user_ref)
        except AssertionError as e:
            LOG.warning(e)
            six.reraise(exception.Unauthorized, exception.Unauthorized(e),
                        sys.exc_info()[2])

    def _lookup_domain(self, domain_info):
        domain_id = domain_info.get('id')
        domain_name = domain_info.get('name')
        domain_ref = None
        if not domain_id and not domain_name:
            raise exception.ValidationError(attribute='id or name',
                                            target='domain')
        try:
            if domain_name:
                domain_ref = self.assignment_api.get_domain_by_name(
                    domain_name)
            else:
                domain_ref = self.assignment_api.get_domain(domain_id)
        except exception.DomainNotFound as e:
            LOG.exception(e)
            raise exception.Unauthorized(e)
        self._assert_domain_is_enabled(domain_ref)
        return domain_ref

    def _validate_and_normalize_auth_data(self, auth_payload):
        if 'user' not in auth_payload:
            raise exception.ValidationError(attribute='user',
                                            target=METHOD_NAME)
        user_info = auth_payload['user']
        user_id = user_info.get('id')
        user_name = user_info.get('name')
        user_ref = None
        if not user_id and not user_name:
            raise exception.ValidationError(attribute='id or name',
                                            target='user')
        self.password = user_info.get('password')
        try:
            if user_name:
                if 'domain' not in user_info:
                    raise exception.ValidationError(attribute='domain',
                                                    target='user')
                domain_ref = self._lookup_domain(user_info['domain'])
                user_ref = self.identity_api.get_user_by_name(
                    user_name, domain_ref['id'])
            else:
                user_ref = self.identity_api.get_user(user_id)
                domain_ref = self.assignment_api.get_domain(
                    user_ref['domain_id'])
                self._assert_domain_is_enabled(domain_ref)
        except exception.UserNotFound as e:
            LOG.exception(e)
            raise exception.Unauthorized(e)
        self._assert_user_is_enabled(user_ref)
        self.user_ref = user_ref
        self.user_id = user_ref['id']
        self.domain_id = domain_ref['id']

    def check_policy(self, action, target):
        role_ids = self.assignment_api.get_roles_for_user_and_domain(
            self.user_id, self.domain_id)

        roles =  [self.assignment_api.get_role(role_id) for role_id in role_ids]
        role_names = [r['name'] for r in roles]
        self.role_names =  role_names
 
        source = {"domain_id": self.domain_id,
                  "roles": self.role_names}
        
        target_dict = {"domain_id": target.domain_id}

        self.policy_api.enforce(source, action, target_dict)



@dependency.requires('identity_api')
class Password(auth.AuthMethodHandler):

    method = METHOD_NAME

    def authenticate(self, context, auth_payload, auth_context):
        """Try to authenticate against the identity backend."""
        user_info = UserAuthInfo.create(auth_payload)

        # FIXME(gyee): identity.authenticate() can use some refactoring since
        # all we care is password matches
        try:
            self.identity_api.authenticate(
                context,
                user_id=user_info.user_id,
                password=user_info.password)
        except AssertionError:
            # authentication failed because of invalid username or password
            msg = _('Invalid username or password')
            raise exception.Unauthorized(msg)

        auth_context['user_id'] = user_info.user_id

@dependency.requires('identity_api')
class ServiceUser(auth.AuthMethodHandler):

    method = "service_user"

    def authenticate(self, context, auth_payload, auth_context):
        """Try to authenticate against the identity backend."""
        service_user_info = UserAuthInfo.create(auth_payload["service"])
        try:
            self.identity_api.authenticate(
                context,
                user_id=service_user_info.user_id,
                password=service_user_info.password)
            user_info = UserAuthInfo.create(auth_payload)
            service_user_info.check_policy("identity:sign_for_user_in_domain",user_info)
        except AssertionError:
            # authentication failed because of invalid username or password
            msg = _('Invalid username or password')
            raise exception.Unauthorized(msg)

        auth_context['user_id'] = user_info.user_id
