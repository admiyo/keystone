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

from keystone import auth
from keystone.auth.plugins import password
from keystone.common import config
from keystone.common import dependency
from keystone import exception
from keystone.i18n import _


CONF = config.CONF


@dependency.requires('identity_api', 'assignment_api', 'policy_api')
class ServiceUserRemote(auth.AuthMethodHandler):
    def _authenticate(self, remote_user, context):
        """Use remote_user to look up the user in the identity backend.

        If remote_user contains an `@` assume that the substring before the
        rightmost `@` is the username, and the substring after the @ is the
        domain name.
        """
        names = remote_user.rsplit('@', 1)
        username = names.pop(0)
        if names:
            domain_name = names[0]
            domain_ref = self.assignment_api.get_domain_by_name(domain_name)
            domain_id = domain_ref['id']
        else:
            domain_id = CONF.identity.default_domain_id
        user_ref = self.identity_api.get_user_by_name(username, domain_id)
        return user_ref

    def authenticate(self, context, auth_info, auth_context):
        """Use REMOTE_USER to look up the user in the identity backend.

        auth_context is an in-out variable that will be updated with the
        user_id from the actual user from the REMOTE_USER env variable.
        """
        try:
            REMOTE_USER = context['environment']['REMOTE_USER']
        except KeyError:
            msg = _('No authenticated user')
            raise exception.Unauthorized(msg)
        try:
            user_ref = self._authenticate(REMOTE_USER, context)
            user_info = password.UserAuthInfo.create(auth_info)

            roles = self.assignment_api.get_roles_for_user_and_domain(
                user_ref['id'],
                user_ref['domain_id'])
            user_ref['roles'] = roles

            # And run policy check
            self.policy_api.self.policy_api.enforce(
                user_ref,
                "identity:token_for_domain",
                user_info)
        except Exception:
            msg = _('Unable to lookup user %s') % (REMOTE_USER)
            raise exception.Unauthorized(msg)

        return user_info
