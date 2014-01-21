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
    def __init__(self, id=uuid.uuid4().hex,
                 user_id=None, role_id=None, issued_before=None,
                 expires_at=None, domain_id=None, project_id=None,
                 trust_id=None, consumer_id=None, access_token_id=None):
        for k, v in locals().copy().iteritems():
            setattr(self, k, v)
        self.revoked_at = timeutils.utcnow()
        if issued_before is None:
            self.issued_before = self.revoked_at

    def to_dict(self, with_id=True):
        keys = ['user_id',
                'role_id',
                'domain_id',
                'project_id']
        event = dict((key, self.__dict__[key]) for key in keys)
        if with_id:
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


#TODO(ayoung)  This code should be moved to the unit  test code once
#revoke_by_tree has replaced it as the way to test token revocation.
def matches(event, token_values):
    """See if the token matches the revocation event.


    Compare each attribute from the event with the corresponding
    value from the token.  If the event does not have a value for
    the attribute, a match is still possible.  If the event has a
    value for the attribute, and it does not match the token, no match
    is possible, so skip the remaining checks.

    :param event one revocation event to match
    :param token_values dictionary with set of values taken from the
    token
    :returns if the token matches the revocation event, indicating the
    token has been revoked
    """

    #something has to match in order to revoke the token
    matched = False

    #The token has three attributes that can match the user_id
    if event.user_id is not None:
        user_id_matched = False
        for attribute_name in ['user_id', 'trustor_id', 'trustee_id']:
            if event.user_id == token_values[attribute_name]:
                user_id_matched = True
                break
        if not user_id_matched:
            return False
        else:
            matched = True

    #The token has two attributes that can match the domain_id
    if event.domain_id is not None:
        dom_id_matched = False
        for attribute_name in ['user_domain_id', 'project_domain_id']:
            if event.domain_id == token_values[attribute_name]:
                dom_id_matched = True
                break
        if not dom_id_matched:
            return False
        else:
            matched = True

    #If any one check does not match, the while token does
    #not match the event. The numerous return False indicate
    # that the token is still valid and short-circuits the
    #rest of the logic.
    attribute_names = ['project_id',
                       'expires_at', 'trust_id', 'consumer_id',
                       'access_token_id']
    for attribute_name in attribute_names:
        if getattr(event, attribute_name) is not None:
            if (getattr(event, attribute_name) !=
                    token_values[attribute_name]):
                        return False
            else:
                matched = True

    if event.role_id is not None:
        roles = token_values['roles']
        role_found = False
        for role in roles:
            if event.role_id == role:
                role_found = True
                break
        if role_found:
            matched = True
        else:
            return False
    matched = (matched and
               event.issued_before > token_values['issued_at'])
    return matched
