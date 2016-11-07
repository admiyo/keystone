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

import abc

import six

import keystone.conf
from keystone import exception


CONF = keystone.conf.CONF


@six.add_metaclass(abc.ABCMeta)
class RoleDriverBase(object):

    def _get_list_limit(self):
        return CONF.role.list_limit or CONF.list_limit

    @abc.abstractmethod
    def create_role(self, role_id, role):
        """Create a new role.

        :raises keystone.exception.Conflict: If a duplicate role exists.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_roles(self, hints):
        """List roles in the system.

        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of role_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_roles_from_ids(self, role_ids):
        """List roles for the provided list of ids.

        :param role_ids: list of ids

        :returns: a list of role_refs.

        This method is used internally by the assignment manager to bulk read
        a set of roles given their ids.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_role(self, role_id):
        """Get a role by ID.

        :returns: role_ref
        :raises keystone.exception.RoleNotFound: If the role doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_role(self, role_id, role):
        """Update an existing role.

        :raises keystone.exception.RoleNotFound: If the role doesn't exist.
        :raises keystone.exception.Conflict: If a duplicate role exists.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_role(self, role_id):
        """Delete an existing role.

        :raises keystone.exception.RoleNotFound: If the role doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_implied_role(self, prior_role_id, implied_role_id):
        """Get a role inference rule.

        :raises keystone.exception.ImpliedRoleNotFound: If the implied role
            doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_implied_role(self, prior_role_id, implied_role_id):
        """Create a role inference rule.

        :raises: keystone.exception.RoleNotFound: If the role doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_implied_role(self, prior_role_id, implied_role_id):
        """Delete a role inference rule.

        :raises keystone.exception.ImpliedRoleNotFound: If the implied role
            doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_role_inference_rules(self):
        """List all the rules used to imply one role from another."""
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_implied_roles(self, prior_role_id):
        """List roles implied from the prior role ID."""
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_url_pattern(self, url_pattern_id, url_pattern):
        """Create a new url_pattern.

        :raises keystone.exception.Conflict: If a duplicate url_pattern exists.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_url_patterns(self, hints):
        """List url_patterns in the system.

        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of url_pattern_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_url_pattern(self, url_pattern_id):
        """Get a url_pattern by ID.

        :returns: url_pattern_ref
        :raises keystone.exception.UrlPatternNotFound: If the
        url_pattern doesn't exist.


        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_url_pattern(self, url_pattern_id, url_pattern):
        """Update an existing url_pattern.

        :raises keystone.exception.UrlPatternNotFound: If the
        url_pattern doesn't exist.
        :raises keystone.exception.Conflict: If a duplicate
        url_pattern exists.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_url_pattern(self, url_pattern_id):
        """Create a new url_pattern.

        :raises keystone.exception.Conflict: If a duplicate url_pattern exists.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_role_to_url_pattern(self, prior_role_id, url_pattern_id):
        """Create a role inference rule.

        :raises: keystone.exception.RoleNotFound: If the role doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_role_to_url_pattern(self, prior_role_id, url_pattern_id):
        """Delete a role inference rule.

        :raises keystone.exception.ImpliedRoleNotFound: If the implied role
            doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_role_to_url_patterns(self):
        """List all the rules used to imply one role from another."""
        raise exception.NotImplemented()  # pragma: no cover
