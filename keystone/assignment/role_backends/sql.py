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
from oslo_db import exception as db_exception

from keystone.assignment.role_backends import base
from keystone.common import driver_hints
from keystone.common import sql
from keystone import exception

# NOTE(henry-nash): From the manager and above perspective, the domain_id
# attribute of a role is nullable.  However, to ensure uniqueness in
# multi-process configurations, it is better to still use a sql uniqueness
# constraint. Since the support for a nullable component of a uniqueness
# constraint across different sql databases is mixed, we instead store a
# special value to represent null, as defined in NULL_DOMAIN_ID below.
NULL_DOMAIN_ID = '<<null>>'


class Role(base.RoleDriverBase):

    @sql.handle_conflicts(conflict_type='role')
    def create_role(self, role_id, role):
        with sql.session_for_write() as session:
            ref = RoleTable.from_dict(role)
            session.add(ref)
            return ref.to_dict()

    @driver_hints.truncated
    def list_roles(self, hints):
        # If there is a filter on domain_id and the value is None, then to
        # ensure that the sql filtering works correctly, we need to patch
        # the value to be NULL_DOMAIN_ID. This is safe to do here since we
        # know we are able to satisfy any filter of this type in the call to
        # filter_limit_query() below, which will remove the filter from the
        # hints (hence ensuring our substitution is not exposed to the caller).
        for f in hints.filters:
            if (f['name'] == 'domain_id' and f['value'] is None):
                f['value'] = NULL_DOMAIN_ID

        with sql.session_for_read() as session:
            query = session.query(RoleTable)
            refs = sql.filter_limit_query(RoleTable, query, hints)
            return [ref.to_dict() for ref in refs]

    def list_roles_from_ids(self, ids):
        if not ids:
            return []
        else:
            with sql.session_for_read() as session:
                query = session.query(RoleTable)
                query = query.filter(RoleTable.id.in_(ids))
                role_refs = query.all()
                return [role_ref.to_dict() for role_ref in role_refs]

    def _get_role(self, session, role_id):
        ref = session.query(RoleTable).get(role_id)
        if ref is None:
            raise exception.RoleNotFound(role_id=role_id)
        return ref

    def get_role(self, role_id):
        with sql.session_for_read() as session:
            return self._get_role(session, role_id).to_dict()

    @sql.handle_conflicts(conflict_type='role')
    def update_role(self, role_id, role):
        with sql.session_for_write() as session:
            ref = self._get_role(session, role_id)
            old_dict = ref.to_dict()
            for k in role:
                old_dict[k] = role[k]
            new_role = RoleTable.from_dict(old_dict)
            for attr in RoleTable.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_role, attr))
            ref.extra = new_role.extra
            return ref.to_dict()

    def delete_role(self, role_id):
        with sql.session_for_write() as session:
            ref = self._get_role(session, role_id)
            session.delete(ref)

    def _get_implied_role(self, session, prior_role_id, implied_role_id):
        query = session.query(
            ImpliedRoleTable).filter(
                ImpliedRoleTable.prior_role_id == prior_role_id).filter(
                    ImpliedRoleTable.implied_role_id == implied_role_id)
        try:
            ref = query.one()
        except sql.NotFound:
            raise exception.ImpliedRoleNotFound(
                prior_role_id=prior_role_id,
                implied_role_id=implied_role_id)
        return ref

    @sql.handle_conflicts(conflict_type='implied_role')
    def create_implied_role(self, prior_role_id, implied_role_id):
        with sql.session_for_write() as session:
            inference = {'prior_role_id': prior_role_id,
                         'implied_role_id': implied_role_id}
            ref = ImpliedRoleTable.from_dict(inference)
            try:
                session.add(ref)
            except db_exception.DBReferenceError:
                # We don't know which role threw this.
                # Query each to trigger the exception.
                self._get_role(session, prior_role_id)
                self._get_role(session, implied_role_id)
            return ref.to_dict()

    def delete_implied_role(self, prior_role_id, implied_role_id):
        with sql.session_for_write() as session:
            ref = self._get_implied_role(session, prior_role_id,
                                         implied_role_id)
            session.delete(ref)

    def list_implied_roles(self, prior_role_id):
        with sql.session_for_read() as session:
            query = session.query(
                ImpliedRoleTable).filter(
                    ImpliedRoleTable.prior_role_id == prior_role_id)
            refs = query.all()
            return [ref.to_dict() for ref in refs]

    def list_role_inference_rules(self):
        with sql.session_for_read() as session:
            query = session.query(ImpliedRoleTable)
            refs = query.all()
            return [ref.to_dict() for ref in refs]

    def get_implied_role(self, prior_role_id, implied_role_id):
        with sql.session_for_read() as session:
            ref = self._get_implied_role(session, prior_role_id,
                                         implied_role_id)
            return ref.to_dict()

    def create_url_pattern(self, url_pattern_id, url_pattern):
        """Create a new url_pattern.

        :raises keystone.exception.Conflict: If a duplicate url_pattern exists.

        """
        # TODO ayoung: Either remove the id, or use it for the create
        with sql.session_for_write() as session:
            ref = UrlPatternTable.from_dict(url_pattern)
            session.add(ref)
            return ref.to_dict()

    def list_url_patterns(self, hints):
        """List url_patterns in the system.

        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of url_pattern_refs or an empty list.

        """
        with sql.session_for_read() as session:
            query = session.query(UrlPatternTable)
            refs = sql.filter_limit_query(UrlPatternTable, query, hints)
            return [ref.to_dict() for ref in refs]

    def _get_url_pattern(self, session, url_pattern_id):
        ref = session.query(UrlPatternTable).get(url_pattern_id)
        if ref is None:
            raise exception.UrlPatterNotFound(role_id=role_id)
        return ref

        
    def get_url_pattern(self, url_pattern_id):
        """Get a url_pattern by ID.

        :returns: url_pattern_ref
        :raises keystone.exception.UrlPatternNotFound: If the
        url_pattern doesn't exist.

        """
        with sql.session_for_read() as session:
            return self._get_url_pattern(session, url_pattern_id).to_dict()

    def update_url_pattern(self, url_pattern_id, url_pattern):
        """Update an existing url_pattern.

        :raises keystone.exception.UrlPatternNotFound: If the
        url_pattern doesn't exist.
        :raises keystone.exception.Conflict: If a duplicate
        url_pattern exists.

        """

        with sql.session_for_write() as session:
            ref = self._get_url_pattern(session, url_pattern_id)
            old_dict = ref.to_dict()
            for k in url_pattern:
                old_dict[k] = url_pattern[k]
            new_url_pattern = UrlPatternTable.from_dict(old_dict)
            for attr in UrlPatternTable.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_url_pattern, attr))
            return ref.to_dict()

    def delete_url_pattern(self, url_pattern_id):
        with sql.session_for_write() as session:
            ref = self._get_url_pattern(session, url_pattern_id)
            session.delete(ref)
        
    def create_role_to_url_pattern(self, prior_role_id, url_pattern_id):
        """Create a role inference rule.

        :raises: keystone.exception.RoleNotFound: If the role doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    def delete_role_to_url_pattern(self, prior_role_id, url_pattern_id):
        """Delete a role inference rule.

        :raises keystone.exception.ImpliedRoleNotFound: If the implied role
            doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    def list_role_to_url_patterns(self):
        """List all the rules used to imply one role from another."""
        raise exception.NotImplemented()  # pragma: no cover


class ImpliedRoleTable(sql.ModelBase, sql.DictBase):
    __tablename__ = 'implied_role'
    attributes = ['prior_role_id', 'implied_role_id']
    prior_role_id = sql.Column(
        sql.String(64),
        sql.ForeignKey('role.id', ondelete="CASCADE"),
        primary_key=True)
    implied_role_id = sql.Column(
        sql.String(64),
        sql.ForeignKey('role.id', ondelete="CASCADE"),
        primary_key=True)

    @classmethod
    def from_dict(cls, dictionary):
        new_dictionary = dictionary.copy()
        return cls(**new_dictionary)

    def to_dict(self):
        """Return a dictionary with model's attributes.

        overrides the `to_dict` function from the base class
        to avoid having an `extra` field.
        """
        d = dict()
        for attr in self.__class__.attributes:
            d[attr] = getattr(self, attr)
        return d


class RoleTable(sql.ModelBase, sql.DictBase):

    def to_dict(self, include_extra_dict=False):
        d = super(RoleTable, self).to_dict(
            include_extra_dict=include_extra_dict)
        if d['domain_id'] == NULL_DOMAIN_ID:
            d['domain_id'] = None
        return d

    @classmethod
    def from_dict(cls, role_dict):
        if 'domain_id' in role_dict and role_dict['domain_id'] is None:
            new_dict = role_dict.copy()
            new_dict['domain_id'] = NULL_DOMAIN_ID
        else:
            new_dict = role_dict
        return super(RoleTable, cls).from_dict(new_dict)

    __tablename__ = 'role'
    attributes = ['id', 'name', 'domain_id']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(255), nullable=False)
    domain_id = sql.Column(sql.String(64), nullable=False,
                           server_default=NULL_DOMAIN_ID)
    extra = sql.Column(sql.JsonBlob())
    __table_args__ = (sql.UniqueConstraint('name', 'domain_id'),)


class UrlPatternTable(sql.ModelBase, sql.DictBase):

    __tablename__ = 'url_pattern'
    attributes = ['id', 'service', 'verb', 'pattern']
    id = sql.Column(sql.String(64), primary_key=True)

    id = sql.Column(sql.String(length=64), primary_key=True)
    service = sql.Column(sql.String(length=64), nullable=False)
    verb = sql.Column(sql.String(length=64))
    pattern = sql.Column(sql.Text, nullable=False)

    @classmethod
    def from_dict(cls, dictionary):
        new_dictionary = dictionary.copy()
        return cls(**new_dictionary)

    def to_dict(self):
        """Return a dictionary with model's attributes.

        overrides the `to_dict` function from the base class
        to avoid having an `extra` field.
        """
        d = dict()
        for attr in self.__class__.attributes:
            d[attr] = getattr(self, attr)
        return d


class RoleToUrlPatternTable(sql.ModelBase, sql.DictBase):
    __tablename__ = 'role_to_url_pattern'
    attributes = ['role_id', 'url_pattern_id']
    role_id = sql.Column(
        sql.String(64),
        sql.ForeignKey('role.id', ondelete="CASCADE"),
        primary_key=True)
    url_pattern_id = sql.Column(
        sql.String(64),
        sql.ForeignKey('url_pattern.id', ondelete="CASCADE"),
        primary_key=True)

    @classmethod
    def from_dict(cls, dictionary):
        new_dictionary = dictionary.copy()
        return cls(**new_dictionary)

    def to_dict(self):
        """Return a dictionary with model's attributes.

        overrides the `to_dict` function from the base class
        to avoid having an `extra` field.
        """
        d = dict()
        for attr in self.__class__.attributes:
            d[attr] = getattr(self, attr)
        return d
