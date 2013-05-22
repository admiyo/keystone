# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Red Hat, Inc.
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

import base64
import os
import sys

from migrate.versioning import api as versioning_api

from keystone.common import sql
from keystone import config

try:
    from migrate.versioning import exceptions as versioning_exceptions
except ImportError:
    try:
        # python-migration changed location of exceptions after 1.6.3
        # See LP Bug #717467
        from migrate import exceptions as versioning_exceptions
    except ImportError:
        sys.exit('python-migrate is not installed. Exiting.')

CONF = config.CONF

class Keys(sql.ModelBase, sql.DictBase):
    __tablename__ = 'kds_keys'
    attributes = ['id', 'key']
    id = sql.Column(sql.String(256), primary_key=True)
    key = sql.Column(sql.JsonBlob())


class KDS(sql.Base):

    def db_sync(self):
        kds_db_sync()

    @sql.handle_conflicts(type='kds_keys')
    def set_shared_key(self, kds_id, key):
        d = {'id': kds_id, 'key': {'key_v1': base64.b64encode(key)}}
        session = self.get_session()
        with session.begin():
            key_ref = Keys.from_dict(d)
            session.add(key_ref)
            session.flush()

    def get_shared_key(self, kds_id):
        session = self.get_session()
        key_ref = session.query(Keys).filter_by(id=kds_id).first()
        if not key_ref:
            return None
        d = key_ref.to_dict()
        k = d.pop('key', None)
        return base64.b64decode(k['key_v1'])

##These are copied from common.  The functions in Common need to be refactored to allow
#them to find and work with repositories stored in extensions
def db_version():
    repo_path = _find_migrate_repo()
    try:
        return versioning_api.db_version(CONF.sql.connection, repo_path)
    except versioning_exceptions.DatabaseNotControlledError:
        return db_version_control(0)

def db_version_control(version=None):
    repo_path = _find_migrate_repo()
    versioning_api.version_control(CONF.sql.connection, repo_path, version)
    return version

def _find_migrate_repo():
    """Get the path for the migrate repository."""
    path = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                        'migrate_repo')
    assert os.path.exists(path)
    return path

def kds_db_sync(version=None):
    current_version = db_version()
    repo_path = _find_migrate_repo()
    if version is None or version > current_version:
        return versioning_api.upgrade(CONF.sql.connection, repo_path, version)
    else:
        return versioning_api.downgrade(
            CONF.sql.connection, repo_path, version)
