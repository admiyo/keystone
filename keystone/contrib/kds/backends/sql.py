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

from keystone.common import sql


class Keys(sql.ModelBase, sql.DictBase):
    __tablename__ = 'kds_keys'
    attributes = ['id', 'key']
    id = sql.Column(sql.String(256), primary_key=True)
    key = sql.Column(sql.JsonBlob())


class KDS(sql.Base):

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
