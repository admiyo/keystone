# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Red Hat, Inc
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

import sqlalchemy as sql


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    kds_table = sql.Table('kds_keys', meta,
        sql.Column('id', sql.String(256), primary_key=True),
        sql.Column('key', sql.Text()))
    kds_table.create(migrate_engine, checkfirst=True)


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    table = sql.Table('kds_keys', meta, autoload=True)
    table.drop(migrate_engine, checkfirst=True)
