import json
import sys

import sqlalchemy as sql

from keystone import config


CONF = config.CONF


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    sql.Table('user', meta, autoload=True)
    sql.Table('role', meta, autoload=True)
    sql.Table('project', meta, autoload=True)
    new_metadata_table = sql.Table('user_project_metadata',
                                   meta,
                                   autoload=True)

    conn = migrate_engine.connect()

    old_metadata_table = sql.Table('metadata', meta, autoload=True)
    session = sql.orm.sessionmaker(bind=migrate_engine)()

    for metadata in session.query(old_metadata_table):
        data = json.loads(metadata.data)
        if config.CONF.member_role_id not in metadata.data:
            sys.stderr.write("appending member role\n" )
            data = json.loads(metadata.data)
            data['roles'].append(config.CONF.member_role_id)

        r = session.query(new_metadata_table).filter_by(
            user_id=metadata.user_id,
            project_id=metadata.tenant_id).first()
        project_id = metadata.tenant_id
        sys.stderr.write("Performing migration of data\n" )

        sys.stderr.write("project id = %s\n" % project_id)
        sys.stderr.write("user id = %s\n" % metadata.user_id)

        if r is not None:
            sys.stderr.write("r is not none\n")
            # roles should be the union of the two role lists
            old_roles = data['roles']
            sys.stderr.write("old_roles =\n")
            sys.stderr.write(json.dumps(old_roles))
            sys.stderr.write("\n")

            new_roles = json.loads(r.data)['roles']
            sys.stderr.write("new_roles =\n")
            sys.stderr.write(json.dumps(new_roles))
            sys.stderr.write("\n")

            data['roles'] = list(set(old_roles) | set(new_roles))
            q = new_metadata_table.update().where(
                new_metadata_table.c.user_id == metadata.user_id and
                new_metadata_table.c.project_id == metadata.tenant_id).values(
                    data=json.dumps(data))
        else:
            sys.stderr.write("r is none\n")
            sys.stderr.write("data =")
            sys.stderr.write(json.dumps(data))
            sys.stderr.write("\n")

            q = new_metadata_table.insert().values(
                user_id=metadata.user_id,
                project_id=metadata.tenant_id,
                data=json.dumps(data))

        conn.execute(q)

    session.close()
    old_metadata_table.drop()
    session.flush()


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    sql.Table('user', meta, autoload=True)
    sql.Table('project', meta, autoload=True)

    metadata_table = sql.Table(
        'metadata',
        meta,
        sql.Column(
            u'user_id',
            sql.String(64),
            primary_key=True),
        sql.Column(
            u'tenant_id',
            sql.String(64),
            primary_key=True),
        sql.Column('data',
                   sql.Text()))
    metadata_table.create(migrate_engine, checkfirst=True)

    user_project_metadata_table = sql.Table(
        'user_project_metadata',
        meta,
        autoload=True)

    metadata_table = sql.Table(
        'metadata',
        meta,
        autoload=True)

    session = sql.orm.sessionmaker(bind=migrate_engine)()

    for metadata in session.query(user_project_metadata_table):
        if 'roles' in metadata:
            metadata_table.insert().values(
                user_id=metadata.user_id,
                tenant_id=metadata.project_id)

    session.close()
