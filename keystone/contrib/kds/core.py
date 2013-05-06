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

"""Main entry point into the Key distribution Server service."""

import os
import errno
import base64

from keystone.openstack.common import jsonutils
from keystone.openstack.common import cryptoutils

from keystone.common import dependency
from keystone.common import logging
from keystone.common import manager
from keystone import config
from keystone import exception


CONF = config.CONF
LOG = logging.getLogger(__name__)
KEY_SIZE = 16


@dependency.provider('kds_api')
class Manager(manager.Manager):
    """Default pivot point for the KDS backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        self.crypto = cryptoutils.SymmetricCrypto(enctype=CONF.kds.enctype,
                                                  hashtype=CONF.kds.hashtype)
        self.hkdf = cryptoutils.HKDF(hashtype=CONF.kds.hashtype)
        self.ttl = CONF.kds.ticket_lifetime
        opt = CONF.kds.master_key.strip()
        if opt.startswith('file:'):
            try:
                f = open(opt[len('file://'):], 'r')
                self.mkey = base64.b64decode(f.read())
                f.close()
            except IOError as e:
                if e.errno == errno.ENOENT:
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    f = os.open(opt[len('file://'):], flags, 0600)
                    self.mkey = self.crypto.new_key(KEY_SIZE)
                    os.write(f, base64.b64encode(self.mkey))
                    os.close(f)
                else:
                    raise
        else:
            raise Exception('Invalid Master Key Option')

        if len(self.mkey) != KEY_SIZE:
            raise Exception('Invalid Master Key Size')

        super(Manager, self).__init__(CONF.kds.driver)

    def _get_master_key(self):
        return self.mkey

    def _get_key(self, key_id):
        """Decrypts the provided encoded key and returns
        the clear text key.

        :param key_id: Key Identifier
        """
        mkey = self._get_master_key()
        if not mkey:
            raise exception.UnexpectedError('Failed to find mkey')

        km = self.hkdf.expand(mkey, key_id, 2 * KEY_SIZE)
        ekey = km[KEY_SIZE:]
        skey = km[:KEY_SIZE]

        # Get Requestor's encypted key
        key = self.driver.get_shared_key(key_id)
        if not ekey:
            raise exception.Unauthorized('Invalid Requestor')
        sig = key[:self.crypto.hashfn.digest_size]
        enc = key[self.crypto.hashfn.digest_size:]

        # signature check
        try:
            sigc = self.crypto.sign(skey, enc, b64decode=False)
            if not sigc == sig:
                raise
        except:
            raise exception.UnexpectedError('Failed to verify key')

        try:
            plain = self.crypto.decrypt(ekey, enc, b64decode=False)
        except:
            raise exception.UnexpectedError('Failed to decrypt key')

        return plain

    def _set_key(self, key_id, keyblock):
        """Encrypts the provided key and returns it.

        :param keyblock: The key to encrypt
        """
        mkey = self._get_master_key()
        if not mkey:
            raise exception.UnexpectedError('Failed to find mkey')

        km = self.hkdf.expand(mkey, key_id, 2 * KEY_SIZE)
        ekey = km[KEY_SIZE:]
        skey = km[:KEY_SIZE]

        try:
            enc = self.crypto.encrypt(ekey, keyblock, b64encode=False)
        except:
            raise exception.UnexpectedError('Failed to encrypt key')

        try:
            sig = self.crypto.sign(skey, enc, b64encode=False)
        except:
            raise exception.UnexpectedError('Failed to sign key')

        self.driver.set_shared_key(key_id, sig + enc)

    def get_sek(self, context, req):
        if not ('metadata' in req):
            raise exception.Forbidden('Invalid Request format')
        meta = req['metadata']
        if not ('requestor' in meta):
            raise exception.Forbidden('Invalid Request format')

        rkey = self._get_key(meta['requestor'])

        try:
            signature = self.crypto.sign(rkey, req['metadata'])
        except:
            raise exception.Unauthorized('Invalid Request')

        if signature != req['signature']:
            raise exception.Unauthorized('Invalid Request')

        if meta['timestamp'] < (time.time() - self.ttl):
            raise exception.Unauthorized('Invalid Request')

        #TODO(simo): check and store signature for replay attack detection

        tkey = self.driver._get_key(meta['target'])
        if not tkey:
            raise exception.Unauthorized('Invalid Target')

        # use new_key to get a random salt
        rndkey = self.hkdf.extract(rkey, self.crypto.new_key(KEY_SIZE))

        info = (meta['requestor'] + '\x00'
                + meta['target'] + '\x00'
                + str(keydata['timestamp']))

        sek = self.hkdf.expand(rndkey, info, KEY_SIZE * 2)
        skey = base64.encode(sek[KEY_LENGTH:])
        ekey = base64.encode(sek[:KEY_LENGTH])
        keydata = {'key': base64.b64encode(rndkey),
                   'timestamp': time.time(),
                   'ttl': self.ttl}
        esek = self.crypto.encrypt(tkey, jsonutils.dumps(keydata))
        sekstore = jsonutils.dumps({'skey':skey, 'ekey':ekey, 'esek':esek})

        rep = {'metadata': jsonutils.dumps({'source': meta['requestor'],
                                            'destination': meta['target'],
                                            'expiration':(keydata['timestamp']
                                                          + keydata['ttl']),
                                            'encryption': True}),
               'sekstore': self.crypto.encrypt(rkey, sekstore),
               'signature': self.crypto.sign(rkey, (rep['metadata']
                                                    + rep['sekstore']))}

        return {'reply': rep}

    def set_key(self, context, req):
        # TODO(simo): authorization
        self._set_key(req['owner'], base64.b64decode(req['key']))

class Driver(object):
    """Interface description for a KDS driver."""

    def set_shared_key(self, kds_id, key):
        """Set key related to kds_id."""
        raise exception.NotImplemented()

    def get_shared_key(self, kds_id):
        """Get key related to kds_id.

        :returns: key
        :raises: keystone.exception.ServiceNotFound
        """
        raise exception.NotImplemented()
