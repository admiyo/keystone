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

import copy
import uuid

from keystone.common import driver_hints
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import default_fixtures


class RoleTests(object):

    def test_get_role_returns_not_found(self):
        self.assertRaises(exception.RoleNotFound,
                          self.role_api.get_role,
                          uuid.uuid4().hex)

    def test_create_duplicate_role_name_fails(self):
        role = unit.new_role_ref(id='fake1', name='fake1name')
        self.role_api.create_role('fake1', role)
        role['id'] = 'fake2'
        self.assertRaises(exception.Conflict,
                          self.role_api.create_role,
                          'fake2',
                          role)

    def test_rename_duplicate_role_name_fails(self):
        role1 = unit.new_role_ref(id='fake1', name='fake1name')
        role2 = unit.new_role_ref(id='fake2', name='fake2name')
        self.role_api.create_role('fake1', role1)
        self.role_api.create_role('fake2', role2)
        role1['name'] = 'fake2name'
        self.assertRaises(exception.Conflict,
                          self.role_api.update_role,
                          'fake1',
                          role1)

    def test_role_crud(self):
        role = unit.new_role_ref()
        self.role_api.create_role(role['id'], role)
        role_ref = self.role_api.get_role(role['id'])
        role_ref_dict = {x: role_ref[x] for x in role_ref}
        self.assertDictEqual(role, role_ref_dict)

        role['name'] = uuid.uuid4().hex
        updated_role_ref = self.role_api.update_role(role['id'], role)
        role_ref = self.role_api.get_role(role['id'])
        role_ref_dict = {x: role_ref[x] for x in role_ref}
        self.assertDictEqual(role, role_ref_dict)
        self.assertDictEqual(role_ref_dict, updated_role_ref)

        self.role_api.delete_role(role['id'])
        self.assertRaises(exception.RoleNotFound,
                          self.role_api.get_role,
                          role['id'])

    def test_update_role_returns_not_found(self):
        role = unit.new_role_ref()
        self.assertRaises(exception.RoleNotFound,
                          self.role_api.update_role,
                          role['id'],
                          role)

    def test_list_roles(self):
        roles = self.role_api.list_roles()
        self.assertEqual(len(default_fixtures.ROLES), len(roles))
        role_ids = set(role['id'] for role in roles)
        expected_role_ids = set(role['id'] for role in default_fixtures.ROLES)
        self.assertEqual(expected_role_ids, role_ids)

    @unit.skip_if_cache_disabled('role')
    def test_cache_layer_role_crud(self):
        role = unit.new_role_ref()
        role_id = role['id']
        # Create role
        self.role_api.create_role(role_id, role)
        role_ref = self.role_api.get_role(role_id)
        updated_role_ref = copy.deepcopy(role_ref)
        updated_role_ref['name'] = uuid.uuid4().hex
        # Update role, bypassing the role api manager
        self.role_api.driver.update_role(role_id, updated_role_ref)
        # Verify get_role still returns old ref
        self.assertDictEqual(role_ref, self.role_api.get_role(role_id))
        # Invalidate Cache
        self.role_api.get_role.invalidate(self.role_api, role_id)
        # Verify get_role returns the new role_ref
        self.assertDictEqual(updated_role_ref,
                             self.role_api.get_role(role_id))
        # Update role back to original via the assignment api manager
        self.role_api.update_role(role_id, role_ref)
        # Verify get_role returns the original role ref
        self.assertDictEqual(role_ref, self.role_api.get_role(role_id))
        # Delete role bypassing the role api manager
        self.role_api.driver.delete_role(role_id)
        # Verify get_role still returns the role_ref
        self.assertDictEqual(role_ref, self.role_api.get_role(role_id))
        # Invalidate cache
        self.role_api.get_role.invalidate(self.role_api, role_id)
        # Verify RoleNotFound is now raised
        self.assertRaises(exception.RoleNotFound,
                          self.role_api.get_role,
                          role_id)
        # recreate role
        self.role_api.create_role(role_id, role)
        self.role_api.get_role(role_id)
        # delete role via the assignment api manager
        self.role_api.delete_role(role_id)
        # verity RoleNotFound is now raised
        self.assertRaises(exception.RoleNotFound,
                          self.role_api.get_role,
                          role_id)

    def test_implied_role_crd(self):        
        role1 = unit.new_role_ref(name= uuid.uuid4().hex)
        self.role_api.create_role(role1['id'], role1)
        role2 = unit.new_role_ref(name= uuid.uuid4().hex)
        self.role_api.create_role(role2['id'], role2)
        # Create
        implied_role_created = self.role_api.create_implied_role(
            role1['id'], role2['id'])
        self.assertEquals(role1['id'], implied_role_created['prior_role_id'])
        self.assertEquals(role2['id'], implied_role_created['implied_role_id'])

        # Read 
        implied_role1 = self.role_api.get_implied_role(role1['id'], role2['id'])
        self.assertEquals(implied_role_created, implied_role1)
        self.assertEquals(role1['id'], implied_role1['prior_role_id'])
        self.assertEquals(role2['id'], implied_role1['implied_role_id'])


        role3 = unit.new_role_ref(name= uuid.uuid4().hex)
        self.role_api.create_role(role3['id'], role3)

        self.assertRaises(exception.ImpliedRoleNotFound,
                          self.role_api.get_implied_role,
                          role1['id'], role3['id'])
        
        self.role_api.create_implied_role(role1['id'], role3['id'])
        
        implied_role2 = self.role_api.get_implied_role(role1['id'], role3['id'])
        self.assertEquals(role1['id'], implied_role2['prior_role_id'])
        self.assertEquals(role3['id'], implied_role2['implied_role_id'])

        # Delete
        implied_list = self.role_api.list_implied_roles(role1['id'])
        self.assertEquals(2, len(implied_list))
        self.assertIn(implied_role1, implied_list)
        self.assertIn(implied_role2, implied_list)

        self.role_api.delete_implied_role(role1['id'], role3['id'])
        implied_list = self.role_api.list_implied_roles(role1['id'])
        self.assertEquals(1, len(implied_list))
        self.assertIn(implied_role1, implied_list)

    @wip('This test does not pass yet.')
    def test_deleting_role_removes_inference_rule(self):
    
        role1 = unit.new_role_ref(name= uuid.uuid4().hex)
        self.role_api.create_role(role1['id'], role1)
        role2 = unit.new_role_ref(name= uuid.uuid4().hex)
        self.role_api.create_role(role2['id'], role2)
        self.role_api.create_implied_role(role1['id'], role2['id'])

        implied_role1 = self.role_api.get_implied_role(role1['id'], role2['id'])

        role3 = unit.new_role_ref(name= uuid.uuid4().hex)
        self.role_api.create_role(role3['id'], role3)        
        self.role_api.create_implied_role(role1['id'], role3['id'])
        
        implied_role2 = self.role_api.get_implied_role(role1['id'], role3['id'])

        implied_list = self.role_api.list_implied_roles(role1['id'])
        self.assertEquals(2, len(implied_list))
        self.assertIn(implied_role1, implied_list)
        self.assertIn(implied_role2, implied_list)

        self.role_api.delete_role(role3['id'])
        implied_list = self.role_api.list_implied_roles(role1['id'])
        self.assertEquals(1, len(implied_list))
        self.assertIn(implied_role1, implied_list)
        self.assertIn(implied_role2, implied_list)
                
    def test_url_pattern_crud(self):
        # Create
        service1 = uuid.uuid4().hex
        url_pattern_ref = unit.new_url_pattern_ref()
        url_pattern_ref['service'] = service1
        url_pattern_1_created = self.role_api.create_url_pattern(
            url_pattern_ref['id'], url_pattern_ref)
        self.assertEquals(url_pattern_1_created, url_pattern_ref)

        # Read: Get
        url_pattern_1 = self.role_api.get_url_pattern(url_pattern_ref['id'])
        self.assertEquals(url_pattern_1, url_pattern_ref)
        

        url_pattern_ref = unit.new_url_pattern_ref()
        url_pattern_ref['service'] = service1
        url_pattern_2_created = self.role_api.create_url_pattern(
            url_pattern_ref['id'], url_pattern_ref)


        service2 = uuid.uuid4().hex
        url_pattern_ref = unit.new_url_pattern_ref()
        url_pattern_ref['service'] = service2
        url_pattern_3_created = self.role_api.create_url_pattern(
            url_pattern_ref['id'], url_pattern_ref)

        # Read:  List all
        all_url_patterns = self.role_api.list_url_patterns()
        self.assertEquals(3, len(all_url_patterns))

        hints = driver_hints.Hints()
        all_url_patterns = self.role_api.list_url_patterns(hints)
        self.assertEquals(3, len(all_url_patterns))


        hints.add_filter('service', service1)
        service_1_url_patterns = self.role_api.list_url_patterns(hints)
        self.assertEquals(2, len(service_1_url_patterns))
        self.assertIn(url_pattern_1_created, service_1_url_patterns)
        self.assertIn(url_pattern_2_created, service_1_url_patterns)
        self.assertNotIn(url_pattern_3_created, service_1_url_patterns)

        hints = driver_hints.Hints()
        hints.add_filter('service', service2)
        service_2_url_patterns = self.role_api.list_url_patterns(hints)
        self.assertEquals(1, len(service_2_url_patterns))
        self.assertNotIn(url_pattern_1_created, service_2_url_patterns)
        self.assertNotIn(url_pattern_2_created, service_2_url_patterns)
        self.assertIn(url_pattern_3_created, service_2_url_patterns)


        # Update
        url_pattern_1_id = url_pattern_1['id']
        
        url_pattern_ref = unit.new_url_pattern_ref()
        url_pattern_ref['id'] = url_pattern_1_created['id']
        url_pattern_1_updated = self.role_api.update_url_pattern(
            url_pattern_1_id,
            url_pattern_ref)

        url_pattern_1_gotten = self.role_api.get_url_pattern(
            url_pattern_1_id)
        
        self.assertEquals(url_pattern_ref, url_pattern_1_updated)
        self.assertEquals(url_pattern_1_gotten, url_pattern_1_updated)
        
        #Delete
        all_url_patterns = self.role_api.list_url_patterns()
        self.assertEquals(3, len(all_url_patterns))
        self.assertIn(url_pattern_1_gotten, all_url_patterns)
        self.assertIn(url_pattern_2_created, all_url_patterns)
        self.assertIn(url_pattern_3_created, all_url_patterns)

        
        self.role_api.delete_url_pattern(url_pattern_1_id)
        all_url_patterns = self.role_api.list_url_patterns()
        self.assertEquals(2, len(all_url_patterns))

        self.assertNotIn(url_pattern_1_gotten, all_url_patterns)
        self.assertIn(url_pattern_2_created, all_url_patterns)
        self.assertIn(url_pattern_3_created, all_url_patterns)
