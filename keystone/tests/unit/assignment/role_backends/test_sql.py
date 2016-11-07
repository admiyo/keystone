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

from keystone.common import driver_hints
from keystone.common import sql
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit.assignment import test_core
from keystone.tests.unit.backend import core_sql
from keystone.tests.unit.utils import wip


class SqlRoleModels(core_sql.BaseBackendSqlModels):

    def test_role_model(self):
        cols = (('id', sql.String, 64),
                ('name', sql.String, 255),
                ('domain_id', sql.String, 64))
        self.assertExpectedSchema('role', cols)

    def test_implied_role_model(self):
        cols = (('prior_role_id', sql.String, 64),
                ('implied_role_id', sql.String, 64))
        self.assertExpectedSchema('implied_role', cols)

    def test_url_pattern_model(self):
        pass
        cols = (('id',sql.String,64),
                ('service',sql.String, 64),
                ('verb', sql.String, 64),
                ('pattern', sql.Text, 0))
        self.assertExpectedSchema('url_pattern', cols)

    def test_role_to_url_pattern_model(self):
        pass
        cols = (('role_id', sql.String, 64),
                ('url_pattern_id', sql.String, 64))
        self.assertExpectedSchema('role_to_url_pattern', cols)


class SqlRole(core_sql.BaseBackendSqlTests, test_core.RoleTests):

    def test_create_null_role_name(self):
        role = unit.new_role_ref(name=None)
        self.assertRaises(exception.UnexpectedError,
                          self.role_api.create_role,
                          role['id'],
                          role)
        self.assertRaises(exception.RoleNotFound,
                          self.role_api.get_role,
                          role['id'])

    def test_create_duplicate_role_domain_specific_name_fails(self):
        domain = unit.new_domain_ref()
        role1 = unit.new_role_ref(domain_id=domain['id'])
        self.role_api.create_role(role1['id'], role1)
        role2 = unit.new_role_ref(name=role1['name'],
                                  domain_id=domain['id'])
        self.assertRaises(exception.Conflict,
                          self.role_api.create_role,
                          role2['id'],
                          role2)

    def test_update_domain_id_of_role_fails(self):
        # Create a global role
        role1 = unit.new_role_ref()
        role1 = self.role_api.create_role(role1['id'], role1)
        # Try and update it to be domain specific
        domainA = unit.new_domain_ref()
        role1['domain_id'] = domainA['id']
        self.assertRaises(exception.ValidationError,
                          self.role_api.update_role,
                          role1['id'],
                          role1)

        # Create a domain specific role from scratch
        role2 = unit.new_role_ref(domain_id=domainA['id'])
        self.role_api.create_role(role2['id'], role2)
        # Try to "move" it to another domain
        domainB = unit.new_domain_ref()
        role2['domain_id'] = domainB['id']
        self.assertRaises(exception.ValidationError,
                          self.role_api.update_role,
                          role2['id'],
                          role2)
        # Now try to make it global
        role2['domain_id'] = None
        self.assertRaises(exception.ValidationError,
                          self.role_api.update_role,
                          role2['id'],
                          role2)

    def test_domain_specific_separation(self):
        domain1 = unit.new_domain_ref()
        role1 = unit.new_role_ref(domain_id=domain1['id'])
        role_ref1 = self.role_api.create_role(role1['id'], role1)
        self.assertDictEqual(role1, role_ref1)
        # Check we can have the same named role in a different domain
        domain2 = unit.new_domain_ref()
        role2 = unit.new_role_ref(name=role1['name'], domain_id=domain2['id'])
        role_ref2 = self.role_api.create_role(role2['id'], role2)
        self.assertDictEqual(role2, role_ref2)
        # ...and in fact that you can have the same named role as a global role
        role3 = unit.new_role_ref(name=role1['name'])
        role_ref3 = self.role_api.create_role(role3['id'], role3)
        self.assertDictEqual(role3, role_ref3)
        # Check that updating one doesn't change the others
        role1['name'] = uuid.uuid4().hex
        self.role_api.update_role(role1['id'], role1)
        role_ref1 = self.role_api.get_role(role1['id'])
        self.assertDictEqual(role1, role_ref1)
        role_ref2 = self.role_api.get_role(role2['id'])
        self.assertDictEqual(role2, role_ref2)
        role_ref3 = self.role_api.get_role(role3['id'])
        self.assertDictEqual(role3, role_ref3)
        # Check that deleting one of these, doesn't affect the others
        self.role_api.delete_role(role1['id'])
        self.assertRaises(exception.RoleNotFound,
                          self.role_api.get_role,
                          role1['id'])
        self.role_api.get_role(role2['id'])
        self.role_api.get_role(role3['id'])


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
