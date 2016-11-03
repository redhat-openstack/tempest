# Copyright 2016 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from tempest.api.object_storage import base
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest import test


class ContainerNegativeTest(base.BaseObjectTest):

    @classmethod
    def resource_setup(cls):
        super(ContainerNegativeTest, cls).resource_setup()

        # use /info to get default constraints
        _, body = cls.account_client.list_extensions()
        cls.constraints = body['swift']

    @test.attr(type=["negative"])
    @test.idempotent_id('30686921-4bed-4764-a038-40d741ed4e78')
    def test_create_container_name_exceeds_max_length(self):
        # Attempts to create a container name that is longer than max
        max_length = self.constraints['max_container_name_length']
        # create a container with long name
        container_name = data_utils.arbitrary_string(size=max_length + 1)
        ex = self.assertRaises(exceptions.BadRequest,
                               self.container_client.create_container,
                               container_name)
        self.assertIn('Container name length of ' + str(max_length + 1) +
                      ' longer than ' + str(max_length), str(ex))

    @test.attr(type=["negative"])
    @test.idempotent_id('41e645bf-2e68-4f84-bf7b-c71aa5cd76ce')
    def test_create_container_metadata_name_exceeds_max_length(self):
        # Attempts to create container with metadata name
        # that is longer than max.
        max_length = self.constraints['max_meta_name_length']
        container_name = data_utils.rand_name(name='TestContainer')
        metadata_name = data_utils.arbitrary_string(size=max_length + 1)
        metadata = {metadata_name: 'penguin'}
        ex = self.assertRaises(exceptions.BadRequest,
                               self.container_client.create_container,
                               container_name, metadata=metadata)
        self.assertIn('Metadata name too long', str(ex))

    @test.attr(type=["negative"])
    @test.idempotent_id('81e36922-326b-4b7c-8155-3bbceecd7a82')
    def test_create_container_metadata_value_exceeds_max_length(self):
        # Attempts to create container with metadata value
        # that is longer than max.
        max_length = self.constraints['max_meta_value_length']
        container_name = data_utils.rand_name(name='TestContainer')
        metadata_value = data_utils.arbitrary_string(size=max_length + 1)
        metadata = {'animal': metadata_value}
        ex = self.assertRaises(exceptions.BadRequest,
                               self.container_client.create_container,
                               container_name, metadata=metadata)
        self.assertIn('Metadata value longer than ' + str(max_length), str(ex))

    @test.attr(type=["negative"])
    @test.idempotent_id('ac666539-d566-4f02-8ceb-58e968dfb732')
    def test_create_container_metadata_exceeds_overall_metadata_count(self):
        # Attempts to create container with metadata that exceeds the
        # default count
        max_count = self.constraints['max_meta_count']
        container_name = data_utils.rand_name(name='TestContainer')
        metadata = {}
        for i in range(max_count + 1):
            metadata['animal-' + str(i)] = 'penguin'

        ex = self.assertRaises(exceptions.BadRequest,
                               self.container_client.create_container,
                               container_name, metadata=metadata)
        self.assertIn('Too many metadata items; max ' + str(max_count),
                      str(ex))

    @test.attr(type=["negative"])
    @test.idempotent_id('1a95ab2e-b712-4a98-8a4d-8ce21b7557d6')
    def test_get_metadata_headers_with_invalid_container_name(self):
        # Attempts to retrieve metadata headers with an invalid
        # container name.
        invalid_name = data_utils.rand_name(name="TestInvalidContainer")

        self.assertRaises(exceptions.NotFound,
                          self.container_client.list_container_metadata,
                          invalid_name)

    @test.attr(type=["negative"])
    @test.idempotent_id('125a24fa-90a7-4cfc-b604-44e49d788390')
    def test_update_metadata_with_nonexistent_container_name(self):
        # Attempts to update metadata using a nonexistent container name.
        nonexistent_name = data_utils.rand_name(
            name="TestNonexistentContainer")
        metadata = {'animal': 'penguin'}

        self.assertRaises(exceptions.NotFound,
                          self.container_client.update_container_metadata,
                          nonexistent_name, metadata)

    @test.attr(type=["negative"])
    @test.idempotent_id('65387dbf-a0e2-4aac-9ddc-16eb3f1f69ba')
    def test_delete_with_nonexistent_container_name(self):
        # Attempts to delete metadata using a nonexistent container name.
        nonexistent_name = data_utils.rand_name(
            name="TestNonexistentContainer")
        metadata = {'animal': 'penguin'}

        self.assertRaises(exceptions.NotFound,
                          self.container_client.delete_container_metadata,
                          nonexistent_name, metadata)

    @test.attr(type=["negative"])
    @test.idempotent_id('14331d21-1e81-420a-beea-19cb5e5207f5')
    def test_list_all_container_objects_with_nonexistent_container(self):
        # Attempts to get a listing of all objects on a container
        # that doesn't exist.
        nonexistent_name = data_utils.rand_name(
            name="TestNonexistentContainer")
        params = {'limit': 9999, 'format': 'json'}
        self.assertRaises(exceptions.NotFound,
                          self.container_client.list_container_contents,
                          nonexistent_name, params)

    @test.attr(type=["negative"])
    @test.idempotent_id('86b2ab08-92d5-493d-acd2-85f0c848819e')
    def test_list_all_container_objects_on_deleted_container(self):
        # Attempts to get a listing of all objects on a container
        # that was deleted.
        container_name = self.create_container()
        # delete container
        resp, _ = self.container_client.delete_container(container_name)
        self.assertHeaders(resp, 'Container', 'DELETE')
        params = {'limit': 9999, 'format': 'json'}
        self.assertRaises(exceptions.NotFound,
                          self.container_client.list_container_contents,
                          container_name, params)

    @test.attr(type=["negative"])
    @test.idempotent_id('42da116e-1e8c-4c96-9e06-2f13884ed2b1')
    def test_delete_non_empty_container(self):
        # create a container and an object within it
        # attempt to delete a container that isn't empty.
        container_name = self.create_container()
        self.addCleanup(self.container_client.delete_container,
                        container_name)
        object_name, _ = self.create_object(container_name)
        self.addCleanup(self.object_client.delete_object,
                        container_name, object_name)

        ex = self.assertRaises(exceptions.Conflict,
                               self.container_client.delete_container,
                               container_name)
        self.assertIn('An object with that identifier already exists',
                      str(ex))
