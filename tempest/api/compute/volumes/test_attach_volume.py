# Copyright 2013 IBM Corp.
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

import logging
import testtools

from tempest.api.compute import base
from tempest.common import compute
from tempest.common.utils.linux import remote_client
from tempest.common import waiters
from tempest import config
from tempest.lib import exceptions as lib_exc
from tempest import test

CONF = config.CONF

LOG = logging.getLogger(__name__)


class AttachVolumeTestJSON(base.BaseV2ComputeTest):
    max_microversion = '2.19'

    @classmethod
    def skip_checks(cls):
        super(AttachVolumeTestJSON, cls).skip_checks()
        if not CONF.service_available.cinder:
            skip_msg = ("%s skipped as Cinder is not available" % cls.__name__)
            raise cls.skipException(skip_msg)

    @classmethod
    def setup_credentials(cls):
        cls.prepare_instance_network()
        super(AttachVolumeTestJSON, cls).setup_credentials()

    @classmethod
    def resource_setup(cls):
        cls.set_validation_resources()
        super(AttachVolumeTestJSON, cls).resource_setup()
        cls.device = CONF.compute.volume_device_name

    def _create_server(self):
        # Start a server and wait for it to become ready
        server = self.create_test_server(
            validatable=True,
            wait_until='ACTIVE',
            adminPass=self.image_ssh_password)
        # Record addresses so that we can ssh later
        server['addresses'] = self.servers_client.list_addresses(
            server['id'])['addresses']
        return server

    def _detach_volume(self, server_id, volume_id):
        try:
            self.servers_client.detach_volume(server_id, volume_id)
            waiters.wait_for_volume_status(self.volumes_client,
                                           volume_id, 'available')
        except lib_exc.NotFound:
            LOG.warning("Unable to detach volume %s from server %s "
                        "possibly it was already detached", volume_id,
                        server_id)

    def _attach_volume(self, server_id, volume_id, device=None):
        # Attach the volume to the server
        kwargs = {'volumeId': volume_id}
        if device:
            kwargs.update({'device': '/dev/%s' % device})
        attachment = self.servers_client.attach_volume(
            server_id, **kwargs)['volumeAttachment']
        waiters.wait_for_volume_status(self.volumes_client,
                                       volume_id, 'in-use')
        self.addCleanup(self._detach_volume, server_id,
                        volume_id)

        return attachment

    @test.idempotent_id('52e9045a-e90d-4c0d-9087-79d657faffff')
    def test_attach_detach_volume(self):
        # Stop and Start a server with an attached volume, ensuring that
        # the volume remains attached.
        server = self._create_server()
        volume = self.create_volume()
        attachment = self._attach_volume(server['id'], volume['id'],
                                         device=self.device)

        self.servers_client.stop_server(server['id'])
        waiters.wait_for_server_status(self.servers_client, server['id'],
                                       'SHUTOFF')

        self.servers_client.start_server(server['id'])
        waiters.wait_for_server_status(self.servers_client, server['id'],
                                       'ACTIVE')

        if CONF.validation.run_validation:
            linux_client = remote_client.RemoteClient(
                self.get_server_ip(server),
                self.image_ssh_user,
                self.image_ssh_password,
                self.validation_resources['keypair']['private_key'],
                server=server,
                servers_client=self.servers_client)

            disks = linux_client.get_disks()
            device_name_to_match = '\n' + self.device + ' '
            self.assertIn(device_name_to_match, disks)

        self._detach_volume(server['id'], attachment['volumeId'])
        self.servers_client.stop_server(server['id'])
        waiters.wait_for_server_status(self.servers_client, server['id'],
                                       'SHUTOFF')

        self.servers_client.start_server(server['id'])
        waiters.wait_for_server_status(self.servers_client, server['id'],
                                       'ACTIVE')

        if CONF.validation.run_validation:
            linux_client = remote_client.RemoteClient(
                self.get_server_ip(server),
                self.image_ssh_user,
                self.image_ssh_password,
                self.validation_resources['keypair']['private_key'],
                server=server,
                servers_client=self.servers_client)

            disks = linux_client.get_disks()
            self.assertNotIn(device_name_to_match, disks)

    @test.idempotent_id('7fa563fe-f0f7-43eb-9e22-a1ece036b513')
    def test_list_get_volume_attachments(self):
        # List volume attachment of the server
        server = self._create_server()
        volume = self.create_volume()
        attachment = self._attach_volume(server['id'], volume['id'],
                                         device=self.device)
        body = self.servers_client.list_volume_attachments(
            server['id'])['volumeAttachments']
        self.assertEqual(1, len(body))
        self.assertIn(attachment, body)

        # Get volume attachment of the server
        body = self.servers_client.show_volume_attachment(
            server['id'],
            attachment['id'])['volumeAttachment']
        self.assertEqual(server['id'], body['serverId'])
        self.assertEqual(volume['id'], body['volumeId'])
        self.assertEqual(attachment['id'], body['id'])

    @test.idempotent_id('757d488b-a951-4bc7-b3cd-f417028da08a')
    def test_list_get_two_volume_attachments(self):
        # NOTE: This test is using the volume device auto-assignment
        # without specifying the device ("/dev/sdb", etc). The feature
        # is supported since Nova Liberty release or later. So this should
        # be skipped on older clouds.
        server = self._create_server()
        volume_1st = self.create_volume()
        volume_2nd = self.create_volume()
        attachment_1st = self._attach_volume(server['id'], volume_1st['id'])
        attachment_2nd = self._attach_volume(server['id'], volume_2nd['id'])

        body = self.servers_client.list_volume_attachments(
            server['id'])['volumeAttachments']
        self.assertEqual(2, len(body))

        body = self.servers_client.show_volume_attachment(
            server['id'],
            attachment_1st['id'])['volumeAttachment']
        self.assertEqual(server['id'], body['serverId'])
        self.assertEqual(attachment_1st['volumeId'], body['volumeId'])
        self.assertEqual(attachment_1st['id'], body['id'])

        body = self.servers_client.show_volume_attachment(
            server['id'],
            attachment_2nd['id'])['volumeAttachment']
        self.assertEqual(server['id'], body['serverId'])
        self.assertEqual(attachment_2nd['volumeId'], body['volumeId'])
        self.assertEqual(attachment_2nd['id'], body['id'])


class AttachVolumeShelveTestJSON(AttachVolumeTestJSON):
    """Testing volume with shelved instance.

    This test checks the attaching and detaching volumes from
    a shelved or shelved offload instance.
    """

    min_microversion = '2.20'
    max_microversion = 'latest'

    def _count_volumes(self, server):
        # Count number of volumes on an instance
        volumes = 0
        if CONF.validation.run_validation:
            linux_client = remote_client.RemoteClient(
                self.get_server_ip(server),
                self.image_ssh_user,
                self.image_ssh_password,
                self.validation_resources['keypair']['private_key'],
                server=server,
                servers_client=self.servers_client)

            command = 'grep -c -E [vs]d.$ /proc/partitions'
            volumes = int(linux_client.exec_command(command).strip())
        return volumes

    def _shelve_server(self, server):
        # NOTE(andreaf) If we are going to shelve a server, we should
        # check first whether the server is ssh-able. Otherwise we
        # won't be able to distinguish failures introduced by shelve
        # from pre-existing ones. Also it's good to wait for cloud-init
        # to be done and sshd server to be running before shelving to
        # avoid breaking the VM
        if CONF.validation.run_validation:
            linux_client = remote_client.RemoteClient(
                self.get_server_ip(server),
                self.image_ssh_user,
                self.image_ssh_password,
                self.validation_resources['keypair']['private_key'],
                server=server,
                servers_client=self.servers_client)
            linux_client.validate_authentication()

        # If validation went ok, or it was skipped, shelve the server
        compute.shelve_server(self.servers_client, server['id'])

    def _unshelve_server_and_check_volumes(self, server, number_of_volumes):
        # Unshelve the instance and check that there are expected volumes
        self.servers_client.unshelve_server(server['id'])
        waiters.wait_for_server_status(self.servers_client,
                                       server['id'],
                                       'ACTIVE')
        if CONF.validation.run_validation:
            counted_volumes = self._count_volumes(server)
            self.assertEqual(number_of_volumes, counted_volumes)

    @test.idempotent_id('13a940b6-3474-4c3c-b03f-29b89112bfee')
    @testtools.skipUnless(CONF.compute_feature_enabled.shelve,
                          'Shelve is not available.')
    def test_attach_volume_shelved_or_offload_server(self):
        # Create server, count number of volumes on it, shelve
        # server and attach pre-created volume to shelved server
        server = self._create_server()
        volume = self.create_volume()
        num_vol = self._count_volumes(server)
        self._shelve_server(server)
        attachment = self._attach_volume(server['id'], volume['id'],
                                         device=self.device)

        # Unshelve the instance and check that attached volume exists
        self._unshelve_server_and_check_volumes(server, num_vol + 1)

        # Get volume attachment of the server
        volume_attachment = self.servers_client.show_volume_attachment(
            server['id'],
            attachment['id'])['volumeAttachment']
        self.assertEqual(server['id'], volume_attachment['serverId'])
        self.assertEqual(attachment['id'], volume_attachment['id'])
        # Check the mountpoint is not None after unshelve server even in
        # case of shelved_offloaded.
        self.assertIsNotNone(volume_attachment['device'])

    @test.idempotent_id('b54e86dd-a070-49c4-9c07-59ae6dae15aa')
    @testtools.skipUnless(CONF.compute_feature_enabled.shelve,
                          'Shelve is not available.')
    def test_detach_volume_shelved_or_offload_server(self):
        # Count number of volumes on instance, shelve
        # server and attach pre-created volume to shelved server
        server = self._create_server()
        volume = self.create_volume()
        num_vol = self._count_volumes(server)
        self._shelve_server(server)
        self._attach_volume(server['id'], volume['id'], device=self.device)
        # Detach the volume
        self._detach_volume(server['id'], volume['id'])

        # Unshelve the instance and check that we have the expected number of
        # volume(s)
        self._unshelve_server_and_check_volumes(server, num_vol)
