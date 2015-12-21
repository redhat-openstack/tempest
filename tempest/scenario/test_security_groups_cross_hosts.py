# Copyright 2013 Red Hat, Inc.
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

from oslo_log import log as logging

from tempest.common import waiters
from tempest.scenario import test_security_groups_basic_ops as base

LOG = logging.getLogger(__name__)


class TestCrossHost(base.TestSecurityGroupsBasicOps):
    """Runs tests in test_security_group_basic_ops

    It enforces that VMs are created on different compute nodes.
    If both VMs are deployed on the same host, try to migrate one of
    them.

    tests:
        1. Security Groups are enforced between hosts
        2. VMs can connect between hosts
        3. implies migration works
    """
    @classmethod
    def resource_setup(cls):
        super(TestCrossHost, cls).resource_setup()
        h_client = cls.admin_manager.hypervisor_client
        hypervisor_list = h_client.list_hypervisors()
        if len(hypervisor_list['hypervisors']) < 2:
            raise cls.skipException("Need at least 2 compute nodes to run")
        LOG.info("Verified multiple Hypervisors exist")

    def setUp(self):
        self.servers = []
        super(TestCrossHost, self).setUp()

    def _create_server(self, name, tenant, security_groups=None):
        server = super(TestCrossHost, self)._create_server(name, tenant,
                                                           security_groups)
        self.servers.append(server)
        host = self.gethost(server)
        LOG.info("Server %s deployed on host %s", server['name'], host)
        if len(self.servers) > 1:
            self.servers = self._distribute_servers()
            LOG.info("2 Servers on 2 Hypervisors")
        return server

    def gethost(self, server):
        client = self.admin_manager.servers_client
        server_details = client.show_server(server['id'])['server']
        return server_details['OS-EXT-SRV-ATTR:host']

    def update_servers(self, servers, client=None):
        if not client:
            client = self.admin_manager.servers_client
        return [serv for serv in servers]

    def _distribute_servers(self):
        """Distribute servers between compute nodes.

        if both servers are on the same compute node, move one to another node
        @return: updated list of servers
        """
        self.assertEqual(2, len(self.servers))
        serv_a, serv_b = self.update_servers(self.servers)
        if self.gethost(serv_a) != self.gethost(serv_b):
            return [serv_a, serv_b]

        self.admin_manager.servers_client.migrate_server(serv_b['id'])
        waiters.wait_for_server_status(
            self.admin_manager.servers_client,
            serv_b['id'],
            'VERIFY_RESIZE')
        self.admin_manager.servers_client.confirm_resize_server(serv_b['id'])
        serv_a, serv_b = self.update_servers(self.servers)
        host = self.gethost(serv_b)
        LOG.info("Server %s migrated to host %s", serv_b, host)
        self.assertNotEqual(self.gethost(serv_a), self.gethost(serv_b),
                            msg="servers aren't deployed on different hosts")
        return [serv_a, serv_b]
