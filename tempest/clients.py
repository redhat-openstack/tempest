# Copyright 2012 OpenStack Foundation
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

from tempest import config
from tempest.lib import auth
from tempest.lib import exceptions as lib_exc
from tempest.lib.services import clients
from tempest.lib.services import identity
from tempest.services import object_storage
from tempest.services import orchestration

CONF = config.CONF
LOG = logging.getLogger(__name__)


class Manager(clients.ServiceClients):
    """Top level manager for OpenStack tempest clients"""

    default_params = config.service_client_config()

    # TODO(jordanP): remove this once no Tempest plugin use that class
    # variable.
    default_params_with_timeout_values = {
        'build_interval': CONF.compute.build_interval,
        'build_timeout': CONF.compute.build_timeout
    }
    default_params_with_timeout_values.update(default_params)

    def __init__(self, credentials, scope='project'):
        """Initialization of Manager class.

        Setup all services clients and make them available for tests cases.
        :param credentials: type Credentials or TestResources
        :param scope: default scope for tokens produced by the auth provider
        """
        _, identity_uri = get_auth_provider_class(credentials)
        super(Manager, self).__init__(
            credentials=credentials, identity_uri=identity_uri, scope=scope,
            region=CONF.identity.region,
            client_parameters=self._prepare_configuration())
        # TODO(andreaf) When clients are initialised without the right
        # parameters available, the calls below will trigger a KeyError.
        # We should catch that and raise a better error.
        self._set_compute_clients()
        self._set_identity_clients()
        self._set_volume_clients()
        self._set_object_storage_clients()
        self._set_image_clients()
        self._set_network_clients()

        self.orchestration_client = orchestration.OrchestrationClient(
            self.auth_provider,
            CONF.orchestration.catalog_type,
            CONF.orchestration.region or CONF.identity.region,
            endpoint_type=CONF.orchestration.endpoint_type,
            build_interval=CONF.orchestration.build_interval,
            build_timeout=CONF.orchestration.build_timeout,
            **self.default_params)

    def _prepare_configuration(self):
        """Map values from CONF into Manager parameters

        This uses `config.service_client_config` for all services to collect
        most configuration items needed to init the clients.
        """
        # NOTE(andreaf) Once all service clients in Tempest are migrated
        # to tempest.lib, their configuration will be picked up from the
        # registry, and this method will become redundant.

        configuration = {}

        # Setup the parameters for all Tempest services which are not in lib.
        # NOTE(andreaf) Since client.py is an internal module of Tempest,
        # it doesn't have to consider plugin configuration.
        for service in clients._tempest_internal_modules():
            try:
                # NOTE(andreaf) Use the unversioned service name to fetch
                # the configuration since configuration is not versioned.
                service_for_config = service.split('.')[0]
                if service_for_config not in configuration:
                    configuration[service_for_config] = (
                        config.service_client_config(service_for_config))
            except lib_exc.UnknownServiceClient:
                LOG.warning(
                    'Could not load configuration for service %s', service)

        return configuration

    def _set_network_clients(self):
        self.network_agents_client = self.network.AgentsClient()
        self.network_extensions_client = self.network.ExtensionsClient()
        self.networks_client = self.network.NetworksClient()
        self.subnetpools_client = self.network.SubnetpoolsClient()
        self.subnets_client = self.network.SubnetsClient()
        self.ports_client = self.network.PortsClient()
        self.network_quotas_client = self.network.QuotasClient()
        self.floating_ips_client = self.network.FloatingIPsClient()
        self.metering_labels_client = self.network.MeteringLabelsClient()
        self.metering_label_rules_client = (
            self.network.MeteringLabelRulesClient())
        self.routers_client = self.network.RoutersClient()
        self.security_group_rules_client = (
            self.network.SecurityGroupRulesClient())
        self.security_groups_client = self.network.SecurityGroupsClient()
        self.network_versions_client = self.network.NetworkVersionsClient()
        self.service_providers_client = self.network.ServiceProvidersClient()

    def _set_image_clients(self):
        if CONF.service_available.glance:
            self.image_client = self.image_v1.ImagesClient()
            self.image_member_client = self.image_v1.ImageMembersClient()
            self.image_client_v2 = self.image_v2.ImagesClient()
            self.image_member_client_v2 = self.image_v2.ImageMembersClient()
            self.namespaces_client = self.image_v2.NamespacesClient()
            self.resource_types_client = self.image_v2.ResourceTypesClient()
            self.namespace_objects_client = \
                self.image_v2.NamespaceObjectsClient()
            self.schemas_client = self.image_v2.SchemasClient()
            self.namespace_properties_client = \
                self.image_v2.NamespacePropertiesClient()

    def _set_compute_clients(self):
        self.agents_client = self.compute.AgentsClient()
        self.compute_networks_client = self.compute.NetworksClient()
        self.migrations_client = self.compute.MigrationsClient()
        self.security_group_default_rules_client = (
            self.compute.SecurityGroupDefaultRulesClient())
        self.certificates_client = self.compute.CertificatesClient()
        eip = CONF.compute_feature_enabled.enable_instance_password
        self.servers_client = self.compute.ServersClient(
            enable_instance_password=eip)
        self.server_groups_client = self.compute.ServerGroupsClient()
        self.limits_client = self.compute.LimitsClient()
        self.compute_images_client = self.compute.ImagesClient()
        self.keypairs_client = self.compute.KeyPairsClient()
        self.quotas_client = self.compute.QuotasClient()
        self.quota_classes_client = self.compute.QuotaClassesClient()
        self.flavors_client = self.compute.FlavorsClient()
        self.extensions_client = self.compute.ExtensionsClient()
        self.floating_ip_pools_client = self.compute.FloatingIPPoolsClient()
        self.floating_ips_bulk_client = self.compute.FloatingIPsBulkClient()
        self.compute_floating_ips_client = self.compute.FloatingIPsClient()
        self.compute_security_group_rules_client = (
            self.compute.SecurityGroupRulesClient())
        self.compute_security_groups_client = (
            self.compute.SecurityGroupsClient())
        self.interfaces_client = self.compute.InterfacesClient()
        self.fixed_ips_client = self.compute.FixedIPsClient()
        self.availability_zone_client = self.compute.AvailabilityZoneClient()
        self.aggregates_client = self.compute.AggregatesClient()
        self.services_client = self.compute.ServicesClient()
        self.tenant_usages_client = self.compute.TenantUsagesClient()
        self.hosts_client = self.compute.HostsClient()
        self.hypervisor_client = self.compute.HypervisorClient()
        self.instance_usages_audit_log_client = (
            self.compute.InstanceUsagesAuditLogClient())
        self.tenant_networks_client = self.compute.TenantNetworksClient()

        # NOTE: The following client needs special timeout values because
        # the API is a proxy for the other component.
        params_volume = {}
        for _key in ('build_interval', 'build_timeout'):
            _value = self.parameters['volume'].get(_key)
            if _value:
                params_volume[_key] = _value
        self.volumes_extensions_client = self.compute.VolumesClient(
            **params_volume)
        self.compute_versions_client = self.compute.VersionsClient(
            **params_volume)
        self.snapshots_extensions_client = self.compute.SnapshotsClient(
            **params_volume)

    def _set_identity_clients(self):
        # Clients below use the admin endpoint type of Keystone API v2
        params_v2_admin = {
            'endpoint_type': CONF.identity.v2_admin_endpoint_type}
        self.endpoints_client = self.identity_v2.EndpointsClient(
            **params_v2_admin)
        self.identity_client = self.identity_v2.IdentityClient(
            **params_v2_admin)
        self.tenants_client = self.identity_v2.TenantsClient(
            **params_v2_admin)
        self.roles_client = self.identity_v2.RolesClient(**params_v2_admin)
        self.users_client = self.identity_v2.UsersClient(**params_v2_admin)
        self.identity_services_client = self.identity_v2.ServicesClient(
            **params_v2_admin)

        # Clients below use the public endpoint type of Keystone API v2
        params_v2_public = {
            'endpoint_type': CONF.identity.v2_public_endpoint_type}
        self.identity_public_client = self.identity_v2.IdentityClient(
            **params_v2_public)
        self.tenants_public_client = self.identity_v2.TenantsClient(
            **params_v2_public)
        self.users_public_client = self.identity_v2.UsersClient(
            **params_v2_public)

        # Clients below use the endpoint type of Keystone API v3, which is set
        # in endpoint_type
        params_v3 = {'endpoint_type': CONF.identity.v3_endpoint_type}
        self.domains_client = self.identity_v3.DomainsClient(**params_v3)
        self.identity_v3_client = self.identity_v3.IdentityClient(**params_v3)
        self.trusts_client = self.identity_v3.TrustsClient(**params_v3)
        self.users_v3_client = self.identity_v3.UsersClient(**params_v3)
        self.endpoints_v3_client = self.identity_v3.EndPointsClient(
            **params_v3)
        self.roles_v3_client = self.identity_v3.RolesClient(**params_v3)
        self.inherited_roles_client = self.identity_v3.InheritedRolesClient(
            **params_v3)
        self.role_assignments_client = self.identity_v3.RoleAssignmentsClient(
            **params_v3)
        self.identity_services_v3_client = self.identity_v3.ServicesClient(
            **params_v3)
        self.policies_client = self.identity_v3.PoliciesClient(**params_v3)
        self.projects_client = self.identity_v3.ProjectsClient(**params_v3)
        self.regions_client = self.identity_v3.RegionsClient(**params_v3)
        self.credentials_client = self.identity_v3.CredentialsClient(
            **params_v3)
        self.groups_client = self.identity_v3.GroupsClient(**params_v3)

        # Token clients do not use the catalog. They only need default_params.
        # They read auth_url, so they should only be set if the corresponding
        # API version is marked as enabled
        if CONF.identity_feature_enabled.api_v2:
            if CONF.identity.uri:
                self.token_client = identity.v2.TokenClient(
                    CONF.identity.uri, **self.default_params)
            else:
                msg = 'Identity v2 API enabled, but no identity.uri set'
                raise lib_exc.InvalidConfiguration(msg)
        if CONF.identity_feature_enabled.api_v3:
            if CONF.identity.uri_v3:
                self.token_v3_client = identity.v3.V3TokenClient(
                    CONF.identity.uri_v3, **self.default_params)
            else:
                msg = 'Identity v3 API enabled, but no identity.uri_v3 set'
                raise lib_exc.InvalidConfiguration(msg)

    def _set_volume_clients(self):

        self.volume_qos_client = self.volume_v1.QosSpecsClient()
        self.volume_qos_v2_client = self.volume_v2.QosSpecsClient()
        self.volume_services_client = self.volume_v1.ServicesClient()
        self.volume_services_v2_client = self.volume_v2.ServicesClient()
        self.backups_client = self.volume_v1.BackupsClient()
        self.backups_v2_client = self.volume_v2.BackupsClient()
        self.encryption_types_client = self.volume_v1.EncryptionTypesClient()
        self.encryption_types_v2_client = \
            self.volume_v2.EncryptionTypesClient()
        self.snapshots_client = self.volume_v1.SnapshotsClient()
        self.snapshots_v2_client = self.volume_v2.SnapshotsClient()
        self.volumes_client = self.volume_v1.VolumesClient()
        self.volumes_v2_client = self.volume_v2.VolumesClient()
        self.volume_v3_messages_client = self.volume_v3.MessagesClient()
        self.volume_types_client = self.volume_v1.TypesClient()
        self.volume_types_v2_client = self.volume_v2.TypesClient()
        self.volume_hosts_client = self.volume_v1.HostsClient()
        self.volume_hosts_v2_client = self.volume_v2.HostsClient()
        self.volume_quotas_client = self.volume_v1.QuotasClient()
        self.volume_quotas_v2_client = self.volume_v2.QuotasClient()
        self.volumes_extension_client = self.volume_v1.ExtensionsClient()
        self.volumes_v2_extension_client = self.volume_v2.ExtensionsClient()
        self.volume_availability_zone_client = \
            self.volume_v1.AvailabilityZoneClient()
        self.volume_v2_availability_zone_client = \
            self.volume_v2.AvailabilityZoneClient()
        self.volume_limits_client = self.volume_v1.LimitsClient()
        self.volume_v2_limits_client = self.volume_v2.LimitsClient()
        self.volume_capabilities_v2_client = \
            self.volume_v2.CapabilitiesClient()
        self.volume_scheduler_stats_v2_client = \
            self.volume_v2.SchedulerStatsClient()

    def _set_object_storage_clients(self):
        # Mandatory parameters (always defined)
        params = self.parameters['object-storage']

        self.account_client = object_storage.AccountClient(self.auth_provider,
                                                           **params)
        self.capabilities_client = object_storage.CapabilitiesClient(
            self.auth_provider, **params)
        self.container_client = object_storage.ContainerClient(
            self.auth_provider, **params)
        self.object_client = object_storage.ObjectClient(self.auth_provider,
                                                         **params)


def get_auth_provider_class(credentials):
    if isinstance(credentials, auth.KeystoneV3Credentials):
        return auth.KeystoneV3AuthProvider, CONF.identity.uri_v3
    else:
        return auth.KeystoneV2AuthProvider, CONF.identity.uri


def get_auth_provider(credentials, pre_auth=False, scope='project'):
    # kwargs for auth provider match the common ones used by service clients
    default_params = config.service_client_config()
    if credentials is None:
        raise lib_exc.InvalidCredentials(
            'Credentials must be specified')
    auth_provider_class, auth_url = get_auth_provider_class(
        credentials)
    _auth_provider = auth_provider_class(credentials, auth_url,
                                         scope=scope,
                                         **default_params)
    if pre_auth:
        _auth_provider.set_auth()
    return _auth_provider
