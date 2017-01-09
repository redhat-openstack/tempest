# Copyright (c) 2016 Hewlett-Packard Enterprise Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

from tempest.lib.services.identity.v3.credentials_client import \
    CredentialsClient
from tempest.lib.services.identity.v3.domains_client import DomainsClient
from tempest.lib.services.identity.v3.endpoints_client import EndPointsClient
from tempest.lib.services.identity.v3.groups_client import GroupsClient
from tempest.lib.services.identity.v3.identity_client import IdentityClient
from tempest.lib.services.identity.v3.inherited_roles_client import \
    InheritedRolesClient
from tempest.lib.services.identity.v3.policies_client import PoliciesClient
from tempest.lib.services.identity.v3.projects_client import ProjectsClient
from tempest.lib.services.identity.v3.regions_client import RegionsClient
from tempest.lib.services.identity.v3.role_assignments_client import \
    RoleAssignmentsClient
from tempest.lib.services.identity.v3.roles_client import RolesClient
from tempest.lib.services.identity.v3.services_client import ServicesClient
from tempest.lib.services.identity.v3.token_client import V3TokenClient
from tempest.lib.services.identity.v3.trusts_client import TrustsClient
from tempest.lib.services.identity.v3.users_client import UsersClient

__all__ = ['CredentialsClient', 'DomainsClient', 'EndPointsClient',
           'GroupsClient', 'IdentityClient', 'InheritedRolesClient',
           'PoliciesClient', 'ProjectsClient', 'RegionsClient',
           'RoleAssignmentsClient', 'RolesClient', 'ServicesClient',
           'V3TokenClient', 'TrustsClient', 'UsersClient', ]
