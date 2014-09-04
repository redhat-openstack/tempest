#!/usr/bin/env python

# Copyright 2014 Red Hat, Inc.
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

import argparse
import ConfigParser
import glanceclient as glance_client
import keystoneclient.exceptions as keystone_exception
import keystoneclient.v2_0.client as keystone_client
import logging
import neutronclient.v2_0.client as neutron_client
import novaclient.client as nova_client
import os
import shutil
import subprocess
import tempfile
import urllib2

from tempest.common import api_discovery

LOG = logging.getLogger(__name__)
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

TEMPEST_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

DEFAULTS_FILE = os.path.join(TEMPEST_DIR, "etc", "default-overrides.conf")
DEFAULT_IMAGE = "http://download.cirros-cloud.net/0.3.1/" \
                "cirros-0.3.1-x86_64-disk.img"

# services and their codenames
SERVICE_NAMES = {
    'baremetal': 'ironic',
    'compute': 'nova',
    'database': 'trove',
    'data_processing': 'sahara',
    'image': 'glance',
    'network': 'neutron',
    'object-store': 'swift',
    'orchestration': 'heat',
    'telemetry': 'ceilometer',
    'volume': 'cinder',
    'queuing': 'marconi',
}

# what API versions could the service have and should be enabled/disabled
# depending on whether they get discovered as supported. Services with only one
# version don't need to be here, neither do service versions that are not
# configurable in tempest.conf
SERVICE_VERSIONS = {
    'image': ['v1', 'v2'],
    'identity': ['v2', 'v3'],
    'volume': ['v1', 'v2'],
    'compute': ['v3'],
}

# Keep track of where the extensions are saved for that service.
# This is necessary because the configuration file is inconsistent - it uses
# different option names for service extension depending on the service.
SERVICE_EXTENSION_KEY = {
    'compute': 'discoverable_apis',
    'object-storage': 'discoverable_apis',
    'network': 'api_extensions',
    'volume': 'api_extensions',
}


def main():
    args = parse_arguments()
    logging.basicConfig(format=LOG_FORMAT)

    if args.verbose:
        LOG.setLevel(logging.INFO)
    if args.debug:
        LOG.setLevel(logging.DEBUG)

    conf = TempestConf()
    if os.path.isfile(DEFAULTS_FILE):
        LOG.info("Reading defaults from file '%s'", DEFAULTS_FILE)
        conf.read(DEFAULTS_FILE)
    if args.patch and os.path.isfile(args.patch):
        LOG.info("Adding options from patch file '%s'", args.patch)
        conf.read(args.patch)
    for section, key, value in args.overrides:
        conf.set(section, key, value, priority=True)

    uri = conf.get("identity", "uri")
    conf.set("identity", "uri_v3", uri.replace("v2.0", "v3"))
    if args.non_admin:
        conf.set("identity", "admin_username", "")
        conf.set("identity", "admin_tenant_name", "")
        conf.set("identity", "admin_password", "")
        conf.set("compute", "allow_tenant_isolation", "False")

    manager = ClientManager(conf, not args.non_admin)
    services = api_discovery.discover(manager.identity_client)
    has_neutron = "network" in services
    if has_neutron:
        manager.add_neutron_client()
    if args.create:
        LOG.info("Creating resources")
        create_tempest_users(manager.identity_client, conf)
    else:
        LOG.info("Querying resources")
    create_tempest_flavors(manager.compute_client, conf, args.create)
    manager.do_images(args.image, args.create)
    manager.do_networks(has_neutron, args.create)
    configure_discovered_services(conf, services)
    configure_boto(conf, services)
    configure_cli(conf)
    configure_horizon(conf)
    LOG.info("Creating configuration file %s" % os.path.abspath(args.out))
    with open(args.out, 'w') as f:
        conf.write(f)


def parse_arguments():
    parser = argparse.ArgumentParser("Generate the tempest.conf file")
    parser.add_argument('--create', action='store_true', default=False,
                        help='create default tempest resources')
    parser.add_argument('--out', default="etc/tempest.conf",
                        help='the tempest.conf file to write')
    parser.add_argument('--patch', default=None,
                        help="""A file in the format of tempest.conf that will
                                override the default values. The
                                patch file is an alternative to providing
                                key/value pairs. If there are also key/value
                                pairs they will be applied after the patch
                                file""")
    parser.add_argument('overrides', nargs='*', default=[],
                        help="""key value pairs to modify. The key is
                                section.key where section is a section header
                                in the conf file.
                                For example: identity.username myname
                                 identity.password mypass""")
    parser.add_argument('--debug', action='store_true', default=False,
                        help='Print debugging information')
    parser.add_argument('--verbose', '-v', action='store_true', default=False,
                        help='Print more information about the execution')
    parser.add_argument('--non-admin', action='store_true', default=False,
                        help='Run without admin creds')
    parser.add_argument('--image', default=DEFAULT_IMAGE,
                        help="""an image to be uploaded to glance. The name of
                                the image is the leaf name of the path which
                                can be either a filename or url. Default is
                                '%s'""" % DEFAULT_IMAGE)
    args = parser.parse_args()

    if args.create and args.non_admin:
        raise Exception("Options '--create' and '--non-admin' cannot be used"
                        " together, since creating" " resources requires"
                        " admin rights")
    args.overrides = parse_overrides(args.overrides)
    return args


def parse_overrides(overrides):
    """Manual parsing of positional arguments.

    TODO(mkollaro) find a way to do it in argparse
    """
    if len(overrides) % 2 != 0:
        raise Exception("An odd number of override options was found. The"
                        " overrides have to be in 'section.key value' format.")
    i = 0
    new_overrides = []
    while i < len(overrides):
        section_key = overrides[i].split('.')
        value = overrides[i + 1]
        if len(section_key) != 2:
            raise Exception("Missing dot. The option overrides has to come in"
                            " the format 'section.key value', but got '%s'."
                            % (overrides[i] + ' ' + value))
        section, key = section_key
        new_overrides.append((section, key, value))
        i += 2
    return new_overrides


class ClientManager(object):
    """
    Manager that provides access to the official python clients for
    calling various OpenStack APIs.
    """
    def __init__(self, conf, admin):
        self.conf = conf
        insecure = conf.get('identity', 'disable_ssl_certificate_validation')
        auth_url = conf.get('identity', 'uri')
        if admin:
            username = conf.get('identity', 'admin_username')
            password = conf.get('identity', 'admin_password')
            tenant_name = conf.get('identity', 'admin_tenant_name')
        else:
            username = conf.get('identity', 'username', 'demo')
            password = conf.get('identity', 'password', 'secret')
            tenant_name = conf.get('identity', 'tenant_name', 'demo')
        # identity client
        creds = {'username': username,
                 'password': password,
                 'tenant_name': tenant_name,
                 'auth_url': auth_url,
                 'insecure': insecure
                 }
        LOG.info("Connecting to keystone at '%s' with username '%s',"
                 " tenant '%s', and password '%s'", auth_url, username,
                 tenant_name, password)
        self.identity_client = keystone_client.Client(**creds)

        # compute client
        kwargs = {'insecure': insecure,
                  'no_cache': True}
        self.compute_client = nova_client.Client('2', username, password,
                                                 tenant_name, auth_url,
                                                 **kwargs)

        # image client
        token = self.identity_client.auth_token
        catalog = self.identity_client.service_catalog
        endpoint = catalog.url_for(service_type='image',
                                   endpoint_type='publicURL')
        creds = {'endpoint': endpoint,
                 'token': token,
                 'insecure': insecure}
        self.image_client = glance_client.Client("1", **creds)

        self.username = username
        self.password = password
        self.tenant_name = tenant_name
        self.insecure = insecure
        self.auth_url = auth_url

    def add_neutron_client(self):
        self.network_client = \
            neutron_client.Client(username=self.username,
                                  password=self.password,
                                  tenant_name=self.tenant_name,
                                  auth_url=self.auth_url,
                                  insecure=self.insecure)

    def upload_image(self, name, data):
        LOG.info("Uploading image: %s" % name)
        data.seek(0)
        return self.image_client.images.create(name=name,
                                               disk_format="qcow2",
                                               container_format="bare",
                                               data=data,
                                               is_public="true")

    def do_images(self, path, create):
        LOG.info("Querying images")
        name = path[path.rfind('/') + 1:]
        name_alt = name + "_alt"
        image_id = None
        image_alt_id = None
        for image in self.image_client.images.list():
            if image.name == name:
                image_id = image.id
            if image.name == name_alt:
                image_alt_id = image.id
        qcow2_img_path = os.path.join(self.conf.get("scenario", "img_dir"),
                                      self.conf.get("scenario",
                                                    "qcow2_img_file"))
        if create and not (image_id and image_alt_id):
            # Make sure image location is writable beforeuploading
            open(qcow2_img_path, "w")
            if path.startswith("http:") or path.startswith("https:"):
                LOG.info("Downloading image file: %s" % path)
                request = urllib2.urlopen(path)
                with tempfile.NamedTemporaryFile() as data:
                    while True:
                        chunk = request.read(64 * 1024)
                        if not chunk:
                            break
                        data.write(chunk)

                    data.flush()
                    if not image_id:
                        image_id = self.upload_image(name, data).id
                    if not image_alt_id:
                        image_alt_id = self.upload_image(name_alt, data).id
                    shutil.copyfile(data.name, qcow2_img_path)
            else:
                with open(path) as data:
                    if not image_id:
                        image_id = self.upload_image(name, data).id
                    if not image_alt_id:
                        image_alt_id = self.upload_image(name_alt, data).id
                shutil.copyfile(path, qcow2_img_path)

        if not (create or os.path.exists(qcow2_img_path)):
            # Make sure the image file exists.
            with open(qcow2_img_path, "w") as image:
                for chunk in self.image_client.images.data(image_id):
                    image.write(chunk)

        self.conf.set('compute', 'image_ref', image_id)
        self.conf.set('compute', 'image_ref_alt', image_alt_id or image_id)

    def do_networks(self, has_neutron, create):
        label = None
        if has_neutron:
            for router in self.network_client.list_routers()['routers']:
                net_id = router['external_gateway_info']['network_id']
                if ('external_gateway_info' in router and net_id is not None):
                    self.conf.set('network', 'public_network_id', net_id)
                    self.conf.set('network', 'public_router_id', router['id'])
                    break
            for network in self.compute_client.networks.list():
                if network.id != net_id:
                    label = network.label
                    break
        else:
            networks = self.compute_client.networks.list()
            if networks:
                label = networks[0].label
        if label:
            self.conf.set('compute', 'fixed_network_name', label)
        else:
            raise Exception('fixed_network_name could not be discovered and'
                            ' must be specified')


class TempestConf(ConfigParser.SafeConfigParser):
    # causes the config parser to preserve case of the options
    optionxform = str

    # set of pairs `(section, key)` which have a higher priority (are
    # user-defined) and will usually not be overwritten by `set()`
    priority_sectionkeys = set()

    def set(self, section, key, value, priority=False):
        """Set value in configuration, similar to `SafeConfigParser.set`

        Creates non-existent sections. Keeps track of options which were
        specified by the user and should not be normally overwritten.

        :param priority: if True, always over-write the value. If False, don't
            over-write an existing value if it was written before with a
            priority (i.e. if it was specified by the user)
        :returns: True if the value was written, False if not (because of
            priority)
        """
        if not self.has_section(section):
            self.add_section(section)
        if not priority and (section, key) in self.priority_sectionkeys:
            LOG.debug("Option '[%s] %s = %s' was defined by user, NOT"
                      " overwriting into value '%s'", section, key,
                      self.get(section, key), value)
            return False
        if priority:
            self.priority_sectionkeys.add((section, key))
        LOG.debug("Setting [%s] %s = %s", section, key, value)
        ConfigParser.SafeConfigParser.set(self, section, key, value)
        return True


def create_tempest_users(identity_client, conf):
    create_user_with_tenant(identity_client,
                            conf.get('identity', 'username'),
                            conf.get('identity', 'password'),
                            conf.get('identity', 'tenant_name'))
    add_admin_to_tenant(identity_client,
                        conf.get('identity', 'admin_username'),
                        conf.get('identity', 'tenant_name'))

    create_user_with_tenant(identity_client,
                            conf.get('identity', 'alt_username'),
                            conf.get('identity', 'alt_password'),
                            conf.get('identity', 'alt_tenant_name'))


def add_admin_to_tenant(identity_client, admin_user, tenant_name):
    """Add the admin user to the specified tenant with the admin role."""
    tenant_id = identity_client.tenants.find(name=tenant_name)
    user_id = identity_client.users.find(name=admin_user)
    role_id = identity_client.roles.find(name='admin')
    try:
        identity_client.tenants.add_user(tenant_id, user_id, role_id)
        LOG.info("Added user '%s' with the admin role to tenant '%s'",
                 admin_user, tenant_name)
    except keystone_exception.Conflict:
        LOG.info("(no change) User '%s' already has the admin role in"
                 " tenant '%s'", admin_user, tenant_name)


def create_user_with_tenant(identity_client, username, password, tenant_name):
    LOG.info("Creating user '%s' with tenant '%s' and password '%s'",
             username, tenant_name, password)
    tenant_description = "Tenant for Tempest %s user" % username
    email = "%s@test.com" % username
    # create tenant
    try:
        identity_client.tenants.create(tenant_name, tenant_description)
    except keystone_exception.Conflict:
        LOG.info("(no change) Tenant '%s' already exists", tenant_name)

    tenant = identity_client.tenants.find(name=tenant_name)
    # create user
    try:
        identity_client.users.create(name=username, password=password,
                                     email=email, tenant_id=tenant.id)
    except keystone_exception.Conflict:
        LOG.info("User '%s' already exists. Setting password to '%s'",
                 username, password)
        user = identity_client.users.find(name=username)
        identity_client.users.update_password(user.id, password)


def create_tempest_flavors(compute_client, conf, allow_creation):
    # m1.nano flavor
    flavor_id = None
    if conf.has_option('compute', 'flavor_ref'):
        flavor_id = conf.get('compute', 'flavor_ref')
    flavor_id = find_or_create_flavor(compute_client,
                                      flavor_id, 'm1.nano',
                                      allow_creation, ram=64)
    conf.set('compute', 'flavor_ref', flavor_id)

    # m1.micro flavor
    alt_flavor_id = None
    if conf.has_option('compute', 'flavor_ref_alt'):
        alt_flavor_id = conf.get('compute', 'flavor_ref_alt')
    alt_flavor_id = find_or_create_flavor(compute_client,
                                          alt_flavor_id, 'm1.micro',
                                          allow_creation, ram=128)
    conf.set('compute', 'flavor_ref_alt', alt_flavor_id)


def find_or_create_flavor(compute_client, flavor_id, flavor_name,
                          allow_creation, ram=64, vcpus=1, disk=0):
    flavor = None
    # try finding it by the ID first
    if flavor_id:
        found = compute_client.flavors.findall(id=flavor_id)
        if found:
            flavor = found[0]
    # if not found previously, try finding it by name
    if flavor_name and not flavor:
        found = compute_client.flavors.findall(name=flavor_name)
        if found:
            flavor = found[0]

    if not flavor and not allow_creation:
        raise Exception("Flavor '%s' not found, but resource creation"
                        " isn't allowed. Either use '--create' or provide"
                        " an existing flavor" % flavor_name)

    if not flavor:
        LOG.info("Creating flavor '%s'", flavor_name)
        flavor = compute_client.flavors.create(flavor_name, ram, vcpus, disk)
    else:
        LOG.info("(no change) Found flavor '%s'", flavor.name)

    return flavor.id


def configure_boto(conf, services):
    if 'ec2' in services:
        conf.set('boto', 'ec2_url', services['ec2']['url'])
    if 's3' in services:
        conf.set('boto', 's3_url', services['s3']['url'])


def configure_cli(conf):
    cli_dir = get_program_dir("nova")
    if cli_dir:
        conf.set('cli', 'enabled', 'True')
        conf.set('cli', 'cli_dir', cli_dir)
    else:
        conf.set('cli', 'enabled', 'False')
    nova_manage_found = bool(get_program_dir("nova-manage"))
    conf.set('cli', 'has_manage', str(nova_manage_found))


def configure_horizon(conf):
    uri = conf.get('identity', 'uri')
    base = uri.rsplit(':', 1)[0]
    assert base.startswith('http:') or base.startswith('https:')
    has_horizon = True
    try:
        urllib2.urlopen(base)
    except urllib2.URLError:
        has_horizon = False
    conf.set('service_available', 'horizon', str(has_horizon))
    conf.set('dashboard', 'dashboard_url', base + '/')
    conf.set('dashboard', 'login_url', base + '/auth/login/')


def configure_discovered_services(conf, services):
    # set service availability
    for service, codename in SERVICE_NAMES.iteritems():
        conf.set('service_available', codename, str(service in services))

    # set service extensions
    for service, ext_key in SERVICE_EXTENSION_KEY.iteritems():
        if service in services:
            extensions = ','.join(services[service]['extensions'])
            conf.set(service + '-feature-enabled', ext_key, extensions)

    # set supported API versions for services with more of them
    for service, versions in SERVICE_VERSIONS.iteritems():
        supported_versions = services[service]['versions']
        section = service + '-feature-enabled'
        for version in versions:
            is_supported = any(version in item
                               for item in supported_versions)
            conf.set(section, 'api_' + version, str(is_supported))


def get_program_dir(program):
    """Get directory path of the external program.

    :param program: name of program, e.g. 'ls' or 'cat'
    :returns: None if it wasn't found, '/path/to/it/' if found
    """
    devnull = open(os.devnull, 'w')
    try:
        path = subprocess.check_output(["which", program], stderr=devnull)
        return os.path.dirname(path.strip())
    except subprocess.CalledProcessError:
        return None


if __name__ == "__main__":
    main()
