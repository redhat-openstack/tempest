#!/usr/bin/env python

# Copyright 2016 Red Hat, Inc.
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
"""
This script will install tempest plugin test packages automatically based on
the OpenStack Components installed.
"""

import rpm
import yum


OS_TEST_PACKAGES = {
    "aodh": "python-aodh-tests",
    "ceilometer": "python-ceilometer-tests",
    "cinder": "python-cinder-tests",
    "designate": "python-designate-tests-tempest",
    "glance": "python-glance-tests",
    "gnocchi": "python-gnocchi-tests",
    "heat": "python-heat-tests",
    "horizon": "python-horizon-tests-tempest",
    "ironic": "python-ironic-tests",
    "keystone": "python-keystone-tests",
    "mistral": "python-mistral-tests",
    "neutron": "python-neutron-tests",
    "neutron-fwaas": "python-neutron-fwaas-tests",
    "neutron-lbaas": "python-neutron-lbaas-tests",
    "neutron-vpnaas": "python-neutron-vpnaas-tests",
    "nova": "python-nova-tests",
    "sahara": "python-sahara-tests-tempest",
    "swift": "python-swift-tests",
    "trove": "python-trove-tests",
    "zaqar": "python-zaqar-tests",
    "watcher": "python-watcher-tests-tempest",
    "manila": "python-manila-tests"
    }


def get_installed_rpms():
    """Provides a list of installed OpenStack rpms"""
    ts = rpm.TransactionSet()
    mi = ts.dbMatch()
    os_rpms = [h['name'] for h in mi if h['name'].startswith('openstack')]
    return os_rpms


def get_required_testpkgs():
    """Get a list required test packages based on installed openstack rpms"""
    os_rpms = get_installed_rpms()

    os_components = ["openstack-" + pkg for pkg in OS_TEST_PACKAGES]

    os_pkgs = list(set([component.replace('openstack-', '') for rpm in os_rpms
                        for component in os_components if component in rpm]))

    required_test_packages = [OS_TEST_PACKAGES[name] for name in os_pkgs]
    return required_test_packages


def install_packages(pkgs):
    """Installs a list of package through yum"""
    yb = yum.YumBase()
    for package in pkgs:
        yb.install(name=package)
    yb.resolveDeps()
    yb.processTransaction()

if __name__ == '__main__':
    install_packages(get_required_testpkgs())
