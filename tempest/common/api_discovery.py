#!/usr/bin/env python

# Copyright 2013 Red Hat, Inc.
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

import json
import urlparse

import httplib2

import keystoneclient.v2_0.client as keystone_client


class Service(object):
    def __init__(self, service_url, token):
        self.service_url = service_url
        self.headers = {'Accept': 'application/json', 'X-Auth-Token': token}

    def do_get(self, url, top_level=False, top_level_path=""):
        if top_level:
            parts = urlparse.urlparse(url)
            if parts.path != '':
                url = url.replace(parts.path, '/') + top_level_path

        r, body = httplib2.Http().request(url, 'GET', headers=self.headers)
        assert r.status <= 400, r
        return body

    def get_extensions(self):
        return []

    def get_versions(self):
        body = self.do_get(self.service_url, top_level=True)
        body = json.loads(body)
        return self.deserialize_versions(body)

    def deserialize_versions(self, body):
        return map(lambda x: x['id'], body['versions'])


class ComputeService(Service):
    def __init__(self, service_url, token):
        super(ComputeService, self).__init__(service_url, token)

    def get_extensions(self):
        body = self.do_get(self.service_url + '/extensions')
        body = json.loads(body)
        return map(lambda x: x['alias'], body['extensions'])


class ImageService(Service):
    def __init__(self, service_url, token):
        super(ImageService, self).__init__(service_url, token)


class NetworkService(Service):
    def __init__(self, service_url, token):
        super(NetworkService, self).__init__(service_url, token)

    def get_extensions(self):
        body = self.do_get(self.service_url + 'v2.0/extensions.json')
        body = json.loads(body)
        return map(lambda x: x['alias'], body['extensions'])


class VolumeService(Service):
    def __init__(self, service_url, token):
        super(VolumeService, self).__init__(service_url, token)

    def get_extensions(self):
        body = self.do_get(self.service_url + '/extensions')
        body = json.loads(body)
        return map(lambda x: x['name'], body['extensions'])


class IdentityService(Service):
    def __init__(self, service_url, token):
        super(IdentityService, self).__init__(service_url, token)

    def get_extensions(self):
        body = self.do_get(self.service_url + '/extensions')
        body = json.loads(body)
        return map(lambda x: x['name'], body['extensions']['values'])

    def deserialize_versions(self, body):
        return map(lambda x: x['id'], body['versions']['values'])


class ObjectStorageService(Service):
    def __init__(self, service_url, token):
        super(ObjectStorageService, self).__init__(service_url, token)

    def get_extensions(self):
        body = self.do_get(self.service_url, top_level=True,
                           top_level_path="info")
        body = json.loads(body)
        # Remove Swift general information from extensions list
        body.pop('swift')
        return body.keys()

    def get_versions(self):
        # swift does not return versions
        return []


service_dict = {'compute': ComputeService,
                'image': ImageService,
                'network': NetworkService,
                'object-store': ObjectStorageService,
                'volume': VolumeService,
                'identity': IdentityService}


def discover(identity_client):
    """
    Returns a dict with discovered apis.
    :param identity_client: A keystone client from official python client.
    :return: A dict with an entry for the type of each discovered service.
        Each entry has keys for 'extensions' and 'versions'.
    """
    token = identity_client.auth_token
    endpoints = identity_client.service_catalog.get_endpoints()
    services = {}
    for (name, descriptor) in endpoints.iteritems():
        if (name in ['ec2', 's3'] or
            name in ['cloudformation', 'orchestration', 'metering']):
            continue

        if name in service_dict:
            service_class = service_dict[name]
        else:
            service_class = Service
        service = service_class(descriptor[0]['publicURL'], token)
        extensions = service.get_extensions()
        versions = service.get_versions()
        services[name] = {'extensions': extensions,
                             'versions': versions}
    return services

