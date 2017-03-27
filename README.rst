===============
Tempest for RDO
===============

This repository was used by RDO until the Newton release.
Each branch of this repository, named after an OpenStack
release, tracks the tag of Tempest which matches the corresponding
OpenStack release.
This RDO-specific repository was required to store the
autoconfiguration code which can write down tempest.conf
by discovering the cloud configuration.

Starting from Ocata, RDO uses the upstream Tempest (like any other
packaged OpenStack component). The discovery-based configuration
script was decoupled and moved to `its own python-tempestconf repository
<https://github.com/redhat-openstack/python-tempestconf/>`_.
