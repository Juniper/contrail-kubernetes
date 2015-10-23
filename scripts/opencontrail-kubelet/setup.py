#
# Copyright (c) 2015 Juniper Networks, Inc.
#

import setuptools


def requirements(filename):
    with open(filename) as f:
        lines = f.read().splitlines()
    return lines

setuptools.setup(
    name='opencontrail-kubelet',
    version='0.3.4',
    packages=setuptools.find_packages(),

    # metadata
    author="OpenContrail",
    author_email="dev@lists.opencontrail.org",
    license="Apache Software License",
    url="http://www.opencontrail.org/",
    description="OpenContrail kubelet plugin",
    long_description="Kubernetes kubelet plugin for OpenContrail",

    install_requires=requirements('requirements.txt'),

    test_suite='opencontrail_kubelet.tests',
    tests_require=requirements('test-requirements.txt'),

    entry_points = {
        'console_scripts': [
            'opencontrail-kubelet-plugin = opencontrail_kubelet.plugin:main',
        ],
    },
)
