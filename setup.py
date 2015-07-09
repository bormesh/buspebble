# vim: set expandtab ts=4 sw=4 filetype=python fileencoding=utf8:

from setuptools import find_packages, setup

setup(

    name="rtapebbletest",

    version="0.0.1",

    packages=find_packages(),

    include_package_data=True,

    package_dir={"rtapebbletest": "rtapebbletest"},

    scripts=[
        "rtapebbletest/scripts/rtapebbletest-run-webapp",
        "rtapebbletest/scripts/rtapebbletest-upgrade-database",
        "rtapebbletest/scripts/rtapebbletest-rebuild-database",
        "rtapebbletest/scripts/rtapebbletest-config",
        "rtapebbletest/scripts/rtapebbletest-yaml-example",
    ],

)
