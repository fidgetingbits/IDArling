#!/usr/bin/env python
from setuptools import find_packages, setup


setup(
    name="idarling",
    version="0.1",
    description="Collaborative Reverse Engineering plugin for IDA Pro",
    url="https://github.com/IDArlingTeam/IDArling",
    packages=find_packages(),
    install_requires=["PySide6; python_version >= '3.9'"],
    include_package_data=True,
    entry_points={
        "idapython_plugins": ["idarling=idarling.plugin:IdarlingPlugin"],
        "console_scripts": ["idarling_server=idarling.server:main"],
    },
)
