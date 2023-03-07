import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='proxychains',
    version='1.0',
    author="acuifex",
    author_email="proxychains@acuifex.ru",
    description="A python module for Chaining of Proxies.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/acuifex/proxychains",
    packages=["proxychains"],
    install_requires=[
        'urllib3',
    ],
    classifiers=[
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        "Operating System :: OS Independent",
    ],
 )