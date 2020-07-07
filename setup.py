import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='yarafilter',
    version='1.0',
    packages=setuptools.find_packages(),
    url='https://github.com/blueforceNL/yarafilter',
    license='MIT',
    author=' Bas van Schaik',
    author_email='b.van.schaik@politie.nl',
    long_description=long_description,
    long_description_content_type="text/markdown",
    description='Filter and deduplicate your yar file collection',
    install_requires=[
         'plyara', 'pathlib'
      ]
)