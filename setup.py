from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.readlines()

setup(
    name='binsniff',
    version='0.1',
    packages=find_packages(),
    author='Sergio Benlloch',
    description='',
    install_requires=requirements,
    entry_points=dict(console_scripts=[
        'binsniff = src.__init__:main'
    ])
)
