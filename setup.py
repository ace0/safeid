"""
PIP setup script for the SafeID package.
"""

from setuptools import setup

def readme():
    with open('README.rst') as f:
        return f.read()

description=\
  """
  SafeID is a proof-of-concept web server library that protects user passwords
  using the Pythia protocol. Web servers can interact with a Pythia server 
  to encrypt new passwords and verify existing passwords.
  """
description = ' '.join(description.split())

setup(name='safeid',
      version='1.3.1',
      description=description,
      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'Intended Audience :: Information Technology',
          'License :: OSI Approved :: MIT License',
          'Operating System :: MacOS',
          'Operating System :: MacOS :: MacOS X',
          'Operating System :: POSIX :: Linux',
          'Operating System :: Unix',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
          'Topic :: Security', 
          'Topic :: Security :: Cryptography',
          'Topic :: System :: Systems Administration :: Authentication/Directory',
      ],
      url='https://bitbucket.org/ace0/safeid',
      author='Adam Everspaugh',
      author_email='ace@cs.wisc.edu',
      license='MIT',
      keywords='password encryption authentication',
      packages=['safeid'],
      install_requires=['httplib2', 'pythiacrypto'],
      zip_safe=False, 
      entry_points={ 'console_scripts': [ 'safeid = safeid.safeid:main' ] },
    )
