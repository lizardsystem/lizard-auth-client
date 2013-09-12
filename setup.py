from setuptools import setup

version = '0.9.dev0'

long_description = '\n\n'.join([
    open('README.rst').read(),
    open('CREDITS.rst').read(),
    open('CHANGES.rst').read(),
    ])

install_requires = [
    'Django',
    'django-extensions',
    'django-nose',
    'requests',
    'itsdangerous',
    ],

tests_require = [
    ]

setup(name='lizard-auth-client',
      version=version,
      description="A client for lizard-auth-server",
      long_description=long_description,
      # Get strings from http://www.python.org/pypi?%3Aaction=list_classifiers
      classifiers=['Programming Language :: Python',
                   'Framework :: Django',
                   ],
      keywords=[],
      author='Erik-Jan Vos',
      author_email='erikjan.vos@nelen-schuurmans.nl',
      url='http://www.nelen-schuurmans.nl/',
      license='MIT',
      packages=['lizard_auth_client'],
      include_package_data=True,
      zip_safe=False,
      install_requires=install_requires,
      tests_require=tests_require,
      extras_require={'test': tests_require},
      entry_points={
          'console_scripts': [
          ]},
      )
