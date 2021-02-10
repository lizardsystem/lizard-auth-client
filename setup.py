from setuptools import setup

version = '3.0.6.dev0'

long_description = '\n\n'.join([
    open('README.rst').read(),
    open('CREDITS.rst').read(),
    open('CHANGES.rst').read(),
])

install_requires = [
    'Django',
    'django-appconf',
    'django-extensions',
    'itsdangerous',
    'requests',
    'PyJWT',
    'django-crispy-forms',
],

tests_require = [
    'pytest',
    'pytest-django',
    'pytest-cov',
    # Py3.5 & factory_boy 3.0.1: pip fails installing with "Generating metadata
    # for package factory-boy produced metadata for project name unknown"
    'factory-boy==2.*',
    'flake8',
]

setup(
    name='lizard-auth-client',
    version=version,
    description="A client for lizard-auth-server",
    long_description=long_description,
    # Get strings from http://www.python.org/pypi?%3Aaction=list_classifiers
    classifiers=['Programming Language :: Python',
                 'Framework :: Django',
                 ],
    keywords=[],
    author='Erik-Jan Vos, Remco Gerlich',
    author_email='remco.gerlich@nelen-schuurmans.nl',
    include_package_data=True,
    url='http://www.nelen-schuurmans.nl/',
    license='MIT',
    packages=['lizard_auth_client'],
    zip_safe=False,
    install_requires=install_requires,
    tests_require=tests_require,
    extras_require={
        'test': tests_require,
        'south': ['south >= 1.0'],
    },
    entry_points={
        'console_scripts': []
    },
)
