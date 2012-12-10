# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
import tempfile


STATICFILES_FINDERS = (
    'staticfiles.finders.FileSystemFinder',
    'staticfiles.finders.AppDirectoriesFinder',
    # Enable 'old' /media directories in addition to /static.
    'staticfiles.finders.LegacyAppDirectoriesFinder',
    # Enable support for django-compressor.
    'compressor.finders.CompressorFinder',
    )

SETTINGS_DIR = os.path.dirname(os.path.realpath(__file__))
BUILDOUT_DIR = os.path.abspath(os.path.join(SETTINGS_DIR, '..'))

LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': {
        'simple':  {'format': '%(levelname)s %(message)s'},
        'verbose': {'format': '%(asctime)s %(name)s %(levelname)s\n%(message)s'}
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
            'level': None
        },
        'logfile': {
            'class': 'logging.FileHandler',
            'filename': os.path.join(BUILDOUT_DIR, 'var', 'log', 'django.log'),
            'formatter': 'verbose',
            'level': 'WARN'
        },
        'null': {
            'class': 'django.utils.log.NullHandler',
            'level': 'DEBUG'
        }
   },
   'loggers': {
       '': {
           'handlers': ['console'],
           'level': 'DEBUG',
           'propagate': True
       },
       'django.db.backends': {
           'handlers': ['null'],
           'level': 'DEBUG',
           'propagate': False
       }
   }
}

DEBUG = True
TEMPLATE_DEBUG = True

ADMINS = (
)
MANAGERS = ADMINS

# ENGINE: 'postgresql_psycopg2', 'postgresql', 'mysql', 'sqlite3' or 'oracle'.
# In case of geodatabase, prepend with:
# django.contrib.gis.db.backends.(postgis)
DATABASES = {
    # If you want to use another database, consider putting the database
    # settings in localsettings.py. Otherwise, if you change the settings in
    # the current file and commit them to the repository, other developers will
    # also use these settings whether they have that database or not.
    # One of those other developers is Jenkins, our continuous integration
    # solution. Jenkins can only run the tests of the current application when
    # the specified database exists. When the tests cannot run, Jenkins sees
    # that as an error.
    'default': {
        'NAME': os.path.join(BUILDOUT_DIR, 'var', 'sqlite', 'test.db'),
        'ENGINE': 'django.contrib.gis.db.backends.spatialite',
        # If you want to use postgres, use the two lines below.
        # 'NAME': 'lizard_auth_client',
        # 'ENGINE': 'django.contrib.gis.db.backends.postgis',
        'USER': 'buildout',
        'PASSWORD': 'buildout',
        'HOST': '',  # empty string for localhost.
        'PORT': '',  # empty string for default.
        }
    }

SITE_ID = 1
TIME_ZONE = 'Europe/Amsterdam'
LANGUAGE_CODE = 'nl-NL'
LANGUAGES = (
    ('en', 'English'),
    ('nl', 'Nederlands'),
)
USE_I18N = True
MEDIA_ROOT = os.path.join(BUILDOUT_DIR, 'var', 'media')
STATIC_ROOT = os.path.join(BUILDOUT_DIR, 'var', 'static')
MEDIA_URL = '/media/'
STATIC_URL = '/static_media/'
SECRET_KEY = 'This is not secret but that is ok.'

# SSO
SSO_STANDALONE = True
# A key identifying this client. Can be published.
SSO_KEY = 'random_generated_key_to_identify_the_client'
# A *secret* shared between client and server. Used to sign the messages exchanged between them.
# Note: as long as the name of this settings contains "SECRET", it is hidden in the Django
# debug output
SSO_SECRET = 'random_generated_secret_key_to_sign_exchanged_messages'
# URL used to redirect the user to the SSO server
SSO_SERVER_PUBLIC_URL = 'http://127.0.0.1:8001/'
# URL used for server-to-server communication
SSO_SERVER_PRIVATE_URL = 'http://127.0.0.1:8001/'

ROOT_URLCONF = 'lizard_auth_client.urls'

TEST_RUNNER = 'django_nose.NoseTestSuiteRunner'

TEMPLATE_CONTEXT_PROCESSORS = (
    # default template context processors
    'django.contrib.auth.context_processors.auth',
    'django.contrib.messages.context_processors.messages',
    'django.core.context_processors.debug',
    'django.core.context_processors.i18n',
    'django.core.context_processors.media',
    'django.core.context_processors.static',
    'django.core.context_processors.request',
)

MIDDLEWARE_CLASSES = (
    # Gzip needs to be at the top.
    'django.middleware.gzip.GZipMiddleware',
    # Below is the default list, don't modify it.
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    )

INSTALLED_APPS = (
    'lizard_auth_client',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.gis',
    'django.contrib.markup',
    'django.contrib.messages',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.staticfiles',
)

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': os.path.join(BUILDOUT_DIR, 'var', 'cache'),
    }
}

try:
    # Import local settings that aren't stored in svn/git.
    from controlnext.local_testsettings import *
except ImportError:
    pass
