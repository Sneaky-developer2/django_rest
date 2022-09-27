"""
Django settings for foodOnline_main project.

Generated by 'django-admin startproject' using Django 4.1.

For more information on this file, see
https://docs.djangoproject.com/en/4.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.1/ref/settings/
"""

from django.contrib.messages import constants as messages
from pathlib import Path
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-bo4)h)h3=z*@l&ufw)28ne&#jf#@o*&fa%8b!#%6#ra$&kqhzb'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'accounts',
    'vendor',
    'menu',
    'marketplace',
    'django.contrib.gis',
    'customers',
    'orders',
    'zarinpal',
    'azbankgateways',
]

AZ_IRANIAN_BANK_GATEWAYS = {
   'GATEWAYS': {
       'ZARINPAL': {
           'SANDBOX': 1,  # 0 disable, 1 active
       },
    #    'IDPAY': {
    #        'X_SANDBOX': 1,  # 0 disable, 1 active
    #    },
   },
   'DEFAULT': 'ZARINPAL',
   'CURRENCY': 'IRR', # اختیاری
   'TRACKING_CODE_QUERY_PARAM': 'tc', # اختیاری
   'TRACKING_CODE_LENGTH': 16, # اختیاری
   'SETTING_VALUE_READER_CLASS': 'azbankgateways.readers.DefaultReader', # اختیاری
   'BANK_PRIORITIES': [
       
       # and so on ...
   ], # اختیاری
}


MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'foodOnline_main.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': ['templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'accounts.context_processors.get_vendor',
                'marketplace.context_processors.get_cart_counter',
                'marketplace.context_processors.get_cart_amounts',
                'accounts.context_processors.get_user_profile',

            ],
        },
    },
]

WSGI_APPLICATION = 'foodOnline_main.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases

# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.sqlite3',
#         'NAME': BASE_DIR / 'db.sqlite3',
#     }
# }

DATABASES = {
    'default': {
        # 'ENGINE': 'django.db.backends.postgresql',
        'ENGINE': 'django.contrib.gis.db.backends.postgis',
        'NAME': 'foodOnline_db',
        'USER': 'postgres',
        'PASSWORD': '1',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}

AUTH_USER_MODEL = 'accounts.User'


# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'static'
STATICFILES_DIRS = [
    'foodOnline_main/static'
]

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'


# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


MESSAGE_TAGS = {
    messages.ERROR: 'danger',

}

# Email configuration
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = 'noob1384noob1384@gmail.com'
EMAIL_HOST_PASSWORD = 'wxplsydrakdvwswf'
EMAIL_USE_TLS = True
DEFAULT_FROM_EMAIL = 'foodOnline Marketplace <noob1384noob1384@gmail.com>'

GOOGLE_API_KEY = 'AIzaSyC4yTudrg9pTcB2khAgrbCMBfVvbviOhVU'


os.environ['PATH'] = os.path.join(
    BASE_DIR, 'myproject\Lib\site-packages\osgeo') + ';' + os.environ['PATH']
os.environ['PROJ_LIB'] = os.path.join(
    BASE_DIR, 'myproject\Lib\site-packages\osgeo\data\proj') + ';' + os.environ['PATH']
GDAL_LIBRARY_PATH = os.path.join(
    BASE_DIR, 'myproject\Lib\site-packages\osgeo\gdal304.dll')
