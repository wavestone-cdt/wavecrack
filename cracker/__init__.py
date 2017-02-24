#!/usr/bin/python
# coding: utf8
import locale
import sys

from flask import Flask
from celery import Celery

import app_settings

# Setup utf-8 encoding
# Default string encoding setting
reload(sys)
sys.setdefaultencoding('utf8')

# Language setting
locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')

# Application definition
app = Flask(__name__)
app.config['DEBUG'] = app_settings.DEBUG
app.config['PROPAGATE_EXCEPTIONS'] = app_settings.DEBUG

# Import settings from app_settings.py
app.secret_key = app_settings.secret_key
app.config['DATABASE'] = app_settings.database
app.config['UPLOAD_FOLDER'] = app_settings.UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 30 * 1024 * 1024

# Celery settings
app.config['CELERY_BROKER_URL'] = app_settings.celery_broker_url
app.config['CELERY_RESULT_BACKEND'] = app_settings.celery_result_backend
app.config['CELERY_TRACK_STARTED'] = True
app.config['CELERY_IGNORE_RESULT'] = False

# Celery initalization
celery = Celery(
    app.name,
    backend=app.config['CELERY_RESULT_BACKEND'],
    broker=app.config['CELERY_BROKER_URL']
)
celery.conf.update(app.config)

# Import the routes here to declare them (and the filters)
from cracker import filters
from cracker import routes

# Import the tasks here to declare them to Celery
from cracker import tasks
