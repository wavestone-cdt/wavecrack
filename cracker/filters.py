#!/usr/bin/python
# coding: utf8

import os
import binascii
import random
import string
from datetime import datetime, timedelta
from time import strftime, strptime, localtime

from flask import render_template, request, session, abort

from cracker import app
from slugify import slugify


def format_datetime(value):
    """
        Date and time display in the expected format
    """
    try:
        datetime_value = strptime(value, "%Y-%m-%dT%H:%M:%S")
    except TypeError:
        datetime_value = localtime()
    return strftime("%A %B %d %Y", datetime_value).decode(
        'utf8') + u' at ' + strftime("%H:%M", datetime_value).decode('utf8')

app.jinja_env.filters['datetime'] = format_datetime

def hex_to_readable(value):
    """
        Convert a hexadecimal string to a latin1 string
    """
    if value.startswith("$HEX["):
        substring = value[5:-1]
        # if length isn't divisible by 2 then return input value
        if len(substring) % 2 != 0:
            return value
        return binascii.unhexlify(substring).decode('latin1')
    return value

app.jinja_env.filters['hex_to_readable'] = hex_to_readable

def slugify_template(value):
    """
        Convert any string to normalized string
    """
    return slugify(value)

app.jinja_env.filters['slugify_template'] = slugify_template

from helper import unslugifyer

def unslugify_template(value):
    """
        Convert any normalized string to the initial string value
    """
    return unslugifyer(value)

app.jinja_env.filters['unslugify_template'] = unslugify_template

@app.before_request
def csrf_protect():
    """
        Protect POST resquests against CSRF and generate CRSF token when it expires
    """
    token = session.get('_csrf_token', None)
    date_token = session.get('csrf_token_date', None)

    if (token is None or date_token is None) and request.method == "GET":
        # No token defined for this user : a new one has to be generated
        return

    if token is None or date_token is None:
        # Post request without token
        abort(403)

    if date_token < datetime.now():
        # Expired token
        session.pop('_csrf_token', None)
        session.pop('csrf_token_date', None)
        return render_template('disconnected.html', title=u'Expired session')

    elif request.method == "POST":
        # Unexpired token : value checking
        if not token or token != request.form.get('_csrf_token'):
            # Request aborted
            abort(403)


def generate_csrf_token():
    """
        Generating a random CSRF token
    """
    if '_csrf_token' not in session:
        # Generating a 40 character token
        session['_csrf_token'] = "".join(random.SystemRandom().choice(
            string.letters + string.digits) for _ in range(40))
        # Generating with a 30 minutes of validity
        session['csrf_token_date'] = datetime.now() + timedelta(minutes=30)

    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token


def is_current_bruteforce_attack_running(dict):
    """
        Retrieving information in the bruteforce log to know whether a bruteforce crack is still running
    """
    last_character_message = ''
    for key in dict:
        if key != 'Bruteforce':
            last_character_message = dict[key]
    if "finished" in last_character_message:
        return True
    else:
        return False

app.jinja_env.filters['is_current_bruteforce_attack_running'] = is_current_bruteforce_attack_running

def is_method_not_started(value):
    """
        Parsing a log status to know if a crack method has already started
    """
    # The log parse returns [] if no information regarding a method was found
    if value == []:
        return "Method not started."
    else:
        return value

app.jinja_env.filters['is_method_not_started'] = is_method_not_started

def get_log_display_css(value):
    """
        Parsing a log status to get the associated css
    """
    # The log parse returns [] if no information regarding a method was found
    if value == []:
        # Not started
        return "notstarted"
    elif "Unknown amount" in value or ". 0/" in value:
        # No hashes cracked for this step
        if "finished" in value:
            # Finished
            return "finished"
        elif "currently running" in value:
            # Currently running
            return "currentlyrunning"
        else:
            return ""
    else:
        return "cracked"

app.jinja_env.filters['get_log_display_css'] = get_log_display_css

def filter_len(value):
    """
        Returns the length of a value
    """
    return len(value)

app.jinja_env.filters['len'] = filter_len