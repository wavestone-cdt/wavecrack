#!/usr/bin/python
# coding: utf8
import os

from flask import g
from tasks import hashcatCrack
from helper import get_hash_type_from_hash_id

import app_settings as conf


def running_crack_nb():
    """
        Return the number of ongoing crack
    """
    # Return the list of ongoing crack including user id, date of launch,
    # hash type and allocated duration
    cur = g.db.execute(
        'select crack_id, output_file, user_id , start_date, hash_type, crack_duration from cracks')
    cracks_status = cur.fetchall()
    running_crack_list = []

    for crack_id, output_file, user_id, start_date, hash_type, crack_duration in cracks_status:
        task_state = get_crack_status(crack_id, output_file)
        if task_state == 1:
            # Task in progress
            hash_name = get_hash_type_from_hash_id(hash_type)

            # Retrieve user from crack id
            cur = g.db.execute(
                'select name from users where id=(?)', [user_id])
            username = cur.fetchone()[0]

            running_crack_list.append(
                [username, start_date, hash_name, crack_duration])

    return running_crack_list


def get_crack_status(task_id, output_file):
    """
        Return the crack status code
    """
    task = hashcatCrack.AsyncResult(task_id)

    return_codes = {
        'SUCCESS': 0,  # \o/
        'STARTED': 1,  # Started
        'PENDING': 2,  # Waiting
        'REVOKED': 3,  # Stopped
        'FAILURE': 5,  # Something went wrong :(
        'RETRY': 6,  # Let's try again
    }
    # Unknown state
    default_return_code = 4

    # If task is successful
    if task.state == 'SUCCESS':
        try:
            # If errors exist, return Failure state code
            if os.path.getsize(os.path.join(conf.log_location, output_file + ":error.log")) != 0:
                return return_codes['FAILURE']
            else:
                return return_codes['SUCCESS']
        except:
            return return_codes['SUCCESS']
    return return_codes.get(task.state, default_return_code)
