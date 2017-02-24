#!/usr/bin/python
# coding=utf-8
import sqlite3
from datetime import datetime
from subprocess import call, check_output, Popen, PIPE, CalledProcessError

from celery.task.control import revoke

from cracker import app_settings

# Import the settings
hashcat_location = app_settings.hashcat_location
database = app_settings.database


def abort_crack(crack_duration, start_date, output_file, crack_id):
    # Test if the crack has been up for longer than it should have
    if (crack_duration <= (datetime.now() -
                           datetime.strptime(start_date, "%Y-%m-%dT%H:%M:%S")).days):

        try:
            # Stop the celery task
            revoke(crack_id, terminate=True)

            # If the revoke does not work, manually kill the task
            ps_process = Popen(["ps", "auxww"], stdout=PIPE)
            ps_output = Popen(["grep", hashcat_location],
                              stdin=ps_process.stdout, stdout=PIPE)
            grep_output = check_output(
                ["grep", output_file], stdin=ps_output.stdout)
            PID = grep_output.split()[1]
            call(["kill", PID])

            print "(Aborting Crack) Crack {} stopped".format(crack_id)

        except CalledProcessError:
            # In case the crack was already stopped
            pass
        except KeyError:
            print "(Aborting Crack) KeyError crack_id : {}".format(crack_id)


# Connection to the database
datab = sqlite3.connect(database)

# Stop the crack if it is older than its theoretical end date
cur = datab.execute(
    'select crack_duration, start_date, output_file, crack_id from cracks')
crack_duration_list = cur.fetchall()

for crack_duration, start_date, output_file, crack_id in crack_duration_list:
    abort_crack(crack_duration, start_date, output_file, crack_id)

# Close the database connection
datab.close()
