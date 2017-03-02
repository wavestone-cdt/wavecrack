#!/usr/bin/python
# coding: utf8

import subprocess
import random
import time
import traceback
import StringIO

import app_settings as conf
from helper import write_to_file_without_errors
from customexceptions import RevokedTaskException, OutOfMemoryException, \
    NoRemainingHashException


def run_hashcat_safe(command, output_file_name):
    """
        Run the hashcat command and handles errors 
    """
    try:
        # Try to run the command
        return_code = launch(command, output_file_name)

    except subprocess.CalledProcessError as e:
        # If we get an error, try to understand what happened

        if e.returncode == 2:
            # This error code means hashcat has been aborted
            raise RevokedTaskException()

        if 'ERROR: hashfile is empty or corrupt' in e.output:
            # This error message means we cracked all the hashes (they are
            # removed from the file when they are cracked).
            raise NoRemainingHashException()

        if 'ERROR: cuMemAlloc() 2' in e.output:
            # This message means there is no GPU memory left.
            raise OutOfMemoryException()

        print "Unknown error found !", e.output
        traceback.print_exc()

        # Write the error in the error file
        with open(conf.log_location + output_file_name + ":error.log", "a+", 0) as error_file:
            write_to_file_without_errors(e.output, error_file)
        raise e

    else:
        return return_code


def launch(command, output_file_name):
    """
        Launch crack and save logs in log directory 
    """
    # We store the error stream in a virtual file, and will only write it to a
    # file after processing the returned error
    error_file = StringIO.StringIO()

    with open(conf.log_location + output_file_name + ".log", "a+", 0) as log_file:
        # Write the command used
        write_to_file_without_errors(
            "Running: %s\n" % " ".join(command), log_file)

        # Execute hashcat and redirect STDOUT to the log file.
        # We keep STDERR in the internal pipe to be able to easily retrieve
        # it later.
        proc = subprocess.Popen(
            command,
            stdout=log_file,
            stderr=subprocess.PIPE,
        )
        
        # Return the return code of the process
        return_code = proc.wait()

        # -2 = gpu-watchdog alarm
        # -1 = error
        #  0 = OK/cracked
        #  1 = exhausted
        #  2 = aborted
        # 255 = hashcat bug, equivalent to 0 or 1
        # (https://github.com/hashcat/hashcat/issues/512)

        if return_code in [0, 1, 255]:
            # Everything is fine
            return 0

        # Ok, something went wrong

        # Retrieve error text from the subprocess.PIPE
        _, stderr = proc.communicate()

        # People have a right to know what went wrong
        write_to_file_without_errors(stderr, log_file)

        # Raise the exception
        raise subprocess.CalledProcessError(
            returncode=return_code,
            cmd=command,
            output=stderr,
        )