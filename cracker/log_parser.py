#!/usr/bin/python
# coding: utf8

import os
import time
import app_settings as conf

def parse_log(output_file_name, crackOption, hash_type):
    
    # Building the log file name from output file name
    with open(os.path.join(conf.log_location, output_file_name + ".log"), 'r+') as log_file:
        # Read the log file
        log = log_file.read()

        cracks_iterator = log.split("Running:")
        crack_counter = 1
        
        # Separate all the crack runs
        for crack_run in cracks_iterator[1:]:
            crack_counter +=1
            
            ##########################################################################################################################
            #  Extraction of the main information : Status, hash recovered, time remaining for the crack, Progress of the hash
            ##########################################################################################################################
            
            # To check if the current crack is running, check if it's the last item of the list and if it doesn't end with "Stopped: ..."
            if crack_counter == len(cracks_iterator) and "Stopped: " not in crack_run.splitlines()[-1]:
                is_currently_running = True
            else:
                is_currently_running = False
            
            # Retrieving information regarding the crack mode in the filename of the first line
            running_mode = crack_run.splitlines()[0].split('/')[-1]
            
            
            method_arg = running_mode.split(':')
            # Successful method value building
            # XXXfilenameXXX:CrackMode:Wordlist/Mask used:Rule
            # XXXfilenameXXX:method_arg[1]:method_arg[2]:method_arg[3]
            has_rule = (len(method_arg) > 3)
            
            if has_rule:
                _, crackmode, wordlist_or_mask, rule = method_arg
            else:
                _, crackmode, wordlist_or_mask = method_arg
            
            if crackmode == "Wordlist" and has_rule and rule != "":
                crackmode = "WordlistVariations"
            
            
            
            
            amount_recovered = get_amount_recovered(crack_run)
            progress_string = get_progress(crack_run)
            time_estimated_string = get_time_estimated(crack_run)
            
            if crackmode == "Bruteforce" or crackmode == "BruteForce_lm":
                update_bruteforced_characters(crack_run, crackmode, crackOption)
            
            elif crackmode == "Keywords":
                for option in crackOption:
                    if option[0] == crackmode:
                        if has_rule and rule != "":
                            option[1][rule] = format_output(is_currently_running, amount_recovered, progress_string, time_estimated_string)
                        else:
                            option[1][crackmode] = format_output(is_currently_running, amount_recovered, progress_string, time_estimated_string)
            
            else:
                for option in crackOption:
                    if option[0] == crackmode:
                        if has_rule and rule != "":
                            option[1][wordlist_or_mask][rule] = format_output(is_currently_running, amount_recovered, progress_string, time_estimated_string)
                        else:
                            option[1][wordlist_or_mask] = format_output(is_currently_running, amount_recovered, progress_string, time_estimated_string)


    return 0

"""
Returns either unknown or the amount recovered depending on whether the information was found
"""
def return_amount_recovered(amount_recovered, progress_string, time_estimated_string):

    if amount_recovered == "":
        amount_recovered = "Unknown amount of passwords recovered."
    else:
        amount_recovered = amount_recovered + " passwords recovered."
    
    if progress_string == "" or progress_string == "100%":
        progress_string = ""
    else:
        progress_string = " Number of combinations tested for this method " + progress_string + "."
        
    
    if time_estimated_string == "":
        time_estimated_string = ""
    else:
        time_estimated_string = " Estimated remaining time:" + time_estimated_string + "."
    
    return amount_recovered + progress_string + time_estimated_string
    
def format_output(is_currently_running, amount_recovered, progress_string, time_estimated_string):
    if is_currently_running:
        return "Method currently running. " + return_amount_recovered(amount_recovered, progress_string, time_estimated_string)
    else:
        return "Method finished. " + return_amount_recovered(amount_recovered, progress_string, time_estimated_string)
        
def get_amount_recovered(chunk):
    # Get the amount of passwords recovered
    # Example: "Recovered......: 0/1 (0.00%) Digests, 0/1 (0.00%) Salts"
    if "Recovered." in chunk:
        recovered_array = chunk.rsplit("Recovered.",1)[1].split(' ')
        amount_recovered = recovered_array[1] + ' ' + recovered_array[2]
    else:
        amount_recovered = ""
    return amount_recovered
    
def get_progress(chunk):
    # Get the current progress of the task
    # Example: "Progress.......: 11508833408/118705120000 (9.70%)"
    if "Progress." in chunk:
        progress_array = chunk.rsplit("Progress.",1)[1].splitlines()[0].split(' ')
        progress_string = progress_array[2]
        # Remove the parenthesis
        progress_string = progress_string[1:-1]
    else:
        progress_string = ""
    return progress_string
    
def get_time_estimated(chunk):
    # Get the estimated time remaining
    # Example: Time.Estimated.: Sat Sep 16 18:44:55 2017 (8 days, 7 hours)
    if "Time.Estimated." in chunk:
        time_estimated_array = chunk.rsplit("Time.Estimated.",1)[1].split('(')
        time_estimated_string = time_estimated_array[1].split(')')[0]
    else:
        time_estimated_string = ""
    return time_estimated_string
    
def update_bruteforced_characters(chunk, crackmode, crackOption):
    # Get the number of characters tested
    # Example: Input.Mode.....: Mask (?a?a?a?a?a?a) [6]
    
    if "Input.Mode." in chunk:
        input_modes = chunk.split("Input.Mode.")[1:]
        for input_mode in input_modes[:-1]:
            current_line = input_mode.splitlines()[0]
            number_of_characters_bruteforced = current_line.split(' ')[3][1:-1]
            
            amount_recovered = get_amount_recovered(input_mode)
            progress_string = get_progress(input_mode)
            time_estimated_string = get_time_estimated(input_mode)
            
            for option in crackOption:
                if option[0] == crackmode:
                    option[1][int(number_of_characters_bruteforced)] = format_output(False, amount_recovered, progress_string, time_estimated_string)
        
        # The last input string is possibly running 
        if "Exhausted" or "Cracked" in input_modes[-2]:
            last_bruteforce_mode_is_currently_running = False
        else:
            last_bruteforce_mode_is_currently_running = True
        input_mode = input_modes[-1]
        current_line = input_mode.splitlines()[0]
        number_of_characters_bruteforced = current_line.split(' ')[3][1:-1]
        
        amount_recovered = get_amount_recovered(input_mode)
        progress_string = get_progress(input_mode)
        time_estimated_string = get_time_estimated(input_mode)
        
        for option in crackOption:
            if option[0] == crackmode:
                option[1][int(number_of_characters_bruteforced)] = format_output(last_bruteforce_mode_is_currently_running, amount_recovered, progress_string, time_estimated_string)