#!/usr/bin/python
# coding: utf8

import os
import app_settings as conf

def parse_log(output_file_name, crackOption, hash_type):
    
    try:
        # Building the log file name from output file name
        with open(os.path.join(conf.log_location, output_file_name + ".log"), 'r+') as log_file:
            # Read the log file
            log = log_file.read()
            pointer = []
            b_pointer = ''

            for line in iter(log.splitlines()):
                my_data = line.split()

                ##########################################################################################################################
                #  Extraction of the principal information : Status, hash recovered, time remaining for the crack, Progress of the hash
                ##########################################################################################################################
                if 'Recovered......:' in line:
                    n_line = line.split()
                    #Mask
                    if pointer[0] == 'Mask':
                        for el in crackOption:
                            if el[0] == pointer[0]:
                                el[1][pointer[0]][1] = n_line[1].split('/')[0] 

                    #Bruteforce
                    if pointer[0] == 'Bruteforce' and b_pointer != '':
                        for el in crackOption:
                            if el[0] == pointer[0]:
                                el[1][b_pointer][1] = n_line[1].split('/')[0]

                    # Keywords, Wordlist
                    elif len(pointer) == 2:
                        for el in crackOption:
                            if el[0] == pointer[0]:
                                el[1][pointer[1]][1] = n_line[1].split('/')[0]

                    # WordlistVariation
                    elif len(pointer) == 3:
                        for el in crackOption:
                            if el[0] == pointer[0]:
                                el[1][pointer[1]][pointer[2]][1] = n_line[1].split('/')[0]

                    # Only for the bruteforce used to crack LM hash in pwdump 
                    elif my_method[1] == 'BruteForce_lm':
                        for el in crackOption:
                            if el[0]== pointer[0]:
                                el[1][b_pointer][1] = n_line[1].split('/')[0]

                    # Only for Wordlist method used in pwdump (The wordlist is made of LM hashes cracked with bruteforce method)
                    elif my_method[1] == 'Dict':
                        for el in crackOption:
                            if el[0]== 'Dict':
                                el[1]['Dict'][1] = n_line[1].split('/')[0]

                elif 'Progress.......:' in line:
                    #Mask
                    if pointer[0] == 'Mask':
                        for el in crackOption:
                            if el[0] == pointer[0]:
                                el[1][pointer[0]][3] = line

                    #Bruteforce
                    if pointer[0] == 'Bruteforce' and b_pointer != '':
                        for el in crackOption:
                            if el[0] == pointer[0]:
                                el[1][b_pointer][3] = line

                    # Keywords, Wordlist
                    elif len(pointer) == 2:
                        for el in crackOption:
                            if el[0] == pointer[0]:
                                el[1][pointer[1]][3] = line

                    # WordlistVariation
                    elif len(pointer) == 3:
                        for el in crackOption:
                            if el[0] == pointer[0]:
                                el[1][pointer[1]][pointer[2]][3] = line

                    # Only for the bruteforce used to crack LM hash in pwdump 
                    elif pointer[0] == 'BruteForce_lm':
                        for el in crackOption:
                            if el[0] == pointer[0]:
                                el[1][b_pointer][3] = line

                    # Only for Wordlist method used in pwdump (The wordlist is made of LM hashes cracked with bruteforce method)
                    elif pointer[0] == 'Dict':
                        for el in crackOption:
                            if el[0] == pointer[0]:
                                el[1][pointer[0]][3] = line

                elif 'Stopped:' or 'Running:' in line:
                    print 'Pointeur {}  &&& B_pointeur {}'.format(pointer, b_pointer)
                    #Mask
                    if pointer and pointer[0] == 'Mask':
                        for el in crackOption:
                            if el[0] == pointer[0]:
                                el[1][pointer[0]][0] = 'Finished'

                    #Bruteforce
                    if pointer and pointer[0] == 'Bruteforce':
                        for el in crackOption:
                            if el[0] == pointer[0]:
                                el[1][pointer[0]][0] = 'Finished'
                                if b_pointer != '':
                                    el[1][b_pointer][0] = 'Finished'

                    # Keywords, Wordlist
                    elif len(pointer) == 2:
                        for el in crackOption:
                            if el[0] == pointer[0]:
                                el[1][pointer[1]][0] = 'Finished'

                    # WordlistVariation
                    elif len(pointer) == 3:
                        for el in crackOption:
                            if el[0] == pointer[0]:
                                el[1][pointer[1]][pointer[2]][0] = 'Finished'  

                    # Only for the bruteforce used to crack LM hash in pwdump 
                    elif pointer and pointer[0] == 'BruteForce_lm':
                        for el in crackOption:
                            if el[0] == pointer[0]:
                                el[1][pointer[0]][0] = 'Finished'
                                if b_pointer != '':
                                    el[1][b_pointer][0] = 'Finished'

                    # Only for Wordlist method used in pwdump (The wordlist is made of LM hashes cracked with bruteforce method)
                    elif pointer and pointer[0] == 'Dict':
                        #b_pointer = ''
                        for el in crackOption:
                            if el[0] == pointer[0]:
                                el[1][pointer[0]][0] = 'Finished'

                ### Special method for bruteforce
                if pointer and (pointer[0] == 'Bruteforce' or pointer[0]=='BruteForce_lm') and 'Input.Mode.....:' in line:
                    n_line = line.split()
                    for el in crackOption:
                        if el[0] == pointer[0]:
                            if b_pointer != '':
                                el[1][b_pointer][0] = 'Finished'
                            b_pointer = n_line[3][1:-1]
                            el[1][b_pointer] = ['','','','']
                            el[1][b_pointer][0] = 'Ongoing'

                ###################################################################################
                #  Method to break the hashes
                ###################################################################################
                if my_data and 'Running:' in line:
                    pointer = []
                    my_command = my_data[-1]
                    my_method = my_command.split(':')

                    if my_method[1] == 'Keywords':
                        pointer.append('Keywords')

                        if my_method[3] == '':
                            for el in crackOption:
                                if el[0] == 'Keywords':
                                    el[1]['Keywords'][0] = 'Ongoing'

                                    pointer.append('Keywords')
                        if my_method[3] != '':
                            for el in crackOption:
                                if el[0] == 'Keywords':
                                    el[1][my_method[3]][0] = 'Ongoing'
                                    pointer.append(my_method[3])

                    elif my_method[1] == 'Wordlist':

                        if my_method[3] == '':
                            pointer.append('Wordlist')
                            for el in crackOption:
                                if el[0] == 'Wordlist':
                                    el[1][my_method[2]][0] = 'Ongoing'
                                    pointer.append(my_method[2])

                        if my_method[3] != '':
                            pointer.append('WordlistVariations')
                            for el in crackOption:
                                if el[0] == 'WordlistVariations':
                                    el[1][my_method[2]][my_method[3]][0] = 'Ongoing'
                                    pointer.append(my_method[2])
                                    pointer.append(my_method[3])

                    elif my_method[1] == 'Mask':
                        pointer.append('Mask')
                        for el in crackOption:
                            if el[0]== 'Mask':
                                el[1]['Mask'][0] = 'Ongoing'

                    elif my_method[1] == 'Bruteforce':
                        pointer.append('Bruteforce')
                        for el in crackOption:
                            if el[0]== 'Bruteforce':
                                el[1]['Bruteforce'][0] = 'Ongoing'

                    elif my_method[1] == 'BruteForce_lm':
                        pointer.append('BruteForce_lm')
                        for el in crackOption:
                            if el[0]== 'BruteForce_lm':
                                el[1]['BruteForce_lm'][0] = 'Ongoing'

                    elif my_method[1] == 'Dict':
                        b_pointer = ''
                        pointer.append('Dict')
                        for el in crackOption:
                            if el[0]== 'Dict':
                                el[1]['Dict'][0] = 'Ongoing'

    except :
        pass

    return 0


