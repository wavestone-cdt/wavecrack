#!/usr/bin/python
# coding: utf8
import os
import tempfile
import app_settings as conf
import subprocess
import os.path

from cracker import celery
from celery.exceptions import Ignore
from customexceptions import NoRemainingHashException, RevokedTaskException
from crackmodes import WordlistBasedCrackMode, BruteforceCrackMode, \
    KeywordsCrackMode, MaskCrackMode, LmMadeWordlistBasedCrackMode, HybridCrackMode
from dictionnary_made_from_cracked_LMhashes import newDict_generation

@celery.task(bind=True)
def hashcatCrack(self, selectedHashtype, hashes, crackOptions, dicoOptions, dicoRulesOptions, output_file_name, selectedMask='', selectedKeywords='', usernames_with_hash=False):
    """
        Celery asynchronous task for hash cracking 
    """
    print("Starting cracking session on task %s" % self.request.id)

    # Files where hashes are stocked
    output_file = os.path.join(
        conf.output_files_folder_location, output_file_name)   
 
    hashes_storage_file = os.path.join(
        conf.hashes_location, output_file_name)

    #If user is using pwdump format, trying to crack LM_hash with Bruteforce 
    #and then depending on LM_hash presence or not, wavecrack crack NT hash with different methods
    if selectedHashtype==999999:

        output_file_nameLM= output_file_name + "LM"
        hashes_storage_LM = os.path.join(
            conf.hashes_location, output_file_nameLM)

        #File used for statistic
        output_file_name_pwdump= output_file_name + "pwdump"
        hashes_storage_pwdump = os.path.join(
            conf.hashes_location, output_file_name_pwdump)

        #Now let's crack LM_hash first 
        with tempfile.NamedTemporaryFile(delete=True) as hashes_LM, tempfile.NamedTemporaryFile(delete=True) as hashes_NTwithLM, tempfile.NamedTemporaryFile(delete=True) as hashes_NTwithoutLM, open(hashes_storage_file, "a") as storage_NTLM, open(hashes_storage_LM, "a+") as storage_LM, open(hashes_storage_pwdump, "a+") as storage_pwdump, tempfile.NamedTemporaryFile(delete=True) as myDict, tempfile.NamedTemporaryFile(delete=True) as newDict:

            LM= ""
            NTwithLM= ""        
            NTwithoutLM= ""
            NTLM=""        
            usernames = ""

            for line in iter(hashes.splitlines()):
                storage_pwdump.write(line + '\n')     
                my_data = line.split(":")

                if usernames_with_hash:
                    usernames += my_data[0] + "\n"

                if my_data[3]!="" and len(my_data[3])==32:
                    storage_NTLM.write(my_data[3].lower() + '\n')

                #We treat non empty an non corrupted (a priori) hashes
                if my_data[2].lower()!="aad3b435b51404eeaad3b435b51404ee" and len(my_data[2])==32:
                    if my_data[2][16:].lower()!="aad3b435b51404ee":
                        LM = my_data[2].lower() + "\n"
                    else:
                        LM = my_data[2][:16].lower() + "\n"
                    NTwithLM = my_data[3].lower() + "\n"
                    hashes_LM.write(LM)
                    storage_LM.write(LM)
                    hashes_NTwithLM.write(NTwithLM)  
            
                else:
                    NTwithoutLM = my_data[3].lower() + "\n"
                    hashes_NTwithoutLM.write(NTwithoutLM)

            storage_NTLM.flush()
            storage_pwdump.flush() 
            hashes_LM.flush()
	    hashes_NTwithLM.flush()
            hashes_NTwithoutLM.flush()
            storage_LM.close()

            #### Bruteforce of LM hashes ####
            # The global options
            options1 = {
                'hashtype_selected': '3000',
                'output_file_name': output_file_name,
                'hash_files': hashes_LM.name,
            }

            output_file_lm = output_file + ":BruteForce_lm::"
            BruteforceCrackMode(options1).run(
                output_file=output_file_lm,
            )

            #### Wordlist attack and then Hybrid attack on NTLMwithLM hashes ####
            #Making the dictionary for the wordlist attack and return the path to the new dictionary 
            try:

                #Algo:
                #Make a python dictionary-> key:hash LM of 16 bits, value: cracked hashes (clear psswd)
                #For each original 32 bits length hashes, get the crack value for each halves thanks to the python dictionary
                #Make a file dictionary on which we will apply rule toggles-lm-ntlm.rule to obtain a more complete dictionary (same pssd but with min/maj variations)
                #Dictionary attack with these new dictionary
                #Then Hybrid attack to find pssd with len>14
                makeDict(output_file_name, hashes_storage_LM, output_file_lm, myDict.name, newDict.name)

                #### Crack of NTwithLM hashes ####
                #First we are making a Wordlist attack to catch all the words with len<=14
                options_NTwithLM = {
                    'hashtype_selected': '1000',
                    'output_file_name': output_file_name,#NTwithLM + ":Dict:",
                    'hash_files': hashes_NTwithLM.name,
                }
                output_file_ntDict= output_file + "NTwithLM:Dict::"
                LmMadeWordlistBasedCrackMode(options_NTwithLM).run(
                    output_file= output_file_ntDict,
                    wordlist=newDict.name
                )

                #Then hybrid attack is launched to catch all the words which len is btw 15 and 20
                options_hybrid = {
                    'hashtype_selected': '1000',
                    'output_file_name': output_file_name,
                    'hash_files': hashes_NTwithLM.name,
                }
                output_file_ntHybrid= output_file + "NTwithLM:Hybrid::"
                HybridCrackMode(options_hybrid).run(
                    output_file= output_file_ntHybrid,
                    wordlist=newDict.name
                )

                #if some NTwithLM hashes were not found, we put them in the NTwithoutLM hashes file
                hashes_NTwithLM.seek(0)
                r = hashes_NTwithLM.read()
                for line in iter(r.splitlines()):
                    my_data = line.split()
                    if my_data and not isInFile(my_data[0], output_file_ntDict) and not isInFile(my_data[0], output_file_ntHybrid):
                        hashes_NTwithoutLM.write(my_data[0] + '\n')
                hashes_NTwithoutLM.flush()

            except IOError:
                pass

            #### Crack of NTwithoutLM hashes ####
            options_NTwithoutLM = {
                'hashtype_selected': '1000',
                'output_file_name': output_file_name,#NTwithoutLM,
                'hash_files': hashes_NTwithoutLM.name,
            }

            # Usernames are handled as new keywords
            if usernames_with_hash:
                selectedKeywords += "\n" + usernames
            output_file_NTwithoutLM = output_file + "NTwithoutLM"
            hashcatCrackMode(self, crackOptions, dicoOptions, dicoRulesOptions, selectedKeywords, selectedMask, output_file_NTwithoutLM, options_NTwithoutLM)

    else:
        # Hashes writing in a temp file
        with tempfile.NamedTemporaryFile(delete=True) as hashes_file:
            # If the hash list includes usernames, they are used like keywords
            # and then deleted from hash list
            with open(hashes_storage_file, "a") as storage:
                if usernames_with_hash:
                    usernames=""
                    for line in iter(hashes.splitlines()):
                        index_separator = line.find(conf.separator)
                        if index_separator > 0:
                            # Username extraction
                            username = line[0:index_separator]
                            usernames += username + "\n"
                            hash = line[index_separator + 1:] + "\n"
                        else:
                            hash = line                        
                        storage.write(hash.lower())
                        hashes_file.write(hash.lower())
                else:
                    storage.write(hashes.lower())
                    hashes_file.write(hashes.lower())

            hashes_file.flush()

            # The global options dictionnary
            options = {
                'hashtype_selected': str(selectedHashtype),
                'output_file_name': output_file_name,
                'hash_files': hashes_file.name,
            }

            # Usernames are handled as new keywords
            if usernames_with_hash:
                selectedKeywords += "\n" + usernames

            hashcatCrackMode(self, crackOptions, dicoOptions, dicoRulesOptions, selectedKeywords, selectedMask, output_file, options)

    print("Finished cracking session for task %s" % self.request.id)
    return True

def makeDict(output_file_name, hashes_storage_LM, output_file_lm, myDictName, newDictName):

    with open(output_file_lm, 'r') as lm, open(hashes_storage_LM, 'r') as storage_LM, open(myDictName, 'w') as myDict, open(newDictName, 'w') as newDict:
        half_LMhash= lm.read()
        cracked_LMhash_dictionary={}
        toWrite1=""
        toWrite2=""
        toWrite=""

        #Making the python dictionary
        for line in iter(half_LMhash.splitlines()):
            half_lm_hash, half_lm_password = line.split(conf.separator)
            cracked_LMhash_dictionary[half_lm_hash.lower()] = half_lm_password.lower()

        #Making the file dictionary
        storage_LM.seek(0)
        full_LMhash_input = storage_LM.read()
        #To avoid duplicate hash in the dict
        avoiding_duplicate_hash=[]

        for line in iter(full_LMhash_input.splitlines()):
            if line.lower() not in avoiding_duplicate_hash:
                avoiding_duplicate_hash.append(line.lower()) 
                if line[:16].lower() in cracked_LMhash_dictionary:
                    toWrite1= cracked_LMhash_dictionary[line[:16].lower()]
                    if line[16:]!="" and line[16:] in cracked_LMhash_dictionary:
                        toWrite2 = cracked_LMhash_dictionary[line[16:].lower()]
                    else:
                        toWrite2 = ""
                    toWrite = toWrite1 + toWrite2 + "\n"
                    myDict.write(toWrite)

        myDict.flush()
        newDict_generation(myDictName, newDictName)

    return True
                

def hashcatCrackMode(self, crackOptions, dicoOptions, dicoRulesOptions, selectedKeywords, selectedMask, output_file, options):
    # We wrap all the calls to the crack modes to catch the
    # NoRemainingHashException exception
    try:
        # Keywords attack
        if "Keywords" in crackOptions:

            # Test the "pure" keywords
            output_file_key = output_file + ":Keywords::"
            KeywordsCrackMode(options).run(
                output_file=output_file_key,
                keywords=selectedKeywords
            )

            # Test variations of the keywords
            for rule_file_name in conf.rule_name_list:
                output_file_keyVar = output_file_key + rule_file_name
                KeywordsCrackMode(options).run(
                    output_file=output_file_keyVar,
                    keywords=selectedKeywords,
                    rule=rule_file_name
                )
    
        # Wordlist attack
        if "Wordlist" in crackOptions:
            for wordlist in dicoOptions:
                output_file_dict = output_file + ":Wordlist:" + wordlist + ":"
                WordlistBasedCrackMode(options).run(
                    output_file=output_file_dict,
                    wordlist=wordlist
                )

        # Wordlist variations attack
        if "WordlistVariations" in crackOptions:
            for wordlist in dicoRulesOptions:
                # For each wordlist to use with rules (eg
                # "dictionnaire-francais")
                for rule_name in conf.rule_name_list:
                    # For each rule (eg "rockyou-30000.rule")
                    output_file_dictVar = output_file + ":Wordlist:" + wordlist + ":" + rule_name
                    WordlistBasedCrackMode(options).run(
                        output_file=output_file_dictVar,
                        wordlist=wordlist,
                        rule=rule_name
                    )

        # Mask attack
        if "Mask" in crackOptions:
            output_file_mask = output_file + ":Mask:" + selectedMask + ":"
            MaskCrackMode(options).run(
                output_file=output_file_mask,
                mask=selectedMask
            )

        # Brute force attack
        if "Bruteforce" in crackOptions:
            # Equal to a 20 chacracters mask
            output_file_bf = output_file + ":Bruteforce::"
            BruteforceCrackMode(options).run(
                output_file=output_file_bf
            )

    except NoRemainingHashException:
        print("Session finished early, we found all the hashes :)")

    except RevokedTaskException:
        print("Revoked/aborted task!")
        # Mark it as revoked, for the list page
        self.update_state(state='REVOKED')
        # We need to raise this Celery exception, otherwise the worker will
        # set the SUCCESS status after finishing (successfully) the task.
        raise Ignore()
    return True

def isInFile(word, f):
    with open(f, 'r') as fi:
        read_fi = fi.read()
        for line in iter(read_fi.splitlines()):
            my_data= line.split(conf.separator)
            if my_data[0]==word:
                return True
    return False    
