#!/usr/bin/python
# coding: utf8
import os
import tempfile

import app_settings as conf
from cracker import celery
from celery.exceptions import Ignore
from customexceptions import NoRemainingHashException, RevokedTaskException
from crackmodes import WordlistBasedCrackMode, BruteforceCrackMode, \
    KeywordsCrackMode, MaskCrackMode


@celery.task(bind=True)
def hashcatCrack(self, selectedHashtype, hashes, crackOptions, dicoOptions, dicoRulesOptions,
                 output_file_name, selectedMask='', selectedKeywords='', usernames_with_hash=False):
    """
        Celery asynchronous task for hash cracking 
    """
    print("Starting cracking session on task %s" % self.request.id)

    # Hashes writing in a temp file
    with tempfile.NamedTemporaryFile(delete=True) as hashes_file:
        hashes_storage_file = os.path.join(
            conf.hashes_location, output_file_name)
        # If the hash list includes usernames, they are used like keywords
        # and then deleted from hash list
        with open(hashes_storage_file, "a") as storage:
            if usernames_with_hash:
                usernames = ""
                for line in iter(hashes.splitlines()):
                    index_separator = line.find(conf.separator)
                    if index_separator > 0:
                        # Username extraction
                        username = line[0:index_separator]
                        usernames += username + "\n"
                        hash = line[index_separator + 1:] + "\n"
                    else:
                        hash = line
                    storage.write(hash)
                    hashes_file.write(hash)
            else:
                storage.write(hashes)
                hashes_file.write(hashes)

        hashes_file.flush()

        # The global options dictionnary
        options = {
            'hashtype_selected': str(selectedHashtype),
            'output_file_name': output_file_name,
            'hash_files': hashes_file.name,
        }

        output_file = os.path.join(
            conf.output_files_folder_location, output_file_name)

        # Usernames are handled as new keywords
        if usernames_with_hash:
            selectedKeywords += "\n" + usernames

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
                output_file_bf = output_file + ":BruteForce::"
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

    print("Finished cracking session for task %s" % self.request.id)
    return True
