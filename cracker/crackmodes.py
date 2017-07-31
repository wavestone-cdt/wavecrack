#!/usr/bin/python
# coding: utf8
import random
import string
import tempfile
import time

from slugify import slugify

import app_settings as conf
from hashcat import run_hashcat_safe
from customexceptions import OutOfMemoryException
from helper import write_to_file_without_errors

# What to export (will be imported whith "import * from crackmodes")
__all__ = [
    'WordlistBasedCrackMode',
    'BruteforceCrackMode',
    'KeywordsCrackMode',
    'MaskCrackMode',
    'LmMadeWordlistBasedCrackMode',
    'HybridCrackMode',
]


class CrackMode():
    """
        Base (abstract) class for crack modes
    """
    name = "noname-crack-mode"

    def __init__(self, options):
        self.sessionID = self._generate_session_id()
        self.options = options

    def run(self, *args, **kwargs):
        """
            Run this cracking mode
        """
        print("Running cracking mode %s, args=%s kwargs=%s"
              % (self.name, args, kwargs))

        # Hashcat options details :
        #     Call the program through hashcat_location
        #     . Option -a 0 or -a 3 : Attack-mode. 0 Straight or 3 Brute-force
        #     . Option -m hashtype_selected : Hash-type
        #     . Option --session "".join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(6) : Assign different name to cracks to be able to launch them concurrently
        #     . Option -p separator : Define separator character between hash and password in output files. By default, it's hash:password
        #     . Option -o output_file_name : Output file path
        #     . Option --potfile-disable : Disable .pot file
        #     . Option --status et --status-timer: Write crack status in a file regularly
        #     . Option --remove et --remove-timer: Remove of hash once it is cracked in input file
        #     . Option hashfile : Specify input hashes file
        #     . Option wordlists_location + "wordlist.txt" :	 Specify wordlist to use

        # Common parameters list
        # Every crack use those parameters to launch hashcat
        self.common_parameters = [
            conf.hashcat_location,
            "--weak-hash-threshold", "0",
            "-p", conf.separator,
            "-m", self.options['hashtype_selected'],
            "--session", self.sessionID,
            "--status",
            "--status-timer=3600",
            "--remove",
            "--remove-timer=30",
            "--restore-disable",
            "--logfile-disable",
        ]

        if not conf.HASHCAT_DISABLE_POT_FILE:
            self.common_parameters.append("--potfile-disable")

        try_number = 1
        return_code = None
        while return_code is None:
            # Run the crack mode, but always retry if we were lacking available
            # memory
            try:
                return_code = self.launch_call(*args, **kwargs)
            except OutOfMemoryException:
                print("Got a Out of Memory exception (try %d): let's sleep and"
                      " hope we'll have more memory when waking up..." % try_number)

                with open(conf.log_location + self.options['output_file_name'] + ".log", "a+", 0) as logfile:
                    write_to_file_without_errors(
                        "\nWe don't have enough GPU memory to run this mode (%s).\n" % self.name, logfile)
                    write_to_file_without_errors("Sleeping %d minutes (try #%d)...\n" % (
                        conf.OOM_DELAY_SLEEP / 60., try_number), logfile)

                    logfile.close()

                try_number += 1
                time.sleep(conf.OOM_DELAY_SLEEP)

        print("Finished cracking mode %s, return code is %s" %
              (self.name, return_code))
        return return_code

    def launch_call(self, *args, **kwargs):
        """
            Use the parameters to call the run_hashcat_safe method 
        """
        raise NotImplementedError()

    def _generate_session_id(self):
        """
            Generates a session ID to identify this run
        """
        return "".join(
            random.SystemRandom().choice(string.ascii_uppercase + string.digits)
            for _ in range(6)
        )


class WordlistBasedCrackMode(CrackMode):
    """
        Crack mode using a wordlist
    """
    name = 'wordlist'

    def launch_call(self, output_file, wordlist, rule=None):
        """
            Look for the wordlist (safely), and optionnaly apply a rule

            @param wordlist: the name of the wordlist to use (eg "english-dictionary")
            @param rule: the rule to apply on the wordlist (eg "rockyou-30000.rule")
        """

        # Find the wordlist file from its name
        wordlist_file = None
        for wordlist_pair in conf.wordlist_dictionary:
            # For all available dictionnaries
            if wordlist == slugify(wordlist_pair):
                # If we found the required wordlist, we save the filename
                wordlist_file = conf.wordlists_location + \
                    conf.wordlist_dictionary[wordlist_pair]
        
        if not wordlist_file:
            raise ValueError("Unable to find wordlist %s!" % wordlist)

        extra_options = []

        # Rule variations on a wordlist
        if rule:
            extra_options += ["-r", conf.hashcat_rules_location + rule]

        return run_hashcat_safe(
            self.common_parameters + ['-a', '0'] + extra_options + [
                self.options['hash_files'],
                wordlist_file,
                "-o", output_file,
            ],
            self.options['output_file_name'],
        )


class BruteforceCrackMode(CrackMode):
    """
        Crack mode using bruteforce
    """
    name = 'bruteforce'

    def launch_call(self, output_file):
        return run_hashcat_safe(
            self.common_parameters + [
                '-a', '3',
                self.options['hash_files'],
                "--increment",
                "?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a",
                "-o", output_file
            ],
            self.options['output_file_name'],
        )


class KeywordsCrackMode(CrackMode):
    """
        Crack mode using a list of keywords
    """
    name = 'keywords'

    def launch_call(self, output_file, keywords, rule=None):
        """
            @param keywords: a string containing one keyword per line
            @param rule: a string identifying the rule to use (ex.: "rockyou-30000.rule")
        """
        # Write the keywords in a temporary file
        with tempfile.NamedTemporaryFile(delete=True) as keywords_listfile:
            keywords_listfile.write(keywords)
            keywords_listfile.flush()

            extra_options = []

            # Rule variations on the keywords
            if rule:
                extra_options += ["-r", conf.hashcat_rules_location + rule]

            return run_hashcat_safe(
                self.common_parameters + ['-a', '0'] + extra_options + [
                    self.options['hash_files'],
                    keywords_listfile.name,
                    "-o", output_file
                ],
                self.options['output_file_name'],
            )


class MaskCrackMode(CrackMode):
    """
        Crack mode using a specified mask
    """
    name = 'mask'

    def launch_call(self, output_file, mask):
        return run_hashcat_safe(
            self.common_parameters + [
                '-a', '3',
                self.options['hash_files'],
                mask,
                "-o", output_file
            ],
            self.options['output_file_name'],
        )

class LmMadeWordlistBasedCrackMode(CrackMode):
    """
        Crack mode using the wordlist built with the cracked LM hashes (this crackmode is only used in case of pwdump format).
    """
    name = 'LMwordlist'

    def launch_call(self, output_file, wordlist, rule=None):

        wordlist_file = wordlist

        return run_hashcat_safe(
            self.common_parameters + ['-a', '0'] + [
                self.options['hash_files'],
                wordlist_file,
                "-o", output_file,
            ],
            self.options['output_file_name'],
        )

class HybridCrackMode(CrackMode):
    """
        Crack mode used for hybrid attack (Cf hybrid attack with hashcat). The wordlist used is the one built with the cracked LM hashes.  
    """
    name = 'hybrid'

    def launch_call(self, output_file, wordlist):
        wordlist_file = wordlist

        return run_hashcat_safe(
            self.common_parameters + [
                '-a', '6',
                self.options['hash_files'],
                wordlist_file,
                "--increment",
                "?a?a",
                "-o", output_file
            ],
            self.options['output_file_name'],
        )
