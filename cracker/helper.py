#!/usr/bin/python
# coding: utf8

import app_settings as conf
from flask import request, Response, g, render_template
from functools import wraps
from cracker.auth_module import check_auth
from filters import hex_to_readable
import string
from slugify import slugify
import hashcat_hashes as hashcatconf
from subprocess import check_output, Popen, PIPE, CalledProcessError

def authenticate():
    """
        Return a 401 error asking for user authentication
    """
    return Response(
        u'Impossible to check your identity, please enter valid credentials (authentication mode: ' +
        conf.AUTH_TYPE + ').\n', 401,
        {'WWW-Authenticate': u'Basic realm="Authentication required"'})


def requires_auth(f):
    """
        Wrapper to check on each page the user authentication
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or check_auth(auth.username, auth.password) == "" or not check_auth(auth.username, auth.password):
            return authenticate()
        else:
            # Successful authentication
            # Rewrite username with lower-case characters
            auth_lower = auth.username.lower()

            cur = g.db.execute(
                'select count(*) from users where name = (?)', [auth_lower])
            # If the user doesn't exist in database, add him
            if cur.fetchone()[0] < 1:
                g.db.execute('insert into users (name, email) values (?,?)', [
                             auth_lower, check_auth(auth.username, auth.password)])
                g.db.commit()
            return f(*args, **kwargs)

    return decorated

def check_perms(f):
    """
        Wrapper to check on each page the user permissions
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'crack_id' in kwargs:
            auth = request.authorization
            if not auth: return authenticate()

            # Successful authentication
            # Rewrite username with lower-case characters
            auth_lower = auth.username.lower()

            # The first argument is the crack_id
            crack_id = kwargs['crack_id']

            # Check user permission to handle this crack_id
            if not check_access_authorization_for_a_crack_id(auth_lower, crack_id):
                return render_template(
                    'crack_details.html',
                    title=u'Unauthorized access',
                    characters_complexity_list=[0, 0, 0, 0]
                )

        return f(*args, **kwargs)

    return decorated


def check_access_authorization_for_a_crack_id(username, crack_id):
    """
        Control access of the user a specified crack_id
    """
    cur = g.db.execute('select count(*) from cracks where crack_id=? and user_id=(select id from users where name = ?)',
                       (crack_id, username,))
    is_allowed = cur.fetchone()[0]
    cur.close()
    if is_allowed < 1:
        # The user tries to access unauthorized <crack_id>
        return False
    else:
        return True


def parameters_getter(parameter, parameters_list, beginsWith=""):
    """
        Tranfer cracking parameters across pages
    """
    try:
        if request.form[beginsWith + parameter]:
            parameters_list.append(parameter)
            return True

    except KeyError:
        return False


def get_hash_type_from_hash_id(hash_id):
    """
        Returns the hash type in a human format from the hash_id
    """
    hash_type = ""
    for hash_struct in hashcatconf.HASHS_LIST:
        hash_struct_id, hash_struct_type, hash_struct_example = hash_struct
        if hash_id == hash_struct_id:
            hash_type = hash_struct_type

    return hash_type


def associate_LM_halves(line, cracked_hashs, method):
    """
        Tranfer cracking parameters across pages
    """
    password_not_found = "*****PASSWORD NOT FOUND YET*****"
    empty_password = "*empty*"
    unknown_password = "???????"
    first_half = line[0][0:16].lower()
    second_half = line[0][16:32].lower()

    if first_half == "aad3b435b51404ee":
        if line[1] == password_not_found:
            line[1] = empty_password + unknown_password
            line[2] = 0
            line[3] = 0
            line[4] = 0
            line[5] = 0
            line[6] = 0
            line[7] = "Empty hash (1st half)"
        elif line[1][:7] != empty_password:
            line[1] = empty_password + line[1][7:14]
            line[7] = "Empty hash (1st half)" + line[7]

    if second_half == "aad3b435b51404ee":
        if line[1] == password_not_found:
            line[1] = unknown_password + empty_password
            line[2] = 0
            line[3] = 0
            line[4] = 0
            line[5] = 0
            line[6] = 0
            line[7] = "Empty hash (2nd half)"
        elif line[1][-7:] != empty_password:
            line[1] = line[1][:-7] + empty_password
            line[7] = line[7] + " - Empty hash (2nd half)"

    if first_half in cracked_hashs:
        pwd_stats = cracked_hashs[first_half]
        pwd = pwd_stats["pwd"]
        lower = pwd_stats["lower"]
        upper = pwd_stats["upper"]
        digits = pwd_stats["digits"]
        special = pwd_stats["special"]
        length = pwd_stats["length"]

        if line[1] == password_not_found:
            line[1] = pwd + unknown_password
            line[2] = lower
            line[3] = upper
            line[4] = digits
            line[5] = special
            line[6] = length
            line[7] = method + " (1st half)"
        else:
            line[1] = pwd + line[1][7:14]
            line[2] += lower
            line[3] += upper
            line[4] += digits
            line[5] += special
            line[6] += length
            line[7] = method + " (1st half) - " + line[7]

    if second_half in cracked_hashs:
        pwd_stats = cracked_hashs[second_half]
        pwd = pwd_stats["pwd"]
        lower = pwd_stats["lower"]
        upper = pwd_stats["upper"]
        digits = pwd_stats["digits"]
        special = pwd_stats["special"]
        length = pwd_stats["length"]

        if line[1] == password_not_found:
            line[1] = unknown_password + pwd
            line[2] = lower
            line[3] = upper
            line[4] = digits
            line[5] = special
            line[6] = length
            line[7] = method + " (2nd half)"
        else:
            line[1] = line[1][0:7] + pwd
            line[2] += lower
            line[3] += upper
            line[4] += digits
            line[5] += special
            line[6] += length
            line[7] = line[7] + " - " + method + " (2nd half)"

    return line


def write_to_file_without_errors(string, file_handler):
    """
        Self explanatory
    """
    try:
        # hashcat bug that writes gigbytes of "bug, how should this happen????" in the log files
        # see https://github.com/hashcat/hashcat/blob/master/src/opencl.c#L1892
        if not "bug, how should this happen????" in string:
            file_handler.write(string)

    except Exception as e:
        pass


def generate_password_and_statistics_list(filename, complete_hash_list, hash_type):
    """
        Parses the crack results to generate statistics and update the complete_hash_list
        hash list with the cracked password and its stats
    """
    maximum_length = 0
    method = get_method_from_filename(filename)
    try:
        with open(filename, "r") as crack_result_file:

            cracked_hashs = dict()
            for crack_entry in crack_result_file:
                # Return separator index if found and -1 otherwise.
                if crack_entry.rfind(conf.separator) == -1:
                    continue
                #remove any leading/trailing whitesace/newline
                crack_entry = crack_entry.strip()

                hash, pwd = crack_entry.rsplit(conf.separator, 1)

                # In case of exotic characters in password, they are stored
                # as $HEX[...] and must be decoded
                pwd = hex_to_readable(pwd)

                # Lowercase the hash once and for all
                hash = hash.lower()

                # Password statistics
                length = len(pwd)
                lower = sum(char in string.ascii_lowercase for char in pwd)
                upper = sum(char in string.ascii_uppercase for char in pwd)
                digits = sum(char in string.digits for char in pwd)
                special = length - (lower + upper + digits)

                cracked_hashs[hash] = dict(pwd=pwd, length=length, lower=lower,
                                    upper=upper, digits=digits, special=special)
    except IOError:
        # Exception : if no password has been found, the file doesn't exist
        return maximum_length

    for line in complete_hash_list:
        hash = line[0].lower()

        # Trick to recompose both halves of an LM hash (hashcat
        # splits LM hashes into two halves)
        if hash_type == "LM":
            line = associate_LM_halves(line, cracked_hashs, method)

        # pwdump format treatment is special
        elif hash_type == "pwdump":
            if 'BruteForce_lm' in str(filename):
                line2 = [line[2], line[3], 0, 0, 0, 0, 0, line[10]]
                line2 = associate_LM_halves(line2, cracked_hashs, method)
                line[3] = line2[1]
                line[10] = line2[7]
            else:
                if hash in cracked_hashs:
                    pwd_stats = cracked_hashs[hash]
                    line[1] = pwd_stats["pwd"]
                    line[4] = pwd_stats["lower"]
                    line[5] = pwd_stats["upper"]
                    line[6] = pwd_stats["digits"]
                    line[7] = pwd_stats["special"]
                    line[8] = pwd_stats["length"]
                    line[9] = method

        # Otherwise, just add the password and its stats to the
        # list
        else:
            if hash in cracked_hashs:
                pwd_stats = cracked_hashs[hash]
                line[1] = pwd_stats["pwd"]
                line[2] = pwd_stats["lower"]
                line[3] = pwd_stats["upper"]
                line[4] = pwd_stats["digits"]
                line[5] = pwd_stats["special"]
                line[6] = pwd_stats["length"]
                line[7] = method

    # Global crack consolidated statistics
    # Length
    maximum_length = max((pwd_stats["length"] for pwd_stats in cracked_hashs.values()))
    # Trick for LM hashes
    if hash_type == "LM":
        maximum_length = 14

    return maximum_length


def get_method_from_filename(filename):
    """
        Retrieves the method used to crack passwords from the file naming convention
    """
    method = ""

    method_arg = filename.split(':')
    # Successful method value building
    # XXXfilenameXXX:CrackMode:Wordlist/Mask used:Rule
    # XXXfilenameXXX:method_arg[1]:method_arg[2]:method_arg[3]

    if len(method_arg) == 4 and method_arg[3] != "":
        # if rules
        _, crackmode, wordlist, _ = method_arg
        if crackmode == "Wordlist":
            method = "Wordlist with variations" + \
                "\n(" + unslugifyer(wordlist) + ")"
        else:
            method = "Keywords with variations"

    elif len(method_arg) == 4 and method_arg[3] == "":
        _, crackmode, wordlist, _ = method_arg
        if crackmode == "Wordlist":
            method = "Wordlist" + \
                "\n(" + unslugifyer(wordlist) + ")"
        else:
            method = crackmode

    elif len(method_arg) == 3:
        _, crackmode, wordlist = method_arg
        if crackmode == "Wordlist":
            method = "Wordlist" + \
                "\n(" + unslugifyer(wordlist) + ")"
        else:
            method = crackmode

    return method


def unslugifyer(wordlist):
    """
        Unslugify dictionary name to display it
    """
    for wl in conf.wordlist_dictionary:
        if slugify(wl) == wordlist:
            return wl

    return wordlist


def get_memory_info(cracks_filenames=[]):
    """
        Retrieves Nvidia GPU memory information from the command nvidia-smi
    """
    total_memory_used, total_memory_free, total_memory = 0, 0, 0
    memory_per_crack = {}
    try:
        nvidia_memory_info = check_output(["nvidia-smi", "--query-gpu=memory.used,memory.free,memory.total", "--format=csv,noheader,nounits"])

        for line in nvidia_memory_info.splitlines():
            # split along commas and strip empty whitespaces
            line = [ int(_.strip()) for _ in line.split(',')]
            total_memory_used += line[0]
            total_memory_free += line[1]
            total_memory += line[2]

    except (OSError, CalledProcessError):
        pass

    memory_per_pid = {}
    try:
        nvidia_process_info = check_output(["nvidia-smi", "--query-compute-apps=pid,used_memory", "--format=csv,noheader,nounits"])

        for line in nvidia_process_info.splitlines():
            # split along commas and strip empty whitespaces
            line = [ int(_.strip()) for _ in line.split(',')]
            try:
                memory_per_pid[line[0]] += line[1]
            except KeyError:
                memory_per_pid[line[0]] = line[1]

    except (OSError, CalledProcessError):
        pass

    try:
        for filename in cracks_filenames:
            # Retrieve the PID from the filename
            ps_process = Popen(["ps", "auxww"], stdout=PIPE)
            ps_output = Popen(["grep", conf.hashcat_location],
                              stdin=ps_process.stdout, stdout=PIPE)
            grep_output = check_output(
                ["grep", filename], stdin=ps_output.stdout)
            PID = int(grep_output.split()[1])

            # Populate the dictionary with the GPU memory used by each crack
            try:
                memory_per_crack[filename] = memory_per_pid[PID]
            except KeyError:
                memory_per_crack[filename] = 0
    except (OSError, CalledProcessError):
        pass

    return total_memory_used, total_memory_free, total_memory, memory_per_crack

def checking_mask_form(var):
    for car in var:
        if car not in ['?', 'l','u','d','s','a','b', '']:
            return False
    return True

def checking_crackMode(liste):
    if len(liste)==0:
        return False
    else:
        return True
