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


def associate_LM_halves(line, hash, pwd, lower, upper, digits, special, method):
    """
        Tranfer cracking parameters across pages
    """
    # Empty LM hash == "AAD3B435B51404EE"
    password_not_found = "*****PASSWORD NOT FOUND YET*****"
    empty_password = "*empty*"
    unknown_password = "???????"

    if line[0][0:16].lower() == "AAD3B435B51404EE".lower():
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

    if line[0][16:32].lower() == "AAD3B435B51404EE".lower():
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

    if line[0][0:16].lower() == hash.lower():
        if line[1] == password_not_found:
            line[1] = pwd + unknown_password
            line[2] = lower
            line[3] = upper
            line[4] = digits
            line[5] = special
            line[6] = len(pwd)
            line[7] = method + " (1st half)"
        else:
            line[1] = pwd + line[1][7:14]
            line[2] += lower
            line[3] += upper
            line[4] += digits
            line[5] += special
            line[6] += len(pwd)
            line[7] = method + " (1st half) - " + line[7]

    if line[0][16:32].lower() == hash.lower():
        if line[1] == password_not_found:
            line[1] = unknown_password + pwd
            line[2] = lower
            line[3] = upper
            line[4] = digits
            line[5] = special
            line[6] = len(pwd)
            line[7] = method + " (2nd half)"
        else:
            line[1] = line[1][0:7] + pwd
            line[2] += lower
            line[3] += upper
            line[4] += digits
            line[5] += special
            line[6] += len(pwd)
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
    try:
        with open(filename, "r") as crack_result_file:
            for line in crack_result_file.readlines():
                # Return separator index if found and -1 otherwise.
                if line.rfind(conf.separator) > 0:
                    hash = line[:line.rfind(conf.separator)]
                    pwd = line[line.rfind(conf.separator) + 1:len(line) - 1]

                    # In case of exotic characters in password, they are stored
                    # as $HEX[...] and must be decoded
                    pwd = hex_to_readable(pwd)

                    # Password statistics
                    length = len(pwd)
                    lower = sum(char in string.ascii_lowercase for char in pwd)
                    upper = sum(char in string.ascii_uppercase for char in pwd)
                    digits = sum(char in string.digits for char in pwd)
                    special = length - (lower + upper + digits)

                    method = get_method_from_filename(filename)

                    for line in complete_hash_list:
                        # Trick to recompose both halves of an LM hash (hashcat
                        # splits LM hashes into two halves)
                        if hash_type == "LM":
                            line = associate_LM_halves(
                                line, hash, pwd, lower, upper, digits, special, method)
                        # Otherwise, just add the password and its stats to the
                        # list
                        else:
                            if line[0] == hash:
                                line[1] = pwd
                                line[2] = lower
                                line[3] = upper
                                line[4] = digits
                                line[5] = special
                                line[6] = len(pwd)
                                line[7] = method

                    # Global crack consolidated statistics
                    # Length
                    maximum_length = max(maximum_length, length)
                    # Trick for LM hashes
                    if hash_type == "LM":
                        maximum_length = 14
            crack_result_file.close()
    except IOError:
        # Exception : if no password has been found, the file doesn't exist
        pass
    return maximum_length


def get_method_from_filename(filename):
    """
        Retrieves the method used to crack passwords from the file naming convention
    """
    method = ""

    method_arg = filename.split(':')
    # Successful method value building
    # XXXfilenameXXX:CrackMode:Wordlist/Mask used:Rule
    # XXXfilenameXXX:method_arg[2]:method_arg[3]:method_arg[4]

    if len(method_arg) == 4:
        # if rules
        _, crackmode, wordlist, _ = method_arg
        if crackmode == "Wordlist":
            method = "Wordlist with variations" + \
                "\n(" + unslugifyer(wordlist) + ")"
        else:
            method = "Keywords with variations"

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
