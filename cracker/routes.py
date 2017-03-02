#!/usr/bin/python
# coding: utf8
import os
import sqlite3
import tempfile
import random
import string
import glob
import csv
import StringIO
from subprocess import call, check_output
from time import strftime

from werkzeug import secure_filename
from flask import render_template, request, g, make_response

from slugify import slugify

import app_settings as conf
from cracker import app, celery
from cracker.crackstatus import running_crack_nb, get_crack_status
from cracker.filters import hex_to_readable
from cracker import hashID
from cracker.helper import requires_auth, check_access_authorization_for_a_crack_id, parameters_getter, get_hash_type_from_hash_id, associate_LM_halves, generate_password_and_statistics_list, get_memory_info
from cracker.tasks import hashcatCrack
import cracker.hashcat_hashes as hashcatconf


def connect_db():
    """
        Connect to the database
    """
    return sqlite3.connect(app.config['DATABASE'])


@app.before_request
def before_request():
    """
        Connecting to the database before each request
    """
    g.db = connect_db()


@app.teardown_request
def teardown_request(exception):
    """
        Connecting to the database after each request
    """
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()


@app.route('/', methods=['GET'])
@requires_auth
def home():
    """
        Homepage
    """
    if app.config['DEBUG']:
        server_version = os.popen("git rev-parse --short HEAD").read()
    else:
        server_version = None

    return render_template(
        'homepage.html',
        title=u'Homepage',
        version=server_version
    )


@app.route('/add', methods=['GET'])
@requires_auth
def new_hashes_form():
    """
        Form to add new hashes
    """
    running_crack_list = running_crack_nb()
    if len(running_crack_list) > conf.MAX_CRACKSESSIONS:
        return render_template(
            'crack_nb.html',
            title=u'Failed launch',
            MAX_CRACKSESSIONS=conf.MAX_CRACKSESSIONS,
            liste_en_cours=running_crack_list,
            crack_count=len(running_crack_list)
        )
    else:
        return render_template(
            'add.html',
            title=u'Add new crack',
            HASHS_LIST=hashcatconf.HASHS_LIST,
            wordlist_dictionary=conf.wordlist_dictionary,
            separator=conf.separator,
            max_size=app.config['MAX_CONTENT_LENGTH'],
            CRACK_DURATIONS=conf.CRACK_DURATIONS
        )


def allowed_file(filename):
    """
        Returning if the extension of the uploaded file is allowed or not
    """
    return '.' in filename and filename.rsplit('.', 1)[-1] in conf.ALLOWED_EXTENSIONS


@app.route('/upload', methods=['GET'])
@requires_auth
def upload_menu():
    """
        Return available file extensions and max size of uploadable file
    """
    return render_template(
        'upload.html',
        title=u'Protected file cracking',
        max_size=app.config['MAX_CONTENT_LENGTH'],
        extension_list=conf.extensions_dictionary
    )


@app.route('/upload/start', methods=['POST'])
@requires_auth
def upload_file():
    """
        Function to handle the upload of a file and launch the associated crack
    """
    file = request.files['file']
    if file and allowed_file(file.filename):
        # Save the file on disk with a random name + file extension
        secure_file_name = secure_filename(file.filename)
        filename = "".join(random.SystemRandom().choice(string.ascii_uppercase + string.digits)
                           for _ in range(6)) + "." + secure_file_name.rsplit('.', 1)[1]
        filext = secure_file_name.rsplit('.', 1)[1]
        filedir = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filedir)

        for extension_and_exec in conf.extensions_dictionary:
            if filename.rsplit('.', 1)[1] == extension_and_exec:
                # Hash extraction from uploaded file
                try:
                    output_hash = check_output([os.path.join(
                        conf.john_location, conf.extensions_dictionary[extension_and_exec]), filedir])
                except:
                    return upload_menu()

                # Delete temp file
                os.remove(filedir)

                # Specific treatment for office2john extension
                if conf.extensions_dictionary[extension_and_exec] == "office2john.py":
                    # Original format have to be modified to agree with hashcat format. At the beginning, it's like : namefile.extension:hash:othersinformation and we just need the hash
                    # Delete the part before the hash
                    output_hash = output_hash[
                        output_hash.find(":") + 1:len(output_hash)]

                    # Delete the part after the hash
                    output_hash = output_hash[0:output_hash.find(":")]

        return render_template(
            'uploaded_file.html', title=u'Uploaded file', filext=filext, output_hash=output_hash)
    else:
        return upload_menu()


@app.route('/status', methods=['GET'])
@requires_auth
def global_state():
    """
        Return an overview of the ongoing cracks
    """
    running_crack_list = running_crack_nb()
    # Retrieve the GPU memory used for each crack (search by output file name)
    total_memory_used, total_memory_free, total_memory, memory_per_crack = \
        get_memory_info([_[4] for _ in running_crack_list])
    
    running_crack_list_and_memory = []
    for crack in running_crack_list:
        try:
            running_crack_list_and_memory.append(crack + [memory_per_crack[crack[4]]])
        except KeyError:
            running_crack_list_and_memory.append(crack + [0])
    
    return render_template(
        'crack_nb.html',
        title=u'Global status',
        MAX_CRACKSESSIONS=conf.MAX_CRACKSESSIONS,
        total_memory_used = total_memory_used,
        total_memory_free = total_memory_free,
        total_memory = total_memory,
        running_crack_list=running_crack_list_and_memory,
        crack_count=len(running_crack_list)
    )


@app.route('/identify-hash', methods=['GET', 'POST'])
@requires_auth
def identify_hash():
    """
        Identify the hash type
    """
    if request.method == 'GET' or not request.form.get('hash', False):
        return render_template('identification.html',
                               title=u'Hash identification')

    elif request.method == 'POST':
        # Information from previous page form
        hashIdentifier = hashID.HashID()
        return render_template('identification_result.html', title=u'Identification result',
                               result=hashID.writeResult(hashIdentifier.identifyHash(request.form.get('hash'))))


@app.route('/add/validate', methods=['POST'])
@requires_auth
def new_hashes_validation():
    """
        Cracking options validation
    """
    # Was a file uploaded ?
    file_content = ""
    if 'file' in request.files:
        file = request.files['file']
        # Check that the file is correct
        if file.filename != '':
            filename, file_extension = os.path.splitext(file.filename)
            if file_extension == ".txt":
                file_content = file.read()
            else:
                # Invalid file name
                return render_template(
                    'add.html',
                    title=u'Add new crack',
                    error=u'Invalid file name',
                    HASHS_LIST=hashcatconf.HASHS_LIST,
                    wordlist_dictionary=conf.wordlist_dictionary,
                    separator=conf.separator,
                    max_size=app.config['MAX_CONTENT_LENGTH'],
                    CRACK_DURATIONS=conf.CRACK_DURATIONS)

    # Retrieve information from previous page form
    if file_content != "":
        hashes = file_content
    else:
        hashes = request.form['hashes']
    hashtype_selected = int(request.form['hashtype'])

    # By default, no options selected
    optionList = []
    wordlistList = []
    wordlistRulesList = []
    selectedMask = ""
    selectedKeywords = ""
    crackDuration = conf.CRACK_DURATIONS[0]

    # Information from previous page form
    usernames = parameters_getter('Withusernames', [])
    selectedMask = request.form['ChosenMask']
    selectedKeywords = request.form['ChosenKeyword']

    parameters_getter('Keywords', optionList)

    if parameters_getter('Wordlist', optionList):
        for dictionary in conf.wordlist_dictionary:
            parameters_getter(slugify(dictionary), wordlistList)

    if parameters_getter('WordlistVariations', optionList):
        for dictionary in conf.wordlist_dictionary:
            parameters_getter("rule" + slugify(dictionary), wordlistRulesList)

    parameters_getter('Mask', optionList)
    parameters_getter('Bruteforce', optionList)

    crackDuration = int(request.form.get('ChosenDuration', ''))
    if crackDuration not in conf.CRACK_DURATIONS:
        crackDuration = conf.CRACK_DURATIONS[0]

    # Retrieve the number of ongoing crack
    running_crack_list = running_crack_nb()

    # If too many cracks are currently launched:
    if len(running_crack_list) > conf.MAX_CRACKSESSIONS:
        # Redirect the user to an error page
        return render_template('crack_nb.html', title=u'Launch error', MAX_CRACKSESSIONS=conf.MAX_CRACKSESSIONS,
                               liste_en_cours=running_crack_list, crack_count=len(running_crack_list))

    # Otherwise, return validation page
    else:
        return render_template(
            'validation.html',
            title=u'Crack form validation',
            usernames_with_hash=usernames,
            crack_duration=crackDuration,
            hashes=hashes,
            HASHS_LIST=hashcatconf.HASHS_LIST,
            hashtype_selected=hashtype_selected,
            crackOptions=optionList,
            wordlistRulesList=wordlistRulesList,
            wordlistList=wordlistList,
            listOfAllWordlists=sorted(conf.wordlist_dictionary),
            mask=selectedMask,
            keywords=selectedKeywords,
            separator=conf.separator
        )


@app.route('/add/start', methods=['POST'])
@requires_auth
def new_hashes_start():
    """
        Effective launch of a crack
    """
    # Retrieve information from previous page form
    hashes = request.form['hashes']
    hashes_count = len(hashes.splitlines())
    hashtype_selected = int(request.form['hashtype'])

    # By default, no options selected
    optionList = []
    wordlistList = []
    wordlistRulesList = []
    selectedMask = ''
    selectedKeywords = ''

    # Information from the previous page form
    usernames = parameters_getter('Withusernames', [])

    selectedKeywords = request.form['ChosenKeyword']
    parameters_getter('Keywords', optionList)
    if parameters_getter('Wordlist', optionList):
        for dictionary in conf.wordlist_dictionary:
            parameters_getter(slugify(dictionary), wordlistList)

    if parameters_getter('WordlistVariations', optionList):
        for dictionary in conf.wordlist_dictionary:
            parameters_getter(
                slugify(dictionary), wordlistRulesList, beginsWith="rule")

    selectedMask = request.form['ChosenMask']
    parameters_getter('Mask', optionList)

    parameters_getter('Bruteforce', optionList)

    crackDuration = int(request.form.get('ChosenDuration', ''))
    if crackDuration not in conf.CRACK_DURATIONS:
        crackDuration = conf.CRACK_DURATIONS[0]

    # Determination of current crack output file
    output_file_name_prefix = strftime("%y-%m-%d_%H-%M")
    output_file_name_suffix = ''.join(random.SystemRandom().choice(
        string.ascii_uppercase + string.digits) for _ in range(6))
    output_file_name = output_file_name_prefix + output_file_name_suffix

    running_crack_list = running_crack_nb()
    if len(running_crack_nb()) > conf.MAX_CRACKSESSIONS:
        return render_template('crack_nb.html', title=u'Launching error', MAX_CRACKSESSIONS=conf.MAX_CRACKSESSIONS,
                               liste_en_cours=running_crack_list, crack_count=len(running_crack_list))
    else:
        # Asynchronous launching:
        # synchronous process is hashcatCrack(a,b,c,d) and
        # asynchronous process is hashcatCrack.delay(a,b,c,d)
        crack_task = hashcatCrack.delay(hashtype_selected, hashes, optionList, wordlistList, wordlistRulesList,
                                        output_file_name, selectedMask, selectedKeywords, usernames_with_hash=usernames)

        # Save crack information in the database
        g.db.execute('insert into cracks (crack_id, user_id, output_file, start_date, hashes_number, hash_type, crack_duration, email_end_job_sent) values (?,(select id from users where name=?),?,?,?,?,?,?)',
                     (crack_task.id,
                      request.authorization.username.lower(),
                      output_file_name,
                      strftime("%Y-%m-%dT%H:%M:%S"),
                      hashes_count,
                      hashtype_selected,
                      crackDuration,
                      0))
        g.db.commit()
        return render_template('launching.html', title=u'Crack launching', _id=crack_task.id)


@app.route('/user/cracks/abort/<crack_id>', methods=['POST'])
@requires_auth
def abort_crack(crack_id):
    """
        Abord a crack
    """
    check_access_authorization_for_a_crack_id(
        request.authorization.username.lower(), crack_id)

    # Revoke function cancels unstarted task of this crack
    print("Calling `revoke` on task %s" % crack_id)
    celery.control.revoke(crack_id, terminate=True, signal='SIGTERM')

    # Failsafe: manually kill the process to prevent revoking error
    try:
        # Retrieve the output file name in order to retrieve its system PID
        cur = g.db.execute(
            'select output_file from cracks where crack_id=?', [crack_id])
        output_filename = str(cur.fetchone()[0])

        # Retrieve the PID and kill the process
        pid = check_output(
            ["pgrep", "-f", "-a", output_filename]).split('\n')[0].split(' ')[0]
        call(["kill", pid])
    except:
        pass

    return render_template('abort.html', title='Crack aborting', cassage_id=crack_id)


@app.route('/user/cracks', methods=['GET'])
@requires_auth
def list_of_cracks():
    """
        List ongoing and previous cracks for a user
    """
    # Retrieve the list of cracks for the current user and their status from
    # the database
    cur = g.db.execute('select crack_id, start_date, output_file, hash_type from cracks where user_id=(select id from users where name = ?) order by start_date desc', [
        request.authorization.username.lower()])

    # Save them in a list
    db_crack_list = cur.fetchall()

    crack_list = []
    for crack in db_crack_list:
        crack_id, start_date, output_file_path, hash_type_id = crack

        # Retrieval of the crack status based on the crack id and the output
        # file
        task_state = get_crack_status(crack_id, output_file_path)

        # Retrieval of the hash type in a human format
        hash_type = get_hash_type_from_hash_id(hash_type_id)

        crack_list.append(
            [crack_id, start_date, output_file_path, hash_type, task_state])

    return render_template(
        'cracks.html', title=u'Cracks list', crack_list=crack_list)


@app.route('/user/cracks/<crack_id>', methods=['GET'])
@requires_auth
def crack_details(crack_id):
    """
        Get a crack details
    """
    if not check_access_authorization_for_a_crack_id(
        request.authorization.username.lower(), crack_id):
        return render_template(
            'crack_details.html',
            title=u'Unauthorized access',
            characters_complexity_list=[0, 0, 0, 0]
        )

    # Retrieve the task from its id
    task = hashcatCrack.AsyncResult(crack_id)

    # Retrieve the hash count, output file and hash type from the database
    cur = g.db.execute(
        'select hashes_number, output_file, hash_type from cracks where crack_id=?', [crack_id])

    query_result = cur.fetchone()
    hashes_number, output_file_path, hash_type_id = query_result

    hashes_count = int(hashes_number)
    output_file = conf.output_files_folder_location + str(output_file_path)
    hash_type = get_hash_type_from_hash_id(hash_type_id)

    # Retrieval of the crack status based on the crack id and the output file
    task_state = get_crack_status(crack_id, output_file)

    # Statistics initialization
    crack_list = []
    maximum_length = 0
    characters_complexity_list = [0, 0, 0, 0]
    percentage_diagram = 0

    # Ongoing or terminated crack: output file reading
    input_hash_file = os.path.join(conf.hashes_location, output_file_path)
    complete_hash_list = []
    try:
        with open(input_hash_file, 'r') as hashes_file:
            lines = hashes_file.read().splitlines()
            for hash in lines:
                # preparing for [hash, password, lower, upper, digits, special,
                # length, method]
                complete_hash_list.append(
                    [hash, "*****PASSWORD NOT FOUND YET*****", None, None, None, None, None, None])
    except IOError:
        pass

    # Find all the files beginning with file content
    result_files = glob.glob(output_file + '*')
    # Add the file path itself in the list
    result_files.append(output_file)

    for file in result_files:
        length = generate_password_and_statistics_list(
            file, complete_hash_list, hash_type)
        maximum_length = max(maximum_length, length)

    # Put the list of actual passwords found in passwords_list and generate
    # global statistics
    passwords_list = []
    number_of_found_passwords = 0
    # Initialize length_distribution with 0 values for all the possible lengths
    length_distribution_list = [0] * (maximum_length + 1)

    for line in complete_hash_list:
        hash, password, lower, upper, digits, special, length, method = line
        if password != "*****PASSWORD NOT FOUND YET*****":
            # removal of potential "*empty*" values in case of LM passwords
            passwords_list.append([hash, password.replace(
                "*empty*", ""), lower, upper, digits, special, length, method])

            # Complexity (lower chars, upper chars, digits, special chars)
            characters_complexity_list[
                sum([lower > 0, upper > 0, digits > 0, special > 0]) - 1] += 1

            # Number of found passwords
            number_of_found_passwords += 1

            # Consolidate the length of the password
            length_distribution_list[length] += 1

    # percentage_diagram : percent of cracked hashes
    if len(complete_hash_list) > 0:
        # the numerator or denominator has to be a float in order to get a
        # float as a result
        percentage_diagram = (number_of_found_passwords /
                              float(len(complete_hash_list))) * 100
    else:
        percentage_diagram = 0

    return render_template(
        'crack_details.html',
        title=u'Crack details',
        task_info=task.info,
        task_state=task_state,
        crack_id=crack_id,
        hashes_count=hashes_count,
        hash_type=hash_type,
        percentage_diagram=percentage_diagram,
        length_distribution_list=length_distribution_list,
        characters_complexity_list=characters_complexity_list,
        crack_list=passwords_list
    )


@app.route('/user/cracks/<crack_id>/debug', methods=['GET'])
@requires_auth
def crack_debug(crack_id):
    """
        Hashcat log display
    """
    if not check_access_authorization_for_a_crack_id(
        request.authorization.username.lower(), crack_id):
        return render_template(
            'crack_details.html',
            title=u'Unauthorized access',
            characters_complexity_list=[0, 0, 0, 0]
        )

    # Retrieve the output file name
    cur = g.db.execute(
        'select output_file from cracks where crack_id=?', [crack_id])
    output_file_name = cur.fetchone()[0]
    try:
        # Building the log file name from output file name
        with open(os.path.join(conf.log_location, output_file_name + ".log"), 'r+') as log_file:
            # Read the log file
            logs = log_file.read()

    except IOError:
        logs = ""

    # contenu_debug
    return render_template(
        'debug.html', title=u'Hashcat commands logs', debug_content=logs)


@app.route('/user/cracks/<crack_id>/csv', methods=['GET'])
@requires_auth
def download_csv(crack_id):
    """
        Generate a csv file
    """
    if not check_access_authorization_for_a_crack_id(
        request.authorization.username.lower(), crack_id):
        return render_template(
            'crack_details.html',
            title=u'Unauthorized access',
            characters_complexity_list=[0, 0, 0, 0]
        )

    # Retrieve the output file name
    cur = g.db.execute(
        'select output_file, hash_type from cracks where crack_id=?', [crack_id])
    query_result = cur.fetchone()

    output_file_path, hash_type_id = query_result

    output_file = conf.output_files_folder_location + str(output_file_path)

    # Hash type
    hash_type = get_hash_type_from_hash_id(hash_type_id)

    # Read the cracked passwords
    input_hash_file = conf.hashes_location + str(output_file_path)
    complete_hash_list = []
    try:
        with open(input_hash_file, 'r') as hashes_file:
            lines = hashes_file.read().splitlines()
            for hash in lines:
                # Preparing for [hash, password, lower, upper, digits, special,
                # length, method]
                complete_hash_list.append(
                    [hash, "*****PASSWORD NOT FOUND YET*****", 0, 0, 0, 0, 0, ""])
    except IOError:
        pass

    # Find all the files beginning with file content
    result_files = glob.glob(output_file + '*')
    # Add the file path itself in the list
    result_files.append(output_file)

    for file in result_files:
        generate_password_and_statistics_list(
            file, complete_hash_list, hash_type)

    csv_response = StringIO.StringIO()
    csvwriter = csv.writer(csv_response, delimiter=';')

    csv_header = ['Hash', 'Password', 'Length', 'Lowercase',
                  'Uppercase', 'Digits', 'Special', 'Method']
    csvwriter.writerow(csv_header)

    # Output the result in csv
    for csv_row in complete_hash_list:
        if csv_row[1] != "*****PASSWORD NOT FOUND YET*****":
            csv_row[1] = csv_row[1].replace("*empty*", "")

        csvwriter.writerow(csv_row)

    response = make_response(csv_response.getvalue())
    response.headers["Content-disposition"] = "attachment; filename=export.csv"
    response.headers["Content-Type"] = "text/csv"

    return response
