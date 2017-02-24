#!/usr/bin/python
# coding: utf8
import os

from cracker import app
from cracker import app_settings

if __name__ == '__main__':
    # Check folders exist
    for folder in [
        app_settings.output_files_folder_location,
        app_settings.log_location
    ]:
        try:
            os.makedirs(os.path.dirname(folder))
            print "Created %s" % app_settings.output_files_folder_location
        except os.error:
            # Already exists
            pass

    # Run the app
    app.run(host='0.0.0.0', port=5000,
            debug=app.config['DEBUG'], threaded=True)
