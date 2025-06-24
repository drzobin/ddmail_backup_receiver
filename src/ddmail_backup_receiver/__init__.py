import os
import sys
from flask import Flask
import logging
import logging.handlers
from logging.config import dictConfig
from logging import FileHandler
import toml


def create_app(config_file=None, test_config=None):
    """Create and configure an instance of the Flask application for backup receiver.

    This function initializes the Flask application with appropriate configuration
    settings loaded from a TOML file. It sets up logging, loads environment-specific
    configurations, and registers blueprints.

    Args:
        config_file (str, optional): Path to the TOML configuration file. Required.
        test_config (dict, optional): Test configuration to override the loaded config.
                                      Not currently used but available for testing.

    Returns:
        Flask: Configured Flask application instance

    Raises:
        SystemExit: If config_file is not provided, MODE environment variable is invalid,
                   or if LOGLEVEL is not properly configured.

    Note:
        The application relies on the MODE environment variable to determine which
        configuration section to load (PRODUCTION, TESTING, or DEVELOPMENT).
        Each mode requires specific configuration parameters in the TOML file.
    """
    # Configure logging.
    log_format = '[%(asctime)s] %(levelname)s in %(module)s %(funcName)s %(lineno)s: %(message)s'
    dictConfig({
        'version': 1,
        'formatters': {'default': {
            'format': log_format
        }},
        'handlers': {
            'wsgi': {
                'class': 'logging.StreamHandler',
                'stream': 'ext://flask.logging.wsgi_errors_stream',
                'formatter': 'default',
            },
        },
        'root': {
            'level': 'INFO',
            'handlers': ['wsgi']
        }
    })


    app = Flask(__name__, instance_relative_config=True)

    toml_config = None

    # Check if config_file has been set.
    if config_file is None:
        print("Error: you need to set path to configuration file in toml format")
        sys.exit(1)

    # Parse toml config file.
    with open(config_file, 'r') as f:
        toml_config = toml.load(f)

    # Set app configurations from toml config file.
    mode = os.environ.get('MODE')
    print("Running in MODE: " + str(mode))

    # Apply configuration for the specific MODE.
    if mode == "PRODUCTION" or mode == "TESTING" or mode == "DEVELOPMENT":

        app.config["SECRET_KEY"] = toml_config[mode]["SECRET_KEY"]
        app.config["PASSWORD_HASH"] = toml_config[mode]["PASSWORD_HASH"]
        app.config["UPLOAD_FOLDER"] = toml_config[mode]["UPLOAD_FOLDER"]
        app.config["BACKUPS_TO_SAVE"] = toml_config[mode]["BACKUPS_TO_SAVE"]

        # Configure logging to file.
        if toml_config[mode]["LOGGING"]["LOG_TO_FILE"] is True:
            file_handler = FileHandler(filename=toml_config[mode]["LOGGING"]["LOGFILE"])
            file_handler.setFormatter(logging.Formatter(log_format))
            app.logger.addHandler(file_handler)

        # Configure logging to syslog.
        if toml_config[mode]["LOGGING"]["LOG_TO_SYSLOG"] is True:
            syslog_handler = logging.handlers.SysLogHandler(address=toml_config[mode]["LOGGING"]["SYSLOG_SERVER"])
            syslog_handler.setFormatter(logging.Formatter(log_format))
            app.logger.addHandler(syslog_handler)


        # Configure loglevel.
        if toml_config[mode]["LOGGING"]["LOGLEVEL"] == "ERROR":
            app.logger.setLevel(logging.ERROR)
        elif toml_config[mode]["LOGGING"]["LOGLEVEL"] == "WARNING":
            app.logger.setLevel(logging.WARNING)
        elif toml_config[mode]["LOGGING"]["LOGLEVEL"] == "INFO":
            app.logger.setLevel(logging.INFO)
        elif toml_config[mode]["LOGGING"]["LOGLEVEL"] == "DEBUG":
            app.logger.setLevel(logging.DEBUG)
        else:
            print("Error: you need to set LOGLEVEL to ERROR/WARNING/INFO/DEBUG")
            sys.exit(1)
    else:
        print("Error: you need to set env variabel MODE to PRODUCTION/TESTING/DEVELOPMENT")
        sys.exit(1)


    app.secret_key = app.config["SECRET_KEY"]

    # Ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Apply the blueprints to the app
    from ddmail_backup_receiver import application
    app.register_blueprint(application.bp)

    return app
