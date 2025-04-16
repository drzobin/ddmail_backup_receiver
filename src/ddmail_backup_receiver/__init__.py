import os
import sys
from flask import Flask


def create_app(config_file=None, test_config=None):
    """Create and configure an instance of the Flask application backup_receiver"""
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
    print("Running in MODE: " + mode)

    # Apply configuration for the specific MODE.
    if mode == "PRODUCTION":
        app.config["SECRET_KEY"] = toml_config["PRODUCTION"]["SECRET_KEY"]
        app.config["PASSWORD_HASH"] = toml_config["PRODUCTION"]["PASSWORD_HASH"]
        app.config["UPLOAD_FOLDER"] = toml_config["PRODUCTION"]["UPLOAD_FOLDER"]

        # Configure logfile.
        file_handler = FileHandler(filename=toml_config["PRODUCTION"]["LOGFILE"])
        file_handler.setFormatter(logging.Formatter(log_format))
        app.logger.addHandler(file_handler)

        # Configure loglevel.
        if toml_config["PRODUCTION"]["LOGLEVEL"] == "ERROR":
            app.logger.setLevel(logging.ERROR)
        elif toml_config["PRODUCTION"]["LOGLEVEL"] == "WARNING":
            app.logger.setLevel(logging.WARNING)
        elif toml_config["PRODUCTION"]["LOGLEVEL"] == "INFO":
            app.logger.setLevel(logging.INFO)
        elif toml_config["PRODUCTION"]["LOGLEVEL"] == "DEBUG":
            app.logger.setLevel(logging.DEBUG)
        else:
            print("Error: you need to set LOGLEVEL to ERROR/WARNING/INFO/DEBUG")
            sys.exit(1)
    elif mode == "TESTING":
        app.config["SECRET_KEY"] = toml_config["TESTING"]["SECRET_KEY"]
        app.config["PASSWORD_HASH"] = toml_config["TESTING"]["PASSWORD_HASH"]
        app.config["UPLOAD_FOLDER"] = toml_config["TESTING"]["UPLOAD_FOLDER"]

        # Configure logfile.
        file_handler = FileHandler(filename=toml_config["TESTING"]["LOGFILE"])
        file_handler.setFormatter(logging.Formatter(log_format))
        app.logger.addHandler(file_handler)

        # Configure loglevel.
        if toml_config["TESTING"]["LOGLEVEL"] == "ERROR":
            app.logger.setLevel(logging.ERROR)
        elif toml_config["TESTING"]["LOGLEVEL"] == "WARNING":
            app.logger.setLevel(logging.WARNING)
        elif toml_config["TESTING"]["LOGLEVEL"] == "INFO":
            app.logger.setLevel(logging.INFO)
        elif toml_config["TESTING"]["LOGLEVEL"] == "DEBUG":
            app.logger.setLevel(logging.DEBUG)
        else:
            print("Error: you need to set LOGLEVEL to ERROR/WARNING/INFO/DEBUG")
            sys.exit(1)
    elif mode == "DEVELOPMENT":
        app.config["SECRET_KEY"] = toml_config["DEVELOPMENT"]["SECRET_KEY"]
        app.config["PASSWORD_HASH"] = toml_config["DEVELOPMENT"]["PASSWORD_HASH"]
        app.config["UPLOAD_FOLDER"] = toml_config["DEVELOPMENT"]["UPLOAD_FOLDER"]

        # Configure logfile.
        file_handler = FileHandler(filename=toml_config["DEVELOPMENT"]["LOGFILE"])
        file_handler.setFormatter(logging.Formatter(log_format))
        app.logger.addHandler(file_handler)

        # Configure loglevel.
        if toml_config["DEVELOPMENT"]["LOGLEVEL"] == "ERROR":
            app.logger.setLevel(logging.ERROR)
        elif toml_config["DEVELOPMENT"]["LOGLEVEL"] == "WARNING":
            app.logger.setLevel(logging.WARNING)
        elif toml_config["DEVELOPMENT"]["LOGLEVEL"] == "INFO":
            app.logger.setLevel(logging.INFO)
        elif toml_config["DEVELOPMENT"]["LOGLEVEL"] == "DEBUG":
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
