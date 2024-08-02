from flask import Blueprint, current_app, request
from argon2 import PasswordHasher
from werkzeug.utils import secure_filename
import os
import time
import subprocess
import logging
import hashlib
import sys

from backup_receiver.validators import is_domain_allowed, is_password_allowed, is_email_allowed, is_sha256_allowed

bp = Blueprint("application", __name__, url_prefix="/")

# Configure logging.
logging.basicConfig(filename="/var/log/ddmail_backup_receiver.log", format='%(asctime)s: %(levelname)s: %(message)s', level=logging.ERROR)

# Get sha256 checksum of file.
def sha256_of_file(file):
    # 65kb
    buf_size = 65536

    sha256 = hashlib.sha256()

    with open(file, 'rb') as f:
        while True:
            data = f.read(buf_size)
            if not data:
                break
            sha256.update(data)

    return sha256.hexdigest()

@bp.route("/receive_backup", methods=["POST"])
def receive_backup():
        # Check if post data contains file.
        if 'file' not in request.files:
            logging.error("receive_backup() file is not in request.files")
            return "error: file is not in request.files"

        # Get post data.
        file = request.files['file']
        filename = request.form.get('filename')
        password = request.form.get('password')
        sha256_from_form = request.form.get('sha256')

        # Check if var is None.
        if file == None:
            logging.error("receive_backup() file is None")
            return "error: file is none"

        # Check if var is None.
        if filename == None:
            logging.error("receive_backup() filename is None")
            return "error: filename is none"

        # Check if var is None.
        if password == None:
            logging.error("receive_backup() password is None")
            return "error: password is none"

        # Check if var is None.
        if sha256_from_form == None:
            logging.error("receive_backup() sha256_from_form is None")
            return "error: sha256_from_form is none"

        # Remove whitespace character.
        filename = filename.strip()
        password = password.strip()
        sha256_from_form = sha256_from_form.strip()

        # Validate filename.

        # Validate sha256 from form.
        if is_sha256_allowed(sha256_from_form) != True:
            logging.error("receive_backup() sha256 checksum validation failed")
            return "error: sha256 checksum validation failed"

        # Validate password.
        if is_password_allowed(password) != True:
            logging.error("receive_backup() password validation failed")
            return "error: password validation failed"

        # Check if password is correct.
        try:
            if ph.verify(current_app.config["PASSWORD_HASH"], password) != True:
                time.sleep(1)
                logging.error("receive_backup() wrong password")
                return "error: wrong password"
        except:
            time.sleep(1)
            logging.error("receive_backup() wrong password")
            return "error: wrong password"
        time.sleep(1)

        # Set folder where uploaded files are stored.
        upload_folder = current_app.config["UPLOAD_FOLDER"]

        # Check if upload folder exist.
        if os.path.isdir(upload_folder) != True:
            logging.error("receive_backup() upload folder " + upload_folder + " do not exist")
            return "error: upload folder " + upload_folder  + " do not exist"

        # Save file to disc.
        full_path = upload_folder + "/" + secure_filename(filename)
        file.save(full_path)

        # Take sha256 checksum of file and compare with checksum from form.
        sha256_from_file = sha256_of_file(full_path)
        if sha256_from_form != sha256_from_file:
            logging.error("receive_backup() sha256 checksum do not match")
            return "error: sha256 checksum do not match"

        logging.info("receive_backup() done")
        return "done"
