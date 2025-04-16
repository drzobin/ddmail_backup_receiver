import os
import time
import hashlib
from flask import Blueprint, current_app, request
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from werkzeug.utils import secure_filename
import ddmail_validators.validators as validators

bp = Blueprint("application", __name__, url_prefix="/")

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
            current_app.logger.error("file is not in request.files")
            return "error: file is not in request.files"

        # Get post data.
        file = request.files['file']
        filename = request.form.get('filename')
        password = request.form.get('password')
        sha256_from_form = request.form.get('sha256')

        # Check if file is None.
        if file == None:
            current_app.logger.error("file is None")
            return "error: file is none"

        # Check if filename is None.
        if filename == None:
            current_app.logger.error("filename is None")
            return "error: filename is none"

        # Check if password is None.
        if password == None:
            current_app.logger.error("receive_backup() password is None")
            return "error: password is none"

        # Check if sha256 checksum is None.
        if sha256_from_form == None:
            current_app.logger.error("receive_backup() sha256_from_form is None")
            return "error: sha256_from_form is none"

        # Remove whitespace character.
        filename = filename.strip()
        password = password.strip()
        sha256_from_form = sha256_from_form.strip()

        # Validate filename.
        if validators.is_filename_allowed(filename) != True:
            current_app.logger.error("filename validation failed")
            return "error: filename validation failed"

        # Validate sha256 from form.
        if validators.is_sha256_allowed(sha256_from_form) != True:
            current_app.logger.error("sha256 checksum validation failed")
            return "error: sha256 checksum validation failed"

        # Validate password.
        if validators.is_password_allowed(password) != True:
            current_app.logger.error("password validation failed")
            return "error: password validation failed"

        # Check if password is correct.
        ph = PasswordHasher()
        try:
            if ph.verify(current_app.config["PASSWORD_HASH"], password) != True:
                current_app.logger.error("wrong password")
                return "error: wrong password1"
        except VerifyMismatchError:
            current_app.logger.error("wrong password")
            return "error: wrong password2"

        # Set folder where uploaded files are stored.
        upload_folder = current_app.config["UPLOAD_FOLDER"]

        # Check if upload folder exist.
        if os.path.isdir(upload_folder) != True:
            current_app.logger.error("upload folder " + upload_folder + " do not exist")
            return "error: upload folder " + upload_folder  + " do not exist"

        # Save file to disc.
        full_path = upload_folder + "/" + secure_filename(filename)
        file.save(full_path)

        # Take sha256 checksum of file and compare with checksum from form.
        sha256_from_file = sha256_of_file(full_path)
        if sha256_from_form != sha256_from_file:
            current_app.logger.error("sha256 checksum do not match")
            return "error: sha256 checksum do not match"

        current_app.logger.info("done")
        return "done"
