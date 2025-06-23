import os
import time
import hashlib
from flask import Blueprint, current_app, request, make_response, Response
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from werkzeug.utils import secure_filename
import ddmail_validators.validators as validators

bp = Blueprint("application", __name__, url_prefix="/")

def sha256_of_file(file) -> str:
    """Calculate the SHA256 checksum of a file.

    This function reads a file in chunks and calculates its SHA256 hash,
    which can be used to verify file integrity.

    Args:
        file (str): Path to the file to calculate checksum for.

    Returns:
        str: Hexadecimal representation of the SHA256 hash.
    """
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
def receive_backup() -> Response:
    """
    Receive and validate backup files uploaded via POST request.

    This function handles the receipt of backup files, validates the submission
    parameters, authenticates the request, and stores the file if all validations pass.

    Returns:
        Response: Flask response with appropriate message and status code

    Request Form Parameters:
        file (FileStorage): The backup file to be uploaded
        filename (str): Name to save the file as
        password (str): Authentication password for the request
        sha256 (str): Expected SHA256 checksum of the file

    Error Responses:
        "error: file is not in request.files": If file parameter is missing
        "error: file is none": If file parameter is empty
        "error: filename is none": If filename parameter is missing
        "error: password is none": If password parameter is missing
        "error: sha256_from_form is none": If sha256 parameter is missing
        "error: filename validation failed": If filename fails validation
        "error: sha256 checksum validation failed": If sha256 fails validation
        "error: password validation failed": If password fails validation
        "error: wrong password": If authentication password is incorrect
        "error: upload folder [path] do not exist": If upload directory doesn't exist
        "error: sha256 checksum do not match": If file checksum doesn't match provided value

    Success Response:
        "done": Operation completed successfully
    """
    # We don't need to manually check the method since Flask handles it through the route decorator
    # This code would only be reached if using POST method based on the route decorator
    # if request.method != 'POST':
    #    return make_response("Method not allowed", 405)


    # Check if post data contains file.
    if 'file' not in request.files:
        current_app.logger.error("file is not in request.files")
        return make_response("error: file is not in request.files", 200)

    # Get post data.
    file = request.files['file']
    filename = request.form.get('filename')
    password = request.form.get('password')
    sha256_from_form = request.form.get('sha256')

    # Check if file is None.
    if file == None:
        current_app.logger.error("file is None")
        return make_response("error: file is none", 200)

    # Check if filename is None.
    if filename == None:
        current_app.logger.error("filename is None")
        return make_response("error: filename is none", 200)

    # Check if password is None.
    if password == None:
        current_app.logger.error("receive_backup() password is None")
        return make_response("error: password is none", 200)

    # Check if sha256 checksum is None.
    if sha256_from_form == None:
        current_app.logger.error("receive_backup() sha256_from_form is None")
        return make_response("error: sha256_from_form is none", 200)

    # Remove whitespace character.
    filename = filename.strip()
    password = password.strip()
    sha256_from_form = sha256_from_form.strip()

    # Validate filename.
    if validators.is_filename_allowed(filename) != True:
        current_app.logger.error("filename validation failed")
        return make_response("error: filename validation failed", 200)

    # Validate sha256 from form.
    if validators.is_sha256_allowed(sha256_from_form) != True:
        current_app.logger.error("sha256 checksum validation failed")
        return make_response("error: sha256 checksum validation failed", 200)

    # Validate password.
    if validators.is_password_allowed(password) != True:
        current_app.logger.error("password validation failed")
        return make_response("error: password validation failed", 200)

    # Check if password is correct.
    ph = PasswordHasher()
    try:
        if ph.verify(current_app.config["PASSWORD_HASH"], password) != True:
            current_app.logger.error("wrong password")
            return make_response("error: wrong password1", 200)
    except VerifyMismatchError:
        current_app.logger.error("wrong password")
        return make_response("error: wrong password", 200)

    # Set folder where uploaded files are stored.
    upload_folder = current_app.config["UPLOAD_FOLDER"]

    # Check if upload folder exist.
    if os.path.isdir(upload_folder) != True:
        current_app.logger.error("upload folder " + upload_folder + " do not exist")
        return make_response("error: upload folder " + upload_folder  + " do not exist", 200)

    # Save file to disc.
    full_path = upload_folder + "/" + secure_filename(filename)
    file.save(full_path)

    # Take sha256 checksum of file and compare with checksum from form.
    sha256_from_file = sha256_of_file(full_path)
    if sha256_from_form != sha256_from_file:
        current_app.logger.error("sha256 checksum do not match")
        return make_response("error: sha256 checksum do not match", 200)

    current_app.logger.info("done")
    return make_response("done", 200)
