import os
import time
import hashlib
import glob
from flask import Blueprint, current_app, request, make_response, Response
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from werkzeug.utils import secure_filename
import ddmail_validators.validators as validators

bp = Blueprint("application", __name__, url_prefix="/")

def sha256_of_file(file: str) -> str:
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


def delete_old_backups(backup_folder: str, backups_to_save: int) -> None:
    """Remove old backups/files that is older then backups_to_save number of files.

    This function will remove old backups/files that is older then backups_to_save number of files.
    It will also log the number of backups removed and if no backups are removed.

    Args:
        backup_folder (str): folder where backups is stored that will be removed.
        backups_to_save (int): number of backups to save.

    Returns:
        None
    """
    # Get list of files in the backup_folder folder.
    list_of_files = filter(
            os.path.isfile,
            glob.glob(backup_folder + '/*')
            )

    # Sort list of files based on last modification time in ascending order.
    list_of_files = sorted(list_of_files, key=os.path.getmtime)

    current_app.logger.debug("list_of_files: %s", list_of_files)

    # If we have less or equal of the int backups_to_save backups then exit.
    if len(list_of_files) <= backups_to_save:
        current_app.logger.info("too few backups for removing old backups")
        return

    list_of_files.reverse()
    count = 0

    # Only save backups_to_save number of backups, remove other.
    for file in list_of_files:
        count = count + 1
        if count <= backups_to_save:
            continue
        else:
            os.remove(file)
            current_app.logger.info("removing: " + backup_folder + "/" + file)

@bp.route("/receive_backup", methods=["POST"])
def receive_backup() -> Response:
    """
    Receive and validate backup files uploaded via POST request.

    This function handles the receipt of backup files, validates the submission
    parameters, authenticates the request, and stores the file if all validations pass.
    After successful storage, it manages backup retention by removing older backups
    based on the configured retention policy.

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
        "error: number of backups to save is not set": If BACKUPS_TO_SAVE configuration is missing
        "error: number of backups to save must be an integer": If BACKUPS_TO_SAVE is not an integer
        "error: number of backups to save must be a positive integer": If BACKUPS_TO_SAVE is not positive

    Success Response:
        "done": Operation completed successfully

    Configuration:
        BACKUPS_TO_SAVE: Controls how many recent backups to retain. Older backups beyond
                        this number will be automatically deleted after a successful upload.
    """
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

    # Take sha256 checksum of file on disc and compare with checksum from form.
    sha256_from_file = sha256_of_file(full_path)
    if sha256_from_form != sha256_from_file:
        current_app.logger.error("sha256 checksum do not match")
        return make_response("error: sha256 checksum do not match", 200)

    # Check if number of backups to save is set.
    if current_app.config["BACKUPS_TO_SAVE"] is None:
        current_app.logger.error("number of backups to save is not set")
        return make_response("error: number of backups to save is not set", 200)

    backups_to_save = current_app.config["BACKUPS_TO_SAVE"]

    # Check if backups_to_save is an integer.
    if not isinstance(backups_to_save, int):
        current_app.logger.error("number of backups to save must be an integer")
        return make_response("error: number of backups to save must be an integer", 200)

    # Check if backups_to_save is a positive integer.
    if backups_to_save <= 0:
        current_app.logger.error("number of backups to save must be a positive integer")
        return make_response("error: number of backups to save must be a positive integer", 200)

    # Delete old backups.
    delete_old_backups(upload_folder, backups_to_save)

    current_app.logger.info("done")
    return make_response("done", 200)
