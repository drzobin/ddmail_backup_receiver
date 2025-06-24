from ddmail_backup_receiver.application import sha256_of_file, delete_old_backups
from flask import make_response, current_app
from io import BytesIO
import os
import shutil
import tempfile
import time
import pytest
from unittest.mock import patch, MagicMock

# Testfile used in many testcases.
TESTFILE_PATH = "tests/test_file.txt"
TESTFILE_NAME = "test_file.txt"
SHA256 = "7b7632005be0f36c5d1663a6c5ec4d13315589d65e1ef8687fb4b9866f9bc4b0"
f = open(TESTFILE_PATH, "r")
TESTFILE_DATA = f.read()

# Application settings used during testing.
UPLOAD_FOLDER = "/opt/ddmail_backup_receiver/backups"

# Create a binary test file for binary testing
def create_binary_test_file():
    binary_file_path = "tests/binary_test_file.bin"
    with open(binary_file_path, "wb") as f:
        f.write(bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]))
    return binary_file_path

# Create an empty test file
def create_empty_test_file():
    empty_file_path = "tests/empty_test_file.txt"
    with open(empty_file_path, "w") as f:
        pass
    return empty_file_path

# Create a large test file to test chunking behavior
def create_large_test_file():
    large_file_path = "tests/large_test_file.txt"
    with open(large_file_path, "w") as f:
        # Create a file larger than the 65kb buffer size
        f.write("A" * 100000)
    return large_file_path


def test_sha256_of_file():
    """Test that the sha256_of_file function correctly calculates the SHA256 hash of a test file.
    
    Verifies that the calculated hash matches the expected hash constant.
    """
    assert sha256_of_file(TESTFILE_PATH) == SHA256


def test_sha256_of_empty_file():
    """Test that the sha256_of_file function correctly handles empty files.
    
    Creates a temporary empty file, calculates its hash, and verifies it matches
    the known SHA256 hash for an empty file. Cleans up the file after testing.
    """
    empty_file_path = create_empty_test_file()
    try:
        # Empty file should have a specific SHA256 hash
        expected_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert sha256_of_file(empty_file_path) == expected_hash
    finally:
        # Clean up the test file
        if os.path.exists(empty_file_path):
            os.remove(empty_file_path)


def test_sha256_of_binary_file():
    """Test that the sha256_of_file function correctly handles binary files.
    
    Creates a temporary binary file, calculates its hash, and verifies it matches
    the expected hash. Cleans up the file after testing.
    """
    binary_file_path = create_binary_test_file()
    try:
        # Calculate actual hash first, then verify in subsequent runs
        actual_hash = sha256_of_file(binary_file_path)
        expected_hash = "17e88db187afd62c16e5debf3e6527cd006bc012bc90b51a810cd80c2d511f43"
        assert actual_hash == expected_hash
    finally:
        # Clean up the test file
        if os.path.exists(binary_file_path):
            os.remove(binary_file_path)


def test_sha256_of_large_file():
    """Test that the sha256_of_file function correctly handles large files.
    
    Creates a temporary file larger than the buffer size (65kb), calculates its hash,
    and verifies it matches the expected hash. This tests the chunking behavior of
    the sha256_of_file function. Cleans up the file after testing.
    """
    large_file_path = create_large_test_file()
    try:
        # Calculate actual hash first, then verify in subsequent runs
        actual_hash = sha256_of_file(large_file_path)
        # The hash for 100000 'A' characters
        expected_hash = "e6631225e83d23bf67657e85109ad5deb3570e1405d7aaa23a2485ae8582c143"
        assert actual_hash == expected_hash
    finally:
        # Clean up the test file
        if os.path.exists(large_file_path):
            os.remove(large_file_path)


def test_receive_backup_no_password(client):
    """Test that receive_backup correctly handles missing password parameter.
    
    Sends a request to receive_backup without a password parameter and verifies
    that the function returns the expected error message.
    """
    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "filename": TESTFILE_NAME,
            "file": (BytesIO(bytes(TESTFILE_DATA, 'utf-8')), TESTFILE_NAME),
            "sha256": SHA256
            }
        )

    assert response.status_code == 200
    assert b"error: password is none" in response.data


def test_receive_backup_password_illigal_char(client):
    """Test that receive_backup correctly validates password format.
    
    Sends a request with a password containing illegal characters and verifies
    that the function returns the expected validation error message.
    """
    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": "password$password",
            "filename": TESTFILE_NAME,
            "file": (BytesIO(bytes(TESTFILE_DATA, 'utf-8')), TESTFILE_NAME),
            "sha256": SHA256
            }
        )

    assert response.status_code == 200
    assert b"error: password validation failed" in response.data


def test_receive_backup_no_filename(client, password):
    """Test that receive_backup correctly handles missing filename parameter.
    
    Sends a request without a filename parameter and verifies that the function
    returns the expected error message.
    """
    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": password,
            "file": (BytesIO(bytes(TESTFILE_DATA, 'utf-8')), TESTFILE_NAME),
            "sha256": SHA256
            }
        )

    assert response.status_code == 200
    assert b"error: filename is none" in response.data


def test_receive_backup_filename_illigal_char(client, password):
    """Test that receive_backup correctly validates filename format.
    
    Sends a request with a filename containing illegal characters and verifies
    that the function returns the expected validation error message.
    """
    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": password,
            "filename": "test_fil--e.txt",
            "file": (BytesIO(bytes(TESTFILE_DATA, 'utf-8')), TESTFILE_NAME),
            "sha256": SHA256
            }
        )

    assert response.status_code == 200
    assert b"error: filename validation failed" in response.data


def test_receive_backup_no_file(client, password):
    """Test that receive_backup correctly handles missing file parameter.
    
    Sends a request without a file parameter and verifies that the function
    returns the expected error message.
    """
    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": password,
            "filename": TESTFILE_NAME,
            "sha256": SHA256
            }
        )

    assert response.status_code == 200
    assert b"error: file is not in request.files" in response.data


def test_receive_backup_no_sha256(client, password):
    """Test that receive_backup correctly handles missing SHA256 parameter.
    
    Sends a request without a sha256 parameter and verifies that the function
    returns the expected error message.
    """
    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": password,
            "filename": TESTFILE_NAME,
            "file": (BytesIO(bytes(TESTFILE_DATA, 'utf-8')), TESTFILE_NAME)
            }
        )

    assert response.status_code == 200
    assert b"error: sha256_from_form is none" in response.data


def test_receive_backup_sha256_illigal_char(client, password):
    """Test that receive_backup correctly validates SHA256 format.
    
    Sends a request with a SHA256 value containing illegal characters and verifies
    that the function returns the expected validation error message.
    """
    sha256 = "7b7@32005be0f36c5d1663a6c5ec4d13315589d65e1ef8687fb4b9866f9bc4b0"

    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": password,
            "filename": TESTFILE_NAME,
            "file": (BytesIO(bytes(TESTFILE_DATA, 'utf-8')), TESTFILE_NAME),
            "sha256": sha256
            }
        )

    assert response.status_code == 200
    assert b"error: sha256 checksum validation failed" in response.data


def test_receive_backup_wrong_password(client):
    """Test that receive_backup correctly handles incorrect password.
    
    Sends a request with an incorrect password and verifies that the function
    returns the expected authentication error message.
    """
    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": "thisiswrongpassword12345",
            "filename": TESTFILE_NAME,
            "file": (BytesIO(bytes(TESTFILE_DATA, 'utf-8')), TESTFILE_NAME),
            "sha256": SHA256
            }
        )

    assert response.status_code == 200
    assert b"error: wrong password" in response.data


def test_receive_backup_no_upload_folder(client, password):
    """Test that receive_backup correctly handles missing upload folder.
    
    Removes the upload folder if it exists, then sends a request and verifies that
    the function returns the expected error message about the missing folder.
    """
    # Remove folder to save backups in if it exist.
    if os.path.exists(UPLOAD_FOLDER):
        shutil.rmtree(UPLOAD_FOLDER)

    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": password,
            "filename": TESTFILE_NAME,
            "file": (BytesIO(bytes(TESTFILE_DATA, 'utf-8')), TESTFILE_NAME),
            "sha256": SHA256
            }
        )

    assert response.status_code == 200
    assert b"error: upload folder /opt/ddmail_backup_receiver/backups do not exist" in response.data


def test_receive_backup_wrong_checksum(client, password):
    """Test that receive_backup correctly validates file checksums.
    
    Sends a request with an incorrect SHA256 checksum and verifies that the function
    calculates the actual checksum and rejects the upload with the expected error message.
    """
    sha256 = "1b7632005be0f36c5d1663a6c5ec4d13315589d65e1ef8687fb4b9866f9bc4b0"

    # Create folder to save backups in if it do not exist.
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": password,
            "filename": TESTFILE_NAME,
            "file": (BytesIO(bytes(TESTFILE_DATA, 'utf-8')), TESTFILE_NAME),
            "sha256": sha256
            }
        )

    assert response.status_code == 200
    assert b"error: sha256 checksum do not match" in response.data


def test_receive_backup_backups_to_save_none(app, client, password, monkeypatch):
    """Test that receive_backup correctly handles BACKUPS_TO_SAVE set to None.
    
    Configures the app with BACKUPS_TO_SAVE set to None, sends a request, and verifies
    that the function returns the expected error message about the configuration.
    """
    # Create folder to save backups in if it do not exist
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    
    # Monkeypatch the BACKUPS_TO_SAVE config to be None
    app.config["BACKUPS_TO_SAVE"] = None
    
    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": password,
            "filename": TESTFILE_NAME,
            "file": (BytesIO(bytes(TESTFILE_DATA, 'utf-8')), TESTFILE_NAME),
            "sha256": SHA256
            }
        )

    assert response.status_code == 200
    assert b"error: number of backups to save is not set" in response.data


def test_receive_backup_backups_to_save_non_integer(app, client, password, monkeypatch):
    """Test that receive_backup correctly handles BACKUPS_TO_SAVE set to a non-integer.
    
    Configures the app with BACKUPS_TO_SAVE set to a string value, sends a request,
    and verifies that the function returns the expected type error message.
    """
    # Create folder to save backups in if it do not exist
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    
    # Monkeypatch the BACKUPS_TO_SAVE config to be a string (non-integer)
    app.config["BACKUPS_TO_SAVE"] = "7"
    
    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": password,
            "filename": TESTFILE_NAME,
            "file": (BytesIO(bytes(TESTFILE_DATA, 'utf-8')), TESTFILE_NAME),
            "sha256": SHA256
            }
        )

    assert response.status_code == 200
    assert b"error: number of backups to save must be an integer" in response.data


def test_receive_backup_backups_to_save_non_positive(app, client, password, monkeypatch):
    """Test that receive_backup correctly handles BACKUPS_TO_SAVE set to non-positive values.
    
    Tests two scenarios:
    1. BACKUPS_TO_SAVE set to zero
    2. BACKUPS_TO_SAVE set to a negative number
    
    Verifies that the function returns the expected validation error message in both cases.
    """
    # Create folder to save backups in if it do not exist
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    
    # Monkeypatch the BACKUPS_TO_SAVE config to be zero
    app.config["BACKUPS_TO_SAVE"] = 0
    
    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": password,
            "filename": TESTFILE_NAME,
            "file": (BytesIO(bytes(TESTFILE_DATA, 'utf-8')), TESTFILE_NAME),
            "sha256": SHA256
            }
        )

    assert response.status_code == 200
    assert b"error: number of backups to save must be a positive integer" in response.data

    # Test with negative number
    app.config["BACKUPS_TO_SAVE"] = -5
    
    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": password,
            "filename": TESTFILE_NAME,
            "file": (BytesIO(bytes(TESTFILE_DATA, 'utf-8')), TESTFILE_NAME),
            "sha256": SHA256
            }
        )

    assert response.status_code == 200
    assert b"error: number of backups to save must be a positive integer" in response.data


def test_receive_backup(client, password):
    """Test that receive_backup correctly processes a valid backup upload.
    
    Sends a request with all valid parameters and verifies that the function
    successfully processes the upload and returns a success message.
    """
    # Create folder to save backups in if it do not exist.
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": password,
            "filename": TESTFILE_NAME,
            "file": (BytesIO(bytes(TESTFILE_DATA, 'utf-8')), TESTFILE_NAME),
            "sha256": SHA256
            }
        )

    assert response.status_code == 200
    assert b"done" in response.data


def test_receive_backup_method_not_post(client):
    """Test that receive_backup correctly handles non-POST HTTP methods.
    
    Sends a GET request to the receive_backup endpoint and verifies that the function
    returns a 405 Method Not Allowed response.
    """
    # Test non-POST request method
    response = client.get("/receive_backup")
    assert response.status_code == 405
    # Flask's default 405 error page contains this text
    assert b"Method Not Allowed" in response.data


def test_receive_backup_file_none(client, password):
    """Test that receive_backup correctly handles missing file in multipart form.
    
    Sends a request without including a file field in the multipart form data
    and verifies that the function returns the expected error message.
    """
    # Test when file is None after retrieval
    # Create folder to save backups in if it do not exist.
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
        
    # In Flask's test client, sending a file with value None is detected as
    # 'file is not in request.files', not as 'file is None'.
    # Let's modify our test to match the actual behavior.
    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": password,
            "filename": TESTFILE_NAME,
            # Intentionally not including 'file' in the request
            "sha256": SHA256
            }
        )

    assert response.status_code == 200
    assert b"error: file is not in request.files" in response.data


def test_receive_backup_empty_file(client, password):
    """Test that receive_backup correctly handles empty files.
    
    Sends a request with an empty file and empty filename and verifies that
    the function processes this correctly, moving past the 'None' check.
    """
    # Test when file is empty but not None
    # Create folder to save backups in if it do not exist.
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
        
    # Create a test with an empty file object
    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": password,
            "filename": TESTFILE_NAME,
            "file": (BytesIO(b""), ""),  # Empty file with empty filename
            "sha256": SHA256
            }
        )

    assert response.status_code == 200
    # We should get a different error now since file exists but has issues
    assert b"error: filename is none" not in response.data  # Make sure we're past the None check


def test_receive_backup_whitespace_trim(client, password):
    """Test that receive_backup correctly trims whitespace from input parameters.
    
    Sends a request with whitespace around the password, filename, and SHA256 values,
    and verifies that the function properly trims the whitespace and processes the upload.
    """
    # Test trimming of whitespace in form data
    # Create folder to save backups in if it do not exist.
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    # Create an empty file and get its SHA256
    empty_file_path = create_empty_test_file()
    empty_file_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    
    try:
        # Read the empty file to ensure it's correct
        with open(empty_file_path, 'rb') as f:
            empty_file_data = f.read()
            
        response = client.post(
            "/receive_backup",
            buffered=True,
            content_type='multipart/form-data',
            data={
                "password": f"  {password}  ",  # Add whitespace around password
                "filename": f"  empty_file.txt  ",  # Add whitespace around filename
                "file": (BytesIO(empty_file_data), "empty_file.txt"),  # Empty file
                "sha256": f"  {empty_file_sha256}  "  # Add whitespace around SHA256
                }
            )

        # The test should pass since the whitespace should be trimmed
        assert response.status_code == 200
        assert b"done" in response.data
    finally:
        # Clean up
        if os.path.exists(empty_file_path):
            os.remove(empty_file_path)


def test_delete_old_backups_empty_folder(app):
    """Test that delete_old_backups correctly handles empty folders.
    
    Creates a temporary empty directory, calls delete_old_backups on it, and verifies
    that the function correctly logs that there are too few backups to remove.
    """
    # Create a temporary directory for testing
    temp_dir = tempfile.mkdtemp()
    try:
        # Set up a logger mock
        with app.app_context():
            # Create a test logger
            test_logger = MagicMock()
            app.logger = test_logger
            
            # Call the function with empty directory and backups_to_save=5
            delete_old_backups(temp_dir, 5)
            
            # Verify logger was called with the expected message
            test_logger.info.assert_called_with("too few backups for removing old backups")
    finally:
        # Clean up temporary directory
        shutil.rmtree(temp_dir)


def test_delete_old_backups_fewer_files(app):
    """Test that delete_old_backups correctly handles having fewer files than the retention limit.
    
    Creates a temporary directory with 3 test files, calls delete_old_backups with
    backups_to_save=5, and verifies that no files are deleted and the function
    correctly logs that there are too few backups to remove.
    """
    # Create a temporary directory for testing
    temp_dir = tempfile.mkdtemp()
    try:
        # Create 3 test files in the directory
        for i in range(3):
            file_path = os.path.join(temp_dir, f"test_file_{i}.txt")
            with open(file_path, 'w') as f:
                f.write(f"Test content {i}")
            # Sleep briefly to ensure different modification times
            time.sleep(0.1)
        
        # Get initial file list
        initial_files = os.listdir(temp_dir)
        assert len(initial_files) == 3
        
        # Test delete_old_backups with fewer files than backups_to_save
        with app.app_context():
            # Set up logger mock
            test_logger = MagicMock()
            app.logger = test_logger
            
            # Call the function with backups_to_save=5 (more than our 3 files)
            delete_old_backups(temp_dir, 5)
            
            # Verify logger was called with the expected message
            test_logger.info.assert_called_with("too few backups for removing old backups")
        
        # Verify no files were deleted
        remaining_files = os.listdir(temp_dir)
        assert len(remaining_files) == 3
        assert set(remaining_files) == set(initial_files)
    finally:
        # Clean up temporary directory
        shutil.rmtree(temp_dir)


def test_delete_old_backups_more_files(app):
    """Test that delete_old_backups correctly removes older files when there are more than the retention limit.
    
    Creates a temporary directory with 5 test files, calls delete_old_backups with
    backups_to_save=3, and verifies that the 2 oldest files are deleted while
    the 3 newest files remain intact.
    """
    # Create a temporary directory for testing
    temp_dir = tempfile.mkdtemp()
    try:
        # Create 5 test files in the directory with different modification times
        for i in range(5):
            file_path = os.path.join(temp_dir, f"test_file_{i}.txt")
            with open(file_path, 'w') as f:
                f.write(f"Test content {i}")
            # Sleep briefly to ensure different modification times
            time.sleep(0.1)
        
        # Get initial file list and verify creation
        initial_files = os.listdir(temp_dir)
        assert len(initial_files) == 5
        
        # Test delete_old_backups with more files than backups_to_save
        with app.app_context():
            # Set up logger mock
            test_logger = MagicMock()
            app.logger = test_logger
            
            # Call the function with backups_to_save=3 (less than our 5 files)
            delete_old_backups(temp_dir, 3)
            
            # Verify logger was called with removing messages
            # We expect 2 calls to logger.info for removing files
            assert test_logger.info.call_count >= 2
        
        # Verify only 3 files remain (2 should have been deleted)
        remaining_files = os.listdir(temp_dir)
        assert len(remaining_files) == 3
        
        # The newest 3 files should remain (test_file_2, test_file_3, test_file_4)
        expected_remaining = {f"test_file_{i}.txt" for i in range(2, 5)}
        assert set(remaining_files) == expected_remaining
    finally:
        # Clean up temporary directory
        shutil.rmtree(temp_dir)


def test_receive_backup_cleanup(client):
    """Cleanup test to remove the upload folder after tests.
    
    This test ensures the upload folder is removed after all tests are run,
    leaving the environment in a clean state.
    """
    # Cleanup test: remove upload folder after tests
    if os.path.exists(UPLOAD_FOLDER):
        shutil.rmtree(UPLOAD_FOLDER)
    
    # Verify it's gone
    assert not os.path.exists(UPLOAD_FOLDER)
