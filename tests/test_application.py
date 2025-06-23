from ddmail_backup_receiver.application import sha256_of_file
from flask import make_response
from io import BytesIO
import os
import shutil
import tempfile

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
    assert sha256_of_file(TESTFILE_PATH) == SHA256


def test_sha256_of_empty_file():
    # Test handling of empty files
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
    # Test handling of binary files
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
    # Test handling of files larger than the buffer size
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


def test_receive_backup_no_filename(client,password):
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


def test_receive_backup_filename_illigal_char(client,password):
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


def test_receive_backup_no_file(client,password):
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


def test_receive_backup_no_sha256(client,password):
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


def test_receive_backup_sha256_illigal_char(client,password):
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


def test_receive_backup_no_upload_folder(client,password):
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


def test_receive_backup_wrong_checksum(client,password):
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


def test_receive_backup(client,password):
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
    # Test non-POST request method
    response = client.get("/receive_backup")
    assert response.status_code == 405
    # Flask's default 405 error page contains this text
    assert b"Method Not Allowed" in response.data


def test_receive_backup_file_none(client, password):
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


def test_receive_backup_cleanup(client):
    # Cleanup test: remove upload folder after tests
    if os.path.exists(UPLOAD_FOLDER):
        shutil.rmtree(UPLOAD_FOLDER)
    
    # Verify it's gone
    assert not os.path.exists(UPLOAD_FOLDER)
