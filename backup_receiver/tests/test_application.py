from backup_receiver.application import sha256_of_file
from io import BytesIO

# Testfile used in many testcases.
TESTFILE_PATH = "backup_receiver/tests/test_file.txt"
TESTFILE_NAME = "test_file.txt"
SHA256 = "7b7632005be0f36c5d1663a6c5ec4d13315589d65e1ef8687fb4b9866f9bc4b0"
f = open(TESTFILE_PATH, "r")
TESTFILE_DATA = f.read()


def test_sha256_of_file():
    assert sha256_of_file(TESTFILE_PATH) == SHA256


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
            "password": "password$",
            "filename": TESTFILE_NAME,
            "file": (BytesIO(bytes(TESTFILE_DATA, 'utf-8')), TESTFILE_NAME),
            "sha256": SHA256
            }
        )

    assert response.status_code == 200
    assert b"error: password validation failed" in response.data


def test_receive_backup_no_filename(client):
    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": "password",
            "file": (BytesIO(bytes(TESTFILE_DATA, 'utf-8')), TESTFILE_NAME),
            "sha256": SHA256
            }
        )

    assert response.status_code == 200
    assert b"error: filename is none" in response.data


def test_receive_backup_filename_illigal_char(client):
    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": "password",
            "filename": "test_fil--e.txt",
            "file": (BytesIO(bytes(TESTFILE_DATA, 'utf-8')), TESTFILE_NAME),
            "sha256": SHA256
            }
        )

    assert response.status_code == 200
    assert b"error: filename validation failed" in response.data


def test_receive_backup_no_file(client):
    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": "password",
            "filename": TESTFILE_NAME,
            "sha256": SHA256
            }
        )

    assert response.status_code == 200
    assert b"error: file is not in request.files" in response.data


def test_receive_backup_no_sha256(client):
    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": "password",
            "filename": TESTFILE_NAME,
            "file": (BytesIO(bytes(TESTFILE_DATA, 'utf-8')), TESTFILE_NAME)
            }
        )

    assert response.status_code == 200
    assert b"error: sha256_from_form is none" in response.data


def test_receive_backup_sha256_illigal_char(client):
    sha256 = "7b7@32005be0f36c5d1663a6c5ec4d13315589d65e1ef8687fb4b9866f9bc4b0"

    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": "password",
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
            "password": "thisiswrongpassword",
            "filename": TESTFILE_NAME,
            "file": (BytesIO(bytes(TESTFILE_DATA, 'utf-8')), TESTFILE_NAME),
            "sha256": SHA256
            }
        )

    assert response.status_code == 200
    assert b"error: wrong password" in response.data


def test_receive_backup_no_upload_folder(client):
    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "password": "password",
            "filename": TESTFILE_NAME,
            "file": (BytesIO(bytes(TESTFILE_DATA, 'utf-8')), TESTFILE_NAME),
            "sha256": SHA256
            }
        )

    assert response.status_code == 200
    assert b"error: upload folder backups do not exist" in response.data
