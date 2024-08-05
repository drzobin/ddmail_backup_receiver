from backup_receiver.application import sha256_of_file
from io import BytesIO

test_file_path = "backup_receiver/tests/test_file.txt"
sha256 = "7b7632005be0f36c5d1663a6c5ec4d13315589d65e1ef8687fb4b9866f9bc4b0"

f = open(test_file_path, "r")
test_file_data = f.read()


def test_sha256_of_file():
    assert sha256_of_file(test_file_path) == sha256


def test_receive_backup_no_password(client):
    response = client.post(
        "/receive_backup",
        buffered=True,
        content_type='multipart/form-data',
        data={
            "filename": "test_file.txt",
            "file": (BytesIO(bytes(test_file_data, 'utf-8')), "test_file.txt"),
            "sha256": sha256
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
            "filename": "test_file.txt",
            "file": (BytesIO(bytes(test_file_data, 'utf-8')), "test_file.txt"),
            "sha256": sha256
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
            "file": (BytesIO(bytes(test_file_data, 'utf-8')), "test_file.txt"),
            "sha256": sha256
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
            "file": (BytesIO(bytes(test_file_data, 'utf-8')), "test_file.txt"),
            "sha256": sha256
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
            "filename": "test_file.txt",
            "sha256": sha256
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
            "filename": "test_file.txt",
            "file": (BytesIO(bytes(test_file_data, 'utf-8')), "test_file.txt")
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
            "filename": "test_file.txt",
            "file": (BytesIO(bytes(test_file_data, 'utf-8')), "test_file.txt"),
            "sha256": sha256
            }
        )

    assert response.status_code == 200
    assert b"error: sha256 checksum validation failed" in response.data
