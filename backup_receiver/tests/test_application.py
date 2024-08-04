from backup_receiver.application import sha256_of_file
from io import BytesIO

def test_sha256_of_file():
    test_file_path = "backup_receiver/tests/test_file.txt"
    test_file_sha256 = "7b7632005be0f36c5d1663a6c5ec4d13315589d65e1ef8687fb4b9866f9bc4b0"
    
    assert sha256_of_file(test_file_path) == test_file_sha256

def test_receive_backup_no_password(client):
    test_file_sha256 = "7b7632005be0f36c5d1663a6c5ec4d13315589d65e1ef8687fb4b9866f9bc4b0"
    test_file_path = "backup_receiver/tests/test_file.txt"
    f = open(test_file_path, "r")
    test_file_data = f.read()

    print("data:"  + str(test_file_data))

    response = client.post("/receive_backup", buffered=True, content_type='multipart/form-data', data={ "filename":"test_file.txt", "file":(BytesIO(bytes(test_file_data, 'utf-8')), "test_file.txt"), "sha256":test_file_sha256})

    assert response.status_code == 200
    assert b"error: password is none" in response.data

def test_receive_backup_password_illigal_char(client):
    test_file_sha256 = "7b7632005be0f36c5d1663a6c5ec4d13315589d65e1ef8687fb4b9866f9bc4b0"
    test_file_path = "backup_receiver/tests/test_file.txt"
    f = open(test_file_path, "r")
    test_file_data = f.read()

    print("data:"  + str(test_file_data))

    response = client.post("/receive_backup", buffered=True, content_type='multipart/form-data', data={ "password":"password$","filename":"test_file.txt", "file":(BytesIO(bytes(test_file_data, 'utf-8')), "test_file.txt"), "sha256":test_file_sha256})

    assert response.status_code == 200
    assert b"error: password validation failed" in response.data
