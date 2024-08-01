from flask import current_app
from backup_receiver.application import sha256_of_file
import pytest
import os

def test_sha256_of_file():
    test_file_path = "backup_receiver/tests/test_file.txt"
    test_file_sha256 = "7b7632005be0f36c5d1663a6c5ec4d13315589d65e1ef8687fb4b9866f9bc4b0"
    
    assert sha256_of_file(test_file_path) == test_file_sha256
