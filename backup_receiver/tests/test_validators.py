from flask import current_app
from backup_receiver.validators import is_password_allowed, is_sha256_allowed
import pytest
import os

def test_is_sha256_allowed():
    assert is_sha256_allowed("a1d4") == False
    assert is_sha256_allowed("a1b2") == False
    assert is_sha256_allowed("7b7632005be0f36c5d1663a6c5ec4d13315589d65e1ef8687fb4b9866f9bc4b0a") == False
    assert is_sha256_allowed("7b7632005be0f36c5d1663a6c5ec4d13315589d651ef8687fB4b9866f9bc4b0") == False
    assert is_sha256_allowed("7b7632005b.0f36c5d1663a6c5ec4d13315589d65e1ef8687fb4b9866f9bc4b0") == False
    assert is_sha256_allowed("7b7632005be\"f36c5d1663a6c5ec4d13315589d65e1ef8687fb4b9866f9bc4b0") == False
    assert is_sha256_allowed("7b7632005be-f36c5d1663a6c5ec4d13315589d65e1ef8687fb4b9866f9bc4b0") == False
    assert is_sha256_allowed("7b7632005b.0f36c5d1663a6c5ec4d13315589d65e1ef8687fb4b9866f9bc4b0") == False
    assert is_sha256_allowed("7b7632005be0f36c5d1663a6c5ec4d13315589d65e1ef8687fb4b9866f9bc4b0") == True

def test_is_password_allowed():
    assert is_password_allowed("aA8/+=") == True
    assert is_password_allowed("aA8/+=\\") == False
    assert is_password_allowed("aA8/+=\\vfgg") == False
    assert is_password_allowed("aAx\"fds") == False
    assert is_password_allowed("a-b3") == False
    assert is_password_allowed("a--b3") == False
    assert is_password_allowed("a<b3") == False
    assert is_password_allowed("a>b5") == False
    assert is_password_allowed("a>>6") == False
