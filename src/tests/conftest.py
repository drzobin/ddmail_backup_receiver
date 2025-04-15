import os
import tempfile

import pytest

from backup_receiver import create_app

@pytest.fixture
def app():
    """Create and configure a new app instance for each test."""
    # Create the app with common test config
    app = create_app({"TESTING": True})

    yield app

@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()

@pytest.fixture
def runner(app):
    """A test runner for the app's Click commands."""
    return app.test_cli_runner()
