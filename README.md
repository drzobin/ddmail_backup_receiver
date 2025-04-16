# What is ddmail_backup_receiver
Application to handle offsite backups for the ddmail project.

## What is DDMail
DDMail is a e-mail system/service that prioritizes security. A current production example can be found at www.ddmail.se

## Operating system
Developt for and tested on debian 12.

## Installing using pip
`pip install ddmail-backup-receiver`

## Building and installing from source using hatchling.
Step 1: clone github repo<br>
`git clone https://github.com/drzobin/ddmail_backup_receiver [code path]`<br>
`cd [code path]`<br>
<br>
Step 2: Setup python virtual environments<br>
`python -m venv [venv path]`<br>
`source [venv path]/bin/activate`<br>
<br>
Step 3: Install package and required dependencies<br>
`pip install -e .[dev]`<br>
<br>
Step 4: Build package<br>
`python -m pip install --upgrade build`<br>
`python -m build`<br> 
<br>
Packages is now located under dist folder<br>
<br>
Step 5: Install package<br>
`pip install dist/[package name].whl`<br>

## Running in development mode
`source [ddmail_backup_receiver venv]/bin/activate`<br>
`export MODE=DEVELOPMENT`<br>
`flask --app ddmail_backup_receiver:create_app(config_file="[full path to config file]") run --host=127.0.0.1 --port 8004 --debug`<br>

## Testing
`cd [code path]`<br>
`pytest --cov=ddmail_backup_receiver tests/ --config=[config file path] --password=[password]`

## Coding
Follow PEP8 and PEP257. Use Flake8 with flake8-docstrings for linting. Strive for 100% test coverage.
