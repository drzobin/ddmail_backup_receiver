import re

# Valdate sha256 checksum. Only allow the following chars:a-z, A-Z  and 0-9
def is_sha256_allowed(checksum):
    if not len(checksum) == 64:
        return False

    pattern = re.compile(r"[a-zA-Z0-9]")

    for char in checksum:
        if not re.match(pattern, char):
            return False

    return True

def is_filename_allowed(filename):
    if len(filename) > 256:
        return False

    if len(filename) < 3:
        return False

    if filename.startswith('.') or filename.startswith('-') or filename.startswith('_'):
        return False
    if filename.endswith('.') or filename.endswith('-') or filename.endswith('_'):
        return False
    if '--' in filename:
        return False
    if '..' in filename:
        return False
    if '__' in filename:
        return False

    pattern = re.compile(r"[a-zA-Z0-9\-\_\.]")

    for char in filename:
        if not re.match(pattern, char):
            return False

    return True

# Validate password. Passwords will be base64 encoded. Only allow the following chars: A-Z, a-z, 0-9 and +/=
def is_password_allowed(password):
    if not len(password) > 16:
        return False
    pattern = re.compile(r"[a-zA-Z0-9\+\/\=]")

    for char in password:
        if not re.match(pattern, char):
            return False

    return True

# Validate domain names. Only allow the following chars: a-z, 0-9 and .-
def is_domain_allowed(domain):
    if not len(domain) > 3:
        return False

    if domain.startswith('.') or domain.startswith('-'):
        return False
    if domain.endswith('.') or domain.endswith('-'):
        return False
    if '--' in domain:
        return False
    if '..' in domain:
        return False

    if domain.find(".") == -1:
        return False

    pattern = re.compile(r"[a-z0-9.-]")
    for char in domain:
        if not re.match(pattern, char):
            return False

    return True

# Validate email address. Only allow the following chars: a-z, 0-9 and @.-
def is_email_allowed(email):
    if not len(email) > 6:
        return False

    if email.count('@') != 1:
        return False
    if email.startswith('.') or email.startswith('@') or email.startswith('-'):
        return False
    if email.endswith('.') or email.endswith('@') or email.endswith('-'):
        return False

    # Validate email part of email.
    splitted_email = email.split('@')
    if splitted_email[0].startswith('.') or splitted_email[0].startswith('-'):
        return False
    if splitted_email[0].endswith('.') or splitted_email[0].endswith('-'):
        return False
    if '--' in splitted_email[0]:
        return False
    if '..' in splitted_email[0]:
        return False

    # Validate Domain part of email.
    if is_domain_allowed(splitted_email[1]) != True:
        return False

    pattern = re.compile(r"[a-z0-9@.-]")
    for char in email:
        if not re.match(pattern, char):
            return False

    return True
