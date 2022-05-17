import bcrypt

# Courtesy of https://stackoverflow.com/users/84131/chris-dutrow.
from werkzeug.utils import redirect


def get_hashed_password(plain_text_password):
    # Hash a password for the first time
    #   (Using bcrypt, the salt is saved into the hash itself)
    plain_text_password_utf = plain_text_password.encode('utf-8')  # I just added this line
    hashed_password = bcrypt.hashpw(plain_text_password_utf, bcrypt.gensalt())
    return hashed_password

def check_password(plain_text_password, hashed_password):
    plain_text_password_utf = plain_text_password.encode('utf-8')  # I just added this line
    hashed_password_utf = hashed_password.encode('utf-8')  # I just added this line
    # Check hashed password. Using bcrypt, the salt is saved into the hash itself
    return bcrypt.checkpw(plain_text_password_utf, hashed_password_utf)
