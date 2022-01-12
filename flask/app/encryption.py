import bcrypt

def encrypt(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed, salt

def check_password(salt, password, hash):
    return hash == encrypt_with_salt(password, salt)

def encrypt_with_salt(password, salt):
    return bcrypt.hashpw(password.encode('utf-8'), salt)

