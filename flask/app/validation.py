import random
import string
import re

min_username_length = 3
max_username_length = 30
min_password_length = 8
max_password_length = 60

def get_random_string(len):
    return ''.join((random.choice(string.ascii_letters + string.digits) for i in range(len)))

def is_username_format(input):
    if len(input) > max_username_length or len(input) < min_password_length:
        return False
    return is_input_safe(input)

    
def is_password_format(input):
    if len(input) > max_password_length or len(input) < min_password_length:
        return False
    return is_input_safe(input)

def is_email_format(input):
    if re.search(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)",input) is None:
        return False
    return is_input_safe(input)

def is_input_safe(input):
    if re.search(r'/[\t\r\n]|(--[^\r\n]*)|(\/\*[\w\W]*?(?=\*)\*\/)/gi',input) is None:
        matches = re.findall(r'[^A-Za-z0-9!@#$%^&+=.:/]*',input)
        for m in matches:
            if m != '':
                return False
        return True
    return False

def validate_password(password):
    msg = ''
    if len(password) < min_password_length:
        msg += "Password must contain least 8 characters!   "
    if re.search('[0-9]',password) is None:
        msg += "Password must contain a number!   "
    if re.search('[a-z]',password) is None:
        msg += "Password must contain a lowercase letter!   "
    if re.search('[A-Z]',password) is None: 
        msg += "Password must contain a uppercase letter!   "
    return msg