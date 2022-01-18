import mariadb
from app import encryption as enc

config = {
      'user': 'root',
      'password': 'root',
      'host': 'mariadb',
      'port': 3306,
      'database': 'pm_db',
      }

connection = mariadb.connect(**config)

def add_new_user(login, password):
    hashed, salt = enc.encrypt(password)
    cursor = connection.cursor(buffered=True)
    cursor.execute("INSERT INTO users(username, passwd, salt) VALUES (%s, %s, %s)", (login, hashed, salt))
    connection.commit()
    cursor.close()

def user_exists(login):
    cursor = connection.cursor(buffered=True)
    cursor.execute('SELECT * FROM users WHERE username = %s', (login, ))
    data = cursor.fetchone()
    cursor.close()
    if data:
        return True
    return False

def validate_user(login, password):
    if user_exists(login):
        salt = get_user_salt(login)
        hashed_psw = enc.encrypt_with_salt(password, salt)
        cursor = connection.cursor(buffered=True)
        cursor.execute('SELECT * FROM users WHERE username = %s AND passwd = %s', (login, hashed_psw))
        data = cursor.fetchone()
        cursor.close()
        if data:
            return True
        return False
    return False

def get_id_from_username(username):
    cursor = connection.cursor(buffered=True)
    cursor.execute('select u.ID from users u where u.username = %s', (username,))
    user_id = cursor.fetchone()[0]
    cursor.close()
    return user_id

def get_user_salt(username):
    cursor = connection.cursor(buffered=True)
    cursor.execute('SELECT salt FROM users WHERE username = %s', (username, ))
    salt = cursor.fetchone()[0]
    cursor.close()
    return salt


def get_passwords(username, master_password):
    cursor = connection.cursor(buffered=True)
    cursor.execute('select p.website, cast(AES_DECRYPT(p.passwd, SHA2(%s,512)) as CHAR) from users u join passwords p on u.ID = p.u_id where u.username = %s', (master_password, username))
    rows = cursor.fetchall()
    cursor.close()
    return rows

def password_exists(website):
    cursor = connection.cursor(buffered=True)
    cursor.execute('SELECT * FROM passwords WHERE website = %s', (website,))
    data = cursor.fetchone()
    cursor.close()
    if data:
        return True
    return False

def add_password(username, website, password, master_password):
    cursor = connection.cursor(buffered=True)
    user_id = get_id_from_username(username)
    cursor.execute("INSERT INTO passwords(u_id, website, passwd) VALUES (%s, %s, AES_ENCRYPT(%s, SHA2(%s,512)))", (user_id, website, password, master_password))
    connection.commit()
    cursor.close()

def remove_old_password(username, website):
    cursor = connection.cursor(buffered=True)
    user_id = get_id_from_username(username)
    cursor.execute("DELETE FROM passwords WHERE u_id=%s AND website=%s", (user_id, website))
    connection.commit()
    cursor.close()

def add_token(token, username):
    del_token(token)
    cursor = connection.cursor(buffered=True)
    user_id = get_id_from_username(username)
    cursor.execute("INSERT INTO tokens(s_id, u_id) VALUES (%s, %s)", (token, user_id))
    connection.commit()
    cursor.close()

def get_user_from_token(token):
    cursor = connection.cursor(buffered=True)
    cursor.execute('SELECT u.username FROM tokens s JOIN users u ON s.u_id = u.ID WHERE s.s_id = %s', (token, ))
    user = cursor.fetchone()[-1]
    cursor.close()
    return user

def del_token(token):
    cursor = connection.cursor(buffered=True)
    cursor.execute("DELETE FROM tokens WHERE s_id=%s", (token, ))
    connection.commit()
    cursor.close()

def del_terminated_tokens():
    cursor = connection.cursor(buffered=True)
    cursor.execute("DELETE FROM tokens WHERE created < ADDDATE(NOW(), INTERVAL -15 MINUTE)")
    connection.commit()
    cursor.close()

def update_login_attempts(username):
    cursor = connection.cursor(buffered=True)
    user_id = get_id_from_username(username)
    if attempt_exists(username):
        cursor.execute("UPDATE failed_log_attempts SET n_attempts = n_attempts + 1 WHERE u_id=%s", (user_id, ))
        cursor.execute("UPDATE failed_log_attempts SET last_attempt = NOW() WHERE u_id=%s", (user_id, ))
        connection.commit()
    else:
        cursor.execute("INSERT INTO failed_log_attempts(u_id, n_attempts) VALUES (%s, %s)", (user_id, 1))
        connection.commit()
    cursor.close()

def get_failed_login_attempts(username):
    cursor = connection.cursor(buffered=True)
    user_id = get_id_from_username(username)
    cursor.execute('SELECT n_attempts FROM failed_log_attempts WHERE u_id = %s', (user_id, ))
    user = cursor.fetchone()[0]
    cursor.close()
    return user

def is_blocked(username):
    cursor = connection.cursor(buffered=True)
    user_id = get_id_from_username(username)
    cursor.execute('SELECT * FROM failed_log_attempts WHERE n_attempts % 5 = 0 AND u_id=%s AND last_attempt > NOW() - INTERVAL 15 MINUTE', (user_id, ))
    user = cursor.fetchone()
    cursor.close()
    if user:
        return True
    return False

def attempt_exists(username):
    cursor = connection.cursor(buffered=True)
    user_id = get_id_from_username(username)
    cursor.execute('SELECT * FROM failed_log_attempts WHERE u_id=%s', (user_id, ))
    user = cursor.fetchone()
    cursor.close()
    if user:
        return True
    return False

def del_attempts(username):
    cursor = connection.cursor(buffered=True)
    user_id = get_id_from_username(username)
    cursor.execute("DELETE FROM failed_log_attempts WHERE u_id=%s", (user_id, ))
    connection.commit()
    cursor.close()

def get_unblock_date(username):
    cursor = connection.cursor(buffered=True)
    user_id = get_id_from_username(username)
    cursor.execute('SELECT DATE_ADD(last_attempt, INTERVAL 5 MINUTE) FROM failed_log_attempts WHERE u_id=%s', (user_id, ))
    date = cursor.fetchone()[0]
    cursor.close()
    return date

