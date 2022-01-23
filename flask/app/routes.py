from flask import Flask, render_template, request, json, redirect, url_for, session, make_response
import mariadb
from functools import wraps
from datetime import datetime
import random
import string
from app import db, app, validation as val, mail

### dekorator do określania podstron, na których trzeba być zalagowanym
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.cookies.get('Session ID') is None:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
def index():
   if request.cookies.get('Session ID') != None:
      return redirect(url_for('home'))
   return redirect(url_for('login'))

def add_attempt(login, request, successful):        
   now = datetime.now()

   current_time = now.strftime("%m/%d/%Y, %H:%M:%S")

   if successful:
      login_info = "SUCCESSFUL :" 
   else:
      login_info = "FAILED :" 
      
   login_info = login_info +  current_time + ", " + request.headers.get('Host') + ", " + request.headers.get('User-Agent')[:75] + ", " + request.headers.get('Accept-Language')[:30]

   db.add_attempt(login,login_info)


@app.route('/login', methods=['GET', 'POST'])
def login():
   msg = ''
   db.del_terminated_tokens() 
   if request.method == 'POST' and 'uname' in request.form and 'psw' in request.form:
      details = request.form
      if val.is_input_safe(details['uname']) and val.is_input_safe(details['psw']):
         login = details['uname']
         password = details['psw']
         

         if db.validate_user(login, password):
            
            add_attempt(login, request, True)

            if db.is_blocked(login):
               date = db.get_unblock_date(login)
               msg = "User " + login + " is blocked until " + str(date)

            else:
               db.del_attempts(login)
               token = val.get_random_string(24)
               db.add_token(token, login)
               res = make_response("Logged in", 302)
               res.set_cookie("Session ID", token, max_age=300, secure=True, httponly=True)
               res.headers['location'] = 'home'
               print(db.get_user_login_attempts(login))
               return res

         elif not login or not password:
            msg = 'Fill out the form!'

         elif db.user_exists(login):

            add_attempt(login, request, False)

            if db.is_blocked(login):
               date = db.get_unblock_date(login)
               msg = "User " + login + " is blocked until " + str(date)
               
            else:
               db.update_login_attempts(login)
               attempts = db.get_failed_login_attempts(login)
               att_left = 5 - attempts % 5

               if att_left == 5:
                  att_left = 0
                  
               msg = 'Incorrect password! You have ' + str(att_left) + ' attempts left!'
                  
         else:
            msg = "User " + login + " does not exist!"
      else:
         msg = "Incorrect input!"

   return render_template("login.html", msg = msg)


@app.route('/logout')
def logout():
   token = request.cookies.get('Session ID')
   db.del_token(token)
   res = make_response("Logged out", 302)
   res.set_cookie('Session ID', '', max_age = 0)
   res.headers['location'] = 'login'
   return res


@app.route('/home')
@login_required
def home():
   token = request.cookies.get('Session ID')
   return render_template('home.html',  username = db.get_user_from_token(token))


@app.route('/home/psw_list', methods=['GET', 'POST'])
@login_required
def psw_list():
   msg = ''

   if request.method == 'POST' and 'mpsw' in request.form:
      master_password = request.form['mpsw']
      token = request.cookies.get('Session ID')
      username = db.get_user_from_token(token)

      if not db.validate_user(username, master_password):
         msg = "Wrong master password!"
         return render_template('psw_list.html', msg=msg)

      rows = db.get_passwords(username, master_password)
      msg = "Your have " + str(len(rows)) + " saved passwords"
      return render_template('psw_list.html',rows=rows, msg=msg)

   msg = "Type in your master password to show saved passwords:"
   return render_template('psw_list.html', msg=msg)

@app.route('/home/attempts', methods=['GET', 'POST'])
@login_required
def attempts_list():

   token = request.cookies.get('Session ID')
   username = db.get_user_from_token(token)
   rows = db.get_user_login_attempts(username)
   msg = "Showing list of saved " + str(len(rows)) + " login attempt(s)"
   return render_template('attempts.html',rows=rows, msg=msg)

@app.route('/home/add_psw', methods=['GET', 'POST'])
@login_required
def add_psw():
   msg = ''
   replaced_flag = False
   rand_psw = val.get_random_string(16)
   
   if request.method == 'POST' and 'wbst' in request.form and 'psw' in request.form:
      details = request.form
      website = details['wbst']
      password = details['psw']
      master_password = details['mpsw']

      if login and password and master_password:

         token = request.cookies.get('Session ID')
         username = db.get_user_from_token(token)

         if not db.validate_user(username, master_password):
            return render_template('add_psw.html', msg="Wrong master password!", rand_psw=rand_psw)

         msg = val.validate_password(password)
         
         if msg != '':
            return render_template('add_psw.html', msg=msg, rand_psw=rand_psw)

         if db.password_exists(website):
            db.remove_old_password(username, website)
            replaced_flag = True
            msg = "Password for " + website + " has been updated!"

         db.add_password(username, website, password, master_password)
         
         if not replaced_flag:
            msg = 'New password has been added!'

      else:
         msg = 'Fill out the form!'
      
   return render_template('add_psw.html', msg=msg, rand_psw=rand_psw)


@app.route('/home/del_psw', methods=['GET', 'POST'])
@login_required
def del_psw():
   msg = ''
   if request.method == 'POST' and 'wbst' in request.form:
      website = request.form['wbst']

      if db.password_exists(website):
         token = request.cookies.get('Session ID')
         username = db.get_user_from_token(token)
         db.remove_old_password(username, website)
         msg = 'Password removed'

      else:
         msg = 'There is no password saved for ' + website

   return render_template('del_psw.html', msg=msg)


@app.route('/register', methods=['GET', 'POST'])
def register():

   msg = ''
   try:
      if request.method == 'POST' and 'uname' in request.form and 'psw' in request.form and 'email' in request.form:
         details = request.form
         if val.is_username_format(details['uname']) and val.is_password_format(details['psw']) and val.is_email_format(details['email']):
            login = details['uname']
            password = details['psw']
            email = details['email']

            if db.user_exists(login):
               msg = 'Username exists!'

            elif login and password:
               msg = val.validate_password(password)
            
               if msg == '':
                  db.add_new_user(login, email, password)
                  msg = 'Successfully registered new account!'

            else:
               msg = 'Fill out the form!'
         else:
            msg = 'Invalid forms input'

      elif request.method == 'POST':
         msg = 'Fill out the form!'

   except mariadb.Error as err:
      return("Something went wrong: {}".format(err))
   
   return render_template('register.html', msg=msg)

@app.route('/send_email', methods=['GET', 'POST'])
def send_recovery_email():

   msg = ''
   try:
      if request.method == 'POST' and 'uname' in request.form:
         details = request.form
         login = details['uname']

         if db.user_exists(login):
            token = val.get_random_string(100)
            db.add_recovery_token(login,token)
            user_email = db.get_email_from_username(login)
            print("bbb" + user_email +"bbb")
            mail.send_mail(user_email,token)
            msg = 'Sent recovery email!'

         elif login:
            msg = 'Username does not exists!'

         else:
            msg = 'Fill out the form!'

      elif request.method == 'POST':
         msg = 'Fill out the form!'

   except mariadb.Error as err:
      return("Something went wrong: {}".format(err))
   
   return render_template('send_email.html', msg=msg)

@app.route('/recovery', methods=['GET', 'POST'])
def recovery():

   msg = ''
   try:
      if request.method == 'POST' and 'uname' in request.form and 'token' in request.form and 'psw' in request.form:
         details = request.form
         if val.is_username_format(details['uname']) and val.is_password_format(details['psw']) and val.is_input_safe(details['token']):
            login = details['uname']
            password = details['psw']
            token = details['token']

            if db.user_exists(login) and db.recovery_token_valid(token,login):
               db.reset_password(login, password)
               db.del_recovery_token(token)
            else:
               msg = 'Invalid token or user doesnt exists'
         else:
            msg = 'Invalid forms input'

      elif request.method == 'POST':
         msg = 'Fill out the form!'

   except mariadb.Error as err:
      return("Something went wrong: {}".format(err))
   
   return render_template('recovery.html', msg=msg)