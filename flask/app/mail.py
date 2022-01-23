import smtplib, sys

from email.mime.text import MIMEText

def send_mail(to_email,token):
    port = 587

    sender = 'pi3mgr7haslo@hotmail.com'

    text = "Your recovery token: " + token
    msg = MIMEText(text)

    msg['Subject'] = 'Recovery token'
    msg['From'] = 'pi3mgr7haslo@hotmail.com'
    msg['To'] = to_email

    user = 'pi3mgr7haslo@hotmail.com'
    password = 'OchronaDanych0)'

    with smtplib.SMTP("smtp.office365.com", port) as server:

        server.starttls()

        server.login(user, password)
        server.sendmail(sender, to_email, msg.as_string())