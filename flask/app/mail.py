import smtplib, sys

from email.mime.text import MIMEText

def send_mail(to_email,token):
    port = 587

    sender = 'SMTP_SERVER_EMAIL'

    text = "Your recovery token: " + token
    msg = MIMEText(text)

    msg['Subject'] = 'Recovery token'
    msg['From'] = sender
    msg['To'] = to_email

    user = 'SMTP_SERVER_EMAIL'
    password = 'password'

    with smtplib.SMTP("smtp.example.org", port) as server:

        server.starttls()

        server.login(user, password)
        server.sendmail(sender, to_email, msg.as_string())
