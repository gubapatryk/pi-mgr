# pi-mgr

Simple web app for storing passwords. Functionalities:
- store and delete password securely decrypted in database
- recover lost master password
- send email with recovery token
- share password with other users

Secrets are hardcoded since I wanted the app to be deterministic and easy to read, normally it's recommended to use env variables or vaults to store secrets.
