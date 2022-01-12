from flask import Flask
from app import validation as val

app = Flask(__name__, template_folder='templates')
app.secret_key = val.get_random_string(16).encode('utf-8')

from app import routes
