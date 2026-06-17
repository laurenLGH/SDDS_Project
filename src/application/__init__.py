from flask import Flask

app = Flask(__name__)

from src.application import routes

if __name__ == '__main__':
    app.run()