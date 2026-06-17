from . import app
from flask import render_template, request
import pandas as pd
import requests

@app.route("/")
@app.route("/index")
def index():
    return render_template("index.html")


@app.route("/run", methods=["POST"])
def run():
    if "file" not in request.files:
        return "No file received", 400

    gi_df = pd.read_csv(request.files["file"])

    response = requests.post(
        "http://localhost:5001/api",
        data=gi_df.to_json(orient="records"),
        headers={"Content-Type": "application/json"}
    )

    results = response.json()
    return render_template("index.html", results=results)
