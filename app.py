
from flask import Flask, render_template, request, jsonify
from pymongo import MongoClient
from dotenv import load_dotenv
import re
import os

app = Flask(__name__)

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000)
db = client["network_detection"]
traffic_collection = db["traffic"]


def detect_attack(text):
    patterns = {
        "SQL Injection": r"""(\bOR\b\s+['"]?1['"]?\s*=\s*['"]?1|UNION\s+SELECT|DROP\s+TABLE)""",
        "XSS": r"<script.*?>.*?</script>",
        "Path Traversal": r"\.\./|\.\.\\",
        "Command Injection": r";\s*(whoami|ls|dir|cat|ping)"
    }

    for attack, pattern in patterns.items():
        if re.search(pattern, text, re.IGNORECASE):
            return "Malicious", attack

    return "Safe", "None"


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


@app.route("/")
def home():
    return "Network Intrusion Detection Backend is Running Successfully!"


@app.route("/api/traffic", methods=["GET", "POST", "OPTIONS"])
def traffic_api():

    if request.method == "OPTIONS":
        return "", 200

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        input_text = data.get("input_text", "").strip()

        if not input_text:
            return jsonify({"error": "Input text is required"}), 400

        status, attack_type = detect_attack(input_text)

        traffic_collection.insert_one({
            "input_text": input_text,
            "status": status,
            "attack_type": attack_type
        })

        return jsonify({
            "status": status,
            "attack_type": attack_type
        })

    documents = list(traffic_collection.find().sort("_id", -1))

    records = [
        {
            "input_text": doc.get("input_text", ""),
            "status": doc.get("status", ""),
            "attack_type": doc.get("attack_type", "")
        }
        for doc in documents
    ]

    return jsonify({
        "total": traffic_collection.count_documents({}),
        "safe": traffic_collection.count_documents({"status": "Safe"}),
        "malicious": traffic_collection.count_documents({"status": "Malicious"}),
        "records": records
    })


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():

    if request.method == "POST":
        input_text = request.form.get("input_text", "").strip()

        if input_text:
            status, attack_type = detect_attack(input_text)

            traffic_collection.insert_one({
                "input_text": input_text,
                "status": status,
                "attack_type": attack_type
            })

    documents = list(traffic_collection.find().sort("_id", -1))

    records = [
        (
            str(doc["_id"]),
            doc.get("input_text", ""),
            doc.get("status", ""),
            doc.get("attack_type", "")
        )
        for doc in documents
    ]

    total = traffic_collection.count_documents({})
    safe = traffic_collection.count_documents({"status": "Safe"})
    malicious = traffic_collection.count_documents({"status": "Malicious"})

    return render_template(
        "index.html",
        records=records,
        total=total,
        safe=safe,
        malicious=malicious
    )


if __name__ == "__main__":
    app.run(debug=True)
