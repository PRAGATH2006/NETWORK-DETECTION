
from flask import Flask, render_template, request, redirect
from pymongo import MongoClient
from dotenv import load_dotenv
import re
import os

app = Flask(__name__)
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    raise ValueError("MONGO_URI is missing in .env file")

client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=10000
)

db = client["network_detection"]
traffic_collection = db["traffic"]



try:
    client.admin.command("ping")
    print("MongoDB Atlas Connected Successfully!")
except Exception as e:
    print("MongoDB Connection Error:", e)



def detect_attack(text):

    patterns = {
        "SQL Injection": r"(\bOR\b\s+['\"]?1['\"]?\s*=\s*['\"]?1|UNION\s+SELECT|DROP\s+TABLE)",
        "XSS": r"<script.*?>.*?</script>",
        "Path Traversal": r"\.\./|\.\.\\",
        "Command Injection": r";\s*(whoami|ls|dir|cat|ping)"
    }

    for attack, pattern in patterns.items():

        if re.search(pattern, text, re.IGNORECASE):
            return "Malicious", attack

    return "Safe", "None"


@app.route("/", methods=["GET", "POST"])
def home():

    if request.method == "POST":

        input_text = request.form["input_text"]

        status, attack_type = detect_attack(input_text)

        try:
            
            traffic_collection.insert_one({
                "input_text": input_text,
                "status": status,
                "attack_type": attack_type
            })

            print("Traffic saved successfully!")

        except Exception as e:
            print("MongoDB Insert Error:", e)

        return redirect("/")

    try:
        documents = list(
            traffic_collection.find().sort("_id", -1)
        )

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

        safe = traffic_collection.count_documents({
            "status": "Safe"
        })

        malicious = traffic_collection.count_documents({
            "status": "Malicious"
        })

    except Exception as e:
        print("MongoDB Fetch Error:", e)
        records = []
        total = 0
        safe = 0
        malicious = 0

    return render_template(
        "index.html",
        records=records,
        total=total,
        safe=safe,
        malicious=malicious
    )


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
