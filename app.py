from flask import Flask, render_template, request, redirect
import sqlite3
import re

app = Flask(__name__)


# Database Creation
def create_database():

    conn = sqlite3.connect("traffic.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            input_text TEXT,
            status TEXT,
            attack_type TEXT
        )
    """)

    conn.commit()
    conn.close()


# Attack Detection
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


# Home Page
@app.route("/", methods=["GET", "POST"])
def home():

    if request.method == "POST":

        input_text = request.form["input_text"]

        status, attack_type = detect_attack(input_text)

        conn = sqlite3.connect("traffic.db")
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO traffic (input_text, status, attack_type)
            VALUES (?, ?, ?)
            """,
            (input_text, status, attack_type)
        )

        conn.commit()
        conn.close()

        return redirect("/")

    # Fetch Traffic Records
    conn = sqlite3.connect("traffic.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM traffic ORDER BY id DESC")
    records = cursor.fetchall()

    # Total Traffic
    cursor.execute("SELECT COUNT(*) FROM traffic")
    total = cursor.fetchone()[0]

    # Safe Traffic
    cursor.execute(
        "SELECT COUNT(*) FROM traffic WHERE status='Safe'"
    )
    safe = cursor.fetchone()[0]

    # Malicious Traffic
    cursor.execute(
        "SELECT COUNT(*) FROM traffic WHERE status='Malicious'"
    )
    malicious = cursor.fetchone()[0]

    conn.close()

    return render_template(
        "index.html",
        records=records,
        total=total,
        safe=safe,
        malicious=malicious
    )


# Run Application
if __name__ == "__main__":

    create_database()

    app.run(debug=True)