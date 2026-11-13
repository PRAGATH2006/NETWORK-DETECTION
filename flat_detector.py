import re

patterns = {
    "SQL Injection": r"union\s+select|or\s+1=1|drop\s+table",
    "XSS Attack": r"<script.*?>",
    "Path Traversal": r"\.\./|\.\.\\",
    "Command Injection": r";\s*(ls|cat|dir|whoami)"
}

def dfa_detection(text):
    state = 0

    for char in text:
        if state == 0 and char == ".":
            state = 1
        elif state == 1 and char == ".":
            state = 2
        elif state == 2 and char == "/":
            return True
        elif char == ".":
            state = 1
        else:
            state = 0

    return False


def analyze_traffic(traffic):
    print("\nTraffic:", traffic)
    detected = False

    for attack, pattern in patterns.items():
        if re.search(pattern, traffic, re.IGNORECASE):
            print("[ALERT]", attack)
            detected = True

    if dfa_detection(traffic):
        print("[ALERT] DFA: Path Traversal")
        detected = True

    if not detected:
        print("[SAFE] Normal Network Traffic")


traffic_data = [
    "GET /home HTTP/1.1",
    "SELECT * FROM users UNION SELECT password FROM admin",
    "<script>alert('hack')</script>",
    "GET /../../etc/passwd HTTP/1.1",
    "GET /products?id=10"
]

print("NETWORK INTRUSION DETECTION SYSTEM")

for traffic in traffic_data:
    analyze_traffic(traffic)

print("\nANALYSIS COMPLETED")