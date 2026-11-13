from collections import Counter

# Sample Network Traffic
traffic_data = [
    ("192.168.1.10", "TCP", 80),
    ("192.168.1.11", "UDP", 53),
    ("192.168.1.10", "TCP", 443),
    ("192.168.1.12", "TCP", 22),
    ("192.168.1.15", "TCP", 80),
    ("192.168.1.12", "TCP", 22),
    ("192.168.1.12", "TCP", 22),
    ("192.168.1.20", "UDP", 53)
]

print("====================================")
print("       NETWORK TRAFFIC ANALYSIS")
print("====================================")

# Protocol Analysis
protocols = Counter(packet[1] for packet in traffic_data)

print("\nProtocol Analysis:")

for protocol, count in protocols.items():
    print(protocol, ":", count)

# Source IP Analysis
ip_count = Counter(packet[0] for packet in traffic_data)

print("\nSource IP Analysis:")

for ip, count in ip_count.items():
    print(ip, ":", count, "packets")

# Detect Suspicious Traffic
print("\nSecurity Analysis:")

for ip, count in ip_count.items():

    if count >= 3:
        print("[ALERT] Suspicious Traffic from", ip)

    else:
        print("[SAFE] Normal Traffic from", ip)

print("\n====================================")
print("       ANALYSIS COMPLETED")
print("====================================")