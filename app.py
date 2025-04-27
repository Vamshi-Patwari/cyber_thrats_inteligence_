from flask import Flask, render_template, jsonify
import json
import os
import csv
import datetime
import ipaddress
import random

app = Flask(__name__)

# Create necessary directories if they don't exist
data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
os.makedirs(data_dir, exist_ok=True)
os.makedirs('templates', exist_ok=True)
os.makedirs('static', exist_ok=True)
print(f"Data directory created at: {data_dir}")

# Function to read and process CSV data
def process_cybersecurity_data(csv_path):
    ip_threats = []
    traffic_analysis = []
    login_attempts = []

    # Mapping for severity levels
    severity_mapping = {
        'Low': 'Low',
        'Medium': 'Medium',
        'High': 'High'
    }

    # Mapping for attack types
    attack_type_mapping = {
        'Malware': 'Malicious',
        'DDoS': 'Scanning',
        'Intrusion': 'Data Exfiltration',
        'Phishing': 'Suspicious'
    }

    # Mapping for status
    status_mapping = {
        'Blocked': 'Blocked',
        'Logged': 'Allowed',
        'Ignored': 'Flagged'
    }

    # Geo-location mapping (for demonstration purposes)
    geo_locations = {
        'Jamshedpur': {'lat': 22.8046, 'lng': 86.2029, 'country': 'India'},
        'Bilaspur': {'lat': 22.0797, 'lng': 82.1409, 'country': 'India'},
        'Bokaro': {'lat': 23.6693, 'lng': 86.1511, 'country': 'India'},
        'Jaunpur': {'lat': 25.7464, 'lng': 82.6837, 'country': 'India'},
        'Anantapur': {'lat': 14.6819, 'lng': 77.6006, 'country': 'India'},
        'Aurangabad': {'lat': 19.8762, 'lng': 75.3433, 'country': 'India'},
        'Eluru': {'lat': 16.7107, 'lng': 81.0952, 'country': 'India'},
        'Phagwara': {'lat': 31.2240, 'lng': 75.7707, 'country': 'India'},
        'Ambala': {'lat': 30.3752, 'lng': 76.7821, 'country': 'India'},
        'Rampur': {'lat': 28.8086, 'lng': 79.0252, 'country': 'India'},
        'Gangtok': {'lat': 27.3389, 'lng': 88.6065, 'country': 'India'},
        'Nandyal': {'lat': 15.4777, 'lng': 78.4870, 'country': 'India'},
        'Silchar': {'lat': 24.8333, 'lng': 92.7789, 'country': 'India'}
    }

    try:
        with open(csv_path, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)

            # Process each row in the CSV
            for i, row in enumerate(reader):
                # Skip if we have enough data
                if i >= 50:  # Limit to 50 rows for performance
                    break

                # Extract location data
                location_parts = row.get('Geo-location Data', '').split(',')
                city = location_parts[0].strip() if location_parts else 'Unknown'

                # Get geo coordinates
                geo_data = geo_locations.get(city, {
                    'lat': random.uniform(10, 40),
                    'lng': random.uniform(70, 90),
                    'country': 'India'
                })

                # Process IP threat data
                if row.get('Source IP Address') and row.get('Attack Type'):
                    severity = severity_mapping.get(row.get('Severity Level', 'Low'), 'Low')
                    threat_type = attack_type_mapping.get(row.get('Attack Type', 'Malware'), 'Suspicious')

                    ip_threat = {
                        'id': str(len(ip_threats) + 1),
                        'ipAddress': row.get('Source IP Address', ''),
                        'type': threat_type,
                        'severity': severity,
                        'lastSeen': row.get('Timestamp', ''),
                        'count': int(float(row.get('Anomaly Scores', '0')) * 2) or random.randint(5, 50),
                        'description': row.get('Payload Data', 'No description available'),
                        'source': row.get('Log Source', 'Unknown'),
                        'location': {
                            'lat': geo_data['lat'],
                            'lng': geo_data['lng'],
                            'country': geo_data['country'],
                            'city': city
                        }
                    }
                    ip_threats.append(ip_threat)

                # Process traffic analysis data
                if row.get('Source IP Address') and row.get('Destination IP Address'):
                    status = status_mapping.get(row.get('Action Taken', 'Logged'), 'Allowed')

                    traffic_entry = {
                        'id': str(len(traffic_analysis) + 1),
                        'timestamp': row.get('Timestamp', ''),
                        'sourceIP': row.get('Source IP Address', ''),
                        'destinationIP': row.get('Destination IP Address', ''),
                        'protocol': row.get('Protocol', 'TCP'),
                        'port': int(row.get('Destination Port', '0')) or random.randint(1, 65535),
                        'bytesTransferred': int(row.get('Packet Length', '0')) * 10 or random.randint(256, 10240),
                        'packetsTransferred': random.randint(1, 32),
                        'duration': round(random.uniform(0.5, 10.0), 1),
                        'status': status
                    }
                    traffic_analysis.append(traffic_entry)

                # Process login attempts and suspicious behavior
                if row.get('User Information') and (
                    'authentication' in row.get('Payload Data', '').lower() or
                    'login' in row.get('Payload Data', '').lower() or
                    'access' in row.get('Payload Data', '').lower() or
                    'authorization' in row.get('Payload Data', '').lower() or
                    'suspicious' in row.get('Payload Data', '').lower() or
                    'unusual' in row.get('Payload Data', '').lower() or
                    int(float(row.get('Anomaly Scores', '0')) or 0) > 30
                ):
                    # Determine status based on action taken and anomaly score
                    anomaly_score = float(row.get('Anomaly Scores', '0') or 0)
                    status = 'Failed'
                    if row.get('Action Taken') == 'Blocked':
                        status = 'Blocked'
                    elif row.get('Action Taken') == 'Logged' and anomaly_score < 30:
                        status = 'Successful'

                    # Determine behavior type
                    behavior_type = 'Suspicious Login'
                    if 'authentication' in row.get('Payload Data', '').lower():
                        behavior_type = 'Authentication Attempt'
                    elif anomaly_score > 70:
                        behavior_type = 'Highly Suspicious Activity'
                    elif 'unusual' in row.get('Payload Data', '').lower():
                        behavior_type = 'Unusual Behavior'

                    login_entry = {
                        'id': str(len(login_attempts) + 1),
                        'timestamp': row.get('Timestamp', ''),
                        'username': row.get('User Information', 'Unknown User'),
                        'ipAddress': row.get('Source IP Address', ''),
                        'deviceInfo': row.get('Device Information', 'Unknown Device'),
                        'location': city + ', ' + geo_data['country'],
                        'status': status,
                        'behaviorType': behavior_type,
                        'anomalyScore': anomaly_score,
                        'description': row.get('Payload Data', 'No description available')[:100] + '...' if len(row.get('Payload Data', '')) > 100 else row.get('Payload Data', 'No description available')
                    }
                    login_attempts.append(login_entry)

        return ip_threats, traffic_analysis, login_attempts

    except Exception as e:
        print(f"Error processing CSV file: {e}")
        return [], [], []

# Try to read data from CSV, otherwise use sample data
csv_path = r"c:\Users\vamsh\Downloads\cybersecurity_attacks.csv"
ip_threats, traffic_analysis, login_attempts = [], [], []

if os.path.exists(csv_path):
    print(f"Reading data from CSV file: {csv_path}")
    ip_threats, traffic_analysis, login_attempts = process_cybersecurity_data(csv_path)
    print(f"Processed {len(ip_threats)} IP threats, {len(traffic_analysis)} traffic entries, and {len(login_attempts)} login attempts")

# If no data was loaded from CSV, use sample data
if not ip_threats:
    print("Using sample data instead")
    ip_threats = [
    {
        "id": "1",
        "ipAddress": "192.168.1.100",
        "type": "Malicious",
        "severity": "High",
        "lastSeen": "2025-04-26T10:15:00",
        "count": 42,
        "description": "This IP address has been observed attempting to exploit known vulnerabilities in web applications. Multiple failed login attempts and SQL injection attacks were detected.",
        "source": "Internal Threat Intelligence",
        "location": {
            "lat": 37.7749,
            "lng": -122.4194,
            "country": "United States",
            "city": "San Francisco"
        }
    },
    {
        "id": "2",
        "ipAddress": "10.0.0.15",
        "type": "Scanning",
        "severity": "Medium",
        "lastSeen": "2025-04-25T14:30:00",
        "count": 18,
        "description": "This IP has been detected performing port scanning activities across the network. The scanning pattern suggests reconnaissance for potential vulnerabilities.",
        "source": "Network IDS",
        "location": {
            "lat": 51.5074,
            "lng": -0.1278,
            "country": "United Kingdom",
            "city": "London"
        }
    },
    {
        "id": "3",
        "ipAddress": "172.16.0.5",
        "type": "Suspicious",
        "severity": "Low",
        "lastSeen": "2025-04-24T09:45:00",
        "count": 7,
        "description": "This IP has exhibited unusual traffic patterns that deviate from baseline behavior. While not clearly malicious, the activity warrants monitoring.",
        "source": "Behavioral Analysis",
        "location": {
            "lat": 35.6762,
            "lng": 139.6503,
            "country": "Japan",
            "city": "Tokyo"
        }
    },
    {
        "id": "4",
        "ipAddress": "203.0.113.42",
        "type": "Malicious",
        "severity": "High",
        "lastSeen": "2025-04-26T08:30:00",
        "count": 31,
        "description": "This IP has been identified as part of a botnet network. It has been observed participating in distributed denial-of-service (DDoS) attacks.",
        "source": "Threat Intelligence Feed",
        "location": {
            "lat": 55.7558,
            "lng": 37.6173,
            "country": "Russia",
            "city": "Moscow"
        }
    },
    {
        "id": "5",
        "ipAddress": "198.51.100.23",
        "type": "Suspicious",
        "severity": "Medium",
        "lastSeen": "2025-04-25T16:45:00",
        "count": 15,
        "description": "This IP has been observed attempting to access sensitive resources without proper authorization. Multiple authentication failures recorded.",
        "source": "Security Information and Event Management (SIEM)",
        "location": {
            "lat": 40.7128,
            "lng": -74.0060,
            "country": "United States",
            "city": "New York"
        }
    },
    {
        "id": "6",
        "ipAddress": "45.33.32.156",
        "type": "Malicious",
        "severity": "High",
        "lastSeen": "2025-04-26T12:10:00",
        "count": 53,
        "description": "This IP is associated with a known command and control (C2) server. Multiple connections to this IP have been observed from compromised systems within the network.",
        "source": "Threat Intelligence Platform",
        "location": {
            "lat": 52.5200,
            "lng": 13.4050,
            "country": "Germany",
            "city": "Berlin"
        }
    },
    {
        "id": "7",
        "ipAddress": "91.189.112.15",
        "type": "Scanning",
        "severity": "Medium",
        "lastSeen": "2025-04-25T22:30:00",
        "count": 27,
        "description": "This IP has been observed conducting extensive port scanning across the network infrastructure. The scanning pattern suggests automated vulnerability assessment tools.",
        "source": "Network Intrusion Detection System",
        "location": {
            "lat": 48.8566,
            "lng": 2.3522,
            "country": "France",
            "city": "Paris"
        }
    },
    {
        "id": "8",
        "ipAddress": "103.235.46.189",
        "type": "Malicious",
        "severity": "High",
        "lastSeen": "2025-04-26T09:15:00",
        "count": 38,
        "description": "This IP has been identified as hosting phishing infrastructure. Multiple spear-phishing emails containing links to this IP have been detected targeting organization employees.",
        "source": "Email Security Gateway",
        "location": {
            "lat": 22.3193,
            "lng": 114.1694,
            "country": "Hong Kong",
            "city": "Hong Kong"
        }
    },
    {
        "id": "9",
        "ipAddress": "185.156.73.54",
        "type": "Suspicious",
        "severity": "Low",
        "lastSeen": "2025-04-24T14:20:00",
        "count": 9,
        "description": "This IP has been observed making unusual API calls to cloud services. While not clearly malicious, the pattern of access deviates from normal behavior.",
        "source": "Cloud Security Monitoring",
        "location": {
            "lat": 59.3293,
            "lng": 18.0686,
            "country": "Sweden",
            "city": "Stockholm"
        }
    },
    {
        "id": "10",
        "ipAddress": "77.88.55.66",
        "type": "Data Exfiltration",
        "severity": "High",
        "lastSeen": "2025-04-26T11:05:00",
        "count": 47,
        "description": "This IP has been observed receiving large data transfers from internal systems during non-business hours. The volume and timing of transfers suggest potential data exfiltration activity.",
        "source": "Data Loss Prevention System",
        "location": {
            "lat": 41.9028,
            "lng": 12.4964,
            "country": "Italy",
            "city": "Rome"
        }
    }
]

if not traffic_analysis:
    print("Using sample traffic data instead")
    traffic_analysis = [
    {
        "id": "1",
        "timestamp": "2025-04-26T10:15:00",
        "sourceIP": "192.168.1.100",
        "destinationIP": "10.0.0.5",
        "protocol": "TCP",
        "port": 443,
        "bytesTransferred": 1245,
        "packetsTransferred": 8,
        "duration": 2.5,
        "status": "Blocked"
    },
    {
        "id": "2",
        "timestamp": "2025-04-26T10:12:00",
        "sourceIP": "172.16.0.5",
        "destinationIP": "10.0.0.10",
        "protocol": "UDP",
        "port": 53,
        "bytesTransferred": 512,
        "packetsTransferred": 4,
        "duration": 1.2,
        "status": "Flagged"
    },
    {
        "id": "3",
        "timestamp": "2025-04-26T10:10:00",
        "sourceIP": "10.0.0.15",
        "destinationIP": "10.0.0.1",
        "protocol": "TCP",
        "port": 80,
        "bytesTransferred": 8192,
        "packetsTransferred": 12,
        "duration": 3.7,
        "status": "Allowed"
    },
    {
        "id": "4",
        "timestamp": "2025-04-26T10:05:00",
        "sourceIP": "192.168.1.5",
        "destinationIP": "10.0.0.2",
        "protocol": "TCP",
        "port": 22,
        "bytesTransferred": 4096,
        "packetsTransferred": 16,
        "duration": 5.1,
        "status": "Allowed"
    },
    {
        "id": "5",
        "timestamp": "2025-04-26T10:01:00",
        "sourceIP": "192.168.1.100",
        "destinationIP": "10.0.0.5",
        "protocol": "TCP",
        "port": 3389,
        "bytesTransferred": 2048,
        "packetsTransferred": 6,
        "duration": 1.8,
        "status": "Blocked"
    },
    {
        "id": "6",
        "timestamp": "2025-04-26T09:58:00",
        "sourceIP": "10.0.0.15",
        "destinationIP": "172.16.0.1",
        "protocol": "UDP",
        "port": 123,
        "bytesTransferred": 256,
        "packetsTransferred": 2,
        "duration": 0.5,
        "status": "Allowed"
    },
    {
        "id": "7",
        "timestamp": "2025-04-26T09:45:00",
        "sourceIP": "103.235.46.189",
        "destinationIP": "10.0.0.25",
        "protocol": "TCP",
        "port": 25,
        "bytesTransferred": 15360,
        "packetsTransferred": 28,
        "duration": 4.2,
        "status": "Blocked"
    },
    {
        "id": "8",
        "timestamp": "2025-04-26T09:42:00",
        "sourceIP": "10.0.0.42",
        "destinationIP": "45.33.32.156",
        "protocol": "TCP",
        "port": 8080,
        "bytesTransferred": 32768,
        "packetsTransferred": 64,
        "duration": 8.5,
        "status": "Flagged"
    },
    {
        "id": "9",
        "timestamp": "2025-04-26T09:38:00",
        "sourceIP": "10.0.0.15",
        "destinationIP": "8.8.8.8",
        "protocol": "UDP",
        "port": 53,
        "bytesTransferred": 512,
        "packetsTransferred": 4,
        "duration": 0.8,
        "status": "Allowed"
    },
    {
        "id": "10",
        "timestamp": "2025-04-26T09:35:00",
        "sourceIP": "77.88.55.66",
        "destinationIP": "10.0.0.50",
        "protocol": "TCP",
        "port": 445,
        "bytesTransferred": 4096,
        "packetsTransferred": 12,
        "duration": 2.3,
        "status": "Blocked"
    },
    {
        "id": "11",
        "timestamp": "2025-04-26T09:30:00",
        "sourceIP": "10.0.0.30",
        "destinationIP": "91.189.112.15",
        "protocol": "TCP",
        "port": 443,
        "bytesTransferred": 8192,
        "packetsTransferred": 16,
        "duration": 3.1,
        "status": "Flagged"
    },
    {
        "id": "12",
        "timestamp": "2025-04-26T09:25:00",
        "sourceIP": "10.0.0.22",
        "destinationIP": "10.0.0.1",
        "protocol": "TCP",
        "port": 3306,
        "bytesTransferred": 65536,
        "packetsTransferred": 128,
        "duration": 12.5,
        "status": "Allowed"
    },
    {
        "id": "13",
        "timestamp": "2025-04-26T09:20:00",
        "sourceIP": "185.156.73.54",
        "destinationIP": "10.0.0.35",
        "protocol": "TCP",
        "port": 21,
        "bytesTransferred": 16384,
        "packetsTransferred": 32,
        "duration": 6.7,
        "status": "Blocked"
    },
    {
        "id": "14",
        "timestamp": "2025-04-26T09:15:00",
        "sourceIP": "10.0.0.40",
        "destinationIP": "10.0.0.5",
        "protocol": "TCP",
        "port": 1433,
        "bytesTransferred": 131072,
        "packetsTransferred": 256,
        "duration": 18.3,
        "status": "Allowed"
    }
]

if not login_attempts:
    print("Using sample login attempts data instead")
    login_attempts = [
        {
            "id": "1",
            "timestamp": "2025-04-26T08:15:32",
            "username": "admin.user",
            "ipAddress": "192.168.1.100",
            "deviceInfo": "Windows 10 / Chrome 98.0.4758",
            "location": "San Francisco, United States",
            "status": "Failed",
            "behaviorType": "Suspicious Login",
            "anomalyScore": 78.5,
            "description": "Multiple failed login attempts from unusual location. Possible brute force attack detected."
        },
        {
            "id": "2",
            "timestamp": "2025-04-26T09:23:15",
            "username": "john.smith",
            "ipAddress": "10.0.0.15",
            "deviceInfo": "macOS 12.3 / Safari 15.4",
            "location": "London, United Kingdom",
            "status": "Successful",
            "behaviorType": "Authentication Attempt",
            "anomalyScore": 12.3,
            "description": "Successful login after password reset. User authenticated from known device and location."
        },
        {
            "id": "3",
            "timestamp": "2025-04-26T10:45:08",
            "username": "system.admin",
            "ipAddress": "203.0.113.42",
            "deviceInfo": "Linux / Firefox 97.0",
            "location": "Moscow, Russia",
            "status": "Blocked",
            "behaviorType": "Highly Suspicious Activity",
            "anomalyScore": 92.7,
            "description": "Attempted privilege escalation after login. Multiple sensitive file access attempts detected."
        },
        {
            "id": "4",
            "timestamp": "2025-04-26T11:12:45",
            "username": "guest.user",
            "ipAddress": "172.16.0.5",
            "deviceInfo": "Android 12 / Chrome Mobile 98.0.4758",
            "location": "Tokyo, Japan",
            "status": "Successful",
            "behaviorType": "Authentication Attempt",
            "anomalyScore": 5.2,
            "description": "Standard login from mobile device. No unusual behavior detected."
        },
        {
            "id": "5",
            "timestamp": "2025-04-26T12:37:22",
            "username": "jane.doe",
            "ipAddress": "198.51.100.23",
            "deviceInfo": "Windows 11 / Edge 99.0.1150",
            "location": "New York, United States",
            "status": "Failed",
            "behaviorType": "Unusual Behavior",
            "anomalyScore": 65.8,
            "description": "Login attempted outside normal working hours. User attempting to access restricted resources."
        }
    ]

# Save sample data to JSON files
ip_threats_file = os.path.join(data_dir, 'ip_threats.json')
traffic_file = os.path.join(data_dir, 'traffic_analysis.json')
login_file = os.path.join(data_dir, 'login_attempts.json')

with open(ip_threats_file, 'w') as f:
    json.dump(ip_threats, f, indent=2)
    print(f"Saved IP threats data to {ip_threats_file}")

with open(traffic_file, 'w') as f:
    json.dump(traffic_analysis, f, indent=2)
    print(f"Saved traffic analysis data to {traffic_file}")

with open(login_file, 'w') as f:
    json.dump(login_attempts, f, indent=2)
    print(f"Saved login attempts data to {login_file}")

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/test')
def test():
    return "Flask is working!"

@app.route('/simple')
def simple():
    return render_template('simple.html')

@app.route('/api/threats')
def get_threats():
    return jsonify(ip_threats)

@app.route('/api/traffic')
def get_traffic():
    return jsonify(traffic_analysis)

@app.route('/api/threat/<threat_id>')
def get_threat_details(threat_id):
    for threat in ip_threats:
        if threat['id'] == threat_id:
            return jsonify(threat)
    return jsonify({"error": "Threat not found"}), 404

@app.route('/api/login-attempts')
def get_login_attempts():
    return jsonify(login_attempts)

@app.errorhandler(404)
def page_not_found(e):
    return f"404 Error: Page not found. {str(e)}", 404

@app.errorhandler(500)
def internal_server_error(e):
    return f"500 Error: Internal server error. {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
