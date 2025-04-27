from flask import Flask, render_template, jsonify
import json
import os

app = Flask(__name__)

# Create necessary directories if they don't exist
data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
os.makedirs(data_dir, exist_ok=True)
os.makedirs('templates', exist_ok=True)
os.makedirs('static', exist_ok=True)
print(f"Data directory created at: {data_dir}")

# Sample data
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
    }
]

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
    }
]

# Save sample data to JSON files
ip_threats_file = os.path.join(data_dir, 'ip_threats.json')
traffic_file = os.path.join(data_dir, 'traffic_analysis.json')

with open(ip_threats_file, 'w') as f:
    json.dump(ip_threats, f, indent=2)
    print(f"Saved IP threats data to {ip_threats_file}")

with open(traffic_file, 'w') as f:
    json.dump(traffic_analysis, f, indent=2)
    print(f"Saved traffic analysis data to {traffic_file}")

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

@app.errorhandler(404)
def page_not_found(e):
    return f"404 Error: Page not found. {str(e)}", 404

@app.errorhandler(500)
def internal_server_error(e):
    return f"500 Error: Internal server error. {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
