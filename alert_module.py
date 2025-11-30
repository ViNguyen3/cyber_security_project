import json
import datetime

class AlertModule:
    def __init__(self, log_file="alerts.log", json_file="alerts.json"):
        self.log_file = log_file
        self.json_file = json_file

        try:
            with open(self.json_file, "r") as f:
                pass
        except FileNotFoundError:
            with open(self.json_file, "w") as f:
                json.dump([], f, indent=4)

    def determine_severity(self, attack_type):
        severity_map = {

            # UNSW-NB15
            "Fuzzers": "Medium",
            "Analysis": "Medium",
            "Backdoor": "High",
            "DoS": "High",
            "Exploits": "High",
            "Generic": "Critical",
            "Reconnaissance": "Medium",
            "Shellcode": "Critical",
            "Worms": "Critical",

            # CICIDS-2017
            "DoS slowloris": "High",
            "DoS SlowHTTPTest": "High",
            "DoS Hulk": "High",
            "DoS GoldenEye": "High",
            "DDoS": "Critical",
            "FTP-Patator": "Medium",
            "SSH-Patator": "Medium",
            "Web Attack: XSS": "Medium",
            "Web Attack: SQL Injection": "High",
            "Web Attack: Brute Force": "Medium",
            "Infiltration": "High",
            "Bot": "Critical",
            "PortScan": "Medium",
            "Heartbleed": "Critical"
        }

        return severity_map.get(attack_type, "Unknown")

    def generate_alert(self, detection):

        if detection["prediction"] != "attack":
            return None

        alert = {
            "alert_id": f"ALERT-{int(datetime.datetime.now().timestamp())}",
            "timestamp": str(datetime.datetime.now()),

            "packet_id": detection.get("packet_id"),
            "src_ip": detection.get("src_ip"),
            "dst_ip": detection.get("dst_ip"),
            "protocol": detection.get("protocol", "N/A"),

            "attack_type": detection.get("attack_type", "Unknown"),
            "confidence": detection.get("confidence", 0.0),
            "severity": self.determine_severity(detection.get("attack_type")),
        }

        self.log_alert(alert)
        self.save_json(alert)
        self.print_alert(alert)

        return alert

    def print_alert(self, alert):
        print("\n MALICIOUS TRAFFIC DETECTED ")
        print("--------------------------------")
        for key, value in alert.items():
            print(f"{key}: {value}")
        print("--------------------------------\n")

    def log_alert(self, alert):
        with open(self.log_file, "a") as f:
            f.write(json.dumps(alert) + "\n")

    def save_json(self, alert):
        with open(self.json_file, "r") as f:
            alerts = json.load(f)

        alerts.append(alert)

        with open(self.json_file, "w") as f:
            json.dump(alerts, f, indent=4)
