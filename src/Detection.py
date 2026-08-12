from models import LogEvent, Alerts

class DetectionEngine:
    def __init__(self):
        self.alerts = []

    def detect(self, LogEvent):
        # Example detection logic
        if "-encodedcommand" in LogEvent.command_line.lower():
            alert = Alerts(
                title="Suspicious PowerShell Command Detected",
                severity="High",
                description=f"Detected a suspicious Obfuscated PowerShell command: {LogEvent.command_line}",
                event=LogEvent,
                mitre_technique="T1059.001",
                confidence=70
            )
            self.alerts.append(alert)

Detect=DetectionEngine()
Alert=Detect.detect(LogEvent)
print(Alert)