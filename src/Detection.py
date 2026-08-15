from src.models import LogEvent, Alerts

class DetectionEngine:
    def __init__(self):
        self.alerts = []

    def detect(self, LogEvent):
        # Example detection logic
        if "-EncodedCommand" in LogEvent.command_line:
            alert = Alerts(
                title="Suspicious PowerShell Command Detected",
                severity="High",
                description=f"Detected a suspicious Obfuscated PowerShell command: {LogEvent.command_line}",
                mitre_technique="T1059.001",
                confidence=70
            )
            self.alerts.append(alert)
        return self.alerts