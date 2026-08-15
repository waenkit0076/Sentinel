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
        if "powershell.exe" and "invoke-webrequest" or "iwr" in LogEvent.commandline.lower():
            alert=Alerts(
                title="Suspicious File Download Attempt Detected",
                severity="High",
                description=f"Detected a suspicious file download attempt using Invoke-WebRequest Command: {LogEvent.command_line}",
                mitre_technique="T1105"
                confidence=80
            )
            self.alerts.append(alert)
        if "certutil.exe" and ".exe" or ".dll" in LogEvent.command_line.lower():
            alert=Alerts(
                title=""                
            )
        return self.alerts