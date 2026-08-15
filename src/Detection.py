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
        
        elif "powershell.exe" and ("invoke-webrequest" or "iwr") in LogEvent.command_line.lower():
            alert=Alerts(
                title="Suspicious File Download Attempt Detected",
                severity="High",
                description=f"Detected a suspicious file download attempt using Invoke-WebRequest Command: {LogEvent.command_line}",
                mitre_technique="T1105",
                confidence=80
            )
        elif "certutil.exe" and (".exe" or ".dll") in LogEvent.command_line.lower():
            alert=Alerts(
                title="Susipcious File Download Attempt Detected",
                severity="High",
                description=f"Detected a suspicious file downloaded using certutil.exe: {LogEvent.command_line}",
                mitre_technique="T1105",
                confidence=70                
            )
            self.alerts.append()
        return self.alerts