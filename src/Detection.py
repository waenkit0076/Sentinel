from src.models import LogEvent, Alerts

class DetectionEngine:
    def __init__(self):
        self.alerts = []
    def detect(self, LogEvent):
        command = LogEvent.command_line.lower()

        if "powershell.exe" in command and "-encodedcommand" in command:
             alert = Alerts(
            title="Suspicious PowerShell Command Detected",
            severity="High",
            description=f"Detected a suspicious obfuscated PowerShell command: {LogEvent.command_line}",
            mitre_technique="T1059.001",
            confidence=70
            )

        elif "powershell.exe" in command and (
             "invoke-webrequest" in command or "iwr" in command
            ):
             alert = Alerts(
            title="Suspicious File Download Attempt Detected",
            severity="High",
            description=f"Detected a suspicious file download attempt using PowerShell: {LogEvent.command_line}",
            mitre_technique="T1105",
            confidence=80
            )

        elif "certutil.exe" in command and (
            ".exe" in command or ".dll" in command
             ):
            alert = Alerts(
            title="Suspicious File Download Attempt Detected",
            severity="High",
            description=f"Detected a suspicious file downloaded using certutil.exe: {LogEvent.command_line}",
            mitre_technique="T1105",
            confidence=70
            )

        else:
            return None

        self.alerts.append(alert)
        return alert