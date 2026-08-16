from src.models import MITRE
from src.Detection import DetectionEngine

MITRE_Techniques={
    "T1059.001":MITRE(
        id = "T1059.001",
        technique = "Command and Scripting Interpreter: Powershell",
        tactic = "Execution"
    ),
    
    "T1024.002":MITRE(
        id="T1024.002",
        technique= "User Execution: Malicious File",
        tactic= "Execution"
    ),
    
    "T1024.003":MITRE(
        id="T1204.003",
        technique="User Execution: Malicious Image",
        tactic="Execution"
    ),
}

def mitre(alert):
    try:
        x=MITRE_Techniques[alert.mitre_technique]
    except KeyError:
        x=None
    return x

        
    
