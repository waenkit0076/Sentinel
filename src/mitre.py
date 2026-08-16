from src.models import MITRE

MITRE_Techniques={
    "T1059_1":MITRE(
        id = "T1059.001",
        technique = "Command and Scripting Interpreter: Powershell",
        tactic = "Execution",
    ),
    
    "T1024_2":MITRE(
        id="T1024.002",
        technique= "User Execution: Malicious File",
        tactic= "Execution"
    ),
    
    "T1024_3":MITRE(
        id="T1204.003",
        technique="User Execution: Malicious Image",
        tactic="Execution"
    ),
}
print(MITRE_Techniques["T1059_1"])