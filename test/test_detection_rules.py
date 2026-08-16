import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.models import LogEvent, Alerts
from src.Parser import SysmonParser
from src.Detection import DetectionEngine
from src.mitre import mitre

parser=SysmonParser()
logs=parser.load("data/sample.json")
events=parser.parse_logs(logs)

det=DetectionEngine()
for event in events:
    Alert=det.detect(event)
    if Alert!=None:
        Mitre=mitre(Alert)
        if Mitre !=None:
            print(Mitre)
        else:
            print("MITRE Mapping Unavailable")
    else:
        print("Not an Issue")
        
    

