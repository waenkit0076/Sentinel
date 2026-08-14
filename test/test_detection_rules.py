import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.models import LogEvent, Alerts
from src.Parser import SysmonParser
from src.Detection import DetectionEngine

parser=SysmonParser()
logs=parser.load("data/sample.json")
events=parser.parse_logs(logs)

det=DetectionEngine()
Alert=det.detect(events[0])
print(Alert)

