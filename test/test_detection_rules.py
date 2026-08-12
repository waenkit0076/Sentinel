from src.models import LogEvent, Alerts
from src.Parser import SysmonParser
from src.Detection import DetectionEngine

parser=SysmonParser()
logs=parser.load("data/sample.json")
events=parser.parse_logs(logs)

det=DetectionEngine()
Alert=det.detect(events)
print(Alert)
