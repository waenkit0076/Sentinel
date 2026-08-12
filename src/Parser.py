import json
from models import LogEvent


class SysmonParser:

    def load(self,address):
        try:
            with open(address) as file:
                x=json.load(file)
            return x
        except FileNotFoundError:
            print(f"File not found: {address}")
            return []
        except json.JSONDecodeError:
            print(f"Error decoding JSON from file: {address}")
            return []
        except Exception as e:
            print(f"Error loading file {address}: {e}")
            return []

    def parse_event(self, event):
        timestamp=event.get("UtcTime") #we are using get function instead of acessing dictionary to avoid error incase of the value not available
        event_id=event.get("EventID")
        host_name=event.get("Computer")
        user=event.get("User")
        process_name=event.get("Image")
        command_line=event.get("CommandLine")
        process_id=event.get("ProcessId")
        parent_process_id=event.get("ParentProcessId")
        destination_ip=event.get("DestinationIp")
        destination_port=event.get("DestinationPort")
        parent_process=event.get("ParentImage")
        return LogEvent(
                    timestamp=timestamp,
                    event_id=event_id,
                    hostname=host_name,
                    user=user,
                    process_name=process_name,
                    command_line=command_line,
                    process_id=process_id,
                    parent_process_id=parent_process_id,
                    parent_process=parent_process                    
                    )
    def parse_logs(self, events):
        parse_events=[]
        for event in events:
            parse_events.append(self.parse_event(event))
        return parse_events

parser=SysmonParser()
events=parser.load("data/sample.json")
ok=parser.parse_logs(events)
print(ok)

        
