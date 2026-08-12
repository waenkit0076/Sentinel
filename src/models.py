import dataclasses

@dataclasses.dataclass
class LogEvent:
    timestamp:str
    event_id:int
    hostname:str
    user:str
    process_name:str
    command_line:str
    process_id:int
    parent_process_id:int
    parent_process:str