import re

class LogEntry:
    ip:str
    rfc:str
    user:str
    timestamp:str
    request:str
    status:str
    response_size:str

    def __init__(self, ip:str, rfc:str, user:str, timestamp:str, request:str, status:str, response_size:str):
        self.ip = ip
        self.rfc = rfc
        self.user = user
        self.timestamp = timestamp
        self.request = request
        self.status = status
        self.response_size = response_size

pattern = re.compile(r'(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]+)" (\d{3}) (\d+|-)')

def parse_line(line:str):
    m = pattern.match(line)
    if not m:
        raise ValueError("Invalid log line format")
    lg = LogEntry(
        ip = m.group(1),
        rfc = m.group(2),
        user = m.group(3),
        timestamp = m.group(4),
        request = m.group(5),
        status = m.group(6),
        response_size = m.group(7)
    )
    return lg

def parse_file(path:str):
    f = open(path,'r')
    try:
        lines = f.readlines()
    except:
        raise ValueError("Error file format")
    return 0

line = '127.0.0.1 ident alice [01/May/2025:07:20:10 +0000] "GET /index.html HTTP/1.1" 200 9481'
log_entry = parse_line(line)
print(log_entry.ip)  # Output: 127.0.0.1
print(log_entry.rfc)  # Output: ident
print(log_entry.user)  # Output: alice
print(log_entry.timestamp)  # Output: 01/May/2025:07:20:10 +0000
print(log_entry.request)  # Output: GET /index.html HTTP/1.1
print(log_entry.status)  # Output: 200
print(log_entry.response_size)  # Output: 9481