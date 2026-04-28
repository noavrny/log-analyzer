import re
import datetime

class LogEntry:
    ip:str
    rfc:str
    user:str
    timestamp:datetime
    request:str
    status:int
    response_size:int
    referrer:str
    user_agent:str

    def __init__(self, ip:str, rfc:str, user:str, timestamp:datetime, request:str, status:int, response_size:int, referrer:str=None, user_agent:str=None):
        self.ip = ip
        self.rfc = rfc
        self.user = user
        self.timestamp = timestamp
        self.request = request
        self.status = status
        self.response_size = response_size
        self.referrer=referrer
        self.user_agent = user_agent
    

pattern = re.compile(r'(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]+)" (\d{3}) (\d+|-)(?:\s+"([^"]*)" "([^"]*)")?')
formatDate = "%d/%b/%Y:%H:%M:%S %z"

def parse_line(line:str):
    m = pattern.match(line)
    if not m:
        raise ValueError("Invalid log line format")
    lg = LogEntry(
        ip = m.group(1),
        rfc = m.group(2),
        user = m.group(3),
        timestamp = datetime.datetime.strptime(m.group(4),formatDate),
        request = m.group(5),
        status = int(m.group(6)),
        response_size = int(m.group(7)) if m.group(7) != '-' else 0,
        referrer = m.group(8),
        user_agent = m.group(9)
    )
    return lg

def parse_file(path:str, skip_invalid:bool = False):
    res = []
    try:
        f = open(path, 'r')
    except OSError:
        raise OSError(f"Can't open file {path}")

    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                res.append(parse_line(line))
            except ValueError:
                if not skip_invalid:
                    raise ValueError(f"Invalid line format in {path}: {line!r}")
    return res

line1 = '127.0.0.1 ident alice [01/May/2025:07:20:10 +0000] "GET /index.html HTTP/1.1" 200 9481'
log_entry = parse_line(line1)
print(log_entry.ip)  # Output: 127.0.0.1
print(log_entry.rfc)  # Output: ident
print(log_entry.user)  # Output: alice
print(log_entry.timestamp)  # Output: 01/May/2025:07:20:10 +0000
print(log_entry.request)  # Output: GET /index.html HTTP/1.1
print(log_entry.status)  # Output: 200
print(log_entry.response_size)  # Output: 9481

line2 = '104.196.220.12 - - [01/May/2025:09:00:00 +0000] "GET /index.html HTTP/1.1" 200 9481 "-" "sqlmap/1.7.8#stable (https://sqlmap.org)"'
log_entry = parse_line(line2)
print(log_entry.ip)  # Output: 104.196.220.12
print(log_entry.rfc)  # Output: -
print(log_entry.user)  # Output: -
print(log_entry.timestamp)  # Output: 01/May/2025:09:00:00 +0000
print(log_entry.request)  # Output: GET /index.html HTTP/1.1
print(log_entry.status)  # Output: 200
print(log_entry.response_size)  # Output: 9481
print(log_entry.referrer)  # Output: -
print(log_entry.user_agent)  # Output: sqlmap/1.7.8#stable (https://sqlmap.org)

entries = parse_file("samples/test.log", skip_invalid=True)
print(f"{len(entries)} entrées parsées")