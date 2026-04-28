from collections import defaultdict
import datetime as dt
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parser import *

class Alert:
    type:str
    severity:str
    ip:str
    description:str
    logs:list

    def __init__(self,type:str,severity:str,ip:str,description:str,logs:list):
        self.type = type
        self.severity = severity
        self.ip = ip
        self.description = description
        self.logs = logs


formatDate = "%d/%b/%Y:%H:%M:%S %z"

def brute_force_detector(logs:list,window_seconds :int,treshold:int):
    d = defaultdict(list)
    failed_logs = [l for l in logs if l.status in (401, 403)]
    alertList = []
    for log in failed_logs:
        d[log.ip].append(log)
    for ip in d:
        timeList = []
        for log in d[ip]:
            timeList.append(log.timestamp)
        timeList.sort()
        for i, ts in enumerate(timeList):
            window = [t for t in timeList[i:] if (t - ts).total_seconds() <= window_seconds]
            if len(window) >=treshold:
                if (len(window) >= 20):
                    severity = "HIGH"
                elif len(window) >= 10:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
                alertList.append(Alert("brute_force",severity,ip,f"Brute-force attack by {ip} with {len(window)} requests",d[ip]))
                break
    return alertList

logs = parse_file("samples/test.log",1)
alertlist = brute_force_detector(logs,15,5)
print(len(alertlist))
for a in alertlist:
    print(a.description)