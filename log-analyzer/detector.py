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
                alertList.append(Alert("brute_force",severity,ip,f"Brute-force attack by {ip} with {len(window)} requests | SEVERITY : {severity}",d[ip]))
                break
    return alertList

KNOWN_SUSPICIOUS_UA = ["sqlmap", "nikto", "masscan", "nmap", "burpsuite", "zgrab", "nuclei", "dirbuster"]

def user_agent_detector(logs:list):
    alertList = []
    ua_logs = [l for l in logs if l.user_agent != None]
    for log in ua_logs:
        ua = log.user_agent.lower()
        for tool in KNOWN_SUSPICIOUS_UA:
            if tool in ua:
                alertList.append(Alert("user_agent","LOW",log.ip,f"User-agent reconnaissance attack by {log.ip} using {ua}",[log]))
                break
    return alertList

logs = parse_file("samples/test.log",1)
alertlist = brute_force_detector(logs,15,5)
alertlist = alertlist + user_agent_detector(logs)
for a in alertlist:
    print(a.description)