from collections import defaultdict
import datetime as dt
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parser import *
import re

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

def directory_scan_detector(logs:list,window_seconds:int,treshold:int):
    alertList = []
    d = defaultdict(list)
    suspicious_logs = [l for l in logs if l.status == 404]
    for log in suspicious_logs:
        d[log.ip].append(log)
    for ip in d:
        timeList = []
        for log in d[ip]:
            timeList.append((log.timestamp,log))
        timeList.sort(key=lambda x: x[0])
        for i, ts in enumerate(timeList):
            window = [l for l in timeList[i:] if (l[0] - ts[0]).total_seconds() <= window_seconds]
            unique_paths = len(set(log[1].request for log in window))
            if unique_paths >=treshold and len(window) >=treshold:
                if (len(window) >= 20):
                    severity = "HIGH"
                elif len(window) >= 10:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
                alertList.append(Alert("directory_scan",severity,ip,f"Directory scan by {ip} with {len(window)} requests",d[ip]))
                break
    return alertList

SQL_PATTERNS = [
    (re.compile(r"union[\s\+%20]+select", re.IGNORECASE), "HIGH"),
    (re.compile(r"'\s*(or|and)\s*'?\d+'?\s*=\s*'?\d+", re.IGNORECASE), "HIGH"),
    (re.compile(r"(sleep|benchmark|waitfor\s+delay)\s*\(", re.IGNORECASE), "HIGH"),
    (re.compile(r";\s*(drop|insert|update|delete)\s+", re.IGNORECASE), "HIGH"),
    (re.compile(r"(--|#|/\*)", re.IGNORECASE), "LOW"),
    (re.compile(r"xp_cmdshell", re.IGNORECASE), "HIGH"),
]

def sql_injection_detector(logs:list):
    alertList = []
    for log in logs:
        for pattern in SQL_PATTERNS:
            m = pattern[0].search(log.request)
            if not m:
                continue
            else:
                alertList.append(Alert("sql_injection",pattern[1],log.ip,f"SQL injection attack by {log.ip}",[log]))
                break
    return alertList

def main_detector(logs:list):
    alertList = brute_force_detector(logs,15,5)
    alertList += user_agent_detector(logs)
    alertList += directory_scan_detector(logs,15,5)
    alertList += sql_injection_detector(logs)
    return alertList