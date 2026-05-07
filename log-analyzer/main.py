from parser import parse_file
from detector import main_detector
from reporter import generate_reports
import sys

if len(sys.argv) < 2:
    print("Usage: python main.py <path_to_logfile>")
    sys.exit(1)
if not sys.argv[1]:
    raise OSError("Missing logs file path or path incorrect")
else:
    logs = parse_file(sys.argv[1],True)
    print(str(len(logs)) + " entrées parsées")
    alertList = main_detector(logs)
    generate_reports(alertList,"reports/report.html")