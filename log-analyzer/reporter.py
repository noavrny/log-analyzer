from jinja2 import Environment, FileSystemLoader
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
env = Environment(loader=FileSystemLoader(os.path.join(BASE_DIR, "../templates/")))

def generate_reports(alerts:list,output_path:str):
    template = env.get_template("report.html")
    html = template.render(alerts=alerts, total=len(alerts))
    try:
        with(open(output_path,'w') as f):
            f.write(html)
    except OSError as e:
        raise OSError(f"Cannot write report to {output_path}: {e}")