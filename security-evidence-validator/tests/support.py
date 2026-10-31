from pathlib import Path
from sev.common import read_json
from sev.http_parser import analyze_directory
from sev.evidence_validator import classify,referenced
from sev.ai_result_validator import facts
ROOT=Path(__file__).resolve().parents[1]

def analysis_for(e,m):
    logs={l['id']:l for l in e['logs']};findings=[]
    for c in m['candidates']:
        ids=referenced(c)
        findings.append({'id':c['id'],'evidence_ids':ids,'classification':classify(c,logs,m['policy'])['classification'],
                         'claims':[{'log_id':lid,'field':f,'value':v} for lid in ids for f,v in facts(logs[lid]).items()]})
    return {'schema_version':'1.0','findings':findings}

def fixture():
    e=analyze_directory(ROOT/'examples/synthetic_http_logs');m=read_json(ROOT/'config/validation_rules.json')
    return e,m,analysis_for(e,m)
