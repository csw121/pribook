from datetime import datetime,timezone
from uuid import uuid4
from . import __version__
from .common import digest
from .validation import validate
from .evidence_validator import referenced,classify

def facts(log):
    out = {k:log[k] for k in ('method','path','status','target_id')}
    for i,(key,value) in enumerate(log['query']):
        out[f'query/{i}/name']=key
        out[f'query/{i}/value']=value
    def walk(value,pointer):
        if isinstance(value,dict):
            for key,v in value.items():
                walk(v,pointer+'/'+key.replace('~','~0').replace('/','~1'))
        elif isinstance(value,list):
            for i,v in enumerate(value):
                walk(v,pointer+'/'+str(i))
        else:
            out['body'+pointer]=value
    walk(log['body'],'')
    return out

def verify(evidence,manifest,analysis):
    for data,name in ((evidence,'evidence'),(manifest,'manifest'),(analysis,'analysis')):
        validate(data,name)
    logs={l['id']:l for l in evidence['logs']}
    candidates={c['id']:c for c in manifest['candidates']}
    issues=[];passed=0;decisions={};seen=set()
    def issue(code,index=None):
        issues.append({'code':code,'candidate_index':index})
    if len(logs)!=len(evidence['logs']):issue('DUPLICATE_LOG_ID')
    if len(candidates)!=len(manifest['candidates']):issue('DUPLICATE_CANDIDATE_ID')
    for index,finding in enumerate(analysis['findings']):
        cid=finding['id']
        if cid in seen:issue('DUPLICATE_CANDIDATE',index)
        seen.add(cid)
        if cid not in candidates:
            issue('UNEXPECTED_CANDIDATE',index);continue
        c=candidates[cid];ids=referenced(c)
        if set(finding['evidence_ids'])!=set(ids):issue('EVIDENCE_COVERAGE',index)
        if any(i not in logs for i in ids):
            issue('UNKNOWN_LOG',index);continue
        decision=classify(c,logs,manifest['policy']);decisions[cid]=decision
        if finding['classification']!=decision['classification']:issue('CLASSIFICATION_MISMATCH',index)
        if decision['classification'] in ('unknown','suspicious'):issue('HUMAN_REVIEW',index)
        required={(lid,field) for lid in ids for field in facts(logs[lid])}
        checked=set()
        for claim in finding['claims']:
            lid,field,value=claim['log_id'],claim['field'],claim['value'];key=(lid,field)
            if key in checked:issue('DUPLICATE_CLAIM',index)
            checked.add(key)
            if lid not in ids or lid not in logs:
                issue('UNEXPECTED_LOG',index);continue
            original=facts(logs[lid])
            if field not in original:
                issue('UNSUPPORTED_OR_ABSENT_FIELD',index);continue
            expected=original[field]
            if type(expected) is not type(value):issue('CLAIM_TYPE_MISMATCH',index)
            elif value!=expected:issue('CLAIM_VALUE_MISMATCH',index)
            else:passed+=1
        if required-checked:issue('CLAIM_COVERAGE',index)
    if set(candidates)-seen:issue('MISSING_CANDIDATE')
    return {'schema_version':'1.0','engine_version':__version__,'run_id':str(uuid4()),
            'created_at':datetime.now(timezone.utc).isoformat(),
            'input_hash':digest({'engine':__version__,'evidence':evidence,'manifest':manifest,'analysis':analysis}),
            'passed_checks':passed,'review_count':len(issues),'status':'blocked' if issues else 'passed',
            'human_review_required':True,'issues':issues,'decisions':decisions}
