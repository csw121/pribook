import re
from urllib.parse import unquote

def result(classification, code):
    return {'classification': classification, 'code': code}

def referenced(c):
    keys = ('requester_identity','owner_identity','owner_access','access') if c['kind']=='idor' else ('suspicious','baseline')
    return sorted(set(c[k] for k in keys))

def body_value(log, field):
    value = log['body']
    if not field.startswith('/'):
        return None
    for key in field[1:].split('/'):
        key = key.replace('~1','/').replace('~0','~')
        if not isinstance(value,dict) or key not in value:
            return None
        value = value[key]
    return value

def same(a,b):
    return type(a) is type(b) and a==b

def identity(log,policy):
    uid = body_value(log,'/user_id')
    return (log['method']=='GET' and log['path']==policy['identity_path'] and log['status']==200
            and not log['query'] and type(uid) in (str,int) and uid!='' and bool(log['session']))

def classify_idor(c,logs,p):
    if any(i not in logs for i in referenced(c)):
        return result('unknown','EVIDENCE_MISSING')
    who,owner,baseline,access = (logs[c[k]] for k in ('requester_identity','owner_identity','owner_access','access'))
    if not identity(who,p) or not identity(owner,p):
        return result('unknown','IDENTITY_MISSING_OR_WRONG_TYPE')
    if (who['target_id']!=access['target_id'] or owner['target_id']!=baseline['target_id']
            or who['session']!=access['session'] or owner['session']!=baseline['session']):
        return result('unknown','SESSION_OR_IDENTITY_TARGET_MISMATCH')
    requester,owner_id = body_value(who,'/user_id'),body_value(owner,'/user_id')
    if type(requester) is not type(owner_id):
        return result('unknown','IDENTITY_TYPE_MISMATCH')
    if not p['owner_only']:
        return result('unknown','POLICY_REQUIRED')
    if (access['method']!='GET' or baseline['method']!='GET' or access['path']!=baseline['path']
            or access['target_id']!=baseline['target_id'] or access['query']!=baseline['query']):
        return result('unknown','RESOURCE_MISMATCH')
    resource = body_value(baseline,p['resource_field'])
    if resource is None or not same(resource,body_value(access,p['resource_field'])):
        return result('unknown','RESOURCE_MISMATCH')
    owners = [body_value(log,p['owner_field']) for log in (baseline,access)]
    if any(v is None or not same(owner_id,v) for v in owners):
        return result('unknown','OWNER_MISSING_OR_MISMATCH')
    if same(requester,owner_id):
        return result('not_confirmed','SAME_USER')
    if baseline['status']!=200:
        return result('unknown','BASELINE_NOT_SUCCESSFUL')
    if access['status'] in (401,403,404):
        return result('not_confirmed','ACCESS_DENIED')
    protected = [(f,body_value(baseline,f)) for f in p['protected_fields']]
    if access['status']==200 and all(type(v) in (str,int,float,bool) and v!='' and v!='[REDACTED]' and same(v,body_value(access,f)) for f,v in protected):
        return result('confirmed','OWNER_ONLY_DATA_RETURNED')
    return result('unknown','PROTECTED_DATA_NOT_ESTABLISHED')

DB_ERROR = re.compile(r'database|sql(?:state|syntax|exception)|query failed',re.I)

def classify_sqli(c,logs):
    if any(i not in logs for i in referenced(c)):
        return result('unknown','EVIDENCE_MISSING')
    suspect,base = logs[c['suspicious']],logs[c['baseline']]
    if (suspect['method']!='GET' or suspect['method']!=base['method'] or suspect['path']!=base['path']
            or suspect['session']!=base['session'] or suspect['target_id']!=base['target_id']):
        return result('unknown','BASELINE_NOT_COMPARABLE')
    parameter = c['parameter']
    sv = [v for k,v in suspect['query'] if k==parameter]
    bv = [v for k,v in base['query'] if k==parameter]
    other = lambda log: sorted((k,v) for k,v in log['query'] if k!=parameter)
    if len(sv)!=1 or len(bv)!=1 or other(suspect)!=other(base):
        return result('unknown','BASELINE_NOT_COMPARABLE')
    if "'" not in unquote(sv[0]) or "'" in unquote(bv[0]) or '[REDACTED]' in (sv[0],bv[0]):
        return result('unknown','INPUT_DIFFERENCE_NOT_ESTABLISHED')
    if suspect['status']==base['status'] and suspect['body']==base['body']:
        return result('unknown','ERROR_ALSO_IN_BASELINE')
    error = body_value(suspect,'/error')
    if suspect['status']==500 and isinstance(error,str) and DB_ERROR.search(error) and base['status']<400:
        return result('suspicious','DIFFERENTIAL_DATABASE_ERROR')
    return result('unknown','SQLI_NOT_ESTABLISHED')

def classify(c,logs,p):
    return classify_idor(c,logs,p) if c['kind']=='idor' else classify_sqli(c,logs)
