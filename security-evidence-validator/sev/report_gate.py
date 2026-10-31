from .ai_result_validator import verify
from .common import SevError

def gate(evidence,manifest,analysis,saved):
    current=verify(evidence,manifest,analysis)
    keys=('schema_version','engine_version','input_hash','passed_checks','review_count','status','human_review_required','issues','decisions')
    if not isinstance(saved,dict) or not saved.get('run_id') or not saved.get('created_at') or any(saved.get(k)!=current[k] for k in keys):
        raise SevError('GATE_STALE_OR_MODIFIED','검증 결과가 현재 입력과 다릅니다. verify를 다시 실행하세요.')
    if current['status']!='passed':
        raise SevError('GATE_BLOCKED','재검토 항목이 있어 보고서 생성을 차단했습니다.')
    return current
