import html
import re
from .report_gate import gate
from .evidence_validator import referenced

def render(evidence,manifest,analysis,saved):
    checked=gate(evidence,manifest,analysis,saved)
    logs={l['id']:l for l in evidence['logs']}
    numbers={l['id']:i+1 for i,l in enumerate(evidence['logs'])}
    lines=['# 보안 점검 보고서 초안','','검토 상태: 자동 사실 검증 통과 / 사람의 최종 승인 필요',
           '이 문서는 최종 제출 승인서가 아닙니다. 원본 진위·권한 정책을 사람이 확인해야 합니다.',
           '',f"입력 지문: `{checked['input_hash']}`",'']
    for index,c in enumerate(manifest['candidates'],1):
        decision=checked['decisions'][c['id']];confirmed=decision['classification']=='confirmed'
        lines += [f'## {index}. '+('소유자 전용 자원 접근 증거' if c['kind']=='idor' else 'SQL 오류 비교'),'',
                  f"- 취약점 분류: {c['kind'].upper()} / {decision['classification']}",
                  f'- 점검 대상: TARGET-{index:03d} (익명)',
                  '- 발견 경위: 분석자가 제공한 기존 HTTP 기록의 오프라인 비교',
                  '- 확인된 사실: 필수 요청·응답 주장이 정규화 증거와 일치함',
                  '- 의심되는 취약점: '+('제공된 소유자 전용 정책 하에서 IDOR 증거 확인' if confirmed else '취약점 확인되지 않음'),
                  '- 실제 확인된 영향: '+('다른 사용자 세션에서 동일 자원의 보호 필드가 반환됨' if confirmed else '보호 정보 접근 성공 입증되지 않음'),
                  '- 확인되지 않은 영향/검증되지 않은 주장: 대량 유출, 관리자 권한, 서버 장악, 서버 내부 구현',
                  '- 위험도 평가: 데이터 민감도와 업무 범위에 대한 사람의 평가 필요',
                  '- 개선 권고: '+('요청마다 서버에서 소유권·권한 검증 및 회귀 테스트' if c['kind']=='idor' else '오류 원인 점검과 매개변수화된 쿼리 사용'),
                  '- 추가 검증 필요 사항: 원본 진위, 공유·역할 예외, 정책 적용 범위, 실제 업무 영향',
                  '- 사람이 승인한 최종 내용: 없음','','### 관찰된 HTTP 요청·응답 및 수행 기록 기반 재현','',
                  '아래는 제공된 기록의 요약이며 프로그램이 대상에 요청을 보내지는 않았습니다.']
        for lid in referenced(c):
            log=logs[lid];path=re.sub(r'/[^/]+','/[segment]',log['path'])
            lines.append(f"- 증거 {numbers[lid]:03d}: {log['method']} {path} → HTTP {log['status']}; 원본을 로컬에서 재검토")
        lines += ['','새 요청이나 수행되지 않은 절차를 재현 단계에 추가하지 않았습니다.','']
    md='\n'.join(lines)
    doc='<!doctype html><html lang="ko"><meta charset="utf-8"><title>보고서 초안</title><body><pre>'+html.escape(md)+'</pre></body></html>'
    return md,doc
