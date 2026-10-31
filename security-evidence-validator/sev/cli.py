import argparse
import sys
from pathlib import Path
from .common import SevError,read_json,write_json,write_text
from .validation import validate
from .http_parser import analyze_directory
from .ollama_client import analyze,local_request
from .ai_result_validator import verify
from .report_generator import render
from .documents import inspect_docx,docx_bytes

def parser():
    p=argparse.ArgumentParser(description='Security Evidence Validator — 로컬 증거 검토')
    sub=p.add_subparsers(dest='command',required=True)
    d=sub.add_parser('doctor');d.add_argument('--settings',default='config/settings.json')
    a=sub.add_parser('analyze');a.add_argument('--input',required=True);a.add_argument('--pattern',default='*.http');a.add_argument('--settings',default='config/settings.json');a.add_argument('--output',default='output/logs.json')
    for name in ('ai-analyze','verify','report'):
        s=sub.add_parser(name);s.add_argument('--logs',default='output/logs.json');s.add_argument('--manifest',default='config/validation_rules.json');s.add_argument('--analysis',default='output/ai_result.json')
        if name=='ai-analyze':s.add_argument('--settings',default='config/settings.json')
        else:s.add_argument('--verification',default='output/verification.json')
        if name=='report':s.add_argument('--output-dir',default='output/report');s.add_argument('--docx',action='store_true')
    s=sub.add_parser('document-analyze');s.add_argument('--input',required=True);s.add_argument('--output',default='output/document_structure.json');s.add_argument('--include-local-text',action='store_true')
    t=sub.add_parser('ai-text');t.add_argument('--input',required=True);t.add_argument('--settings',default='config/settings.json');t.add_argument('--encoding',choices=['utf-8-sig','utf-16','cp949'],default='utf-8-sig');t.add_argument('--output',default='output/text_review.json');t.add_argument('--markdown',default='output/text_review.md')
    s=sub.add_parser('serve');s.add_argument('--port',type=int,default=8765)
    return p

def execute(args):
    if args.command=='ai-text':
        from .text_analyzer import analyze_text,render_review
        result=analyze_text(args.input,read_json(args.settings),args.encoding,progress=lambda current,total: print(f'TXT 분석 중: {current}/{total}',flush=True),notice=lambda message: print(message,flush=True))
        write_json(args.output,result);write_text(args.markdown,render_review(result))
        print(f"TXT {len(result['sources'])}개 / {len(result['reviews'])}개 조각 검토 완료 / 인용 미확인 {result['quote_review_count']}건. 결과는 미검증 자료이며 보고서 게이트는 blocked입니다.");return 0
    if args.command=='doctor':
        settings=validate(read_json(args.settings),'settings')
        print('Python '+sys.version.split()[0]+'; jsonschema 설치됨; 대상 HTTP 요청 기능 없음')
        tags=local_request(settings['ollama_url'],'/api/tags',timeout=min(settings['timeout'],10))
        if not isinstance(tags,dict) or not isinstance(tags.get('models'),list):raise SevError('OLLAMA_TAGS_INVALID','모델 목록이 올바르지 않습니다.')
        if not any(isinstance(m,dict) and m.get('name')==settings['model'] for m in tags['models']):raise SevError('MODEL_MISSING','로컬 Ollama에 설정 모델이 필요합니다.')
        print('Ollama 연결 및 모델 설치 확인; 실제 추론은 ai-analyze로 확인하세요.');return 0
    if args.command=='analyze':
        settings=validate(read_json(args.settings),'settings');data=analyze_directory(args.input,args.pattern,settings['session_cookie'])
        validate(data,'evidence');write_json(args.output,data);print(f"로그 {len(data['logs'])}개 정규화 완료. 결과는 로컬 민감자료로 보관하세요.");return 0
    if args.command=='document-analyze':
        write_json(args.output,inspect_docx(args.input,args.include_local_text));print('로컬 DOCX 구조 분석 완료');return 0
    if args.command=='serve':
        from .local_api import serve
        serve(args.port);return 0
    evidence=read_json(args.logs);manifest=read_json(args.manifest)
    if args.command=='ai-analyze':
        write_json(args.analysis,analyze(evidence,manifest,read_json(args.settings)));print('AI 응답 저장 완료. 아직 미검증 상태입니다. verify를 실행하세요.');return 0
    analysis=read_json(args.analysis)
    if args.command=='verify':
        try:checked=verify(evidence,manifest,analysis)
        except Exception:
            write_json(args.verification,{'status':'blocked','error':'VERIFIER_FAILED','human_review_required':True});raise
        write_json(args.verification,checked)
        print(f"{checked['status']}: 일치 {checked['passed_checks']}, 재검토 {checked['review_count']}; 최종 사람 승인 필요")
        return 0 if checked['status']=='passed' else 2
    md,html=render(evidence,manifest,analysis,read_json(args.verification));out=Path(args.output_dir)
    write_text(out/'draft.md',md);write_text(out/'draft.html',html)
    if args.docx:(out/'draft.docx').write_bytes(docx_bytes(md))
    print('보고서 초안 저장 완료. 최종 제출에는 사람의 승인이 필요합니다.');return 0

def main(argv=None):
    args=parser().parse_args(argv)
    try:return execute(args)
    except SevError as e:print(f'{e.code}: {e.message}',file=sys.stderr);return 2
    except KeyboardInterrupt:return 130
    except (OSError,ValueError,TypeError,RecursionError,OverflowError):
        print('OPERATION_FAILED: 파일·설정·입력·실행 환경을 확인하세요. 원본 값은 출력하지 않습니다.',file=sys.stderr);return 2
