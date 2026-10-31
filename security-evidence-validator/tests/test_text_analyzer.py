import copy
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path
from contextlib import redirect_stdout,redirect_stderr
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler,HTTPServer
from sev.common import SevError,canonical,read_json
from sev.text_analyzer import analyze_text,read_sources,redact,render_review
from sev.ai_result_validator import verify
from sev.report_gate import gate
from sev.cli import main
from tests.support import ROOT,fixture

REVIEW={'summary':'동료가 작성한 가상 보안 분석 자료입니다.','claims':[{'claim':'문서가 접근통제 문제를 주장함','quote':'다른 사용자 자료가 반환되었다.','assessment':'needs_original_evidence','reason':'원본 HTTP 요청·응답과 권한 정책 확인이 필요합니다.'}],'questions':['원본 HTTP 증거가 있나요?']}

def response(review=REVIEW):return {'done':True,'response':canonical(review)}

class TextTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'자료.txt';self.path.write_text('다른 사용자 자료가 반환되었다.\n검증되지 않은 동료의 주장이다.',encoding='utf-8')
        self.settings=read_json(ROOT/'config/settings.json')
    def analyze(self):return analyze_text(self.path,self.settings)
    def test_plain_txt_needs_no_http_or_manifest(self):
        with patch('sev.text_analyzer.local_request',return_value=response()):r=self.analyze()
        self.assertEqual(r['status'],'unverified_text_review');self.assertEqual(r['report_gate'],'blocked');self.assertTrue(r['human_review_required'])
        self.assertEqual(r['reviews'][0]['claims'][0]['character_start'],0)
    def test_hallucinated_quote_quarantined(self):
        review=copy.deepcopy(REVIEW);review['claims'][0]['quote']='없는 근거 문장'
        with patch('sev.text_analyzer.local_request',return_value=response(review)) as request:r=self.analyze()
        self.assertEqual(request.call_count,2);self.assertEqual(r['reviews'][0]['claims'],[])
        self.assertFalse(r['reviews'][0]['unmatched_claims'][0]['quote_matched'])
        self.assertNotIn('character_start',r['reviews'][0]['unmatched_claims'][0])
        self.assertEqual(r['report_gate'],'blocked');self.assertEqual(r['quote_review_count'],1)
    def test_no_confirmed_assessment_allowed(self):
        review=copy.deepcopy(REVIEW);review['claims'][0]['assessment']='confirmed'
        with patch('sev.text_analyzer.local_request',return_value=response(review)):self.assertRaises(SevError,self.analyze)
    def test_incomplete_response(self):
        with patch('sev.text_analyzer.local_request',return_value={'done':False,'response':canonical(REVIEW)}):self.assertRaises(SevError,self.analyze)
    def test_invalid_json_response(self):
        with patch('sev.text_analyzer.local_request',return_value={'done':True,'response':'not json'}):self.assertRaises(SevError,self.analyze)
    def test_masks_credentials_before_local_call(self):
        self.path.write_text('Authorization: Bearer synthetic-auth\nCookie: session=synthetic-cookie\n{"password":"synthetic-pass", "access_token":"synthetic-token"}\n다른 사용자 자료가 반환되었다.',encoding='utf-8')
        with patch('sev.text_analyzer.local_request',return_value=response()) as request:self.analyze()
        prompt=request.call_args.args[2]['prompt']
        for secret in ['synthetic-auth','synthetic-cookie','synthetic-pass','synthetic-token']:self.assertNotIn(secret,prompt)
        self.assertIn('[REDACTED]',prompt)
    def bad_review(self):
        r=copy.deepcopy(REVIEW);r['claims'][0]['quote']='원문에 없는 인용';return r
    def test_retry_repairs_exact_quote(self):
        with patch('sev.text_analyzer.local_request',side_effect=[response(self.bad_review()),response()]) as request:r=self.analyze()
        self.assertEqual(request.call_count,2);self.assertTrue(r['reviews'][0]['claims'][0]['quote_matched'])
        self.assertEqual(r['quote_retry_count'],1);self.assertEqual(r['quote_review_count'],0)
        self.assertEqual(r['reviews'][0]['initial_quote_mismatch_count'],1)
    def test_mixed_claims_keep_matched_and_separate_invalid(self):
        review=copy.deepcopy(REVIEW);bad=self.bad_review()['claims'][0];bad['claim']='다른 미확인 주장';review['claims'].append(bad)
        with patch('sev.text_analyzer.local_request',return_value=response(review)):r=self.analyze()
        self.assertEqual(len(r['reviews'][0]['claims']),1);self.assertEqual(len(r['reviews'][0]['unmatched_claims']),1)
    def test_whitespace_difference_never_counted_as_exact(self):
        review=copy.deepcopy(REVIEW);review['claims'][0]['quote']='다른  사용자 자료가 반환되었다.'
        with patch('sev.text_analyzer.local_request',return_value=response(review)):r=self.analyze()
        self.assertEqual(r['reviews'][0]['claims'],[]);self.assertEqual(r['quote_review_count'],1)
    def test_omitted_bad_claim_kept_for_review(self):
        empty={'summary':'요약','claims':[],'questions':[]}
        with patch('sev.text_analyzer.local_request',side_effect=[response(self.bad_review()),response(empty)]):r=self.analyze()
        self.assertEqual(r['quote_review_count'],1);self.assertEqual(r['reviews'][0]['claims'],[])
    def test_first_good_claim_preserved_if_retry_omits_it(self):
        first=copy.deepcopy(REVIEW);bad=self.bad_review()['claims'][0];bad['claim']='별도 주장';first['claims'].append(bad)
        empty={'summary':'요약','claims':[],'questions':[]}
        with patch('sev.text_analyzer.local_request',side_effect=[response(first),response(empty)]):r=self.analyze()
        self.assertEqual(len(r['reviews'][0]['claims']),1);self.assertEqual(r['quote_review_count'],1)
    def test_first_of_ten_chunks_mismatch_does_not_abort(self):
        self.path.write_text('가'*25000,encoding='utf-8')
        bad=self.bad_review();empty={'summary':'요약','claims':[],'questions':[]}
        with patch('sev.text_analyzer.local_request',side_effect=[response(bad),response(bad)]+[response(empty)]*9) as request:r=self.analyze()
        self.assertEqual(len(r['reviews']),10);self.assertEqual(request.call_count,11)
        self.assertEqual(r['reviews'][-1]['character_end'],25000);self.assertEqual(r['quote_review_count'],1)
    def test_unmatched_rendered_as_ai_text_not_source(self):
        with patch('sev.text_analyzer.local_request',return_value=response(self.bad_review())):r=self.analyze()
        md=render_review(r);self.assertIn('원문 불일치 주장 — 근거로 사용 금지',md)
        self.assertNotIn('문서에서 확인한 인용:',md);self.assertEqual(r['report_gate'],'blocked')
    def test_invalid_retry_json_still_fails(self):
        with patch('sev.text_analyzer.local_request',side_effect=[response(self.bad_review()),{'done':True,'response':'bad json'}]):self.assertRaises(SevError,self.analyze)
    def test_cp949(self):
        self.path.write_bytes('한글 분석 자료'.encode('cp949'))
        self.assertRaises(SevError,read_sources,self.path)
        self.assertEqual(read_sources(self.path,'cp949')[0]['text'],'한글 분석 자료')
    def test_utf16(self):
        self.path.write_bytes('한글 분석 자료'.encode('utf-16'));self.assertEqual(read_sources(self.path,'utf-16')[0]['text'],'한글 분석 자료')
    def test_empty_binary_and_hwp_rejected(self):
        for text in ('','\x00binary'):
            self.path.write_text(text);self.assertRaises(SevError,read_sources,self.path)
        self.assertRaises(SevError,read_sources,Path(self.tmp.name)/'report.hwp')
    def test_folder_accepts_uppercase_txt(self):
        (Path(self.tmp.name)/'OTHER.TXT').write_text('문서');sources=read_sources(Path(self.tmp.name));self.assertEqual(len(sources),2)
    def test_fragmented_long_line_without_truncation(self):
        self.path.write_text('가'*6000,encoding='utf-8')
        empty={'summary':'부분 문서 요약','claims':[],'questions':[]}
        with patch('sev.text_analyzer.local_request',return_value=response(empty)) as request:r=self.analyze()
        self.assertEqual(request.call_count,3);self.assertEqual(r['reviews'][0]['character_start'],0);self.assertEqual(r['reviews'][-1]['character_end'],6000)
        self.assertEqual(''.join(json.loads(call.args[2]['prompt'])['chunk'] for call in request.call_args_list),'가'*6000)
    def test_total_limit_fails_before_model(self):
        self.path.write_text('x'*170000)
        with patch('sev.text_analyzer.local_request') as request:self.assertRaises(SevError,self.analyze)
        request.assert_not_called()
    def test_remote_ollama_rejected_before_call(self):
        self.settings['ollama_url']='http://example.com:11434'
        with patch('sev.text_analyzer.local_request') as request:self.assertRaises(SevError,self.analyze)
        request.assert_not_called()
    def test_cli_writes_separate_review_files(self):
        with patch('sev.text_analyzer.local_request',return_value=response()),redirect_stdout(io.StringIO()) as out:
            code=main(['ai-text','--input',str(self.path),'--settings',str(ROOT/'config/settings.json'),'--output',str(Path(self.tmp.name)/'review.json'),'--markdown',str(Path(self.tmp.name)/'review.md')])
        self.assertEqual(code,0);self.assertNotIn('다른 사용자 자료가 반환되었다',out.getvalue())
        self.assertEqual(read_json(Path(self.tmp.name)/'review.json')['report_gate'],'blocked')
        self.assertIn('취약점 확인 또는 검증된 보고서가 아닙니다',(Path(self.tmp.name)/'review.md').read_text(encoding='utf-8'))
    def test_cli_saves_quarantined_claims_with_warning(self):
        with patch('sev.text_analyzer.local_request',return_value=response(self.bad_review())),redirect_stdout(io.StringIO()) as out:
            code=main(['ai-text','--input',str(self.path),'--settings',str(ROOT/'config/settings.json'),'--output',str(Path(self.tmp.name)/'review.json'),'--markdown',str(Path(self.tmp.name)/'review.md')])
        self.assertEqual(code,0);self.assertIn('인용 미확인 1건',out.getvalue());self.assertNotIn('원문에 없는 인용',out.getvalue())
        self.assertEqual(read_json(Path(self.tmp.name)/'review.json')['quote_review_count'],1)
        self.assertIn('원문 불일치 주장 — 근거로 사용 금지',(Path(self.tmp.name)/'review.md').read_text(encoding='utf-8'))
    def test_text_result_rejected_by_evidence_gate(self):
        e,m,a=fixture()
        with patch('sev.text_analyzer.local_request',return_value=response()):r=self.analyze()
        self.assertRaises(SevError,verify,e,m,r);self.assertRaises(SevError,gate,e,m,a,r)
    def test_untrusted_markdown_fenced(self):
        with patch('sev.text_analyzer.local_request',return_value=response()):r=self.analyze()
        r['reviews'][0]['summary']='```\n<script>untrusted</script>\n```';text=render_review(r)
        self.assertIn('````\n```\n<script>',text)

class TextHTTPTests(unittest.TestCase):
    def test_real_loopback_protocol(self):
        received={}
        class Fake(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                received.update(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
                data=canonical(response()).encode();self.send_response(200);self.end_headers();self.wfile.write(data)
        with HTTPServer(('127.0.0.1',0),Fake) as server:
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                with tempfile.TemporaryDirectory() as d:
                    path=Path(d)/'자료.txt';path.write_text('다른 사용자 자료가 반환되었다.',encoding='utf-8')
                    settings=read_json(ROOT/'config/settings.json');settings['ollama_url']=f'http://127.0.0.1:{server.server_port}'
                    result=analyze_text(path,settings)
            finally:server.shutdown();thread.join()
        self.assertEqual(result['report_gate'],'blocked');self.assertFalse(received['stream']);self.assertFalse(received['think']);self.assertEqual(received['options']['temperature'],0.2)
