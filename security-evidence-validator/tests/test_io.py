import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from contextlib import redirect_stdout,redirect_stderr
from sev.common import SevError,loads,read_json,write_json
from sev.http_parser import parse_http,analyze_directory
from sev.ai_result_validator import verify
from sev.report_generator import render
from sev.documents import docx_bytes,inspect_docx
from sev.ollama_client import local_url
from sev.cli import main
from tests.support import ROOT,fixture

class ParserTests(unittest.TestCase):
    def raw(self,body='{"id":7}'):
        return 'GET /api/items/7?token=never-share HTTP/1.1\r\nHost: synthetic.invalid\r\nCookie: session=secret-cookie\r\nAuthorization: Bearer secret-auth\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n'+body
    def test_crlf_redaction(self):
        l=parse_http(self.raw('{"password":"secret-pass","nested":{"token":"secret-token"}}'),'01',b'salt');text=json.dumps(l)
        for secret in ['secret-cookie','secret-auth','secret-pass','secret-token','never-share']:self.assertNotIn(secret,text)
        self.assertEqual(l['query'][0][1],'[REDACTED]');self.assertEqual(l['status'],200)
    def test_session_batch(self):
        a=parse_http(self.raw(),'a',b'salt');b=parse_http(self.raw(),'b',b'salt');c=parse_http(self.raw(),'c',b'other')
        self.assertEqual(a['session'],b['session']);self.assertNotEqual(a['session'],c['session'])
    def test_invalid_json(self):self.assertRaises(SevError,parse_http,self.raw('{bad'),'01',b'salt')
    def test_duplicate_json(self):self.assertRaises(SevError,parse_http,self.raw('{"id":1,"id":2}'),'01',b'salt')
    def test_multiple_responses(self):self.assertRaises(SevError,parse_http,self.raw()+'\nHTTP/1.1 500 Bad\n\n','01',b'salt')
    def test_missing_response(self):self.assertRaises(SevError,parse_http,'GET / HTTP/1.1\n\n','01',b'salt')
    def test_missing_target(self):self.assertRaises(SevError,parse_http,self.raw().replace('Host: synthetic.invalid\r\n',''),'01',b'salt')
    def test_plaintext_hashed(self):
        l=parse_http(self.raw().replace('application/json','text/plain').replace('{"id":7}','sensitive plaintext'),'01',b'salt')
        self.assertNotIn('sensitive plaintext',json.dumps(l));self.assertIn('text_sha256',l['body'])
    def test_url_credentials(self):self.assertRaises(SevError,parse_http,self.raw().replace('/api/items/7?token=never-share','http://u:p@synthetic.invalid/'),'01',b'salt')
    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as d:self.assertRaises(SevError,analyze_directory,d)
    def test_malformed_json_and_nonfinite(self):
        for text in ('{"a":1,"a":2}','{"a":NaN}','not json','{"a":1e999}'):self.assertRaises(SevError,loads,text)

class ReportingTests(unittest.TestCase):
    def test_formats_and_structure(self):
        e,m,a=fixture();md,html=render(e,m,a,verify(e,m,a))
        self.assertIn('사람의 최종 승인 필요',md);self.assertIn('증거 004',md);self.assertNotIn('SYNTHETIC protected note',md);self.assertNotIn('attacker-synthetic',html)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'report.docx';p.write_bytes(docx_bytes(md));r=inspect_docx(p)
            self.assertGreater(len(r['headings']),0);self.assertEqual(r['tables_rows_cell_counts'],[])
    def test_hallucination_blocks(self):
        e,m,a=fixture();a['findings'][0]['claims'][0]['value']='DELETE';self.assertRaises(SevError,render,e,m,a,verify(e,m,a))
    def test_forged_pass_blocks(self):
        e,m,a=fixture();r=verify(e,m,a);a['findings'][0]['classification']='unknown';r['status']='passed';self.assertRaises(SevError,render,e,m,a,r)
    def test_docx_tables_images(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'local.docx'
            with zipfile.ZipFile(p,'w') as z:
                z.writestr('word/document.xml','<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:tbl><w:tr><w:tc/><w:tc/></w:tr></w:tbl></w:body></w:document>');z.writestr('word/media/test.png',b'fake')
            r=inspect_docx(p);self.assertEqual(r['tables_rows_cell_counts'],[[2]]);self.assertEqual(r['images'],1)
    def test_entity_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'bad.docx'
            with zipfile.ZipFile(p,'w') as z:z.writestr('word/document.xml','<!DOCTYPE x [<!ENTITY evil "secret">]><x>&evil;</x>')
            self.assertRaises(SevError,inspect_docx,p)
    def test_hwp_pdf_unsupported(self):
        self.assertRaises(SevError,inspect_docx,'private.hwp');self.assertRaises(SevError,inspect_docx,'private.pdf')

class CLITests(unittest.TestCase):
    def run_main(self,args):
        with redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()):return main(args)
    def test_full_pipeline(self):
        with tempfile.TemporaryDirectory() as d:
            logs=str(Path(d)/'logs.json');a=str(ROOT/'examples/synthetic_analysis.json');m=str(ROOT/'config/validation_rules.json');v=str(Path(d)/'v.json');out=str(Path(d)/'report')
            self.assertEqual(self.run_main(['analyze','--input',str(ROOT/'examples/synthetic_http_logs'),'--settings',str(ROOT/'config/settings.json'),'--output',logs]),0)
            opts=['--logs',logs,'--manifest',m,'--analysis',a,'--verification',v]
            self.assertEqual(self.run_main(['verify']+opts),0);self.assertEqual(self.run_main(['report']+opts+['--output-dir',out,'--docx']),0);self.assertTrue((Path(out)/'draft.docx').exists())
            e=read_json(logs);e['logs'][0]['status']=500;write_json(logs,e)
            self.assertEqual(self.run_main(['report']+opts+['--output-dir',str(Path(d)/'blocked')]),2);self.assertFalse((Path(d)/'blocked').exists())
    def test_sqli_blocks(self):
        with tempfile.TemporaryDirectory() as d:
            e,_,_=fixture();p=Path(d)/'logs.json';write_json(p,e)
            code=self.run_main(['verify','--logs',str(p),'--manifest',str(ROOT/'examples/sqli_rules.json'),'--analysis',str(ROOT/'examples/synthetic_sqli_analysis.json'),'--verification',str(Path(d)/'v.json')])
            self.assertEqual(code,2);self.assertEqual(read_json(Path(d)/'v.json')['status'],'blocked')
    def test_malformed_no_report(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'bad.json';p.write_text('{bad');self.assertEqual(self.run_main(['verify','--logs',str(p)]),2)

class LocalOnlyTests(unittest.TestCase):
    def test_remote_rejected(self):
        for url in ['https://api.example.com','http://example.com:11434','http://127.0.0.1:11434/path','http://u:p@127.0.0.1:11434','http://127.0.0.1:11434?x=1','http://localhost:11434']:self.assertRaises(SevError,local_url,url)
    def test_loopback_accepted(self):self.assertEqual(local_url('http://127.0.0.1:11434/'),'http://127.0.0.1:11434')
