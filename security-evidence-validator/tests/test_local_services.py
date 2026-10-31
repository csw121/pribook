import json
import threading
import unittest
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler,HTTPServer
from unittest.mock import patch
from sev.ollama_client import analyze,local_request
from sev.local_api import handler_class
from sev.common import canonical,read_json,SevError
from tests.support import ROOT,fixture

class RunningServer:
    def __init__(self,handler):self.server=HTTPServer(('127.0.0.1',0),handler)
    def __enter__(self):
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        return 'http://127.0.0.1:'+str(self.server.server_port)
    def __exit__(self,*args):self.server.shutdown();self.server.server_close();self.thread.join()

class OllamaProtocolTests(unittest.TestCase):
    def test_structured_roundtrip(self):
        e,m,a=fixture();received={}
        class Fake(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                received.update(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
                data=canonical({'done':True,'response':canonical(a)}).encode();self.send_response(200);self.end_headers();self.wfile.write(data)
        with RunningServer(Fake) as url:
            settings=read_json(ROOT/'config/settings.json');settings['ollama_url']=url;self.assertEqual(analyze(e,m,settings),a)
        self.assertFalse(received['stream']);self.assertFalse(received['think']);self.assertEqual(received['options']['temperature'],0.2);self.assertIn('properties',received['format']);self.assertNotIn('attacker-synthetic',received['prompt'])
    def test_redirect_blocked(self):
        class Redirect(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                self.send_response(302);self.send_header('Location','https://example.com/leak');self.end_headers()
        with RunningServer(Redirect) as url:self.assertRaises(SevError,local_request,url,'/api/tags')
    def test_incomplete_response(self):
        e,m,a=fixture()
        with patch('sev.ollama_client.local_request',return_value={'done':False,'response':canonical(a)}):self.assertRaises(SevError,analyze,e,m,read_json(ROOT/'config/settings.json'))

class LocalAPITests(unittest.TestCase):
    token='synthetic-test-token-'+'x'*32
    def post(self,url,path,bundle,token=None,origin=None):
        headers={'Content-Type':'application/json','Authorization':'Bearer '+(token or self.token)}
        if origin:headers['Origin']=origin
        request=urllib.request.Request(url+path,data=canonical(bundle).encode(),headers=headers)
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=5) as response:return json.loads(response.read())
    def test_verify_and_report(self):
        e,m,a=fixture();bundle={'evidence':e,'manifest':m,'analysis':a}
        with RunningServer(handler_class(self.token)) as url:
            self.assertEqual(self.post(url,'/verify',bundle)['status'],'passed');self.assertTrue(self.post(url,'/report',bundle)['human_review_required'])
    def test_auth_and_origin(self):
        e,m,a=fixture();bundle={'evidence':e,'manifest':m,'analysis':a}
        with RunningServer(handler_class(self.token)) as url:
            for token,origin in [('wrong',None),(self.token,'https://untrusted.invalid')]:
                with self.assertRaises(urllib.error.HTTPError) as caught:self.post(url,'/verify',bundle,token,origin)
                self.assertEqual(caught.exception.code,403)
    def test_uncertain_report_blocks(self):
        e,m,a=fixture();a['findings'][0]['classification']='unknown'
        with RunningServer(handler_class(self.token)) as url:
            with self.assertRaises(urllib.error.HTTPError) as caught:self.post(url,'/report',{'evidence':e,'manifest':m,'analysis':a})
            self.assertEqual(caught.exception.code,422)
