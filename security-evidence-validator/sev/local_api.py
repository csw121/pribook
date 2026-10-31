import hmac
import os
from http.server import BaseHTTPRequestHandler,HTTPServer
from .common import loads,canonical,SevError
from .ai_result_validator import verify
from .report_generator import render

def handler_class(token):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def respond(self,status,value):
            data=canonical(value).encode();self.send_response(status)
            self.send_header('Content-Type','application/json; charset=utf-8')
            self.send_header('Content-Length',str(len(data)));self.send_header('Cache-Control','no-store')
            self.end_headers();self.wfile.write(data)
        def do_POST(self):
            if self.headers.get('Origin') or not hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+token):
                self.respond(403,{'error':'API_FORBIDDEN'});return
            try:
                if self.headers.get('Transfer-Encoding'):raise ValueError()
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=2_000_000 or self.headers.get_content_type()!='application/json':raise ValueError()
                self.connection.settimeout(10)
                bundle=loads(self.rfile.read(length).decode())
                if not isinstance(bundle,dict) or set(bundle)!={'evidence','manifest','analysis'}:raise ValueError()
                checked=verify(**bundle)
                if self.path=='/verify':self.respond(200,checked)
                elif self.path=='/report':
                    md,html=render(**bundle,saved=checked)
                    self.respond(200,{'markdown':md,'html':html,'human_review_required':True})
                else:self.respond(404,{'error':'API_NOT_FOUND'})
            except SevError as e:self.respond(422,{'error':e.code})
            except (ValueError,UnicodeError,OSError,TypeError):self.respond(400,{'error':'API_INVALID_REQUEST'})
    return Handler

def serve(port):
    token=os.environ.get('SEV_API_TOKEN','')
    if len(token)<32 or not token.isascii():
        raise SevError('API_TOKEN_REQUIRED','SEV_API_TOKEN 로컬 환경변수에 최소 32자 ASCII 무작위 토큰을 설정하세요.')
    with HTTPServer(('127.0.0.1',port),handler_class(token)) as server:
        server.serve_forever()
