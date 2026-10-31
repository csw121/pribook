"""로컬 Open WebUI 서버 측 사용자 도구 예제. 실제 Open WebUI 연동은 미검증."""
import json
import os
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise ValueError('리다이렉트 차단')

class Tools:
    def verify_evidence(self,bundle_json: str) -> str:
        """evidence, manifest, analysis가 담긴 bundle JSON을 로컬 검증기로 전달합니다."""
        token=os.environ.get('SEV_API_TOKEN','')
        if len(token)<32:return 'SEV_API_TOKEN 로컬 설정이 필요합니다.'
        try:
            bundle=json.loads(bundle_json)
            req=urllib.request.Request('http://127.0.0.1:8765/verify',data=json.dumps(bundle,allow_nan=False).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+token})
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
            with opener.open(req,timeout=30) as response:return response.read(2_000_000).decode()
        except Exception:
            return '로컬 검증 실패. 프로세스·JSON·인증을 확인하고 보고서 작성을 보류하세요.'
