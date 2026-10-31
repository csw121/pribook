# Open WebUI 연동 준비

실제 Open WebUI 설치 환경에서는 시험하지 않았습니다. CLI를 먼저 검증하세요. 모델 이름은 **Security Evidence Analyst**, 기반은 `qwen3.5:9b`입니다. `sev/ollama_client.py`의 RULES를 모델 규칙으로 참고하되 프롬프트가 검증기를 대신하지 않습니다.

```powershell
$env:SEV_API_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
python main.py serve
```

토큰은 로컬 프로세스 환경변수로만 주입합니다. 채팅/공개 설정에 노출하지 마세요. 검증기는 **127.0.0.1:8765**에만 바인딩합니다. 같은 토큰을 Open WebUI 서버 측 환경에도 주입하고 `integrations/open_webui_tool.py`를 해당 설치의 사용자 Tool로 수동 등록합니다. 버전별 등록 방법은 설치 버전의 공식 문서를 따릅니다.

검증기와 Open WebUI 백엔드가 같은 PC·네트워크 네임스페이스에서 실행되어야 합니다. 컨테이너의 127.0.0.1은 호스트 주소가 아니며 Docker 연결은 미검증입니다. API를 외부 공개하는 방법은 제공하지 않습니다. 브라우저 Origin 요청은 거부하므로 프런트엔드에서 직접 호출하지 않습니다.

`POST /verify`와 `POST /report`는 Authorization Bearer 토큰 및 JSON `{ "evidence": ..., "manifest": ..., "analysis": ... }` bundle을 받습니다. 전자는 검증 결과만 반환하고 후자는 현재 bundle을 재검증해 통과한 초안만 반환합니다. 임의 파일 경로/대상 요청 기능은 없습니다. blocked/오류면 보고서로 진행하지 않습니다. 최종 제출에는 여전히 사람의 승인이 필요합니다.
