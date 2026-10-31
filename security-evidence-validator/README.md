# Security Evidence Validator — 복구본 1.0.1

이전 클라우드 환경에 접근할 수 없어 **대화에 남은 코드와 요구사항을 바탕으로 다시 구성한 복구본**입니다. 이전 ZIP을 회수한 것이 아니며 파일의 바이트 단위 동일성을 주장하지 않습니다. 이전 테스트 이력과 별도로 현재 복구본을 다시 검증합니다. 기존 Java 저장소 파일을 지우지 않고 `security-evidence-validator/` 하위에 구성했습니다.

허가된 점검에서 **이미 확보한** HTTP 기록을 오프라인 비교하고 로컬 Ollama의 주장을 Python으로 검증합니다. 검증 통과 후에만 Markdown/HTML/선택적 DOCX 보고서 **초안**을 생성합니다. 자동 검증은 최종 제출 승인이 아니며 원본 진위·권한 정책·영향을 사람이 검토해야 합니다. 대상 스캔·요청 재현·무차별 대입·외부 상용 AI 호출 기능은 없습니다.

## Windows 11 설치

Python 3.13 이상, 로컬 Ollama와 `qwen3.5:9b`를 사용합니다. 검증기는 GPU가 필요하지 않습니다. 두 PC의 VRAM 적합성은 실제 추론으로 확인하세요.

```powershell
cd Security-Evidence-Validator
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

PowerShell 활성화가 제한되면 정책 변경 없이 `.\.venv\Scripts\python.exe main.py ...`처럼 직접 실행할 수 있습니다. Git 저장소를 받은 경우 먼저 `security-evidence-validator` 폴더로 들어갑니다. 경로에 공백이 있으면 따옴표를 사용하세요. Linux에서는 Python 3.13 venv를 만들고 `source .venv/bin/activate`를 사용합니다.

## AI 없이 가상 로그로 전체 흐름 검증

```powershell
python main.py analyze --input examples/synthetic_http_logs
python main.py verify --analysis examples/synthetic_analysis.json
python main.py report --analysis examples/synthetic_analysis.json --docx
python main.py document-analyze --input output/report/draft.docx
```

예제 분석은 **테스트용 정답 fixture이며 실제 AI 추론 결과가 아닙니다**. 가상 소유자 전용 정책 하에서 도서/문서 자원 접근을 검증합니다. 실제 서비스에 정책을 그대로 적용해 취약점을 확정하지 마세요. `output/`에 정규화 로그·검증 결과·초안이 저장됩니다.

정상 검색에도 동일 오류가 발생하는 SQLi 사례:

```powershell
python main.py verify --manifest examples/sqli_rules.json --analysis examples/synthetic_sqli_analysis.json --verification output/sqli_verification.json
```

이 명령의 예상 결과는 `blocked`, 종료 코드 2입니다. 두 요청에 동일 DB 오류가 있으므로 원인은 불명입니다. 의심 요청에만 오류가 있어도 `suspicious`로 남겨 사람의 검토를 요구하며 SQLi 성공을 확정하지 않습니다.

## 실제 로컬 Ollama

```powershell
ollama pull qwen3.5:9b
# Ollama가 실행 중이 아니면 별도 창에서 ollama serve
python main.py doctor
python main.py analyze --input examples/synthetic_http_logs
python main.py ai-analyze
python main.py verify
python main.py report --docx
```

`config/settings.json`의 기본값은 `http://127.0.0.1:11434`, context 8192, temperature 0.2, timeout 120초입니다. Thinking OFF, stream OFF, JSON Schema를 전달합니다. context는 1024~16384 범위에서 설정하며 메모리/추론 실패 시 4096 등으로 낮추세요. 실제 Qwen 응답 품질, 학교 RTX A2000 12GB/노트북 RTX4060 8GB 처리량은 로컬 확인이 필요합니다. doctor는 목록만 확인하므로 추론 성공을 의미하지 않습니다. coverage 누락을 자동으로 채워 통과시키지 않습니다.

## 입력·검증 계약

- UTF-8 파일당 **단일 텍스트 요청 + 단일 최종 응답**, 헤더/본문 사이 빈 줄. CRLF/LF, HTTP/1.0·1.1 및 사람이 준비한 HTTP/2 텍스트 상태행을 지원합니다. Host 또는 절대 HTTP(S) URL 필수입니다.
- gzip/chunked 해제는 사용자가 미리 수행합니다. HAR/ZAP/Burp 직접 내보내기, 바이너리 HTTP/2, 요청 본문·Authorization 기반 신원 증명은 지원하지 않습니다. JSON 외 응답은 본문 해시만 저장하므로 원문 오류 문자열의 판정에 쓰지 않습니다.
- `analyze --pattern "log_*.txt"`로 파일명 패턴을 변경합니다. 파일 stem이 로그 ID이며 하나의 배치로 읽습니다. 파일당 2MB, JSON 입력 10MB 한도. 중복 JSON 키와 NaN/Infinity/넘침 수를 거부합니다.
- evidence/manifest/analysis/settings의 JSON Schema는 `sev/*.schema.json`입니다. manifest는 **분석자가 직접** 후보·필수 증거·권한 정책을 정하며 AI가 수정하도록 허용하지 않습니다. 기본 예제의 identity_path는 query 없는 `GET /api/me`, status 200, JSON `/user_id`입니다.
- IDOR 후보는 requester_identity, owner_identity, owner_access, access 로그를 명시합니다. 신원·세션·API 대상·경로/쿼리·자원 ID·소유권·다른 사용자·소유자 전용 정책·보호 필드 반환을 모두 확인합니다. 신원/소유권이 없으면 `None != owner_id` 비교를 하지 않고 중단합니다. 역할 예외/공유 정책/조작된 원본의 진위를 자동 추론하지 않습니다.
- resource_field/owner_field/protected_fields는 `/data/owner_id` 같은 JSON Pointer를 사용합니다. 보호 필드는 스칼라 잎 필드로 명시합니다. 가려진 값을 보호 데이터 반환 증거로 사용하지 않습니다.
- AI는 각 후보와 정확한 evidence_ids, classification, claims를 반환합니다. 참조 로그의 method/path/status/target_id, query/{번호}/name·value, 모든 body 스칼라 잎 필드를 정확한 타입/값으로 주장해야 합니다. `body/owner_id`처럼 JSON Pointer escaping을 씁니다. 문자열/숫자/불리언/null을 구별하고 int/float도 엄격히 구별합니다. 임의 서버 구현 서술·미지원 필드·누락·중복은 차단합니다.

## 보고서 게이트와 개인정보

검증 결과는 입력 데이터·정책/후보·AI 분석·엔진 버전의 SHA-256 지문, run_id, 생성 시각을 기록합니다. 보고서 생성 시 **항상 재검증**하고 저장된 상태·카운트·판정과 비교합니다. 오래된 입력·변조된 통과 상태·검증 오류·재검토 항목은 보고서를 차단합니다. 최종 승인 워크플로/전자서명은 제공하지 않고 `human_review_required`는 항상 true입니다. 생성이 차단되어도 이전 초안 파일은 남을 수 있으니 입력 지문을 확인하세요.

쿠키/Authorization/요청 본문은 정규화 출력에 넣지 않습니다. 세션은 배치마다 다른 비밀키의 HMAC으로만 비교하며 다른 배치끼리 비교하면 안 됩니다. 민감 key/query(password/token/cookie/email/phone 등)를 가리지만 **임의 문자열의 모든 개인정보를 탐지하지는 않습니다**. 경로·일반 응답·오류 문자열에는 민감정보가 남을 수 있어 logs.json, manifest, AI 결과 역시 비공개 로컬 자료로 취급하세요. 로컬 Ollama에는 정규화된 증거가 전달됩니다.

`private/`, `output/`, `.venv/`는 Git 제외입니다. 원본 HTTP 로그·HWP·AI 결과를 클라우드로 업로드하지 마세요. 오류 메시지에 원본 값/스택을 출력하지 않습니다. Ollama는 명시적인 loopback IP만 허용하고 proxy·redirect로 외부에 보내지 않습니다. 의존성 설치/모델 다운로드만 별도 인터넷 접근이 필요합니다. 대회 사용 가능 여부는 대회 규정을 확인하세요.

## 추가 안내

- [DOCX/한글 로컬 처리](docs/DOCUMENTS.md): HWP/PDF 직접 파싱·HWP 생성은 미구현.
- [Open WebUI와 로컬 API](docs/OPEN_WEBUI.md): 서버 측 Tool 준비; 실제 Open WebUI 연동 미검증.
- [검증 및 복구 기록](docs/VALIDATION.md): 현재 복구본 테스트 결과와 제한.
- [학교 PC 원본과 병합](docs/MERGING.md): 비공개 원본을 로컬에서 비교하고 어댑터·회귀 테스트로 병합.

`python main.py --help`와 각 명령의 `--help`로 입출력 경로를 확인하세요. 종료 코드: 0 성공, 2 차단/입력/환경 오류, 130 중단. 이식용 ZIP은 `python tools/package_project.py --output 경로/프로젝트.zip`으로 생성할 수 있습니다. 내부 경로는 파일 배포 서비스의 다운로드 링크가 아니므로 별도로 파일을 전달해야 합니다.
